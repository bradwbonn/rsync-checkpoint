from cloudant import Cloudant
from flask import Flask, render_template, request, jsonify, session
import atexit
import cf_deployment_tracker
import os
import json
from passlib.hash import pbkdf2_sha256

# Emit Bluemix deployment event
cf_deployment_tracker.track()

app = Flask(__name__)

# Cloudant database definitions
main_db_name = 'rsynccheckpoint'
auth_db_name = 'rsyncauth'
client = None
main_db = None
scan_db = None

# dict to hold results of scan sync data
# Source is always first in each array, target is always second
results = dict(
    hostnames = [],
    ids = [],
    scandates = [],
    scancomplete = [],
    filecount = [],
    synchronized = 0,
    dirsize = [],
    errors = [],
    missing = 0,
    orphaned = 0,
    stale = 0
)

# Active session user name
session_user = None

# Views in main database
# Format is <view> = [<ddocname>,<viewname>,<mapfunction>,<reducefunction>]
maindb_views = dict(
    all_relations = ['_design/relationships',
                     'allrelations',
                     'function (doc) {if (doc.type === "relationship") { emit(doc.name, 1);}}',
                     None],
    all_hosts = ['_design/hosts',
                 'allhosts',
                 'function (doc) {if (doc.type === "host") { emit([doc.name, doc.ip4], 1);}}',
                 None],
    recent_scans = ['_design/scans',
                    'recentscans',
                    'function (doc) {if (doc.type === "scan") {emit([doc.hostID, doc.success, doc.started], doc.database);}}',
                    "_count"]
)

# Views in scan database(s)
# Format is <view> = [<ddocname>,<viewname>,<mapfunction>,<reducefunction>]
# MAKE SURE DDOC NAME INCLUDES LEADING "_design/"!
scandb_views = dict(
    file_types = [
        '_design/filetypes',
        'types',
        'function (doc) {if (doc.type === "file" && doc.goodscan === true) { filetype = doc.name.substr((~-doc.name.lastIndexOf(".") >>> 0) + 2); emit([doc.host, doc.relationship, filetype], doc.size); } }',
        '_stats'
    ],
    problem_files = [ 
        '_design/problemfiles',
        'problemfiles',
        'function (doc) {if (doc.type === "file" && doc.status.state !== "ok") {emit([doc.scanID,doc.path,doc.name], doc.status.detail);}}',
        '_count'
    ],
    source_files = [
        '_design/sourcefiles',
        'sourcefiles',
        'function (doc) { if (doc.type === "file" && doc.goodscan === true && doc.source === true) {emit(doc._id, doc.datemodified); }}',
        None
    ],
    check_for_delete = [
        '_design/deleted',
        'expected',
        'function (doc) { if (doc.type === "file" && doc.status.state === "ok") { emit([doc.host,doc.path,doc.name],doc.datemodified); } }',
        '_count'
    ],
    missing_files = [
        '_design/syncstate',
        'missing',
        'function (doc) {if (doc.type === "file") {emit([doc.syncpath,doc.name,doc.host],doc.size); } }',
        '_stats'
    ],
    checksums = [
        '_design/heavyscan',
        'checksums',
        'function (doc) {if (doc.type === "file" && doc.goodscan === true && doc.checksum) {emit(doc._id,doc.checksum); } }',
        None
    ],
    scanned_files = [
        '_design/files',
        'scanned',
        'function (doc) {if (doc.type === "file" && doc.goodscan === true) { emit(doc._id,doc.size); } }',
        '_stats'
    ],
    sync = [
        '_design/sync',
        'sync',
        'function (doc) { if (doc.type === "file" && doc.goodscan === true) { emit([doc.IDprefix,doc.syncIDprefix],doc.datemodified); }}',
        '_stats'
    ],
    duplicate_files = [
        '_design/duplicates',
        'duplicates',
        'function (doc) { if (doc.type === "file" && doc.goodscan === true && doc.checksum && doc.status.state === "ok") { emit([doc.name,doc.datemodified,doc.checksum,doc.size,doc.host],doc.path); } }',
        '_count'
    ],
    file_statuses = [
        '_design/statuses',
        'bystatedetail',
        'function (doc) { if (doc.type === "file" && doc.goodscan === true && doc.status) { emit([doc.status.state,doc.status.detail,doc._id],doc.size); } }',
        '_stats'
    ]
)

# Search design documents
search_indexes = dict(
    files = [
        '_design/filesearch',
        'function (doc) {if (doc.type === "file") {index("name", doc.name, {"store": true}); index("path", doc.path);}}'
    ],
    hosts = [
        '_design/hostsearch',
        'function (doc) {if (doc.type === "host") {index("hostname", doc.hostname, {"store": true});}}'
    ]
)

# Cloudant authentication information should be here, in order to avoid embedding credentials
if 'VCAP_SERVICES' in os.environ:
    vcap = json.loads(os.getenv('VCAP_SERVICES'))
    print('Found VCAP_SERVICES')
    if 'cloudantNoSQLDB' in vcap:
        creds = vcap['cloudantNoSQLDB'][0]['credentials']
        user = creds['username']
        password = creds['password']
        url = 'https://' + creds['host']
        client = Cloudant(user, password, url=url, connect=True)
        main_db = client[main_db_name]
elif os.path.isfile('vcap-local.json'):
    with open('vcap-local.json') as f:
        vcap = json.load(f)
        print('Found local VCAP_SERVICES')
        creds = vcap['services']['cloudantNoSQLDB'][0]['credentials']
        user = creds['username']
        password = creds['password']
        url = 'https://' + creds['host']
        client = Cloudant(user, password, url=url, connect=True)
        main_db = client[main_db_name]

# On Bluemix, get the port number from the environment variable PORT
# When running this app on the local machine, default the port to 8000
port = int(os.getenv('PORT', 8000))

# Check login against Cloudant database
def check_credentials(username,password):
    # Open Cloudant auth DB
    authdb = client[auth_db_name]
    # Lookup doc for username and get hash
    try:
        with Document(authdb, username) as doc:
            if pbkdf2_sha256.verify(password, doc['password']):
                return True
            else:
                return False
    # if doc doesn't exist, fail.
    except:
        return False

# *** MVP WORKAROUND ***
# hosts for test are currently HARD CODED
def get_host_IDs():
    return ["6f98988e776b10b84d4b9a37ddc94ea0","c04975184afdc984ad0c41361137bc48"]

# FUTURE TO-DO: Create admin console for managing users and/or sign-up system
# Would also automate API key generation for scan clients
# *** OUT OF SCOPE FOR MVP ***

# Get the scan database(s) for the session
# Right now this uses the first scan db it finds
def get_scan_db():
    thisview = maindb_views['recent_scans']
    result = main_db.get_view_result(thisview[0], thisview[1], reduce=False, descending=True)
    host_ids = get_host_IDs()
    if result != None:
        lastscan = result[[host_ids[0],{},{}]:[host_ids[0],None,0]]
        if (lastscan != None) and (len(lastscan) > 0):            
            host_a_db_name = lastscan[0]['value']
            # TEMP MVP WORKAROUND
            scan_db = client[host_a_db_name]
        else:
            host_a_db_name = None
        lastscan = result[[host_ids[1],{},{}]:[host_ids[1],None,0]]
        if (lastscan != None) and (len(lastscan) > 0):
            host_b_db_name = lastscan[0]['value']
            # TEMP MVP WORKAROUND
            scan_db = client[host_b_db_name]
        else:
            host_b_db_name = None
            
        return ([host_a_db_name, host_b_db_name])
        
    else:
        # logging.debug("Previous scan not found for any host.")
        return None
    pass

# If session is not logged in, present login screen, otherwise load sync status screen.
@app.route('/')
def home():
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        # TO-DO: Build current status page and display
        return render_template('status.html')

# Login form submission
@app.route('/login', methods=['POST'])
def do_login():
    
    POST_USERNAME = str(request.form['username'])
    POST_PASSWORD = str(request.form['password'])
    
    if check_credentials(POST_USERNAME, POST_PASSWORD) == True:
        session['logged_in'] = True
        session_user = POST_USERNAME
    else:
        flash('invalid login!')
    return home()

# Logout session
@app.route("/logout")
def logout():
    session['logged_in'] = False
    return home()

# Obtain the most current scan database(s)
# MVP: These will almost always be the same.
def get_scan_db(host):
    thisview = maindb_views['recent_scans']
    result = main_db.get_view_result(
        thisview[0],
        thisview[1],
        reduce=False,
        descending=True,
        include_docs=True,
        limit=1
    )
    print_local(result)
    scan_db = result

# Uses scan DB and host ID to obtain most recent scan for host
# TO-DO: Improve efficiency by reducing DB queries
def scanning_errors(host_id):
    scan_id = last_scan(host_id)
    errors = 0
    ddoc = scandb_views['problem_files'][0]
    view = scandb_views['problem_files'][1]
    result = scan_db.get_view_result(
        ddoc,
        view,
        reduce=True,
        group_level=1
        )
    errors = result[[scan_id,None,None]:[scan_id,{},{}]]['value']
    return errors

# MVP shows only basic summary stats.  later version will support drill-down into problem files

# /**  TO-DO:
#  * Endpoint to get JSON of current sync status between the two hosts
#  * <code>
#  * GET https://localhost:8000/api/syncstate
#  * </code>
#  *
#  * Response:
#  * JSON of results{}

@app.route('/api/syncstate', methods=['GET'])
def update_syncstate():
    
    # MVP: Obtain data each time.  IN future, make a separate update button to
    # force an update of this data from Cloudant. Otherwise, use cached results
    # for display in the app, and only refresh every 60 seconds maximum.
    
    # Get recent scan DB(s) # MVP: right now they're the same
    # sets global 'scan_db' variable
    get_scan_db()

    # Get last scan times for each host (and scan IDs?)
    results['ids'] = get_scan_ids()
    results['scandates'] = get_scan_times(results['ids'])
    results['scancomplete'] = are_scans_complete(results['ids'])
    
    # Get good files (matching on both hosts)
    results['synchronized'] = get_files_good()
    
    # Get orphaned files
    results['orphaned'] = get_files_orphaned()
    
    # Get files scanned count
    results['filecount'] = get_files_scanned()
    
    # Get scan error counts
    results['errors'][0] = scanning_errors(source_host) 
    results['errors'][1] = scanning_errors(target_host)
    
    # files existing on source but not destination
    results['missing'] = get_files_missiong()
    
    # "Stale" files? (These might be files existing on target but needing update)
    results['stale'] = get_files_stale()
    
    # Return summary JSON
    return jsonify(results)

@atexit.register
def shutdown():
    if client:
        client.disconnect()
        
# Enable active "log" when testing on local machine        
def print_local(output):
    if port == '8000':
        print str(output)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=port, debug=True)
