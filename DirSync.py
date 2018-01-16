from cloudant import Cloudant
from cloudant.document import Document
#import cloudant
from flask import Flask, render_template, request, jsonify, session, flash
from time import sleep
import atexit
import cf_deployment_tracker
import os
import json
from re import sub
from passlib.hash import pbkdf2_sha256

# On Bluemix, get the port number from the environment variable PORT
# When running this app on the local machine, default the port to 8000
port = int(os.getenv('PORT', 8000))

# Enable active "log" when testing on local machine        
def print_local(output):
    if port == 8000:
        print str(output)

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
# MVP WORKAROUND: Hosts are HARD-CODED!
results = dict(
    hostnames = ['Source','Target'],
    ids = ["6f98988e776b10b84d4b9a37ddc94ea0","c04975184afdc984ad0c41361137bc48"],
    scanids = [],
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
    print_local('Found VCAP_SERVICES')
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
        print_local('Found local VCAP_SERVICES')
        creds = vcap['services']['cloudantNoSQLDB'][0]['credentials']
        user = creds['username']
        password = creds['password']
        url = 'https://' + creds['host']
        client = Cloudant(user, password, url=url, connect=True)
        main_db = client[main_db_name]
else:
    print('ERROR: No Cloudant connection information available!')

# Check login against Cloudant database
def check_credentials(username,password):
    # Open Cloudant auth DB
    authdb = client[auth_db_name]
    # Lookup doc for username and get hash
    try:
        with Document(authdb, username) as doc:
            # password created with pbkdf2_sha256.hash("<password>")
            if pbkdf2_sha256.verify(password, doc['password']):
                return True
            else:
                return False
    # if doc doesn't exist, fail.
    except Exception as e:
        print_local(e)
        return False

# *** MVP WORKAROUND ***
# hosts for test are currently HARD CODED
def get_host_IDs():
    return ["6f98988e776b10b84d4b9a37ddc94ea0","c04975184afdc984ad0c41361137bc48"]

# FUTURE TO-DO: Create admin console for managing users and/or sign-up system
# Would also automate API key generation for scan clients
# *** OUT OF SCOPE FOR MVP ***

## Get the scan database(s) for the session
## Right now this uses the first scan db it finds
#def get_scan_db():
#    thisview = maindb_views['recent_scans']
#    result = main_db.get_view_result(thisview[0], thisview[1], reduce=False, descending=True)
#    host_ids = get_host_IDs()
#    print_local(host_ids)
#    if result != None:
#        lastscan = result[[host_ids[0],{},{}]:[host_ids[0],None,0]]
#        if (lastscan != None) and (len(lastscan) > 0):            
#            host_a_db_name = lastscan[0]['value']
#            # TEMP MVP WORKAROUND
#            scan_db = client[host_a_db_name]
#        else:
#            host_a_db_name = None
#        lastscan = result[[host_ids[1],{},{}]:[host_ids[1],None,0]]
#        if (lastscan != None) and (len(lastscan) > 0):
#            host_b_db_name = lastscan[0]['value']
#            # TEMP MVP WORKAROUND
#            scan_db = client[host_b_db_name]
#        else:
#            host_b_db_name = None
#            
#        return ([host_a_db_name, host_b_db_name])
#        
#    else:
#        # logging.debug("Previous scan not found for any host.")
#        return None
#    pass

# If session is not logged in, present login screen, otherwise load sync status screen.
@app.route('/')
def home():
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        # TO-DO: Build current status page and display
        statusDict = update_syncstate()
        return render_template(
            'status.html',
            host1=statusDict['hostnames'][0],
            host2=statusDict['hostnames'][1],
            scandate1=statusDict['scandates'][0],
            scandate2=statusDict['scandates'][1],
            filecount1=statusDict['filecount'][0],
            filecount2=statusDict['filecount'][1],
            scanerr1=statusDict['errors'][0],
            scanerr2=statusDict['errors'][1],
            missing=statusDict['missing'],
            stale=statusDict['stale'],
            orphaned=statusDict['orphaned']
        )

# Login form submission
@app.route('/login', methods=['POST'])
def do_login():
    
    POST_USERNAME = str(request.form['username'])
    POST_PASSWORD = str(request.form['password'])
    
    if check_credentials(POST_USERNAME, POST_PASSWORD) == True:
        session['logged_in'] = True
        session_user = POST_USERNAME
        print_local('Logged in!')
    else:
        print_local('Invalid login: ' + POST_USERNAME)
        flash('invalid login!')

    return home()

# Logout session
@app.route("/logout")
def logout():
    session['logged_in'] = False
    return home()

## Obtain the most current scan database(s)
## MVP: These will almost always be the same.
## NO LONGER NEEDED, rolled into scan_details
#def get_scan_db():
#    thisview = maindb_views['recent_scans']
#    result = main_db.get_view_result(
#        thisview[0],
#        thisview[1],
#        reduce=False,
#        descending=True,
#        include_docs=False,
#        limit=1
#    )
#    print_local(result[0][0]['value'])
#    scan_db = client[result[0][0]['value']]
#    # This isn't going to give both IDs, just the ID of the most recent scan, regardless of host
#    # results['scanids'] = result[0][0]['id']

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

def get_files_scanned(host_id, scan_id): 
    ddoc = scandb_views['file_types'][0]
    view = scandb_views['file_types'][1]
    stats = dict()

    result = scan_db.get_view_result(
        ddoc,
        view,
        group_level=2,
        reduce=True
    )
    stats = result[[host_id,scan_id,None]:[host_id,scan_id,{}]]
    
    if len(stats) > 0:
        print_local(stats)
        return stats
    else:
        zeroes = dict(
            sum = 0,
            count = 0,
            min = 0,
            max = 0,
            sumsqr = 0
        )
        print_local("No files scanned so far!")
        return zeroes

def get_files_stale(target_host_id, scan_id):
    ddoc = scandb_views['stale_files'][0]
    view = scandb_views['stale_files'][1]
    result = scan_db.get_view_result(
        ddoc,
        view,
        reduce=True
    )
    stale = result[[target_host_id,scan_id,None],[target_host_id,scan_id,'{}']]
    
# set each host's recent scan ID, time started
def get_scan_details(hosts):
    thisview = maindb_views['recent_scans']
    for host in hosts:
        resultCollection = main_db.get_view_result(
            thisview[0],
            thisview[1],
            reduce=False,
            descending=True,
            include_docs=False
        )
        result = resultCollection[[host,True,{}]:[host,True,0]]
        if scan_db == None:
            scan_db = client[result[0][0]['value']]
        results['scanids'].append(result[0][0]['id'])
        results['scandates'].append(result[0][0]['doc']['started'])

def get_files_orphaned(target_host_id, scan_id):
    ddoc = scandb_views['orphaned_files'][0]
    view = scandb_views['orphaned_files'][1]
    result = scan_db.get_view_result(
        ddoc,
        view,
        reduce=True
    )
    orphaned = result[[target_host_id,scan_id,None],[target_host_id,scan_id,'{}']]
    print_local(orphaned)
    return(orphaned)

def get_files_good(target_host_id,scan_id):
    ddoc = scandb_views['uptodate_files'][0]
    view = scandb_views['uptodate_files'][1]
    result = scan_db.get_view_result(
        ddoc,
        view,
        reduce=True
    )
    goods = result[[target_host_id,scan_id,None],[target_host_id,scan_id,'{}']]
    print_local(goods)
    return(goods)

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
    # get_scan_db() # Function rolled into scan_details

    # Get last scan times for each host (and scan IDs?)
    get_scan_details(results['ids'])
    
    # results['scancomplete'] = are_scans_complete(results['ids']) # Not in MVP
    
    print_local(results)
    
    # Get good files (matching on both hosts)
    results['synchronized'] = get_files_good(results['ids'][1], results['scanids'][1]) # MVP Complete
    
    # Get orphaned files
    results['orphaned'] = get_files_orphaned(results['ids'][1], results['scanids'][1]) # MVP Complete
    
    # Get files scanned count (returns stats right now)
    results['filecount'][0] = get_files_scanned(results['ids'][0],results['scanids'][0]) # MVP Complete
    results['filecount'][1] = get_files_scanned(results['ids'][1],results['scanids'][1]) # MVP Complete
    
    # Get scan error counts
    results['errors'][0] = scanning_errors(source_host) # MVP Complete
    results['errors'][1] = scanning_errors(target_host) # MVP Complete
    
    # files existing on source but not destination
    results['missing'] = get_files_missing() # How to do: Determine all files with count of 1 for existing between both hosts.
    
    # "Stale" files? (These might be files existing on target but needing update)
    results['stale'] = get_files_stale() # MVP Complete
    
    # Return summary JSON
    return jsonify(results)

@atexit.register
def shutdown():
    if client:
        client.disconnect()

if __name__ == '__main__':
    app.secret_key = 'algareajb342942804joefijoasdofa8d9f7ashgbu4iakwjalfdasdf234ubyito8gh9siuefjkbkdfbaydf89p8buosidnjf'
    app.config['SESSION_TYPE'] = 'cloudant'
    app.run(host='0.0.0.0', port=port, debug=True)
