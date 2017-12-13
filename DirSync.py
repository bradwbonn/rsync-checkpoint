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

# /**  TO-DO:
#  * Endpoint to get JSON of current sync status between the two hosts
#  * <code>
#  * GET https://localhost:8000/api/syncstate
#  * </code>
#  *
#  * Response:
#  * {
#  *  "source": {
#  *   "hostname": "str",
#  *   "id":"str",
#  *   "lastscan": "date/time",
#  *   "filecount": 0,
#  *   "totalsize": 0,
#  *   "errors": 0,
#  *   "corruptedfiles": 0
#  *   },
#  *  "target": {same as above},
#  *  "stats": {
#  *   "syncpercent": 00.0,
#  *   "missingfilecount": 0,
#  *   "extrafiles": 0  # (Files existing on target but not source)
#  *   }
#  *  }
#  */

@app.route('/api/syncstate', methods=['POST'])
def get_syncstate():
    pass

#@app.route('/api/visitors', methods=['POST'])
#def put_visitor():
#    user = request.json['name']
#    if client:
#        data = {'name':user}
#        db.create_document(data)
#        return 'Hello %s! I added you to the database.' % user
#    else:
#        print('No database')
#        return 'Hello %s!' % user

@atexit.register
def shutdown():
    if client:
        client.disconnect()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=port, debug=True)
