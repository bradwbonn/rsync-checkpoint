#!/usr/bin/env python

# Known issues:
# * Files that are moved, then altered between scans will be marked as deleted in their old location

# to-do:
# * check_existing() is not working due to failure to remove checked items from the list. 
# * switch check_existing() to use Cloudant lib
# * Verify check_excluded() is working properly because it's probably not

# Possible status values based on current code:
# status: {'state': 'error', 'detail': 'error reason'}
# status: {'state': 'ok', 'detail': None}
# status: {'state': 'ok', 'detail': 'possibly corrupted'}
# status: {'state': 'moved', 'detail': new_location[0]['id']}
# status: {'state': 'deleted', 'detail': int(time.time())}

# Prep
import json, base64, sys, hashlib, time, re
import os, logging, argparse

from datetime import datetime
from cloudant.client import Cloudant
from cloudant.design_document import DesignDocument
from cloudant.result import Result
from cloudant.document import Document
from cloudant.view import View
from cloudant import cloudant

import requests # Still needed for a few specific Cloudant queries. Hopefully not for long

logging_levels = dict(
        CRITICAL = 50,
        ERROR = 40,
        WARNING = 30,
        INFO = 20,
        DEBUG = 10,
    )

config = dict(
    # Name of database in Cloudant for everything except file entries
    main_db_name = 'rsynccheckpoint',
    # Name of the database in Cloudant which we're using for scanning today
    scan_db_name = '',
    # Number of docs per bulk request (Defaults to 2000 during initial configuration)
    doc_threshold = 2000,
    # Use this filename for configuration settings. JSON-formatted
    default_config_filename = 'dirscansync.json',
    # Slot for user-specified config file to read
    passed_config_file = '',
    # Cloudant account name
    cloudant_account = '',
    # Cloudant login username
    cloudant_user = '',
    # Cloudant password
    cloudant_auth = '',
    # Verbose setting (Default is off)
    be_verbose = False,
    # ID of the relationship for this sync (Cloudant doc _id)
    relationship = '',
    # ID of the current host (Cloudant doc _id)
    host_id = '',
    # ID of the opposite host (Cloudant doc _id)
    other_host_id = '',
    # Flags for current relationship's sync setup
    rsync_flags = '',
    # Ignored files and directories by rsync process for this relationship
    rsync_excluded = [],
    # ID of the source host (Cloudant doc _id)
    rsync_source = '',
    # ID of the destination host (Cloudant doc _id)
    rsync_target = '',
    # Full path of source's root sync directory
    rsync_source_dir = '',
    # Full path of target's root sync directory
    rsync_target_dir = '',
    # IP addresses of hosts in the relationship
    source_ip = '',
    target_ip = '',
    # Flag for whether we're scanning a source or target
    is_source = True,
    # Ultra-scan option. As in ULTRA-SLOW.  But performs 100% certainty of data integrity
    ultra_scan = False,
    # Time threshold to being writing to a new scan database in seconds (default is 30 days) #OBSOLETE WITH NEW ROLLOVER STRATEGY?
    db_rollover = 2592000,
    # Time threshold to retain older scan databases for in seconds (default is 90 days)
    db_max_age = 7776000,
    # Version number of the views in use by this script
    viewversion = 0.042,
    # Maximum number of keys to post to a view (for URI length limitation controls)
    # This can be increased once Cloudant-Python Issue #90 is resolved
    post_threshold = 2000
)

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
        'function (doc) {if (doc.type === "file" && doc.goodscan === true) { filetype = doc.name.substr((~-doc.name.lastIndexOf(".") >>> 0) + 2); emit([doc.host, doc.scanID, filetype], doc.size); } }',
        '_stats'
    ],
    problem_files = [ 
        '_design/problemfiles',
        'problemfiles',
        'function (doc) {if (doc.type === "file" && doc.goodscan !== true) {emit([doc.scanID,doc.path,doc.name], 1);}}',
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

# Cloudant Query indexes
scan_index = dict(
    fields = [
        {'datemodified': 'desc'},
        'IDprefix',
        'syncIDprefix',
        'size',
        'checksum'
    ]
)

# Main execution code
def main():
    
    # Process command-line settings
    myargs = get_args()
    
    # Setup logging
    try:
        logging.basicConfig(filename='dirscan_log.txt', level=logging_levels[myargs.l])
        logging.captureWarnings(True)
    except Exception:
        sys.exit("Can't open local log file, exiting.")
    
    # If config file exists, read it in and execute scan
    if (os.path.exists(myargs.config)):
        
        # Load configuration settings from file
        ver("Loading " + myargs.config)
        load_config(myargs.config)
        logging.debug(json.dumps(config, sort_keys=True, indent=4, separators=(',', ': ')))
        logging.info("Reading in configuration file: {0}".format(myargs.config))
        
        if myargs.check:
            config_check()
            
        elif myargs.flush:
            with cloudant(config['cloudant_user'],config['cloudant_auth'],account=config['cloudant_account']) as client:
                purge_old_dbs(client)
                
        else:
            # Initiate scan
            ver("Initiating scan...")
            with cloudant(config['cloudant_user'],config['cloudant_auth'],account=config['cloudant_account']) as client:
                # Create scan object and execute
                this_scan = FileScan(client, maindb_views, scandb_views, config)
                elapsed_time = this_scan.run()
                ver("Scan completed at {0} on {1} files.".format(this_scan.scandoc['ended'],this_scan.scandoc['filecount']))

        # We're done here
        sys.exit()

    # If configuration file doesn't exist, run setup process
    else:
        create_initial_config(myargs.config)

# Check current configuration and database status and output to screen (Future)
def config_check():
    from pprint import pprint
    from progressbar import ProgressBar
    pprint(config)
    # Initialize Cloudant connection
    try:
        client = Cloudant(config['cloudant_user'], config['cloudant_auth'], account=config['cloudant_account'])
        client.connect()
        print client['rsynccheckpoint'].metadata()
    except Exception:
        logging.fatal("Unable to connect to Cloudant")
        sys.exit(" Can't open Cloudant connection")
    if raw_input(" Update any out-of-date views to version {0}?".format(config['viewversion'])) in ('y','Y'):
        dblist = client.all_dbs()
        pbar = ProgressBar()
        for db in pbar(dblist):
            if db == 'rsynccheckpoint':
                check_views(db, client, maindb_views)
                insert_search_indexes(db, client, search_indexes['hosts'])
            elif db[:7] == 'scandb-':
                check_views(db, client, scandb_views)
                insert_search_indexes(db, client, search_indexes['files'])
    client.disconnect()

# Assemble and write the JSON-formatted configuration file for the host we're running on
def create_initial_config(config_file):
    import getpass
    # Initialize Cloudant client instance and obtain user credentials
    auth_not_set = True
    while (auth_not_set):
        print " The configuration file {0} cannot be found. Creating a new configuration.".format(config_file)
        print " You will need a Cloudant account to use this script."
        print " Go to www.cloudant.com to create one if you don't have it yet."
        print " Enter Cloudant account name (DNS name before .cloudant.com):"
        config['cloudant_account'] = raw_input("> ")
        print " Enter login username (often the same as the account name):"
        input_string = " ["+ config['cloudant_account'] + "] > "
        config['cloudant_user'] = raw_input(input_string)
        if len(config['cloudant_user']) == 0:
            config['cloudant_user'] = config['cloudant_account']
        config['cloudant_auth'] = getpass.getpass()

        try:
            client = Cloudant(config['cloudant_user'], config['cloudant_auth'], account=config['cloudant_account'])
            client.connect()
            auth_not_set = False
        except Exception:
            print " Sorry, try again."

    # Create database object
    try:
        # Open existing database
        maindb = client[config['main_db_name']]
        ver(" Main scan database found")
        logging.debug("{0} found".format(config['main_db_name']))
        
    except Exception:
        logging.info("Creating {0}".format(config['main_db_name']))
        # Create database if it doesn't exist
        maindb = client.create_database(config['main_db_name'])
        ver(" Database created")
    
    # Give a delay to allow the database to respond        
    wait = True
    while (wait):
        if (maindb.exists()):
            wait = False
        else:
            ver(" Waiting for database to become available...")
            time.sleep(10)
            
    # Insert design documents for required indexes in main db
    # Check each ddoc for existence before inserting
    check_views(maindb, client, maindb_views)
    
    # Begin process of collecting data
    relationship_status = ''
    while (relationship_status not in ("y", "Y", "n", "N")):
        relationship_status = raw_input(" Is the relationship for this host already set up? (y/n) > ")
        
    if (relationship_status in ("y","Y")):
        # For cases where the relationship is already defined
        # Have the user get the existing relationship to complete
        relationshipdocID = list_relationships(maindb)
        
        # Setup this host in the relationship at hand.
        create_host_entry(maindb, relationshipdocID)
        
        # Check to see if hosts and dirs are defined in relationship
        with Document(maindb, relationshipdocID) as reldoc:
            # If all are defined
            if (len(reldoc['sourcehost']) > 0 and len(reldoc['sourcedir']) > 0 and len(reldoc['targethost']) > 0 and len(reldoc['targetdir']) > 0):
                # Set relationship to active
                reldoc['active'] = True
                print "Both hosts are now set up for this relationship!"
                print "To initiate a scan, use 'dirscan.py -c /path/to/" + config_file + "'"
                    
    else:
        # Have the user set up a new relationship then 
        relationshipdocID = create_new_relationship(maindb)
        
        # Choose the relationship automatically and run host setup
        config_file_dict = create_host_entry(maindb, relationshipdocID)
        write_config_file(config_file_dict, config_file)
        
        print " Now run this setup on the other host."
    client.disconnect()

# Take a given database and relationship document object and create a new host entry, plus write config file to local system
def create_host_entry(db, relationshipdocID):
    # Get the relationship document from Cloudant DB
    relationshipdoc = Document(db, relationshipdocID)
    relationshipdoc.fetch()
    
    print " Editing relationship: " + relationshipdoc['name']

    # Get hosts by ID's from relationship, open docs and print names if they exist
    config_count = 0
    if (relationshipdoc['sourcehost'] != "UNDEFINED"):
        try:
            with Document(db, document_id=relationshipdoc['sourcehost']) as sourcedoc:
                print "Source host: " + sourcedoc['hostname']
            config_count = config_count + 1
        except:
            sys.exit("ERROR: Looks like that relationship's source host is no longer present.")
    else:
        print "Source host: NOT CONFIGURED"
        
    if (relationshipdoc['targethost'] != "UNDEFINED"):
        try:
            with Document(db, document_id=relationshipdoc['targethost']) as targetdoc:
                print "Target host: " + targetdoc['hostname']
            config_count = config_count + 1
        except:
            sys.exit("ERROR: Looks like that relationship's target host is no longer present.")
    else:
        print "Target host: NOT CONFIGURED"
       
    # If both are configured, exit for now. (Future expansion may allow editing relationships) 
    if (config_count == 2):
        print "Sorry, relationship is already configured. Cannot modify."
        sys.exit()
    
    # Get the information from the user about this host
    is_this_source = ''
    while (is_this_source not in ("Y","y","N","n")):
        is_this_source = raw_input("Are we on the source host right now? (Y/N): ")
    new_hostname = raw_input("Enter it's friendly hostname: ")
    this_host_IP4 = raw_input("Enter IPv4 address of this host: ")
    this_host_IP6 = raw_input("Enter IPv6 address of this host (Optional): ")
    this_host_directory = raw_input("Enter this host's sync root directory (full path required): ")
    # Add a trailing slash if one is not present in the user input for path consistency
    if (this_host_directory[len(this_host_directory)-1] != "/"):
        this_host_directory = this_host_directory + "/"
    # Validate path exists
    if os.path.exists(this_host_directory) != True:
        sys.exit("Invalid path, try again.")
    
    # Create the new host document in the database and get it's ID
    hostdoc = Document(db)
    hostdoc.create()
    hostdoc['type'] = 'host'
    hostdoc['hostname'] = new_hostname
    hostdoc['ip4'] = this_host_IP4
    hostdoc['ip6'] = this_host_IP6
    new_host_ID = hostdoc['_id']
    hostdoc.save()
        
    # Update the relationship document
    if (is_this_source in ("Y","y")):
        config['is_source'] = True
        which_host = 'sourcehost'
        which_dir = 'sourcedir'
    else:
        config['is_source'] = False
        which_host = 'targethost'
        which_dir = 'targetdir'
    relationshipdoc.update_field(
        action = relationshipdoc.field_set,
        field = which_host,
        value = new_host_ID
    )
    relationshipdoc.update_field(
        action = relationshipdoc.field_set,
        field = which_dir,
        value = this_host_directory
    )

    # Populate config file's content for host
    config_file_content = dict(
        cloudant_auth = config['cloudant_auth'],
        cloudant_user = config['cloudant_user'],
        cloudant_account = config['cloudant_account'],
        relationship = relationshipdoc['_id'],
        host_id = new_host_ID,
        threshold = config['doc_threshold']
    )
    
    return config_file_content
    
# Write a JSON-formatted file with the passed configuration settings
def write_config_file(config_dict, filename):
    if os.path.exists(filename):
        overwrite = raw_input(" Existing configuration file found! Overwrite? (Y/N) ")
        if overwrite in ('n', 'N'):
            # IMPROVEMENT: Make an undo function for changes in database
            sys.exit(" Exiting")
    try:
        data = open(filename, 'w')
    except IOError as e:
        print "I/O error({0}): {1}".format(e.errno, e.strerror)
        sys.exit(2)
    json.dump(config_dict, data)
    data.close()
    print " " + filename +" written."
    print " This file contains your Cloudant authentication information, so be sure to secure it appropriately!"

# Load configuration from file and database into configuration dictionary
def load_config(config_file):
    try:
        data = open(config_file)
    except IOError as e:
        print "I/O error({0}): {1}".format(e.errno, e.strerror)
        sys.exit(2)
    config_json = json.load(data)
    data.close()
    config['cloudant_auth'] = config_json['cloudant_auth']
    config['cloudant_user'] = config_json['cloudant_user']
    config['cloudant_account'] = config_json['cloudant_account']
    config['relationship'] = config_json['relationship']
    config['host_id'] = config_json['host_id']
    config['doc_threshold'] = config_json['threshold']
    
    # Connect to database
    with cloudant(config['cloudant_user'], config['cloudant_auth'], account=config['cloudant_user']) as client:
        db = client[config['main_db_name']]
        #db = CloudantDatabase(client, config['main_db_name'])
        # Read in configuration of relationship from database
        with Document(db, config['relationship']) as relationshipdoc:
            config['rsync_flags'] = relationshipdoc['rsyncflags']
            config['rsync_excluded'] = relationshipdoc['excludedfiles']
            config['rsync_source'] = relationshipdoc['sourcehost']
            config['rsync_target'] = relationshipdoc['targethost']
            config['rsync_source_dir'] = relationshipdoc['sourcedir']
            config['rsync_target_dir'] = relationshipdoc['targetdir']
        
        # Get hosts' IP addresses
        with Document(db, config['rsync_source']) as sourcedoc:
            config['source_ip'] = sourcedoc['ip4']
        with Document(db, config['rsync_target']) as targetdoc:
            config['target_ip'] = targetdoc['ip4']
            
    # Set flag for whether we're scanning a source or target
    if (config['host_id'] == config['rsync_source']):
        config['is_source'] = True
        config['other_host_id'] = config['rsync_target']
    else:
        config['is_source'] = False
        config['other_host_id'] = config['rsync_source']

def get_args():
    # New argument processing section

    argparser = argparse.ArgumentParser(description = 'Directory scan tool for rsync-checkpoint')
    group = argparser.add_mutually_exclusive_group()
    argparser.add_argument(
        '-c',
        dest='config',
        metavar='config file',
        type=str,
        nargs='?',
        help='Configuration file to use for scan operation. Defaults to trying ./{0}'.format(config['default_config_filename']),
        default = config['default_config_filename']
        )
    argparser.add_argument(
        '-v',
        action='store_true',
        help='Be verbose during operation'
        )
    argparser.add_argument(
        '-x',
        metavar='file',
        type=file,
        nargs='?',
        help='During setup, include a file which lists all directories or files to ignore during scan'
        )
    group.add_argument(
        '-u',
        action='store_true',
        help='Update an existing configuration'
        ) # Right now, this does nothing
    argparser.add_argument(
        '-l',
        metavar='logging level',
        choices=logging_levels,
        nargs = '?',
        help = 'Level of logging to the local log file during scan operation. Defaults to WARNING',
        default = 'WARNING',
        type=str
        )
    argparser.add_argument(
        '--deep',
        action='store_true',
        help='Use the file checksum operation during scan for full file completeness and file corruption checking purposes. Note: Much heavier scan operation!'
        )
    group.add_argument(
        '--check',
        action='store_true',
        help='Output a summary of the current configuration, check the views for completeness, then exit'
        )
    group.add_argument(
        '--flush',
        action='store_true',
        help='Flush any old or stale scan databases from the Cloudant account, then exit.'
        )
    
    myargs = argparser.parse_args()
    
    config['be_verbose'] = myargs.v
    config['ultra_scan'] = myargs.deep
    
    # Input any excludes for this scan, if passed during configuration stage
    if myargs.x != None:
        for exclude in myargs.x:
            if exclude.isspace():
                continue
            else:
                config['rsync_excluded'].append(exclude)
        myargs.x.close()
    
    return myargs
    

class FileScan(object):
    
    def __init__(
                self,
                client,
                maindb_views,
                scandb_views,
                config_dict
            ):
        
        # base variables
        self.file_doc_batch = []
        self.missing_files = []
        self.complete = False
        self.client = client
        self.maindb_views = maindb_views
        self.scandb_views = scandb_views
        self.verbose = config_dict['be_verbose']
        self.config = config_dict
        self.speed = 0
        
        # Open main database. Order is important here.
        self.maindb = client[config_dict['main_db_name']]
        
        # Initialize the Cloudant DB scan document and values
        self.scandoc = Document(self.maindb)
        
        # Open scan database. If non-existent, create a new one
        self.scan_db_name = self.select_scan_db()
        try:
            self.scandb = client[self.scan_db_name]
            self.scandoc['firstscan'] = False
        except KeyError as e:
            self.ver("Unable to open database {0}".format(self.scan_db_name))
            logging.warn("Unable to open database {0}".format(self.scan_db_name))
            self.scan_db_name = self.new_scan_db()
            self.scandb = client[self.scan_db_name]
            self.scandoc['firstscan'] = True
        
        self.scandoc.create()
        self.scandoc['started'] = 0
        self.scandoc['ended'] = 0
        self.scandoc['relationship'] = self.config['relationship']
        self.scandoc['source'] = self.config['is_source']
        self.scandoc['filecount'] = 0
        self.scandoc['errorcount'] = 0
        self.scandoc['directorysize'] = 0
        self.scandoc['type'] = 'scan'
        self.scandoc['success'] = False
        self.scandoc['hostID'] = self.config['host_id']
        self.scandoc['previousscanID'] = ''
        self.scandoc['database'] = self.scan_db_name
        self.scandoc['deepscan'] = self.config['ultra_scan']
        if (config['is_source']):
            self.scandoc['directory'] = self.config['rsync_source_dir']
        else:
            self.scandoc['directory'] = self.config['rsync_target_dir']
        
        # Save scan document so far and obtain an _id
        self.scandoc.save()
    
    def new_scan_db(self):
        # Create a new scan database for this relationship
        new_scan_db_name = 'scandb-' + str(int(time.time()))
        logging.info("Creating a new database for this scan: " + new_scan_db_name)
        try:
            new_scan_db = self.client.create_database(new_scan_db_name)
        except Exception:
            logging.fatal("Cannot create scan database")
            sys.exit("Something has gone wrong. See log for details")
            
        # Wait for new scandb to come online
        wait = True
        while (wait):
            if (new_scan_db.exists()):
                wait = False
            else:
                time.sleep(10)
        
        # Populate scandb views
        self.check_views(new_scan_db_name, scandb_views)
        # self.insert_search_indexes(new_scan_db_name, client, search_indexes['files'])
        
        # insert viewversion document
        with Document(new_scan_db,document_id="scanversion") as versiondoc:
            versiondoc['current'] = self.config['viewversion']
            versiondoc['history']= []
        
        # Set database name for this_scan
        return new_scan_db_name
    
    def select_scan_db(self):
        thisview = self.maindb_views['recent_scans']
        result = self.maindb.get_view_result(thisview[0], thisview[1], reduce=False,descending=True)   
        if result != None:
            logging.debug("Previous scans found")
            self.ver("Previous scans located")
            lastscan = result[[config['host_id'],{},{}]:[config['host_id'],None,0]]
            if (lastscan != None) and (len(lastscan) > 0):
                logging.debug("This host's scan database located: {0}".format(lastscan[0]['value']))
                self.ver("This host's scan database located: {0}".format(lastscan[0]['value']))
                return lastscan[0]['value']
            lastscan = result[[config['other_host_id'],{},{}]:[config['other_host_id'],None,0]]
            if (lastscan != None) and (len(lastscan) > 0):
                logging.debug("Other host's scan database located: {0}".format(lastscan[0]['value']))
                self.ver("Other host's scan database located: {0}".format(lastscan[0]['value']))
                return lastscan[0]['value']
            else:
                logging.debug("Previous scan not found for either host in the relationship.")
                self.ver("Previous scan not found for either host in the relationship.")
                return self.new_scan_db()
        else:
            logging.debug("Previous scan not found for any host.")
            self.ver("Previous scan not found for any host.")
            return self.new_scan_db()
        
    def run(self):
        
        self.scandoc['started'] = int(time.time())
        
        logging.info("Scanning using database: " + self.scandoc['database'])
        logging.info("Scan started at " + datetime.utcnow().isoformat(' ') + " UTC")
        self.ver("Scan database: {0} Excluding: {1}".format(self.scandoc['database'], self.config['rsync_excluded']))
        
        # Iterate through filesystem
        self.sweep()
        
        # Process files in DB that are no longer found at their previous locations on the filesystem
        self.check_missing()
            
        # Update scan document with final results
        if self.scandoc['errorcount'] == 0:
            self.scandoc['success'] = True
        self.scandoc['ended'] = int(time.time())
        
        # Save scan document    
        self.scandoc.save()
        
        # Record completion time and speed
        self.speed = round(self.scandoc['filecount']  / ((self.scandoc['ended'] - self.scandoc['started']) / float(60)),1)
        logging.info("Rate of scan: {0} files per minute".format(self.speed))
        logging.debug("Full scan stats: ")
        logging.debug(json.dumps(self.scandoc, sort_keys=True, indent=4, separators=(',', ': ')))
        
        self.complete = True
        
        # Return time elapsed
        return self.scandoc['ended'] - self.scandoc['started']
  
    # Check all files in batch against existing DB entries.
    # Found entries are checked for corruption, then removed from the batch
    # Corrupted entries in DB updated whenever found
    def check_existing(self):
        
        ids_to_find = dict()
        for filedict in self.file_doc_batch:
            ids_to_find[filedict['_id']] = filedict
        
        # Check for any existing docs based on the full ID of each file.  Uses primary index
        # Currently using requests library - should be able to use Cloudant library now
        myurl = 'https://{0}.cloudant.com/{1}/_all_docs?include_docs=true'.format(
            self.config['cloudant_account'],
            self.scandb.metadata()['db_name']
        )
        my_header = {'Content-Type': 'application/json'}
        try:
            r = requests.post(
                myurl,
                headers = my_header,
                auth = (config['cloudant_user'],config['cloudant_auth']),
                data = json.dumps({ 'keys': ids_to_find.keys() })
            )
            result = r.json()
        except Exception as e:
            logging.fatal("Unable to execute HTTP POST: {0}".format(e))
            sys.exit("Unable to execute HTTP POST: {0}".format(e))
        
        # If the deep scan is enabled, validate checksums against existing files in DB. Otherwise use date/size
        if self.config['ultra_scan'] == True:
            check_field = 'checksum'
        else:
            check_field = 'size'
            
        # If we've found some matching file IDs, check them for any change in size or checksum
        # The file's ID should be changed if the content has updated because it's tied to the update date.
        # If it hasn't, there's something likely wrong with the file
        for f in result['rows']:
            
            # If the contents of the file have changed locally:
            if f['doc'][check_field] != ids_to_find[f['key']][check_field]:
                
                # Update the existing file document's content details, append a possible corruption warning.
                now = int(time.time())
                logging.warning("{0} mismatch from previous scan for {1}".format(check_field,possible_corrupt_file['name']))
                
                # Update the document in the database for the file directly.
                # One DB operation per changed file.
                # Might be best done in bulk, but first iteration using "easier" method
                with Document(self.scandb, document_id=f['key']) as doc:
                    doc['error'] = "{0} mismatch without filesystem date change found on {1}. Possible file corruption!".format(check_field, pretty_time(now))
                    doc['status'] = {'state': 'ok', 'detail': 'possibly corrupted'}
                    doc[check_field] = f['value']
            
            # Remove file's entry from the batch
            # We have to remove the revision field for it to match the batch dictionary
            doc_minus_rev = f['doc']
            doc_minus_rev.pop('_rev', None)
            self.file_doc_batch.remove(doc_minus_rev)
    
    # For each missing file, check to see if it exists somewhere else on the host now.
    # Currently done as one DB operation per file, but this is only for files that have
    # been moved or deleted, so their frequency will be much less
    def check_missing(self):
        for missing_file in self.missing_files:
            view = self.scandb_views['duplicate_files']
            result = self.scandb.get_view_result(
                view[0],
                view[1],
                reduce=False
            )
            with Document(self.scandb, document_id=missing_file) as doc:
                bound = [doc.name,doc.datemodified,doc.checksum,doc.size,doc.host]
                new_location = result[bound:bound]
                if new_location[0]['id'] != None:
                    # File has moved.  Set previous doc's status and continue
                    doc.status = {'state': 'moved', 'detail': new_location[0]['id']}
                else:
                    # File is nowhere else in DB. Set as deleted and note time
                    doc.status = {'state': 'deleted', 'detail': int(time.time())}
        del self.missing_files[:]
    
    def batch_process(self):
        # If this is the first in the database, don't bother checking anything.
        # Just insert all the file documents.  (We've just created the database and it's empty)
        if self.scandoc['firstscan'] == True:
            self.scandb.bulk_docs(self.file_doc_batch)
            del self.file_doc_batch[:]
        # Otherwise, check the files against the database
        else:
            self.check_existing()
            if len(self.file_doc_batch) > 0:
                self.scandb.bulk_docs(self.file_doc_batch)
                del self.file_doc_batch[:]
    
    def check_excluded(self, file_path):
        for exclude in self.config['rsync_excluded']: # TO-DO: May have to switch to using a regular expression here
            if exclude in file_path:
                self.ver("Skipping excluded file {0}".format(file_path))
                logging.debug("Skipping {0}".format(file_path))
                return True
            else:
                return False
            
    def get_filesystem_metadata(self, root, name):
        
        filedict = dict()
        
        # Get the scan path for the host opposite this one in order to construct the opposite host's file ID prefix
        if self.config['is_source'] == True:
            other_host_scan_dir = self.config['rsync_target_dir']
        else:
            other_host_scan_dir = self.config['rsync_source_dir']

        # Values stored regardless of OS detail check
        filedict['IDprefix'] = self.get_file_id(self.config['host_id'], os.path.join(root,name), self.scandoc['directory'], 0)
        filedict['syncIDprefix'] = self.get_file_id(self.config['other_host_id'], os.path.join(root,name), other_host_scan_dir, 0)
        filedict['name'] = name
        filedict['scanID'] = self.scandoc['_id'] # Un-needed... this will not update unless the file changes
        filedict['host'] = self.config['host_id']
        filedict['relationship'] = self.config['relationship']
        filedict['path'] = root
        filedict['datescanned'] = int(time.time()) # Should probably be removed... this will not update unless the file changes
        filedict['type'] = "file"
        filedict['source'] = self.config['is_source']
        filedict['syncpath'] = self.trim_sync_path(os.path.join(root,name))
        
        # Values from detail check
        try:
            stat = os.stat(os.path.join(root,name))
            filedict['size'] = int(stat.st_size)
            filedict['permissionsUNIX'] = stat.st_mode
            filedict['datemodified'] = int(stat.st_mtime)
            filedict['owner'] = stat.st_uid
            filedict['group'] = stat.st_gid
            filedict['goodscan'] = True
            # Construct it's custom ID
            filedict['_id'] = self.get_file_id(config['host_id'], os.path.join(root,name), self.scandoc['directory'], int(stat.st_mtime))
            if (config['ultra_scan'] == True):
                filedict['checksum'] = self.compute_file_checksum(root,name)
            # Handle cases where the filename / path can't be properly encoded due to Unicode issues
            if '-ERROR' in filedict['_id']:
                filedict['status'] = {'state': 'error', 'detail': 'Path encode error'}
            else:
                filedict['status'] = {'state': 'ok', 'detail': None}
            
            # Increment size of directory in scan document
            self.scandoc['directorysize'] = self.scandoc['directorysize'] + filedict['size']
        
        except OSError as e:
            # Store as bad scan of file and iterate errors. Also set ID without a timestamp
            filedict['_id'] = self.get_file_id(config['host_id'], os.path.join(root,name), scan['directory'], 0)
            self.scandoc['errorcount'] = self.scandoc['errorcount'] + 1
            filedict['status'] = {'state': 'error', 'detail': "OS error: {0} {1}".format(e.errno, e.strerror)}
            logging.error("File {0} can't be scanned: {1} {2}".format(os.path.join(root,name), e.errno, e.strerror))
        
        return filedict
        
    def sweep(self):
        
        for root, dirs, files in os.walk(self.scandoc['directory'], topdown=False):
            for name in files:
                
                # Skip excluded files / directories
                if self.check_excluded(os.path.join(root,name)) == True:
                    continue
                
                # Obtain detailed information on the file from the filesystem and add it to the batch
                thisfile = self.get_filesystem_metadata(root, name)
                self.file_doc_batch.append(thisfile)
                self.scandoc['filecount'] = self.scandoc['filecount'] + 1
                
                # Process once we have the threshold number of docs
                if len(self.file_doc_batch) >= self.config['doc_threshold']:
                    self.ver("Scanning... Total files so far: {0}".format(self.scandoc['filecount']))
                    self.batch_process()
                    
            # Iterate through directory tree, checking for any missing files
            if (self.scandoc['firstscan'] == False):
                
                for directory in dirs:
                    
                    # Get full list of most recent doc IDs in the directory from DB
                    view = self.scandb_views['check_for_delete']
                    result = self.scandb.get_view_result(
                        view[0],
                        view[1],
                        reduce=False
                    )
                    
                    # Get all files marked as "ok" in database for this directory
                    this_dir_result = result[[self.config['host_id'],directory,None]:[self.config['host_id'],directory,{}]]
                    this_dir_path = os.path.join(root,directory)
                    
                    # Get all files currently in the filesystem directory
                    try:
                        actual_files = os.listdir(this_dir_path)
                    except OSError as e:
                        self.ver("Couldn't open {0}: {1}".format(this_dir_path, e))
                    
                    # check filesystem for any missing files locally.
                    # Store the IDs of any that aren't there so we can process them after the sweep is finished
                    for d in this_dir_result:
                        if d['key'][2] not in actual_files:
                            self.missing_files.append(d['id'])
                            self.ver("Missing file logged for check: {0}".format(d['id']))
                            
            
        # Process any remaining files in the batch
        if len(self.file_doc_batch) > 0:
            self.ver("Scanning... Total files so far: {0}".format(self.scandoc['filecount']))
            self.batch_process()
            
    def get_file_id(self, host_id, full_path, top_dir, timestamp):
        # trim the top_dir from the full path
        pathtrim = len(top_dir)
        relative_path = full_path[pathtrim:]
        if timestamp == 0:
            appender = ''
        else:
            appender = str(timestamp)
        try:
            f1 = relative_path.decode('utf-8', errors='replace')
            filehash = hashlib.sha1(host_id + f1.encode('utf-8', errors='replace')).hexdigest() + appender
            logging.debug("Hashing input: {0},{1}{2}, {3} Output:{4}".format(host_id,top_dir,full_path,timestamp,filehash))
        except UnicodeDecodeError:
            logging.error("Can't decode: " + relative_path)
            filehash = hashlib.sha1(host_id).hexdigest() + appender + '-ERROR'
        except UnicodeEncodeError:
            logging.error("Can't encode: " + relative_path)
            filehash = hashlib.sha1(host_id).hexdigest() + appender + '-ERROR'
        return(filehash)

    def trim_sync_path(self, fullpath):
        if self.config['is_source'] == True:
            return(re.sub('^{0}'.format(self.config['rsync_source_dir']),'',fullpath))
        else:
            return(re.sub('^{0}'.format(self.config['rsync_target_dir']),'',fullpath))
        
    def compute_file_checksum(self, root, fname):
        path = os.path.join(root,fname)
        filehash = hashlib.md5()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                filehash.update(chunk)
        return filehash.hexdigest()

    def ver(self, string):
        if self.config['be_verbose'] == True:
            print string

    # Check database views in database with <dbname> using client <c>, and the set of <views>
    def check_views(self, dbname, views):
        
        def updater():
            # Open each ddoc / view combo for existing
            for thisview in views.values():
                ddoc = DesignDocument(db,thisview[0])
                if ddoc.exists() == False:
                    # Create ddoc and view
                    logging.info("Creating {0}/{1}".format(thisview[0],thisview[1]))
                    self.ver("Creating {0}/{1}".format(thisview[0],thisview[1]))
                    ddoc = DesignDocument(db, document_id=thisview[0])
                    ddoc.add_view(thisview[1], thisview[2], reduce_func = thisview[3])
                    ddoc.save()
                else:
                    # doc exists, check view
                    ddoc.fetch()
                    oldview = ddoc.get_view(thisview[1])
                    # if view not there
                    if oldview == None:
                        # insert it
                        logging.info("Inserting {1} into {0}".format(thisview[0],thisview[1]))
                        self.ver("Inserting {1} into {0}".format(thisview[0],thisview[1]))
                        ddoc.add_view(thisview[1],thisview[2],thisview[3])
                        ddoc.save()
                    # if view function is different
                    elif (oldview['map'] != thisview[2]):
                        # Update
                        logging.info("Updating {0}/{1}".format(thisview[0],thisview[1]))
                        self.ver("Updating {0}/{1}".format(thisview[0],thisview[1]))
                        ddoc.update_view(thisview[1],thisview[2],thisview[3])
                        ddoc.save()
                    else:
                        self.ver("Skipping {0}/{1}".format(thisview[0],thisview[1]))
                        continue
        
        db = self.client[dbname]
        versiondoc = Document(db,document_id="scanversion")
        if versiondoc.exists() != True:
            versiondoc.create()
            versiondoc['current'] = self.config['viewversion']
            versiondoc['history']= []
            versiondoc.save()
            self.ver("Database is new")
            updater()
        else:
            versiondoc.fetch()
        if versiondoc['current'] < self.config['viewversion']:
            self.ver("Database is older version. Upgrading views.")
            updater()
            versiondoc.update_field(action=versiondoc.list_field_append, field='history', value = versiondoc['current'])
            versiondoc.update_field(action=versiondoc.field_set, field='current', value = config['viewversion'])
            versiondoc.save()
        else:
            self.ver("Database is up-to-date!")

# Print if verbose
def ver(string):
    if config['be_verbose'] == True:
        print string

# Create a relationship entity and write an associated document into the database
def create_new_relationship(db):
    doc = Document(db)
    doc.create()
    print " Let's define one then!"
    print " Enter a name for this relationship"
    doc['name'] = raw_input(" > ")
    doc['type'] = 'relationship'
    doc['active'] = False
    doc['sourcehost'] = 'UNDEFINED'
    doc['sourcedir'] = ''
    doc['targethost'] = 'UNDEFINED'
    doc['targetdir'] = ''
    doc['rsyncflags'] = []
    config['relationship'] = doc['_id']
    
    # If excludes file not specified at runtime
    if len(config['rsync_excluded']) == 0:
        # Prompt for list of files/directories to exclude, one per line
        print "If you would like to exclude any files or directories from scanning, enter them one per line now."
        print "(Enter when finished)"
        exclude_line = ' '
        while (len(exclude_line) > 0):
            exclude_line = raw_input(" > ")
            # Enter each into a new array, if line empty, finish
            if (len(exclude_line) > 0):
                config['rsync_excluded'].append(exclude_line)
    else:
        # print first 3 entries and "...", informing user these will be used
        print "Exclusions list has been read:"
        count = 0
        while (count < len(config['rsync_excluded']) and count < 3):
            print config['rsync_excluded'][count]
            count = count + 1
        if (len(config['rsync_excluded']) > 3):
            print "...and so on"
        print "Matching paths will not be scanned on either the source or target hosts."
        
    # Write array of excluded paths to doc
    doc['excludedfiles'] = config['rsync_excluded']
    
    # Set delete flag if in use    
    if (raw_input(" Are deletions being sync'd? (Y/N) >") in ("y", "Y")):
        doc['rsyncflags'].append('delete')
        
    # Input any other rsync flags in use
    print " (Optional) What flags are being used by rsync?"
    flags = raw_input(" (Enter on one line, no spaces): ")
    for flag in flags:
        doc['rsyncflags'].append(flag)
    
    # Save changes to document
    doc.save()
    # Return the doc _id of the new relationship
    return config['relationship']    
    
# TO-DO: Find a host by name, using search index
def find_host(host_name):
    pass

# Find a relationship by listing all known relationships and letting the user choose the appropriate one
def list_relationships(db):
    print "| Which relationship is this host part of?"
    print "| ID | Relationship                       |"

    # Open view (no context handlers supported currently)
    ddoc = DesignDocument(db, document_id=maindb_views['all_relations'][0])
    view = View(ddoc, maindb_views['all_relations'][1])
        
    # Iterate through relationships, storing and printing a key for each
    relationship_key = 0
    relationship_set = ['']
    for row in view(include_docs=False, limit=10)['rows']:
        relationship_key = relationship_key + 1
        print "|  " + str(relationship_key) + " | " + row['key']
        relationship_set.append(row['id'])
        
    # Ask user to select desired relationship from list
    # TO-DO: Input validation
    relationship_selected = raw_input(" > ")

    # Pass back the appropriate relationship document _id
    return relationship_set[int(relationship_selected)]

# Output a formatted date/time from UTC timestamp
def pretty_time(timestamp):
    return (datetime.fromtimestamp(int(timestamp)).ctime())
    
# Clean up derelict scan databases in the Cloudant account
def purge_old_dbs(client):
    day = 86400
    dblist = client.all_dbs()
    current_time = int(time.time())
    for db in dblist:
        if 'scandb-' not in db:
            continue
        elif ((current_time - int(db[7:])) > day):
            # If the database is older than one day, and has no documents besides ddocs
            empty_db = client[db]
            if empty_db.doc_count() < (len(scandb_views) + len(search_indexes) + 1):
                ver("Deleting empty database: " + db)
                empty_db.delete()
                dblist.remove(db)
                
    # If the database is older than a week, and has no successful completed scans associated with it
    # on any host, remove it.
    main_db = client[config['main_db_name']]
    thisview = maindb_views['recent_scans']
    result = main_db.get_view_result(thisview[0], thisview[1], reduce=False)
    validscans = []
    for r in result:
        if (r['key'][1] == True) and (r['value'] not in validscans):
            validscans.append(r['value'])
    for db in dblist:
        if ('scandb-' in db) and (db not in validscans) and ((current_time - int(db[7:])) > 7 * day):
            ver("Deleting {0} due to no successful scans for {1} days.".format(db,7))
            doomed_db = client[db]
            doomed_db.delete()
    
# Check database views in database with <dbname> using client <c>, and the set of <views>
def check_views(dbname, c, views):
    
    def updater():
        # Open each ddoc / view combo for existing
        for thisview in views.values():
            ddoc = DesignDocument(db,thisview[0])
            if ddoc.exists() == False:
                # Create ddoc and view
                logging.info("Creating {0}/{1}".format(thisview[0],thisview[1]))
                ver("Creating {0}/{1}".format(thisview[0],thisview[1]))
                ddoc = DesignDocument(db, document_id=thisview[0])
                ddoc.add_view(thisview[1], thisview[2], reduce_func = thisview[3])
                ddoc.save()
            else:
                # doc exists, check view
                ddoc.fetch()
                oldview = ddoc.get_view(thisview[1])
                # if view not there
                if oldview == None:
                    # insert it
                    logging.info("Inserting {1} into {0}".format(thisview[0],thisview[1]))
                    ver("Inserting {1} into {0}".format(thisview[0],thisview[1]))
                    ddoc.add_view(thisview[1],thisview[2],thisview[3])
                    ddoc.save()
                # if view function is different
                elif (oldview['map'] != thisview[2]):
                    # Update
                    logging.info("Updating {0}/{1}".format(thisview[0],thisview[1]))
                    ver("Updating {0}/{1}".format(thisview[0],thisview[1]))
                    ddoc.update_view(thisview[1],thisview[2],thisview[3])
                    ddoc.save()
                else:
                    ver("Skipping {0}/{1}".format(thisview[0],thisview[1]))
                    continue
    
    db = c[dbname]
    versiondoc = Document(db,document_id="scanversion")
    if versiondoc.exists() != True:
        versiondoc.create()
        versiondoc['current'] = config['viewversion']
        versiondoc['history']= []
        versiondoc.save()
        ver("Database is new")
        updater()
    else:
        versiondoc.fetch()
    if versiondoc['current'] < config['viewversion']:
        ver("Database is older version. Upgrading views.")
        updater()
        versiondoc.update_field(action=versiondoc.list_field_append, field='history', value = versiondoc['current'])
        versiondoc.update_field(action=versiondoc.field_set, field='current', value = config['viewversion'])
        versiondoc.save()
    else:
        ver("Database is up-to-date!")


def insert_search_indexes(dbname, client, searchddoc):
    db = client[dbname]
    with Document(db, searchddoc[0]) as doc:
            doc['views'] = {}
            doc['language'] = 'javascript'
            doc['indexes'] = dict()
            doc['indexes']['newSearch'] = dict()
            doc['indexes']['newSearch']['analyzer'] = "standard"
            doc['indexes']['newSearch']['index'] = searchddoc[1]

if __name__ == "__main__":
    main()
    
