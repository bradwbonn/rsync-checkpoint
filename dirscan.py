#!/usr/bin/env python

# Prep
import json
import base64
import sys
import hashlib
import time
import re
from datetime import datetime
from cloudant.account import Cloudant
from cloudant.design_document import DesignDocument
from cloudant.result import Result
from cloudant.document import Document
from cloudant.views import View
from cloudant import cloudant
import getpass
import os
import logging
import argparse
import requests # Still needed for a few specific Cloudant queries.

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
    # Time threshold to being writing to a new scan database in seconds (default is 30 days)
    db_rollover = 2592000,
    # Time threshold to retain older scan databases for in seconds (default is 90 days)
    db_max_age = 7776000,
    # Version number of the views in use by this script
    viewversion = 0.03,
    # Maximum number of keys to post to a view (for URI length limitation controls)
    # This can be increased once Cloudant-Python Issue #90 is resolved
    post_threshold = 100
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

# Views in each per-diem file scan dbs
# Format is <view> = [<ddocname>,<viewname>,<mapfunction>,<reducefunction>]
# MAKE SURE DDOC NAME INCLUDES LEADING "_design/"!
scandb_views = dict(
    file_types = [
        '_design/files',
        'typesscanned',
        'function (doc) {if (doc.type === "file" && doc.goodscan === true) { filetype = doc.name.substr((~-doc.name.lastIndexOf(".") >>> 0) + 2); emit([doc.host, doc.scanID, filetype], doc.size); } }',
        '_stats'
    ],
    problem_files = [ 
        '_design/files',
        'problemfiles',
        'function (doc) {if (doc.type === "file" && doc.goodscan === false) {emit([doc.scanID,doc.path,doc.name], 1);}}',
        '_count'
    ],
    source_files = [
        '_design/sourcefiles',
        'sourcefiles',
        'function (doc) { if (doc.type === "file" && doc.goodscan === true && doc.source === true) {emit(doc._id, doc.datemodified); }}',
        None
    ],
    uptodate_files = [
        '_design/syncstate',
        'uptodate',
        'function (doc) {if (doc.type === "file" && doc.goodscan === true && doc.source === false && doc.orphaned === "no" && (doc.datemodified >= doc.sourcemodified)) {emit([doc.host, doc.scanID, doc.datemodified],doc.size);}}',
        '_stats'
    ],
    stale_files = [
        '_design/syncstate',
        'stale',
        'function (doc) {if (doc.type === "file" && doc.goodscan === true && doc.source === false && doc.orphaned === "no" && (doc.datemodified < doc.sourcemodified)) {emit([doc.host, doc.scanID, doc.datemodified],doc.size);}}',
        '_stats'
    ],
    orphaned_files = [
        '_design/syncstate',
        'orphaned',
        'function (doc) {if (doc.type === "file" && doc.goodscan === true && doc.source === false && doc.orphaned === "yes") {emit([doc.host, doc.scanID, doc.datemodified],doc.size);}}',
        '_stats'
    ],
    unknown_files = [
        '_design/syncstate',
        'unknown',
        'function (doc) {if (doc.type === "file" && doc.goodscan === true && doc.source === false && doc.orphaned === "unknown") {emit([doc.host, doc.scanID, doc.datemodified],doc.size);}}',
        '_stats'
    ],
    source_prefixes = [
        '_design/sourcefiles',
        'prefixes',
        'function (doc) {if (doc.type === "file" && doc.goodscan === true && doc.source === true) {emit(doc.IDprefix,doc.datemodified);}}',
        '_count'
    ],
    missing_files = [
        '_design/syncstate',
        'missing',
        'function (doc) {if (doc.type === "file") {emit([doc.syncpath,doc.name,doc.host],doc.size);}}',
        '_stats'
    ]
)

# Search design documents
search_indexes = dict(
    files = [
        '_design/search',
        'files',
        'function (doc) { index("name", doc.name, "store": true); index("path", doc.path);}',
        None
    ]
)

# Main execution code
def main():
    
    # New argument processing section
    logging_levels = dict(
        CRITICAL = 50,
        ERROR = 40,
        WARNING = 30,
        INFO = 20,
        DEBUG = 10,
    )
    argparser = argparse.ArgumentParser(description = 'Directory scan tool for rsync-checkpoint')
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
    argparser.add_argument(
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
        '--check',
        action='store_true',
        help='Output a summary of the current configuration, check the views for completeness, and exit'
        )
    myargs = argparser.parse_args()
    config['be_verbose'] = myargs.v
    
    # Input any excludes for this scan, if passed during configuration stage
    if myargs.x != None:
        for exclude in myargs.x:
            if exclude.isspace():
                continue
            else:
                config['rsync_excluded'].append(exclude)
        myargs.x.close()
        
    # Setup logging
    try:
        logging.basicConfig(filename='dirscan_log.txt', level=logging_levels[myargs.l])
        logging.captureWarnings(True)
    except Exception:
        sys.exit("Can't open local log file, exiting.")
    
    # If config file exists, read it in and execute scan
    if (os.path.exists(myargs.config)):            
        # Load configuration settings from file
        if (config['be_verbose']):
            print "Loading " + myargs.config
        load_config(myargs.config)
        logging.debug(json.dumps(config, sort_keys=True, indent=4, separators=(',', ': ')))
        logging.info("Reading in configuration file: {0}".format(myargs.config))
        
        if myargs.check:
            config_check()
        else:
            # Initiate scan
            scanstarttime = datetime.utcnow().isoformat(' ')
            scanstartraw = time.time()
            logging.info("Scan started at " + scanstarttime + " UTC")
            if config['be_verbose'] == True:
                print "Initiating scan now..."
            completion = directory_scan()
            scanfinishtime = datetime.utcnow().isoformat(' ')
            scanfinishraw = time.time()
            # Log scan completion status
            if (completion != False):
                logging.info("Scan successfully completed at: " + scanfinishtime + " UTC")
                speed = round(completion  / ((scanfinishraw - scanstartraw) / float(60)),1)
                logging.info("Rate of scan: {0} files per minute".format(speed))
                if config['be_verbose'] == True:
                    print "Scan successfully completed at " + scanfinishtime
            else:
                if config['be_verbose'] == True:
                    print "Scan completed with errors at " + scanfinishtime
                logging.warn("Scan completed with errors at: " + scanfinishtime + " UTC")
        
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
    except Exception:
        logging.fatal("Unable to connect to Cloudant")
        sys.exit(" Can't open Cloudant connection")
    if raw_input(" Update any out-of-date views to version {0}?".format(config['viewversion'])) in ('y','Y'):
        dblist = client.all_dbs()
        pbar = ProgressBar()
        for db in pbar(dblist):
            if db == 'rsynccheckpoint':
                check_views(db, client, maindb_views)
            elif db[:7] == 'scandb-':
                check_views(db, client, scandb_views)
    client.disconnect()

# Assemble and write the JSON-formatted configuration file for the host we're running on
def create_initial_config(config_file):
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
        if config['be_verbose'] == True:
            print " Main scan database found"
        logging.debug("{0} found".format(config['main_db_name']))
        
    except Exception:
        logging.info("Creating {0}".format(config['main_db_name']))
        # Create database if it doesn't exist
        maindb = client.create_database(config['main_db_name'])
        if config['be_verbose'] == True:
            print " Database created"
    
    # Give a delay to allow the database to respond        
    wait = True
    while (wait):
        if (maindb.exists()):
            wait = False
        else:
            if config['be_verbose'] == True:
                print " Waiting for database to become available..."
            time.sleep(10)
            
    # Insert design documents for required indexes in main db
    # Check each ddoc for existence before inserting
    populate_views(maindb, maindb_views)
    
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

# filesystem scan function 
def directory_scan():
    
    # Init local variables
    this_scan = dict(
        database = '',
        started = int(time.time()),
        ended = 0,
        source = False,
        type = 'scan',
        success = False,
        errorcount = 0,
        hostID = config['host_id'],
        directory = '',
        directorysize = 0,
        relationship = config['relationship'],
        firstscan = True,
        previousscanID = '',
        filecount = 0
    )
    
    if (config['is_source']):
        this_scan['source'] = True
        this_scan['directory'] = config['rsync_source_dir']
    else:
        this_scan['source'] = False
        this_scan['directory'] = config['rsync_target_dir']
        
    # Initialize Cloudant connection
    try:
        client = Cloudant(config['cloudant_user'], config['cloudant_auth'], account=config['cloudant_account'])
        client.connect()
    except Exception:
        logging.fatal("Unable to connect to Cloudant")
        sys.exit("Something went wrong. See log for errors")
        
    # Open main database
    try:
        maindb = client[config['main_db_name']]
    except Exception:
        logging.fatal("Main database cannot be found in Cloudant account")
        sys.exit("Something went wrong. See log for errors")
        
    # Database creation function
    def new_scan_db():
        # Create a new database for this week
        new_scan_db_name = 'scandb-' + str(int(time.time()))
        logging.info("Creating a new database for this scan: " + new_scan_db_name)
        try:
            new_scan_db = client.create_database(new_scan_db_name)
        except Exception:
            logging.fatal("Cannot create scan database")
            sys.exit("Something has gone wrong. See log for details")
            
        # Wait for new scandb to come online
        wait = True
        while (wait):
            if (new_scan_db.exists()):
                wait = False
            else:
                if config['be_verbose'] == True:
                    print "Waiting for database to become available..."
                time.sleep(10)
        
        # Populate scandb views
        populate_views(new_scan_db, scandb_views)
        
        # insert viewversion document
        versiondoc = Document(new_scan_db,document_id="scanversion")
        versiondoc.create()
        versiondoc['current'] = config['viewversion']
        versiondoc['history']= []
        versiondoc.save()
                
        # Set database name for this_scan
        this_scan['database'] = new_scan_db_name
        
    # Scan database selection function
    def scan_db_selection(maindb):
        db_logic = dict()
        # Get this host's last successful scan info (if it exists)
        thisview = maindb_views['recent_scans']
        beginhere = [config['host_id'],True,{}]
        endhere = [config['host_id'],True,0]
        raw_result = maindb.get_view_raw_result(thisview[0], thisview[1], startkey=beginhere , endkey=endhere , limit=1, reduce=False, descending=True)['rows']
        if len(raw_result) == 1:
            logging.debug("Previous scan found for this host: "+ raw_result[0]['id'])
            db_logic['this_host_scanned'] = True
            this_scan['firstscan'] = False
            this_scan['previousscanID'] = raw_result[0]['id']
            db_logic['last_scan_DB'] = raw_result[0]['value']
            db_logic['last_scan_complete'] = raw_result[0]['key'][2]
        else:
            logging.debug("Previous scan NOT FOUND for this host.")
            db_logic['this_host_scanned'] = False
        
        # Get the other host's last scan info (if it exists, even if it's running)
        beginhere = [config['other_host_id'],True,{}]
        endhere = [config['other_host_id'],False,0] 
        raw_result = maindb.get_view_raw_result(thisview[0], thisview[1], startkey=beginhere , endkey=endhere , limit=1, reduce=False, descending=True)['rows']
        if len(raw_result) == 1:
            logging.debug("Previous scan found for opposite host: " + raw_result[0]['id'])
            db_logic['other_host_scanned'] = True
            db_logic['other_host_last_scan'] = raw_result[0]['id']
            db_logic['other_host_last_scan_DB'] = raw_result[0]['value']
            db_logic['other_host_last_scan_complete'] = raw_result[0]['key'][2]
        else:
            logging.debug("Previous scan NOT found for opposite host.")
            db_logic['other_host_scanned'] = False
            
        # Determine current scan database basis
        # General idea is to use the same database as the other host is currently using, provided that the database isn't older than one month.
        # If the current scanning host sees that the database is too old, it'll create a new one and start inserting documents into it.  Until the
        # other host runs another scan and sees that there's a newer DB in use by the other host, we read from the older database during the check
        # for the state of a target file when needed.
    
        # Database naming format: join('scandb-',<UTC Timestamp>)
        currenttime = int(time.time())
        # If other host has begun a scan: 
        if (db_logic['other_host_scanned']):
    
            logging.debug("Other host was previously scanned")
            # and selected database is NOT older than 30 days:
            if ((currenttime - int(db_logic['other_host_last_scan_DB'][7:])) < config['db_rollover']):
                
                # Use the same database as the other host for this_scan
                logging.debug("Using same DB as other host")
                this_scan['database'] = db_logic['other_host_last_scan_DB']
                
            # Else if the other host has begun a scan, and the selected database is older than 30 days
            if ((currenttime - int(db_logic['other_host_last_scan_DB'][7:])) >= config['db_rollover']):
                logging.info("Previous scan DB too old.")
                # Create a new database
                new_scan_db()
                
            # If the other host is using an older DB, set the flag and open it
            if (this_scan['database'] != db_logic['other_host_last_scan_DB']):
                logging.info("Databases are skewed, setting older_scandb value")
                db_logic['db_skew'] = True
                db_logic['older_scandb'] = client[db_logic['other_host_last_scan_DB']]
            else:
                db_logic['db_skew'] = False
                
        # Else If there is no prior scan for either host
        elif (not this_host_scanned and not other_host_scanned):
            logging.info("Neither host has been scanned previously")
            # create a new database
            new_scan_db()
        
        # Else if there is a local scan, but not a remote scan
        elif (this_host_scanned and not other_host_scanned):
            logging.info("This host has been scanned, but the other hasn't yet.")
            logging.debug("DB time: " + db_logic['last_scan_DB'][7:] + " Current time: " + str(currenttime))
            # If selected DB is older than 30 days
            if (currenttime - int(db_logic['last_scan_DB'][7:]) >= config['db_rollover']):
                logging.info("Previous scan DB too old.")
                new_scan_db()
            else:
                this_scan['database'] = db_logic['last_scan_DB']
            
        else:
            # Something has gone horribly wrong
            logging.fatal("Database selection logic unresolvable")
            sys.exit("Something has gone wrong. See log for details.")
        
        # Return the relevant data for the database with the other host
        return(db_logic)
        
    # Run the database selection logic to determine the scan database to use and create it if needed
    db_logic = scan_db_selection(maindb)
        
    if db_logic['other_host_scanned'] == True:
        config['other_host_last_scan_complete'] = db_logic['other_host_last_scan_complete']
        
    # Open the selected scan database. If it was somehow accidentally deleted, create a new one of the same name
    try:
        scandb = client[this_scan['database']]
    except:
        logging.error("Scan db " + this_scan['database'] + " can't be found in Cloudant. Creating a replacement.")
        new_scan_db()
        scandb = client[this_scan['database']]
    
    # Check scan DB version
    #check_views(this_scan['database'],client,scandb_views)
        
    # Create new scan document from this_scan dictionary and keep open for duration of scan
    scandoc = maindb.create_document(this_scan)
    logging.info("Scanning using database: " + this_scan['database'])
        
    # Total files scanned counter
    this_scan['filecount'] = 0
        
    if config['be_verbose'] == True:
        print "Beginning filesystem scan"
        
    # HEAVY SCAN OPERATION BEGINS HERE
    walk_filesystem(scandb, this_scan, scandoc['_id'])
    # HEAVY SCAN OPERATION ENDS HERE
    
    # Update scan document with final results
    if this_scan['errorcount'] > 0:
        this_scan['success'] = False
    else:
        this_scan['success'] = True
    updates = [
        ['errorcount',this_scan['errorcount']],
        ['filecount',this_scan['filecount']],
        ['directorysize',this_scan['directorysize']],
        ['ended',int(time.time())],
        ['success', this_scan['success']]
    ]
    for thisfield in updates:
        scandoc[thisfield[0]] = thisfield[1]
        
    scandoc.save()
    logging.debug("Full scan stats: ")
    logging.debug(json.dumps(updates, sort_keys=True, indent=4, separators=(',', ': ')))
    
    # Now that this scan is complete, wipe out any expired databases
    purge_old_dbs(client)
    
    # Close database out
    client.disconnect()
    if this_scan['success'] == True:
        return(this_scan['filecount'])
    else:
        return(False)

# Remove local filesystem path prefix to sync directory
def trim_path(fullpath, is_source):
    if is_source == True:
        return(re.sub('^{0}'.format(config['rsync_source_dir']),'',fullpath))
    else:
        return(re.sub('^{0}'.format(config['rsync_target_dir']),'',fullpath))

# The "Heavy" operation which iterates through the specified path and updates the database appropriately
def walk_filesystem(scandb, scandict, scanID):

    # List of document dictionaries scanned
    file_doc_batch = []
    # Dictionary of files on a target system to be deeper analyzed
    stale_analysis_files = dict()
    
    # Function that only runs on a target.
    def stale_analysis(stale_analysis_files):
        # Dict that gives the target ID for each source ID
        targetmap = dict()
        # Dict that stores files to be checked as orphans
        orphan_check = dict()
        logging.debug("Running target batch analysis")
        for targetfileID in stale_analysis_files.keys():
            # Map the target ID to the source ID and store in target file's dictionary
            full_path = os.path.join(stale_analysis_files[targetfileID]['path'],stale_analysis_files[targetfileID]['name'])
            stale_analysis_files[targetfileID]['sourceIDPrefix'] = get_file_id(
                config['rsync_source'],
                full_path,
                config['rsync_target_dir'],
                0
            )
            expected_source_file_ID = stale_analysis_files[targetfileID]['sourceIDPrefix'] + str(config['other_host_last_scan_complete'])
            targetmap[expected_source_file_ID] = targetfileID
        
        # Cover all STALE, and UPTODATE files by locating good recent completed scans of source
        #ddoc = DesignDocument(scandb, document_id=scandb_views['source_files'][0])
        #ddoc.fetch()
        #view = View(ddoc, scandb_views['source_files'][1])
        logging.debug("Passing list of keys to source_files view")
        logging.info("Searching for stale and up-to-date files.")
        sourceFilesResult = scandb.get_view_result(scandb_views['source_files'][0], scandb_views['source_files'][1], keys=targetmap.keys(), reduce=False)
        logging.debug(sourceFilesResult[:])
        for row in sourceFilesResult[:]:
            # Store timestamp of source file into target file dict (for stale check)
            logging.debug(row)
            stale_analysis_files[targetmap[row['id']]]['sourcemodified'] = row['value']
            stale_analysis_files[targetmap[row['id']]]['orphaned'] = 'no'
            logging.info("File: {0} was scanned on source at: {1}".format(row['id'], datetime.fromtimestamp(row['value']).ctime()))
            # Remove the doc as finished so we don't alter it further
            targetmap.pop(row['id'],None)
        
        # Cover any ORPHANED files by checking to see if the file was scanned on source but NOT in the most recent completed scan
        if len(targetmap) > 0:
            logging.info("Processing any potential orphaned files...")
            for sourceID in targetmap.keys():
                # remove timestamp suffixes and put into orphan check dictionary
                orphan_check[sourceID[:40]] = targetmap[sourceID]
                logging.info("Checking target: {0} -> against source: {1} ?".format(targetmap[sourceID], sourceID[:40]))
            # post all suffixes to sourceprefixes view
            ddoc = DesignDocument(scandb, document_id=scandb_views['source_prefixes'][0])
            view = View(ddoc, scandb_views['source_prefixes'][1])
            tempresult = view(keys=orphan_check.keys(), reduce=False)['rows']
            for row in tempresult:
                try:
                    orphanID = orphan_check[row['key']]
                    logging.info("File: {0} confirmed as orphaned".format(orphanID))
                    stale_analysis_files[orphanID]['orphaned'] = 'yes'
                    orphan_check.pop(row['key'], None)
                except:
                    continue # This is in place to skip over entries of files that have been already scanned
        
        # Cover any UNKNOWN files (which are any remaining after orphan_check)
        if len(orphan_check) > 0:
            logging.info("Unknown files found:")
            for targetID in orphan_check.values():
                logging.debug("File ID {0}".format(targetID))
                stale_analysis_files[targetID]['orphaned'] = 'unknown'
                logging.info("File: {0} in an unknown sync state. No data on source file found".format(targetID))
            orphan_check.clear()
        
        # Write the dictionary of target files to the database
        target_files = stale_analysis_files.values()
        scandb.bulk_docs(target_files)
        # Empty the dictionary
        stale_analysis_files.clear()
        
    # Function that runs regardless of source or target. Fills needed information
    def local_file_check(filedict, root, name):
        # Set all default values for the current file's record in the database.
        # Construct it's custom ID based on the timestamp that the scan began at.
        prefix = get_file_id(config['host_id'], os.path.join(root,name), scandict['directory'], 0)
        filedict['_id'] = prefix + str(scandict['started'])
        filedict['IDprefix'] = prefix
        filedict['name'] = name
        filedict['scanID'] = scanID
        filedict['host'] = config['host_id']
        filedict['relationship'] = config['relationship']
        filedict['path'] = root
        filedict['datescanned'] = int(time.time())
        filedict['size'] = 0
        filedict['permissionsUNIX'] = 0
        filedict['datemodified'] = 0
        filedict['owner'] = 0
        filedict['group'] = 0
        filedict['goodscan'] = False
        filedict['type'] = "file"
        #filedict['orphaned'] = False
        if config['is_source'] == True:
            filedict['source'] = True
            filedict['syncpath'] = trim_path(os.path.join(root,name), True)
        else:
            filedict['source'] = False
            filedict['syncpath'] = trim_path(os.path.join(root,name), False)
        
        
        # Obtain detailed stats on file from OS if possible
        try:
            stat = os.stat(os.path.join(root,name))
            #filedict['datescanned'] = int(time.time())
            filedict['size'] = stat.st_size
            filedict['permissionsUNIX'] = stat.st_mode
            filedict['datemodified'] = stat.st_mtime
            filedict['owner'] = stat.st_uid
            filedict['group'] = stat.st_gid
            filedict['goodscan'] = True
            scandict['directorysize'] = scandict['directorysize'] + filedict['size']
            if (config['ultra_scan'] == True):
                filedict['checksum'] = compute_file_checksum(os.path.join(root,name))
        except OSError as e:
            # Store as bad scan of file and iterate errors
            scandict['errorcount'] = scandict['errorcount'] + 1
            logging.error("File {0} can't be scanned: {1} {2}".format(os.path.join(root,name), e.errno, e.strerror))

    verbose_counter = 0
    # Iterate through directory structure
    for root, dirs, files in os.walk(scandict['directory'], topdown=False):
        # Prune any skipped files and directories from excludes list
        dirs[:] = [d for d in dirs if d not in config['rsync_excluded']]
        files[:] = [d for d in files if d not in config['rsync_excluded']]
        
        for name in files:
            verbose_counter = verbose_counter + 1
            if (verbose_counter / 100 == float(verbose_counter) / 100 and config['be_verbose'] == True):
                print " Scanned {0} files...".format(verbose_counter)
            # Iterate counter for scan
            scandict['filecount'] = scandict['filecount'] + 1
            filedict = dict()
                
            # run operation for all local files, regardless of source or target
            local_file_check(filedict, root, name)
            
            if (config['is_source']):
                # Easy. We're done with this file since it's on a source host.
                # Simply put it into the array for batch insert into the database.
                file_doc_batch.append(filedict)
                # If we're at _bulk_docs threshold, write to db and empty the batch array for the next loop.
                if len(file_doc_batch) >= config['doc_threshold']:
                    scandb.bulk_docs(file_doc_batch)
                    file_doc_batch = []
                    logging.info("Inserted a batch of source files into db")
            else:
                # We're on a target host, so we aren't finished yet.
                # Add file to the dictionary of filedicts to perform stale analysis for and run function if at batch size
                stale_analysis_files[filedict['_id']] = filedict
                if len(stale_analysis_files) >= config['post_threshold']:
                    logging.info("Running stale analysis on a batch of {0} analyzed target files".format(len(stale_analysis_files)))
                    stale_analysis(stale_analysis_files)
                else:
                    # Move on to the next file, doing nothing
                    logging.debug("nextfile")
                    continue
    
    # *** FILESYSTEM SCAN COMPLETE ***
    # Insert any remaining documents below the threshold when we're out of files to scan
    if len(file_doc_batch) > 0:
        logging.debug("Executing final insertion of {0} files into {1}".format(len(file_doc_batch),scandb))
        scandb.bulk_docs(file_doc_batch)
        file_doc_batch = []
        logging.debug("Final flush of scanned source files to db complete")
    if len(stale_analysis_files) > 0:
        logging.debug("Executing final stale analysis of {0} files".format(len(stale_analysis_files)))
        stale_analysis(stale_analysis_files)
        logging.debug("Final flush of analyzed target files to db complete")
    

# Return the unique ID for a file based upon hash and last scan timestamp
# Currently uses a 40-characer sha1 hash of the hostid, path and filename and appends the passed timestamp
# Removes the passed top_dir in order to make the ID consistent between the hosts when the root path is not the same
# ^ ID will still not be consistent since the host changes???
# Returns only the hash if a zero is passed as the timestamp
def get_file_id(host_id, full_path, top_dir, timestamp):
    # trim the top_dir from the full path
    pathtrim = len(top_dir)
    relative_path = full_path[pathtrim:]
    #logging.debug("Relative file path: " + relative_path)
    try:
        f1 = relative_path.decode('utf-8', errors='replace')
        filehash = hashlib.sha1(host_id + f1.encode('utf-8', errors='replace')).hexdigest()
        logging.debug("Hashing input: {0},{1}{2}, {3} Output:{4}".format(host_id,top_dir,full_path,timestamp,filehash))
    except UnicodeDecodeError:
        logging.warn("Path Decode error: " + relative_path)
        filehash = hashlib.sha1(host_id).hexdigest()        
    except UnicodeEncodeError:
        logging.warn("Path Encode error: " + relative_path)
        filehash = hashlib.sha1(host_id).hexdigest()
    if timestamp == 0:
        return (filehash)
    else:
        return (filehash + str(timestamp))

# Insanely-slow but ultra-effective scanner process that computes an md5 hash of every file it encounters
# Currently this option is hard-coded to be disabled.
# I might incorporate it as an option if performance isn't TOO awful
def compute_file_checksum(fname):
    filehash = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            filehash.update(chunk)
    return filehash.hexdigest()
    
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
    
# Clean up derelict scan databases in the Cloudant account
def purge_old_dbs(client):
    dblist = client.all_dbs()
    current_time = int(time.time())
    for db in dblist:
        if 'scandb-' not in db:
            continue
        elif ((current_time - int(db[7:])) > config['db_max_age']):
            # If the extracted timestamp is older than the threshold
            logging.info("Deleting out-dated database: " + db)
            # execute a database delete command
            doomed_db = client[db]
            doomed_db.delete()
        elif ((current_time - int(db[7:])) > 86400):
            # If the database is older than one day, and has no documents besides ddocs
            empty_db = client[db]
            if empty_db.doc_count() < 10:
                logging.info("Deleting empty database: " + db)
                empty_db.delete()
                
    # If the database is older than one month, and has no successful completed scans associated with it
    main_db = client[config['main_db_name']]
    thisview = maindb_views['recent_scans']
    result = main_db.get_view_result(thisview[0], thisview[1], reduce=False)
    for r in result:
        if (r['value'] in dblist) and (r['key'][1] == False) and (current_time - int(r['value'][7:]) > 2592000):
            logging.info("Deleting {0} due to no successful scans for one week.".format(r['value']))
            doomed_db = client[r['value']]
            doomed_db.delete()
            dblist.remove(r['value'])

# Insert the passed dictionary of views into the passed database
# Needs a method for upgrading existing views in case they change with a new version of the script
def populate_views(db, viewdict):
    for viewname in viewdict:
        view = viewdict[viewname]
        ddoc = DesignDocument(db, document_id=view[0])
        if (ddoc.exists()):
            # If view exists, go to the next one. Otherwise create it
            ddoc.fetch()
            try:
                ddoc.get_view(view[1])
                logging.debug("Design document and view found, moving on")
            except:
                logging.debug("Design document "+ view[0] +" found, adding view: " + view[1])
                ddoc.add_view(view[1], view[2], reduce_func = view[3])
                ddoc.save()
        else:
            try:
                ddoc = DesignDocument(db, document_id=view[0])
                ddoc.add_view(view[1], view[2], reduce_func=view[3])
                ddoc.save()
                logging.debug("Inserted design document " + view[0] + " view: " + view[1])
            except Exception:
                logging.fatal("Cannot insert design document into scan database: " + view[0])
                sys.exit("Something has gone wrong. See log for details")

# Check database views in database with <dbname> using client <c>, and the set of <views>
def check_views(dbname, c, views):
    db = c[dbname]
    versiondoc = Document(db,document_id="scanversion")
    if versiondoc.exists() != True:
        versiondoc.create()
        versiondoc['current'] = config['viewversion']
        versiondoc['history']= []
        versiondoc.save()
    else:
        versiondoc.fetch()
    if versiondoc['current'] < config['viewversion']:
        # Open each ddoc / view combo for existing
        for thisview in views.values():
            ddoc = DesignDocument(db,thisview[0])
            if ddoc.exists() == False:
                # Create ddoc and view
                logging.info("Creating {0}{1}".format(thisview[0],thisview[1]))
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
                    ddoc.add_view(thisview[1],thisview[2],thisview[3])
                    ddoc.save()
                # if view function is different
                elif (oldview['map'] != thisview[2]):
                    # Update
                    logging.info("Updating {0}{1}".format(thisview[0],thisview[1]))
                    ddoc.update_view(thisview[1],thisview[2],thisview[3])
                    ddoc.save()
                else:
                    continue
        versiondoc.update_field(action=versiondoc.list_field_append, field='history', value = versiondoc['current'])
        versiondoc.update_field(action=versiondoc.field_set, field='current', value = config['viewversion'])

if __name__ == "__main__":
    main()

