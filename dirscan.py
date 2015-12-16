#!/usr/bin/env python

# Prep
import json
import getopt
#from getopt import GetoptError
import base64
import sys
import hashlib
import time
import datetime
from cloudant.account import Cloudant
from cloudant.design_document import DesignDocument
from cloudant.result import Result
from cloudant.document import Document
from cloudant.views import View
from cloudant import cloudant
import getpass
import os
import logging

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
    # Slot for base64 auth string (Not currently used)
    # cloudant_auth_string = '',
    # Help string printed if invalid options or '-h' used
    help_text = "Usage: dirscan.py [-c <configfile>] [-u] [-x <excludes_file>] [-v]",
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
    # Setting to use for logging level.  Recommend no higher than INFO unless actually debugging
    log_level = logging.INFO
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
scandb_views = dict(
    file_types = [
        '_design/files',
        'typesscanned',
        'function (doc) {if (doc.type === "file" && doc.goodscan === true) { filetype = fname.substr((~-doc.name.lastIndexOf(".") >>> 0) + 2); emit([doc.host, doc.scanID, filetype], doc.size); } }',
        '_stats'
    ],
    target_scanned = [
        '_design/scanresults',
        'targetfiles',
        'function (doc) {if (doc.type === "file" && doc.goodscan === true && doc.source === false) {emit([doc.scanID, doc.orphaned, doc.stale], doc.size);}}',
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
        'function (doc) { if (doc.type === "file" && doc.goodscan === true && doc.source === true) {emit(doc.id, doc.datemodified); }}',
        None
    ]
)

# Main execution code
def main(argv):
    # Enable warning logs
    try:
        logging.basicConfig(filename='dirsync_errorlog.txt', level=config['log_level'])
        logging.captureWarnings(True)
    except Exception:
        sys.exit("Can't open local log file.")
    
    # Check options for validity, print help if user fat-fingered anything
    try:
        opts, args = getopt.getopt(argv,"hc:x:uv")
    except getopt.GetoptError:
        print config['help_text']
        sys.exit(2)
    
    # Process passed options
    for opt, arg in opts:
        if opt == '-h':
            print help
            sys.exit()
        elif opt in ("-c"):
            if len(arg) < 6:
                sys.exit(config['help_text'])
            config['passed_config_file'] = arg
        elif opt in ("-u"):
            # This doesn't do anything yet
            # Eventually meant to be the parameter for an update to existing configuration
            update = 1
        elif opt in ("-v"):
            config['be_verbose'] = True
        elif opt in ("-x"):
            if len(arg) < 1:
                sys.exit(config['help_text'])
            get_excludes(arg)
    
    # If config file is specfied, read it in and execute scan
    if (len(config['passed_config_file']) > 0):
        scanstarttime = datetime.datetime.utcnow().isoformat(' ')        
        logging.info("Scan started at " + scanstarttime + " UTC")
        
        # Load configuration settings from file
        if (config['be_verbose']):
            print "Loading " + config['passed_config_file']
        load_config(config['passed_config_file'])
        
        # Initiate scan
        logging.debug(json.dumps(config, sort_keys=True, indent=4, separators=(',', ': ')))

        if config['be_verbose'] == True:
            print "Initiating scan now..."
        completion = directory_scan()
        scanfinishtime = datetime.datetime.utcnow().isoformat(' ')
        # Log scan completion status
        if (completion):
            logging.info("Scan successfully completed at: " + scanfinishtime + " UTC")
            if config['be_verbose'] == True:
                print "Scan successfully completed at " + scanfinishtime
        else:
            if config['be_verbose'] == True:
                print "Scan completed with errors at " + scanfinishtime
            logging.warn("Scan completed with errors at: " + scanfinishtime + " UTC")
        
        # We're done here
        sys.exit()

    # If no configuration file is passed, ask to run initialization process
    else:
        newfile = raw_input("No configuration file specified. Create? (Y/N) > ")
        if (newfile in ('y','Y')):
            create_initial_config()
        else:
            print "Exiting..."
            sys.exit()

# Assemble and write the JSON-formatted configuration file for the host we're running on
def create_initial_config():
    # Initialize Cloudant client instance and obtain user credentials
    auth_not_set = True
    while (auth_not_set):
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
            print " Database found"
        
    except Exception:
        
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
                print "To initiate a scan, use 'dirscan.py -c /path/to/" + config['default_config_filename'] + "'"
                    
    else:
        # Have the user set up a new relationship then 
        relationshipdocID = create_new_relationship(maindb)
        
        # Choose the relationship automatically and run host setup
        create_host_entry(maindb, relationshipdocID)
        
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
    # TO-DO: Validate path exists
    # validate_path(this_host_directory)
    
    # Create the new host document in the database and get it's ID
    # TO-DO: CHECK TO SEE IF I CAN DO THIS WITH A DICT INSERT
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

    # Write host's config file to disk
    write_config_file(config_file_content)

# Write a JSON-formatted file with the passed configuration settings
def write_config_file(config_dict):
    # config_json = json.dump(config_dict)
    try:
        data = open(config['default_config_filename'], 'w')
    except IOError as e:
        print "I/O error({0}): {1}".format(e.errno, e.strerror)
        sys.exit(2)
    json.dump(config_dict, data)
    data.close()
    print " " + config['default_config_filename'] +" written."
    print " This file contains your Cloudant authentication hash, so be sure to secure it appropriately!"

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
                logging.debug("Previous scan DB too old.")
                # Create a new database
                new_scan_db()
                
            # If the other host is using an older DB, set the flag and open it
            if (this_scan['database'] != db_logic['other_host_last_scan_DB']):
                logging.debug("Databases are skewed, setting older_scandb value")
                db_logic['db_skew'] = True
                db_logic['older_scandb'] = client[db_logic['other_host_last_scan_DB']]
            else:
                db_logic['db_skew'] = False
                
        # Else If there is no prior scan for either host
        elif (not this_host_scanned and not other_host_scanned):
            logging.debug("Neither host has been scanned previously")
            # create a new database
            new_scan_db()
        
        # Else if there is a local scan, but not a remote scan
        elif (this_host_scanned and not other_host_scanned):
            logging.debug("This host has been scanned, but the other hasn't yet.")
            logging.debug("DB time: " + db_logic['last_scan_DB'][7:] + " Current time: " + str(currenttime))
            # If selected DB is older than 30 days
            if (currenttime - int(db_logic['last_scan_DB'][7:]) >= config['db_rollover']):
                logging.debug("Previous scan DB too old.")
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
        
    # Open the selected scan database. If it was somehow accidentally deleted, create a new one of the same name
    try:
        scandb = client[this_scan['database']]
    except:
        logging.error("Scan db " + this_scan['database'] + " can't be found in Cloudant.")
        new_scan_db()
        scandb = client[this_scan['database']]
        
    # Create new scan document from this_scan dictionary and keep open for duration of scan
    scandoc = maindb.create_document(this_scan)
    logging.info("Scanning using database: " + this_scan['database'])
        
    # Total files scanned counter
    this_scan['filecount'] = 0
        
    # Dictionary of document dictionaries scanned
    file_doc_batch = []
        
    if config['be_verbose'] == True:
        print "Beginning filesystem scan"
        
    # HEAVY SCAN OPERATION BEGINS HERE
    # Iterate through directory structure
    for root, dirs, files in os.walk(this_scan['directory'], topdown=False):
        # Prune any skipped files and directories from excludes list
        dirs[:] = [d for d in dirs if d not in config['rsync_excluded']]
        files[:] = [d for d in files if d not in config['rsync_excluded']]
        
        for name in files:
            # Iterate counter for scan
            this_scan['filecount'] = this_scan['filecount'] + 1
            filedict = dict()
            
            # Obtain base file information and store into dict
            # Set all defaults
            filedict['_id'] = get_file_id(config['host_id'], os.path.join(root,name), this_scan['directory'], this_scan['started'])
            filedict['name'] = name
            filedict['scanID'] = scandoc['_id']
            filedict['host'] = config['host_id']
            filedict['relationship'] = config['relationship']
            filedict['path'] = root
            filedict['datescanned'] = 0
            filedict['size'] = 0
            filedict['permissionsUNIX'] = 0
            filedict['datemodified'] = 0
            filedict['owner'] = 0
            filedict['group'] = 0
            filedict['goodscan'] = False
            filedict['source'] = True
            filedict['type'] = "file"
            
            # Obtain detailed stats on file from OS if possible
            try:
                stat = os.stat(os.path.join(root,name))
                filedict['datescanned'] = int(time.time())
                filedict['size'] = stat.st_size
                filedict['permissionsUNIX'] = stat.st_mode
                filedict['datemodified'] = stat.st_mtime
                filedict['owner'] = stat.st_uid
                filedict['group'] = stat.st_gid
                filedict['goodscan'] = True
                this_scan['directorysize'] = this_scan['directorysize'] + filedict['size']
                if (config['ultra_scan'] == True):
                    filedict['checksum'] = compute_file_hash(os.path.join(root,name))
            except OSError as e:
                # Store as bad scan of file and iterate errors
                this_scan['errorcount'] = this_scan['errorcount'] + 1
                logging.warn("File {0} can't be scanned: {1} {2}".format(os.path.join(root,name), e.errno, e.strerror))

            if (config['is_source']):
                # We're done scanning this file.  Put it into the array.
                file_doc_batch.append(filedict)

            else:
                # We're on a target host, so we aren't finished yet.
                filedict['source'] = False
                
                # Check for source file scanned in database 
                # Passing a zero to ignore the timestamp and return only the unique file hash
                source_id_hash = get_file_id(config['other_host_id'], os.path.join(root,name), this_scan['directory'], 0)
                
                logging.debug("other host ID: " + config['other_host_id'])
                logging.debug("file path: " + os.path.join(root,name))
                logging.debug("source_id_hash: " + source_id_hash)
                
                if db_logic['db_skew']:
                    source_file = db_logic['older_scandb'].all_docs(descending=True, endkey=source_id_hash, startkey=source_id_hash + str(99999999999999999999), limit=1, include_docs=True)['rows']
                else:
                    source_file = scandb.all_docs(descending=True, endkey=source_id_hash, startkey=source_id_hash + str(99999999999999999999), limit=1, include_docs=True)['rows']
                
                # If file has been scanned:
                if len(source_file) > 0:
                    logging.debug("Source file scanned on other host: YES")
                    # Get the file's Scan timestamp from it's ID
                    sfst = source_file[0]['id'][40:]
                    source_file_scan_time = int(sfst)
                    
                    # If the file scan timestamp is >= last successful scan date
                    if (source_file_scan_time >= db_logic['other_host_last_scan_complete']):
                        # It's not orphaned
                        filedict['orphaned'] = 'no'

                        # But to determine if it's stale, check the scanned file's modified date against the most recent source version.
                        thisview = scandb_views['source_files']
                        if db_logic['db_skew']:
                            result = db_logic['older_scandb'].get_view_raw_result(thisview[0],thisview[1], key=source_file[0]['id'])['rows']
                        else:
                            result = scandb.get_view_raw_result(thisview[0],thisview[1], key=source_file[0]['id'])['rows']
                        
                        if (len(result) > 0 and result[0]['value'] > filedict['datemodified']):
                            # If source is newer,
                            # In future, this may also include if the latest source scan is older than a configured age threshold
                            filedict['stale'] = True
                        else:
                            # If source is same or older age, it's up-to-date
                            filedict['stale'] = False
    
                    # Else if the timestamp is < last successful completed scan ID for host
                    # File is orphaned and automatically stale
                    else:
                        filedict['orphaned'] = 'yes'
                        filedict['stale'] = True

                # If the file hasn't ever been scanned on the source we don't know what it's status is
                else:
                    logging.debug("Source file scanned on other host: NO")
                    filedict['orphaned'] = "unknown"
                    filedict['stale'] = False
                
                # Finished, add to array
                file_doc_batch.append(filedict)
                                            
        # If we're at _bulk_docs threshold
        if ((this_scan['filecount'] > 1) and (int(this_scan['filecount']) / int(config['doc_threshold']) == int(this_scan['filecount']) / float(config['doc_threshold']))):
            # write batch to database
            scandb.bulk_docs(file_doc_batch)
            # flush batch array
            file_doc_batch = []

    # Insert any remaining documents below the threshold
    if len(file_doc_batch) > 0:
        scandb.bulk_docs(file_doc_batch)
        file_doc_batch = []
    
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
    logging.info("Scan stats: ")
    logging.info(json.dumps(updates, sort_keys=True, indent=4, separators=(',', ': ')))
    
    # Now that this scan is complete, wipe out any expired databases
    purge_old_dbs(client)
    
    # Close database out
    client.disconnect()
    
    return(this_scan['success'])

# Return the unique ID for a file based upon hash and last scan timestamp
# Currently uses a 40-characer sha1 hash of the hostid, path and filename and appends the most recent UTC
# Removes the passed top_dir in order to make the ID consistent between the hosts when the root path is not the same
# Returns only the hash if a zero is passed as the timestamp
def get_file_id(host_id, full_path, top_dir, timestamp):
    # trim the top_dir from the full path
    pathtrim = len(top_dir)
    relative_path = full_path[pathtrim:]
    logging.debug("Relative file path: " + relative_path)
    try:
        f1 = relative_path.decode('utf-8', errors='replace')
        filehash = hashlib.sha1(host_id + f1.encode('utf-8', errors='replace')).hexdigest()
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
def compute_file_hash(fname):
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

# Read in the excludes file passed at startup and store to the config array
def get_excludes(filename):
    try:
        data = open(filename)
    except IOError as e:
        print "I/O error({0}): {1}".format(e.errno, e.strerror)
        sys.exit(2)
    for exclude in data:
        if exclude.isspace():
            continue
        else:
            config['rsync_excluded'].append(exclude)
    
# Check for scan databases older than retention threshold and delete them
# TO-DO: Delete scan dbs without any successful scan documents associated with them and are beyond a certain threshold in number
def purge_old_dbs(client):
    dblist = client.all_dbs()
    current_time = int(time.time())
    for db in dblist:
        if 'scandb-' not in db:
            continue
        else:
            # If the extracted timestamp is older than the threshold
            if ((current_time - int(db[7:])) > config['db_max_age']):
                logging.info("Deleting out-dated database: " + db)
                # execute a database delete command
                doomed_db = Database(client,db)
                doomed_db.delete()

# Insert the passed dictionary of views into the passed database
def populate_views(db, viewdict):
    for viewname in viewdict:
        view = viewdict[viewname]
        ddoc = DesignDocument(db, document_id=view[0])
        if (ddoc.exists()):
            logging.debug("Design Document "+ view[0] +" found, adding view: " + view[1])
            ddoc.fetch()
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

# TO-DO: Utilize bulk calls to check for stale file states en-masse.
def bulk_stale_check():
    pass

if __name__ == "__main__":
    main(sys.argv[1:])

