#!/usr/bin/env python

# Prep
import json
from getopt import getopt
from getopt import GetoptError
from base64 import b64encode
import hashlib
import datetime
import time
from cloudant.account import Cloudant
from cloudant import cloudant
from getpass import getpass
from os import walk
from os import path

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
    cloudant_user = '',
    # Slot for base64 auth string
    cloudant_auth_string = '',
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
    db_max_age = 7776000
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
                    'function (doc) {if (doc.type === "scan") {emit([doc.host, doc.success, doc.started], doc.database);}}',
                    None]
)

# Views in each per-diem file dbs
# Format is <view> = [<ddocname>,<viewname>,<mapfunction>,<reducefunction>]
filedb_views = dict(
    file_types = [  #FIX THIS SO IT DETERMINES EXTENSION
        '_design/files',
        'typesscanned',
        'function (doc) {if (doc.type === "file" && doc.goodscan === true) { emit([doc.host, doc.scanID, filetype], doc.size); } }',
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
        
        # Load configuration settings from file
        if (config['be_verbose']):
            print "Loading " + config['passed_config_file']
        load_config(config['passed_config_file'])
        
        # Initiate scan
        if (config['be_verbose']):
            print config
            print "Initiating scan now..."
        completion = directory_scan()
        
        # If scan completed successfully, output when verbose
        if (config['be_verbose']):
            if (completion):
                scanfinishtime = datetime.datetime.utcnow().isoformat(' ')
                print "Scan successfully completed at " + scanfinishtime
            else:
                print "Scan aborted."
        
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
        print "You will need a Cloudant account to use this script."
        print "Go to www.cloudant.com to create one if you don't have it yet."
        print "Enter Cloudant account name (DNS name before .cloudant.com):"
        config['cloudant_user'] = raw_input("> ")
        print "Enter login username (often the same as the account name):"
        input_string = "["+ config['cloudant_user'] + "] > "
        cloudant_login = raw_input(input_string)
        if len(cloudant_login) == 0:
            cloudant_login = config['cloudant_user']
        cloudant_pass = getpass.getpass()
        usrPass = cloudant_login + ":" + cloudant_pass
        config['cloudant_auth_string'] = base64.b64encode(usrPass)
        try:
            client = Cloudant(cloudant_login, cloudant_pass, account=config['cloudant_user'])
            client.connect()
            auth_not_set = False
        except Exception:
            print "Sorry, try again."

    # Create database object
    try:
        # Open existing database
        maindb = client[config['main_db_name']]
        if config['be_verbose'] == True:
            print "Database found"
        # To-do: validate views
        
    except Exception:
        
        # Create database if it doesn't exist
        maindb = client.create_database(config['main_db_name'])
        if config['be_verbose'] == True:
            print "Database created"
        
        # Insert design documents for required indexes in main db
        for view in maindb_views:
            with DesignDocument(db, document_id=view[0]) as ddoc:
                ddoc.add_view(view[1], view[2], reduce_func=view[3])
    
    # Begin process of collecting data
    relationship_status = ''
    while (relationship_status not in ("y", "Y", "n", "N")):
        relationship_status = raw_input("Is the relationship for this host already set up? (y/n) > ")
        
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
        
        print "Now run this setup on the other host."
    client.disconnect()

# Take a given database and relationship document object and create a new host entry, plus write config file to local system
def create_host_entry(db, relationshipdocID):
    # Get the relationship document from Cloudant DB
    relationshipdoc = Document(db, relationshipdocID)
    relationshipdoc.fetch()
    
    print "Editing relationship: " + relationshipdoc['name']

    # Get hosts by ID's from relationship, open docs and print names if they exist
    config_count = 0
    if (relationshipdoc['sourcehost'] != "UNDEFINED"):
        print "Source host: " + sourcedoc['hostname']
        config_count = config_count + 1
    else:
        print "Source host: NOT CONFIGURED"
        
    if (relationshipdoc['targethost'] != "UNDEFINED"):
        print "Target host: " + targetdoc['hostname']
        config_count = config_count + 1
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
    
    # TO-DO: Validate path exists
    # validate_path(this_host_directory)
    
    # Create the new host document in the database and get it's ID
    with Document(db) as sourcedoc:
        sourcedoc['type'] = 'host'
        sourcedoc['hostname'] = new_hostname
        sourcedoc['ip4'] = this_host_IP4
        sourcedoc['ip6'] = this_host_IP6
        sourcedoc.create()
        new_host_ID = sourcedoc['_id']
        
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
        action = doc.field_set,
        field = which_host,
        value = new_host_ID
    )
    relationshipdoc.update_field(
        action = doc.field_set,
        field = which_dir,
        value = this_host_directory
    )

    # Populate config file's content for host
    config_file_content = dict(
        auth = config['cloudant_auth_string'],
        cloudant_user = config['cloudant_user'],
        relationship = relationshipdoc['_id'],
        host_id = new_host_ID,
        threshold = config['doc_threshold']
    )

    # Write host's config file to disk
    write_config_file(config_file_content)

# Write a JSON-formatted file with the passed configuration settings
def write_config_file(config_dict):
    config_json = json.dump(config_dict)
    try:
        data = open(config['default_config_filename'])
    except IOError as e:
        print "I/O error({0}): {1}".format(e.errno, e.strerror)
        sys.exit(2)
    data.write(config_json)
    data.close()
    print config['default_config_filename'] +" written."
    print "This file contains your Cloudant authentication hash, so be sure to secure it appropriately!"

# Load configuration from file and database into configuration dictionary
def load_config(config_file):
    try:
        data = open(config_file)
    except IOError as e:
        print "I/O error({0}): {1}".format(e.errno, e.strerror)
        sys.exit(2)
    config_json = json.load(data)
    data.close()
    config['cloudant_auth'] = config_json['auth']
    config['cloudant_user'] = config_json['cloudant_user']
    config['relationship'] = config_json['relationship']
    config['host_id'] = config_json['host_id']
    config['doc_threshold'] = config_json['threshold']
    
    # Connect to database
    with cloudant(config['cloudant_user'], config['cloudant_auth']) as client:
        with CloudantDatabase(client, config['main_db_name']) as db:
    
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

# TO-DO: filesystem scan function 
def directory_scan():
    sys.exit("Not implemented")
    
    # Init local variables
    this_scan = dict(
        database = '',
        started = time.time(),
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
        client = Cloudant(config['cloudant_user'], config['cloudant_auth'])
        client.connect()
    except Exception:
        sys.exit("FAIL: Unable to open connection to Cloudant")

    # Open main database
    try:
        maindb = client[config['main_db_name']]
    except Exception:
        sys.exit("FAIL: Main database can't be found")

    # Get this host's last successful scan info (if it exists)
    thisview = maindb_views['recentscans']
    beginhere = [config['host_id'],True,'']
    endhere = [config['host_id'],True,{}]
    with maindb.get_view_raw_result(thisview[0], thisview[1], startkey=beginhere , endkey=endhere , limit=1, reduce=False, descending=True) as raw_result:
        if len(raw_result) > 0:
            this_host_scanned = True
            this_scan['firstscan'] = False
            this_scan['previousscanID'] = raw_result['_id']
            last_scan_DB = raw_result['value']
            last_scan_complete = raw_result['key'][2]
        else:
            this_host_scanned = False
    
    # Get the other host's last scan info (if it exists, even if it's running)
    beginhere = [config['other_host_id'],False,'']
    endhere = [config['other_host_id'],True,{}]
    with maindb.get_view_raw_result(thisview[0], thisview[1], startkey=beginhere , endkey=endhere , limit=1, reduce=False, descending=True) as raw_result:
        if len(raw_result) > 0:
            other_host_scanned = True
            other_host_last_scan = raw_result['_id']
            other_host_last_scan_DB = raw_result['value']
            other_host_last_scan_complete = raw_result['key'][2]
        else:
            other_host_scanned = False
        
    # Determine current scan database basis
    # General idea is to use the same database as the other host is currently using, provided that the database isn't older than one month.
    # If the current scanning host sees that the database is too old, it'll create a new one and start inserting documents into it.  Until the
    # other host runs another scan and sees that there's a newer DB in use by the other host, we read from the older database during the check
    # for the state of a target file when needed.

    # Database naming format: join('scandb-',<UTC Timestamp>)
        
    # Database creation function
    def new_scan_db():
        # Create a new database for this week
        new_scan_db_name = join('scandb-',time.time())
        try:
            new_scan_db = client.create_database(new_scan_db_name)
        except Exception:
            sys.exit("FATAL: Cannot create new temporal scan database")
            
        # Populate filedb_views
        for thisview in scandb_views:
            with DesignDocument(db, document_id=view[0]) as ddoc:
                ddoc.add_view(view[1], view[2], reduce_func=view[3])
                
        # Set database name for this_scan
        this_scan['database'] = new_scan_db_name
        
    # If other host has begun a scan: 
    if (other_host_scanned):
        # and selected database is NOT older than 30 days:
        if (datetime.timedelta(time.time(),other_host_last_scan_DB[7:]) < config['db_rollover']):
            
            # Use the same database as the other host for this_scan
            this_scan['database'] = other_host_last_scan_DB
            
        # Else if the other host has begun a scan, and the selected database is older than 30 days
        if (datetime.timedelta(time.time(),other_host_last_scan_DB[7:]) >= config['db_rollover']):
            
            # Create a new database
            new_scan_db()
            
    # Else If there is no prior scan for either host
    elif (not this_host_scanned and not other_host_scanned):
        # create a new database
        new_scan_db()
        
    else:
        # Something has gone horribly wrong
        sys.exit("FATAL: Database selection logic unresolvable")


    # Create new scan document from this_scan dictionary and keep open for duration of scan
    scandoc = maindb.create_document(this_scan)
    
    # Open the scan database
    scandb = client[this_scan['database']]
    
    # If the other host is using an older DB, set the flag and open it
    if (this_scan['database'] != other_host_last_scan_DB):
        db_skew = True
        older_scandb = client[other_host_last_scan_DB]
    else:
        db_skew = False

    # Total files scanned counter
    filecount = 0
    
    # Dictionary of document dictionaries scanned
    file_doc_batch = []
    
    if config['be_verbose'] == True:
        print "Beginning filesystem scan"
        
    # Iterate through directory structure
    for root, dirs, files in os.walk(this_scan['directory'], topdown=False):
        for name in files:
            # Iterate counter for scan
            filecount = filecount + 1
            
            # Obtain base file information and store into dict
            filedict['_id'] = get_file_id(config['host_id'], os.path.join(root,name), this_scan['started'])
            filedict['name'] = name
            filedict['scanID'] = scandoc['_id']
            filedict['host'] = config['host_id']
            filedict['relationship'] = config['relationship']
            filedict['path'] = root
            
            # Obtain detailed stats on file from OS if possible
            try:
                stat = os.stat(os.path.join(root,name))
                filedict['datescanned'] = time.time()
                filedict['size'] = stat['st_size']
                filedict['permissionsUNIX'] = stat['st_mode']
                filedict['datemodified'] = stat['st_mtime']
                filedict['owner'] = stat['st_uid']
                filedict['group'] = stat['st_gid']
                filedict['goodscan'] = True
                this_scan['directorysize'] = this_scan['directorysize'] + filedict['size']
                if (config['ultra_scan'] == True):
                    filedict['checksum'] = compute_file_hash(os.path.join(root,name))
            except:
                # permissions problem most likely, store as bad scan of file and iterate errors
                filedict['goodscan'] = False
                this_scan['errorcount'] = this_scan['errorcount'] + 1
                
            if (config['is_source']):
                # We're done scanning this file.  Put it into the array.
                filedict['source'] = True
                file_doc_batch.append(filedict)

            else:
                # We're on a target host, so we aren't finished yet.
                filedict['source'] = False
                
                # Check for source file scanned in database 
                source_id_hash = hashlib.sha1(join(config['other_host_id'],os.path.join(root,name))).hexdigest()
                if db_skew:
                    source_file = older_scandb.all_docs(descending=True, startkey=source_id_hash, endkey=join(source_id_hash, 99999999999999999999), limit=1)
                else:
                    source_file = scandb.all_docs(descending=True, startkey=source_id_hash, endkey=join(source_id_hash, 99999999999999999999), limit=1)
                
                # If file has been scanned:
                if len(source_file) > 0:
                    # Get the file's Scan timestamp from it's ID
                    sfst = source_file['_id'][40:]
                    source_file_scan_time = int(sfst)
                    
                    # If the file scan timestamp is >= last successful scan date
                    if (source_file_scan_time >= other_host_last_scan_complete):
                        # It's not orphaned
                        filedict['orphaned'] = 'no'

                        # But to determine if it's stale, check the scanned file's modified date against the most recent source version.
                        thisview = filedb_views['sourcefiles']
                        if db_skew:
                            result = older_scandb.get_view_raw_result(thisview[0],thisview[1], key=source_file['_id'])
                        else:
                            result = scandb.get_view_raw_result(thisview[0],thisview[1], key=source_file['_id'])
                        
                        if (result['value'] > filedict['datemodified']):
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
                    filedict['orphaned'] = "unknown"
                    filedict['stale'] = False
                
                # Finished, add to array
                file_doc_batch.append(filedict)
                
                            
        # If we're at _bulk_docs threshold
        if ((filecount > 1) and (int(filecount) / int(config['threshold']) == int(filecount) / float('threshold'))):
            # write batch to database
            scandb.bulk_docs(file_doc_batch)
            # flush batch array
            file_doc_batch = []

    # Insert any remaining documents below the threshold
    if len(file_doc_batch) > 0:
        scandb.bulk_docs(file_doc_batch)
        file_doc_batch = []
    
    # Update scan document with final results
    if this_scan['errorcount'] > 0:
        this_scan['success'] = False
    else:
        this_scan['success'] = True
    updates = [
        ['errorcount',this_scan['errorcount']],
        ['filecount',this_scan['filecount']],
        ['directorysize',this_scan['directorysize']],
        ['ended',time.time()],
        ['success', this_scan['success']]
    ]
    for thisfield in updates:
        scandoc[thisfield[0]] = thisfield[1]
    scandoc.save()
    
    # Close database out
    client.disconnect()

# Return the unique ID for a file based upon hash and last scan timestamp
# Currently uses a 40-characer sha1 hash of the hostid, path and filename and appends the most recent UTC
def get_file_id(host_id, full_path, timestamp):
    filehash = hashlib.sha1(join(host_id,full_path)).hexdigest()
    return (join(filehash,timestamp))

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
    with Document(db) as doc:
        print " Let's define one then!"
        print " Enter a name for this relationship"
        doc['name'] = raw_input(" > ")
        doc['type'] = 'relationship'
        doc['active'] = False
        doc['sourcehost'] = ''
        doc['sourcedir'] = ''
        doc['targethost'] = ''
        doc['targetdir'] = ''
        config['relationship'] = doc['_id']
        
        # If excludes file not specified at runtime
        if len(config['rsync_excluded']) > 0:
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
            
    # Return the doc _id of the new relationship
    return config['relationship']    
    
# TO-DO: Find a host by name, using search index
def find_host(host_name):
    sys.exit("Not implemented")

# Find a relationship by listing all known relationships and letting the user choose the appropriate one
def list_relationships(db):
    print "| Which relationship is this host part of?"
    print "| ID | Relationship                       |"
    
    # Open view
    with DesignDocument(db, maindb_views['all_relations'][0]) as ddoc:
        with View(ddoc, maindb_views['all_relations'][1]) as view:
            
            # Iterate through relationships, storing and printing a key for each
            relationship_key = 0
            relationship_set = []
            for row in view(include_docs=False, limit=10)['rows']:
                relationship_key = relationship_key + 1
                print "| " + relationship_key + " | " + row['key'][0]
                relationship_set[relationship_key] = row['_id']
                
            # Ask user to select desired relationship from list
            relationship_selected = -1
            while (relationship_selected not in relationship_set):
                relationship_selected = raw_input("| > ")
        
    # Pass back the appropriate relationship document _id
    return relationship_set[relationship_selected]

# Read in the excludes file passed at startup and store to the config array
def get_excludes(filename):
    try:
        data = open(filename)
    except IOError as e:
        print "I/O error({0}): {1}".format(e.errno, e.strerror)
        sys.exit(2)
    for exclude in data:
        if exclude.isspace():
            next()
        else:
            config['rsync_excluded'].append(exclude)
    
# TO-DO: Check for scan databases older than retention threshold and delete them
def purge_old_dbs():
    sys.exit("Not Implemented")

if __name__ == "__main__":
    main(sys.argv[1:])

