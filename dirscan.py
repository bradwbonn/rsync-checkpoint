#!/usr/bin/env python

# Prep
import json
import getopt
import base64
import sys
import datetime
import time
from cloudant.account import Cloudant
import getpass
#import requests

config = dict(
    # Name of database in Cloudant for everything except file entries
    main_db_name = 'rsynccheckpoint',
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
    help_text = "Usage: dirscan.py [-c <configfile>] [-u]",
    # Verbose setting (Default is off)
    be_verbose = False,
    # ID of the relationship for this sync (Cloudant doc _id)
    relationship = '',
    # ID of the current host (Cloudant doc _id)
    host_id = '',
    # Flags for current relationship's sync setup
    rsync_flags = '',
    # Ignored files and directories by rsync process for this relationship
    rsync_excluded = [],
    # ID of the source host (Cloudant doc _id)
    rsync_source = '',
    # ID of the destination host (Cloudant doc _id)
    rsync_target = '',
    # Full path of source directory
    rsync_source_dir = '',
    # Full path of target directory
    rsync_target_dir = '',
    # IP addresses of hosts in the relationship
    source_ip = '',
    target_ip = '',
    # Flag for whether we're scanning a source or target
    is_source = True
)

# Main execution code
def main(argv):
    # Check options for validity, print help if user fat-fingered anything
    try:
        opts, args = getopt.getopt(argv,"hc:uv")
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
                print help
                sys.exit()
            config['passed_config_file'] = arg
        elif opt in ("-u"):
            update = 1 #this doesn't do anything yet
        elif opt in ("-v"):
            config['be_verbose'] = True
    
    # If config file is specfied, read it in and execute scan
    if (len(config['passed_config_file']) > 0):
        # Load configuration settings from file
        if (config['be_verbose']):
            print "Loading " + config['passed_config_file']
        load_config(config['passed_config_file'])
        
        if (config['be_verbose']):
            print config
            print "Initiating scan now..."

        # Initiate scan
        completion = directory_scan()
        
        # If scan completed successfully, output when verbose
        if (config['be_verbose']):
            if (completion):
                scanfinishtime = datetime.datetime.utcnow().isoformat(' ')
                print "Scan successfully completed at " + scanfinishtime
            else:
                print "Scan failure, see logs for details."
        sys.exit()
    else:
        newfile = raw_input("No configuration file specified. Do you wish to create one (Y/N) ? ")
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

    # Create database object for interaction
    try:
        maindb = client[config['main_db_name']]
        if config['be_verbose'] == True:
            print "Database found"
    except Exception:
        # Create database if it doesn't exist
        maindb = client.create_database(config['main_db_name'])
        if config['be_verbose'] == True:
            print "Database created"
    
    # Begin process of collecting data
    relationship_status = ''
    while (relationship_status not in ("y", "Y", "n", "N")):
        relationship_status = raw_input("Is this host part of an existing relationship in the database (y/n) > ")
        
    # For cases where the relationship is already defined
    if (relationship_status in ("y","Y")):
        # List relationships in database in pages, giving a line number for each for them to choose
        # Get back a usable relationship document in Cloudant
        relationshipdoc = list_relationships(client)
        
        # Create this host's entry for the relationship at hand.
        create_host_entry(maindb, relationshipdoc)
    else:
        # Create a new relationship for use, then choose the relationship automatically and run host setup
        relationshipdoc = create_new_relationship(maindb)
        create_host_entry(maindb, relationshipdoc)
    client.disconnect()

# Take a given database and relationship document object and create a new host entry, plus write config file to local system
def create_host_entry(db, relationshipdoc):
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
    print config['default_config_name'] +" written. This file contains your Cloudant authentication hash, so be sure to secure it appropriately!"
    print "To initiate a scan using cron, use 'dirscan.py -c /path/to/" + config['default_config_filename'] + "' in order to have it scan based on these config settings."
    
# If first run, prompt user for information about scan: BROKEN- NEEDS TO INSERT HOST DOCUMENTS FIRST IN ORDER TO GET THEIR ID'S THEN CREATE RELATIONSHIP
def create_initial_config_old():
    # This host
    this_host_name = raw_input("What is this host's 'friendly name?' > ")
    # Check for existing host record(s)
    
    # If no host record exists, prompt for info about this host
    this_host_ipv4 = raw_input("What is this host's rsync IPV4 address? > ") #needs input validation
    this_host_ipv6 = raw_input("What is this host's rsync IPV6 address? (leave blank if N/A) > ") # needs input validation
    this_host_dir = raw_input("What directory on this host is being sync'd? (full path) > ")
    relationship_status = ""
    # If source, ask if existing relationship is in place
    while (relationship_status not in ("y", "Y", "n", "N")):
        relationship_status = raw_input("Is this host part of an existing rsync relationship (y/n) > ")
    # If yes, prompt to search for existing destination host and relationship
    
    if (relationship_status in ("y","Y")):
        opposite_host_name = raw_input("What is the friendly name of the other host? (Set previously) > ")
        # TO-DO: Iterate through host matches to find the correct one
        opposite_host_ID = find_host(opposite_host_name)
        this_host_ID = find_host(this_host_name)
        # TO-DO: Once correct host is found, iterate through relationships to find the correct one (showing directories and source status)
        relationship_ID = find_relationship(opposite_host_ID,this_host_ID)
        
    # If no, prompt for destination host friendly name and create host and relationship document in database
    else:
        this_host_source = ""
        opposite_host_name = raw_input("Set a friendly name for the other host. (Used for setting up the other side) > ")
        opposite_host_ipv4 = raw_input("Other host's rsync IPV4 address > ") # TO-DO: needs input validation
        opposite_host_ipv6 = raw_input("Other host's rsync IPV6 address (leave blank if N/A) > ") # TO-DO: needs input validation
        opposite_host_dir = raw_input("What directory on the other host is being sync'd? (full path) > ")
        relationship_name = raw_input("Enter a memorable name for the sync relationship between these hosts > ")
        print "Enter any rsync flags in use. (such as -a, --delete) List as single letters or words with dashes. Separate by spaces."
        print "Do not list any that accept file input"
        rsync_flags = raw_input(" > ")
        rsync_excludes = raw_input("Enter full path to file of excluded files/directories that's fed to rsync using --excludes > ")
        # Process flags into array
        
        # Process excludes file contents into array
        
        # Construct relationship document #BROKEN- HAS TO BE EXECUTED AFTER HOST CREATION IN ORDER TO OBTAIN THEIR UNIQUEIDS
        while (this_host_source not in ("y", "Y", "n", "N")):
            this_host_source = raw_input("Is the host we're on the source of the rsync data? (y/n) > ")
        if (this_host_source in ("Y","y")):
            relationship_document = {'type':'relationship', 'sourcehost':this_host_name, 'targethost':opposite_host_name, 'sourcedir':this_host_dir, 'targetdir':opposite_host_dir, 'active':true, 'name':relationship_name}
        else:
            relationship_document = {'type':'relationship', 'sourcehost':opposite_host_name, 'targethost':this_host_name, 'sourcedir':opposite_host_dir, 'targetdir':this_host_dir, 'active':true, 'name':relationship_name}

        # Construct new host document for the opposite end
        opposite_host_document = {'type':'host', 'ip4':opposite_host_ipv4, 'hostname':opposite_host_name, 'ip6':opposite_host_ipv6}

        # Constrcut new host document for this host
        this_host_document = {'type':'host', 'ip4':this_host_ipv4, 'ip6':this_host_ipv6, 'hostname':this_host_name}

    # prompt for Cloudant URL and login parameters to obtain a new auth string
    auth_not_set = 1
    while (auth_not_set):
        cloudant_user = raw_input("Enter Cloudant account name (DNS name before .cloudant.com) > ")
        cloudant_login = raw_input("Enter login username (usually the account name) > ")
        cloudant_pass = raw_input("Enter password > ")
        usrPass = userid + ":" + password
        cloudant_auth = base64.b64encode(usrPass)
        test_URI = "https://" + cloudant_user + ".cloudant.com"
        # Test auth by opening a cookie session, if not good try again
        if (test_auth(test_URI, cloudant_login, cloudant_pass)):
            auth_not_set = 0

    # Print summary of changes to be written to database and config file to be created
    passdisplay = "*" * len(cloudant_pass)
    main_DB_URI = "https://" + cloudant_user + ".cloudant.com/rsynccheckpoint"
    print "This is the information which will be stored in the configuration file and associated cloudant database:"
    formatter = "%r : %r %r %r"
    print formatter % ("This Host and IP", this_host_name, this_host_ipv4, this_host_ipv6)
    print formatter % ("Opposite Host and IP", opposite_host_name, opposite_host_ipv4, opposite_host_ipv6)
    print "Data will be flowing thus:"
    formatter2 = "%r::%r -> %r::%r"
    print formatter2 % (relationship_document['sourcehost'], relationship_document['sourcedir'], relationship_document['targethost'], relationship_document['targetdir'])
    print "Rsync flags:" + rsync_flags
    if (len(rsync_excludes) > 0):
        print "Files/Dirs to exclude: " + rsync_excludes
    print formatter % ("Database", main_DB_URI,"","")
    print formatter % ("User",cloudant_user,"","")
    print formatter % ("Pass",passdisplay,"","")
    print "The configuration file 'dirscanconf.json' will be created in the current directory."
    print "Be sure to move it where it will be readable by the script when called by cron."
    while (approval not in ("y", "Y", "n", "N")):
        approval = raw_input("Is this all correct? (Y/N) > ")
    # If approved, execute writes and prompt to initiate first scan.
    if (approval in ("n","N")):
        print "Exiting..."
        sys.exit()
    else:
        config_file_dir = {'mainDB':main_DB_URI, 'bulkthreshold': 10000, 'auth':cloudant_auth, 'relationship':relationshipID, 'thishost':hostID, 'description':"This JSON document is used by dirscan.py for it's operations. CHANGE WITH CAUTION!"}
        # For future: Make threashold dependent upont number of total files during scan???
        try:
            config_file = open('dirscanconf.json', 'w')
        except IOError as e:
            print "I/O error({0}): {1}".format(e.errno, e.strerror)
        sys.exit(2)
        config_file.write(json.dumps(config_file_dir))
        config_file.close()
        if not (insert_single_doc_guid(this_host_document, main_DB_URI, cloudant_auth)):
            print "Failed to insert document into database, exiting."
            sys.exit()
        if not (insert_single_doc_guid(opposite_host_document, main_DB_URI, cloudant_auth)):
            print "Failed to insert document into database, exiting."
            sys.exit()
        if not (insert_single_doc_guid(relationship_document, main_DB_URI, cloudant_auth)):
            print "Failed to insert document into database, exiting."
            sys.exit()

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
    else:
        config['is_source'] = False

# Create and delete a cookie session using the passed credentials to test login 
def test_auth(baseURI, user, password):
    fullURI = baseURI + "/_session"
    fullheaders = {"Content-Type": "application/x-www-form-urlencoded"}
    response = requests.post(
        fullURI,
        headers = fullheaders,
        params = {'name': user, 'password': password}
    )
    if (response.status_code not in (200,201,202)):
        return(False)
    requests.delete(
        fullURI,
        headers = {"Content-Type": requests.cookies['AuthSession']}
    )
    return(True)

# TO-DO: scan function with parameters passed
def directory_scan():
    print "Not Implemented yet"
    # Initialize by getting:
        # Last successful scan document
        # Current per-diem database (based on UTC)
    
    # Iterate through directory structure
    # For each file:
        # Obtain all relevant file information (name,extension,path,size,permissions,owner,group,datemodified)
        # Build document structure, adding: host,datescanned,relationship,scanID,scansuccess,source
        # Add document to dictionary object
        # increment filecount and total size of scan variables
        # If dictionary has threshold docs, or on last doc, upload via _bulk_docs API to current per-diem database
    # Write summary scan document to main database
 
    # For a destination scan:
    # Iterate through directory structure
    # For each file:
        # Obtain all relevant file information (name,extension,path,size,permissions,owner,group,datemodified)
        # Check against source file in database
        #  If, the UTC Timestamp of asc=false,limit=1 of the source file ID queried is >= last successful scan,
        #            then orphaned="no",
        #        If the UTC timestamp is < last successful COMPLETED scan ID, then orphaned="yes"
        #        If the file returns as non-existent in the database based on that ID (in other words, the string returned
        #            does not match the startkey sent to the query), then orphaned="unknown"
        # Check the scanned file's modified date against the most recent source version. If source is newer,
        #           OR if the latest source scan is older than <threshold>, then stale=true, otherwise stale=false.
        #           If file is orphaned, skip this check and set stale=true
        # Build document structure, adding: host,datescanned,relationship,scanID,scansuccess,notsource,stale,orphaned
        # Add document to dictionary object
        # increment filecount and total size of scan variables
        # If dictionary has threshold docs, or on last doc, upload via _bulk_docs API to current per-diem database
    # Write summary scan document to main database

# TO-DO: Create a relationship entity and write an associated document into the database
def create_new_relationship(db):
    print "Not implemented yet"
    sys.exit()
    
# TO-DO: Find a host by name
def find_host(host_name):
    print "Not implemented yet"
    sys.exit()

# TO-DO: Find a relationship by listing all known relationships and letting the user choose the appropriate one
def list_relationships(cloudant_client):
    print "Not implemented yet"
    sys.exit()
    
if __name__ == "__main__":
    main(sys.argv[1:])
# -------------------------------------------------------------------------------------------------------------------------
# SCRATCH SPACE BELOW HERE
# Insert a file document into the database using it's unique ID and adds the current timestamp
# NOT LIKELY TO BE USED DUE TO BULK API USAGE
#def insert_file_doc(dictionary, baseURI, db, auth64creds, fileid):
#    fullURI = baseURI + "/" + db + "/" + fileid + time.time()
#    response = requests.put(
#        fullURI,
#        data=json.dumps(dictionary),
#        headers={"Content-Type": "application/json","Authorization": "Basic "+auth64creds}
#    )
#    if (response.status_code in (202,201,200)):
#        return(True)
#    else:
#        print "Bulk upload failure: " + response.status_code
#        return(False)

## Insert a document into the database, passing the dictionary object, URI (including database), and base64 auth string, returns true if successful
## DEPRECATED, USING CLOUDANT LIB create_document()
#def insert_single_doc_guid(dictionary, URI, auth64creds):
#    response = requests.post(
#        URI,
#        data=json.dumps(dictionary),
#        headers={"Content-Type": "application/json","Authorization": "Basic "+auth64creds}
#    )
#    if (response.status_code in (202,201,200)):
#        return(True)
#    else:
#        print "Could not insert document: " + response.status_code + response.json()["error"]
#        return(False)
#
## Upload a batch of source file documents using the bulk API, return HTTP status code
## DEPRECATED, USING CLOUDANT LIB bulk_docs()
#def insert_source_batch(doc_array, baseURI, db, auth64creds):
#    fullURI = baseURI + "/" + db + "/" + "_bulk_docs"
#    fullheaders = {"Content-Type": "application/json","Authorization": "Basic "+auth64creds}
#    response = requests.post(
#        fullURI,
#        data={"docs": doc_array},
#        headers=fullheaders
#    )
#    return(response.status_code)
#
## Returns the requests object for the associated document
## DEPRECATED, USING CLOUDANT LIB fetch()
#def get_doc_by_ID(account, database, auth, docID):
#    fullURI = "https://" + account + ".cloudant.com/" + database + "/" + docID
#    fullheader = {"Content-Type":"application/json","Authentication":"Basic "+auth}
#    response = requests.get(
#        URI,
#        headers = fullheader
#    )
#    return(response)
  