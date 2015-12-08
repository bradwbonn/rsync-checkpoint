#!/usr/bin/env python

# Prep
import json
import getopt
import base64
import sys
import datetime
import time
from cloudant import cloudant
from getpass import getpass

config = dict(
    # Name of database in Cloudant for everything except file entries
    main_db_name = 'rsynccheckpoint',
    # Number of docs per bulk request
    doc_threshold = 2000,
    # Use this filename for configuration settings. JSON-formatted
    default_config_filename = 'dirscansync.json',
    # Slot for user-specified config file to read
    passed_config_file = '',
    # Slot for base64 auth string
    cloudant_auth_string = '',
    # Help string printed if invalid options or '-h' used
    help_text = "Usage: dirscan.py [-c <configfile>] [-u]",
    # Verbose setting (Default is off)
    be_verbose = False
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
        if (config['be_verbose']):
            print "Loading " + config['passed_config_file']
        configuration_json = read_config(config['passed_config_file'])
        completion = directory_scan(configuration_json)
        if (completion):
            scanfinishtime = datetime.datetime.utcnow().isoformat(' ')
            if (config['be_verbose']):
                print "Scan successfully completed at " + scanfinishtime
            sys.exit()
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

# Obtain the username and password of the Cloudant account to use when creating the configuration file
# Return the opened Cloudant class object for interaction
def get_cloudant_auth():
    auth_not_set = 1
    while (auth_not_set):
        print "You will need to have a Cloudant account created at www.cloudant.com to use this script."
        cloudant_user = raw_input("Enter Cloudant account name (DNS name before .cloudant.com) > ")
        cloudant_login = raw_input("Enter login username (often the same as the account name) > ")
        cloudant_pass = getpass.getpass()
        usrPass = userid + ":" + password
        config['cloudant_auth_string'] = base64.b64encode(usrPass)
        test_URI = "https://" + cloudant_user + ".cloudant.com"
        # Test auth by opening a cookie session, if not good try again
        if (test_auth(test_URI, cloudant_login, cloudant_pass)):
            auth_not_set = 0
            client = cloudant(cloudant_login,cloudant_pass, account=cloudant_user)
            return client
        else:
            print "Login failed, please try again."

# Assemble and write the JSON-formatted configuration file for the host we're running on
def create_initial_config():
    # Initialize Cloudant client instance and obtain user credentials
    client = get_cloudant_auth()
    # Create database object for interaction
    maindb = cloudant.database.CloudantDatabase(client, config['main_db_name'])
    while (relationship_status not in ("y", "Y", "n", "N")):
        relationship_status = raw_input("Is this host part of an existing relationship in the database (y/n) > ")
    if (relationship_status in ("y","Y")):
        relationship_json = list_relationships(client) # TO-DO: list relationships in database in pages, giving a line number for each for them to choose
        # Get hosts by ID's, print names and let user choose which host we are on. Pass that hostID for the config file
        source_host_json = client.
            #get_doc_by_ID(cloudant_user, config['main_db_name'], config['cloudant_auth_string'], relationship_json['sourcehost']).json()
        target_host_json = get_doc_by_ID(cloudant_user, config['main_db_name'], config['cloudant_auth_string'], relationship_json['targethost']).json()
        print "Source host: " + source_host_json['hostname']
        print "Target host: " + target_host_json['hostname']
        while (is_this_source not in ("Y","y","N","n")):
            is_this_source = raw_input("Are we on the source host right now? (Y/N) ")
        if (is_this_source in ("Y","y")):
            hostID = source_host_json['_id']
        else:
            hostID = target_host_json['_id']    
        #config_filename = config['default_config_name']
        write_config_file(config['default_config_filename'], config['cloudant_auth_string'], cloudant_user, relationship_ID, hostID, config['doc_threshold']) #TO-DO: make new JSON config file
        print config['default_config_name'] +" written. This file contains your Cloudant authentication hash, so be sure to secure it appropriately!"
        print "To initiate a scan using cron, use 'dirscan.py -c /path/to/" + config['default_config_filename'] + "' in order to have it scan based on these config settings."
    else:
        create_new_relationship(config['cloudant_auth_string'])
    run_now = raw_input("Would you like to run the first scan now? (Y/N) ")
    if (run_now in ("Y","y")):
        # Populate config JSON based on new file?
        config_json = read_config(config['default_config_filename'])
        directory_scan(config_json)
    print "Exiting"
    sys.exit()

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
        

# Load configuration file from passed path and return resulting JSON
def read_config(config_file):
    try:
        data = open(config_file)
    except IOError as e:
        print "I/O error({0}): {1}".format(e.errno, e.strerror)
        sys.exit(2)
    config_json = json.load(data)
    data.close()
    return(config_json)

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
      
# TO-DO: Get relevant information from main database:
def init_scan():
    # Relationship document
    # Host documents
    # Last successful scan document
    # Current per-diem database (based on UTC)

# TO-DO: scan function with parameters passed
def directory_scan(config_json):
    # Iterate through directory structure
    # For each file:
        # Obtain all relevant file information (name,extension,path,size,permissions,owner,group,datemodified)
        # Build document structure, adding: host,datescanned,relationship,scanID,scansuccess,source
        # Add document to dictionary object
        # increment filecount and total size of scan variables
        # If dictionary has threshold docs, or on last doc, upload via _bulk_docs API to current per-diem database
    # Write summary scan document to main database
 
# TO-DO: For a destination scan:
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
    
# TO-DO: Find a host by name
def find_host(host_name):

# TO-DO: Find a relationship by listing all known relationships and letting the user choose the appropriate one
def list_relationships(cloudant_client):
    
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

# Insert a document into the database, passing the dictionary object, URI (including database), and base64 auth string, returns true if successful
# DEPRECATED, USING CLOUDANT LIB create_document()
def insert_single_doc_guid(dictionary, URI, auth64creds):
    response = requests.post(
        URI,
        data=json.dumps(dictionary),
        headers={"Content-Type": "application/json","Authorization": "Basic "+auth64creds}
    )
    if (response.status_code in (202,201,200)):
        return(True)
    else:
        print "Could not insert document: " + response.status_code + response.json()["error"]
        return(False)

# Upload a batch of source file documents using the bulk API, return HTTP status code
# DEPRECATED, USING CLOUDANT LIB bulk_docs()
def insert_source_batch(doc_array, baseURI, db, auth64creds):
    fullURI = baseURI + "/" + db + "/" + "_bulk_docs"
    fullheaders = {"Content-Type": "application/json","Authorization": "Basic "+auth64creds}
    response = requests.post(
        fullURI,
        data={"docs": doc_array},
        headers=fullheaders
    )
    return(response.status_code)

# Returns the requests object for the associated document
# DEPRECATED, USING CLOUDANT LIB fetch()
def get_doc_by_ID(account, database, auth, docID):
    fullURI = "https://" + account + ".cloudant.com/" + database + "/" + docID
    fullheader = {"Content-Type":"application/json","Authentication":"Basic "+auth}
    response = requests.get(
        URI,
        headers = fullheader
    )
    return(response)
  