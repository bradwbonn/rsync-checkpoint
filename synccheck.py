#!/usr/bin/env python

# Script to check the state of an rsync relationship

# Prep
import json
import getopt
import base64
import sys
import hashlib
from datetime import datetime
import time
from cloudant.account import Cloudant
from cloudant.design_document import DesignDocument
from cloudant.result import Result
from cloudant.document import Document
from cloudant.views import View
from cloudant import cloudant
import getpass
import os
from pprint import pprint
import requests
import re

config = dict(
    # Name of database in Cloudant for everything except file entries
    main_db_name = 'rsynccheckpoint',
    # Name of the database in Cloudant which we're using for scanning today
    scan_db_name = '',
    # Number of docs per bulk request (Defaults to 2000 during initial configuration)
    doc_threshold = 2000,
    # Slot for user-specified config file to read
    config_file = './dirscansync.json',
    # Cloudant account name
    cloudant_account = '',
    # Cloudant login username
    cloudant_user = '',
    # Cloudant password
    cloudant_auth = '',
    # Help string printed if invalid options or '-h' used
    help_text = "Usage: synccheck.py -c <configfile>  (If no config file specified, script reads ./dirscansync.json by default)",
    # ID of the relationship for this sync (Cloudant doc _id)
    relationship = '',
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
    host_id = '',
    source_ip = '',
    target_ip = ''
)

scandb_views = dict(
    file_types = [
        '_design/files',
        'typesscanned',
        'function (doc) {if (doc.type === "file" && doc.goodscan === true) { filetype = doc.name.substr((~-doc.name.lastIndexOf(".") >>> 0) + 2); emit([doc.host, doc.scanID, filetype], doc.size); } }',
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

# Main
def main(argv):
    # Check options for validity, print help if user fat-fingered anything
    try:
        opts, args = getopt.getopt(argv,"hc:")
    except getopt.GetoptError:
        print config['help_text']
        sys.exit(2)
        
    for opt, arg in opts:
        if opt == '-h':
            print config['help_text']
            sys.exit()
        elif opt in ("-c"):
            config['config_file'] = arg
        
    load_config(config['config_file'])
    
    results = check_relationship()
    print_relationship(results)
    

# Load configuration from file and database into configuration dictionary
def load_config(config_file):
    try:
        data = open(config_file)
    except IOError as e:
        print "I/O error({0}): {1}".format(e.errno, e.strerror)
        print "Unable to load configuration file, exiting."
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
            # config['rsync_excluded'] = relationshipdoc['excludedfiles']
            config['rsync_source'] = relationshipdoc['sourcehost']
            config['rsync_target'] = relationshipdoc['targethost']
            config['rsync_source_dir'] = relationshipdoc['sourcedir']
            config['rsync_target_dir'] = relationshipdoc['targetdir']
        
        # Get hosts' IP addresses and names
        with Document(db, config['rsync_source']) as doc:
            config['source_ip'] = doc['ip4']
            config['source_name'] = doc['hostname']
        with Document(db, config['rsync_target']) as doc:
            config['target_name'] = doc['hostname']
            config['target_ip'] = doc['ip4']
        
# Print the status of the relationship with pretty formatting
def print_relationship(datalines):
    
    # Define print formatting
    width = 74
    hostline = "| Source: {0:26} | Target: {1:25} |"
    doubleline = "| {0:34} | {1:<33} |"
    header = "_" * width
    title = "Relationship between"
    spacer = (width / 2 - 1) - (len(title)/2)
    titleline = "|"+" "*(spacer) + title + " "*(spacer) + "|"
    divider = "|"+"-"*(width-2)+"|"
    footer = "|"+"_"*(width-2)+"|"
    dataline = "| {0:21}: {1:<11} | {2:20}: {3:<11} |"
    
    # Output to shell
    print header
    print titleline
    print divider
    print hostline.format(config['source_name'], config['target_name'])
    print doubleline.format("Last Scanned At:","Last Scanned At:")
    # Print date scanned
    print doubleline.format(datalines[2][1],datalines[2][3])
    print divider
    # Print middle items
    lines = [5,0,1,3,4]
    for val in lines:
        print dataline.format(datalines[val][0],datalines[val][1],datalines[val][2],datalines[val][3])
    # Print final stats
    lines = [6,7,8]
    for line in lines:
        print doubleline.format(datalines[line][1],datalines[line][2])
    print footer
    print ""

# Output a formatted date/time from UTC timestamp
def pretty_time(timestamp):
    return (datetime.fromtimestamp(timestamp).ctime())

# Obtain the appropriate relationship information and return the populated list
# results = [[host1,data,host2,data],[host1,data,host2,data],...]
def check_relationship():
    sourceresults = []
    targetresults = []
    results = []
    get_sync_results = True
    target_scan_id = ''
    
    # Connect to database
    with cloudant(config['cloudant_user'], config['cloudant_auth'], account=config['cloudant_user']) as client:
        db = client[config['main_db_name']]
        # Data we need for each host:
        for host in (config['rsync_source'], config['rsync_target']):
            
            # Data set for this host
            host_scan = dict(
                Scan_complete = 'No',
                Last_scanned = '',
                Files = '',
                Scanning_errors = '',
                Directory_size = '',
                Scan_Database = ''
            )
            
            # Function to fill one array or the other
            def fill_scan_line(resultslist):
                for key in host_scan.keys():
                    resultslist.append([key, host_scan[key]])
                    
            # Get the other host's last scan info (if it exists, even if it's running)
            view_result = get_scan_db(host)
            
            # Open host's last scan doc (if exists)
            if (len(view_result) > 0):
                # NEEDS IMPROVEMENT - All data coming from host's last scan doc
                # This means this data only updates when a scan document is updated!
                # Last scan time
                host_scan['Last_scanned'] = pretty_time(view_result['key'][2])
                # Files found
                host_scan['Files'] = "{:,}".format(view_result['doc']['filecount'])
                # Scan errors
                host_scan['Scanning_errors'] = view_result['doc']['errorcount']
                # Total data size
                host_scan['Directory_size'] = data_size_pretty(view_result['doc']['directorysize'])
                # Did the last scan finish?
                if view_result['doc']['ended'] > 0:
                    host_scan['Scan_complete'] = "Yes"
                else:
                    host_scan['Scan_complete'] = "No"
                # Scan database name
                host_scan['Scan_Database'] = re.sub('scandb-','',view_result['value'])
                config['scan_db_name'] = view_result['value']
                        
            # If host's last scan doesn't exist, change host name to UNSCANNED
            # Don't allow sync results check to run
            else:
                host = "UNSCANNED"
                get_sync_results = False
                    
            # If host is source
            if (host == config['rsync_source']):
                fill_scan_line(sourceresults)
                source_scan_id = view_result['id']
            # Host is target
            else:
                fill_scan_line(targetresults)
                target_scan_id = view_result['id']
                
        # Populate results[] using source & target
        for i,item in enumerate(sourceresults):
            thisline = [sourceresults[i][0], sourceresults[i][1], targetresults[i][0], targetresults[i][1]]
            results.append(thisline)
            
        if (get_sync_results):    
            # Get statistics about sync state:
            # syncresults = []
            # syncresults.append(['Files missing from target',sourceresults[0][1] - targetresults[0][1]])
            # Open scan database
            try:
                scandb = client[config['scan_db_name']]
            except:
                sys.exit("Can't open scan database")
                
            stale_files = 0
            orphaned_files = 0
            # Stale files - Query View for stale files on target            
            # stale_result = stale_view(scandb, target_scan_id) BROKEN DUE TO Cloudant-Python BUG
            stale_result = stale_view_temp(target_scan_id)
            if len(stale_result) > 0:
                for row in stale_result:
                    if row['key'][2] == True:
                        stale_files = stale_files + row['value']['count']
            
            # Orphaned files - Query view for orphand files on target
            # orphan_result = orphan_view(scandb, target_scan_id) BROKEN DUE TO Cloudant-Python BUG
            orphan_result = orphan_view_temp(target_scan_id)
            if len(orphan_result) > 0:
                orphaned_files = orphan_result[0]['value']['count']
                
            source_files_so_far = files_scanned_temp(config['rsync_source'])
            target_files_so_far = files_scanned_temp(config['rsync_target'])
            
            missing_files = "{:,}".format(source_files_so_far['count'] - target_files_so_far['count'])
            
            results.append(['','Probable missing files on target',missing_files,''])            
            results.append(['','Orphaned files on target',orphaned_files,''])
            results.append(['','Stale files on target',stale_files,''])
            
            # TO-DO: Final sync percentage by bytes
                
    return(results)

def stale_view_temp(scan_id):
    url = "https://{0}.cloudant.com/{1}/{2}/_view/{3}".format(
        config['cloudant_account'],
        config['scan_db_name'],
        scandb_views['target_scanned'][0],
        scandb_views['target_scanned'][1]
    )
    payload = {
        "startkey": '["'+scan_id+'",null,null]',
        "endkey": '["'+scan_id+'",{},true]',
        "group_level": 3,
        "reduce": 'true',
    }
    response = requests.get(
        url,
        auth = (config['cloudant_user'], config['cloudant_auth']),
        params = payload
    )
    if response.status_code in (201,200,202):
        jsondata = response.json()
    else:
        response.raise_for_status()
        sys.exit("Bad http request")
    return jsondata['rows']
    
def orphan_view_temp(scan_id):
    url = "https://{0}.cloudant.com/{1}/{2}/_view/{3}".format(
        config['cloudant_account'],
        config['scan_db_name'],
        scandb_views['target_scanned'][0],
        scandb_views['target_scanned'][1]
    )
    payload = {
        "startkey": '["'+scan_id+'","yes"]',
        "endkey": '["'+scan_id+'","yes"]',
        "group_level": 2,
        "reduce": 'true',
    }
    response = requests.get(
        url,
        auth = (config['cloudant_user'], config['cloudant_auth']),
        params = payload
    )
    if response.status_code in (201,200,202):
        jsondata = response.json()
    else:
        response.raise_for_status()
        sys.exit("Bad http request")
    return jsondata['rows']

def get_scan_db(host):
    thisview = maindb_views['recent_scans']
    url = "https://{0}.cloudant.com/{1}/{2}/_view/{3}".format(
        config['cloudant_account'],
        config['main_db_name'],
        thisview[0],
        thisview[1]
    )
    payload = {
        "startkey": '["'+ host +'",true,{}]',
        "endkey": '["'+ host +'",false,0]',
        "limit": 1,
        "reduce": 'false',
        "descending": 'true',
        "include_docs": 'true'
    }
    response = requests.get(
        url,
        auth = (config['cloudant_user'], config['cloudant_auth']),
        params = payload
    )
    if response.status_code in (201,200,202):
        jsondata = response.json()
    else:
        response.raise_for_status()
        sys.exit("Bad http request")
    return jsondata['rows'][0]

def files_scanned_temp(host_id):
    
    scan_database_info = get_scan_db(host_id)
    scan_database = scan_database_info['value']
    scan_id = scan_database_info['id']
    url = "https://{0}.cloudant.com/{1}/{2}/_view/{3}".format(
        config['cloudant_account'],
        scan_database,
        scandb_views['file_types'][0],
        scandb_views['file_types'][1]
    )
    payload = {
        "startkey": '["'+ host_id +'","'+scan_id+'",null]',
        "endkey": '["'+ host_id +'","'+scan_id+'",{}]',
        "group_level": 2,
        "reduce": 'true',
    }
    response = requests.get(
        url,
        auth = (config['cloudant_user'], config['cloudant_auth']),
        params = payload
    )
    if response.status_code in (201,200,202):
        jsondata = response.json()
    else:
        response.raise_for_status()
        sys.exit("Bad http request")
    return (jsondata['rows'][0]['value'])

def directory_size_temp(scan_id):
    pass

def scanning_errors_temp(scan_id):
    pass

def data_size_pretty(size):
    measure = 0
    while (size > 1024):
        size = size / 1024
        measure = measure + 1
    codes = ['',' KB',' MB',' GB',' TB',' PB']
    formattedsize = "{:,}".format(size)
    return (formattedsize + codes[measure])

# BROKEN due to Cloudant-Python bug on "group_level"
def stale_view(scandb,scan_id):
    ddoc = scandb_views['target_scanned'][0]
    view = scandb_views['target_scanned'][1]
    start_key = [scan_id,None,None]
    end_key = [scan_id,{},True]
    result = scandb.get_view_raw_result(ddoc,
                                        view,
                                        group_level=3,
                                        startkey = start_key,
                                        endkey = end_key,
                                        reduce=True
                                        )['rows']
    return (result)

# BROKEN due to Cloudant-Python bug on "group_level"
def orphan_view(scandb,scan_id):
    ddoc = scandb_views['target_scanned'][0]
    view = scandb_views['target_scanned'][1]
    start_key = [scan_id,"yes"]
    end_key = [scan_id,"yes"]
    result = scandb.get_view_raw_result(ddoc,
                                        view,
                                        group_level=2,
                                        startkey = start_key,
                                        endkey = end_key,
                                        reduce=True
                                        )['rows']
    return (result)

if __name__ == "__main__":
    main(sys.argv[1:])
    # a