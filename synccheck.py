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
    help_text = "Usage: synccheck.py -c <configfile> -r <interval>",
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
        opts, args = getopt.getopt(argv,"hc:r:")
    except getopt.GetoptError:
        print config['help_text']
        sys.exit(2)
    
    continuous = False    
    for opt, arg in opts:
        if opt == '-h':
            print config['help_text']
            sys.exit()
        elif opt in ("-c"):
            config['config_file'] = arg
        elif opt in ("-r"):
            continuous = True
            if (len(arg) == 0 or int(arg) < 1):
                interval = int(5 * 60)
            else:
                interval = int(arg) * 60
        
    load_config(config['config_file'])
    
    while (continuous):
        results = check_relationship()
        print_relationship(results)
        time.sleep(interval)
        
    results = check_relationship()
    print_relationship(results)
    

# Load configuration from file and database into configuration dictionary
# Gets us: hostIDs, relationshipID, auth, dirs, host names, rsync flags, threshold, maindbname
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
def print_relationship(data):
    
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
    print hostline.format(data['hostnames'][0], data['hostnames'][1])
    print doubleline.format("Last Scanned At:","Last Scanned At:")
    # Print date scanned
    print doubleline.format(data['scandates'][0],data['scandates'][1])
    print divider
    # Print middle items
    lines = [
        ["Scan completed",'scancomplete'],
        ["Files",'filecount'],
        ["Directory size",'dirsize'],
        ["Scanning errors", 'errors'],
        ["Scan database", 'scandbs']
    ]
    for line in lines:
        label = line[0]
        datapoints = data[line[1]]
        print dataline.format(label,datapoints[0],label,datapoints[1])
    # Print final stats
    lines = [
        ["Files missing from target", 'missing'],
        ["Orphaned files on target", 'orphaned'],
        ["Stale files on target", 'stale']
    ]
    for line in lines:
        label = line[0]
        print doubleline.format(label,data[line[1]])
    print footer
    print ""

# Output a formatted date/time from UTC timestamp
def pretty_time(timestamp):
    return (datetime.fromtimestamp(timestamp).ctime())

def check_relationship():
    pass
    # Source is always first in each array, target is always second
    results = dict(
        hostnames = [],
        scandates = [],
        scancomplete = [],
        filecount = [],
        dirsize = [],
        errors = [],
        scandbs = [],
        missing = 0,
        orphaned = 0,
        stale = 0
    )

    # Store hostnames
    results['hostnames'] = [config['source_name'],config['target_name']]
    
    # Get both hosts' last scan info
    sourcescan = get_scan_db(config['rsync_source'])
    targetscan = get_scan_db(config['rsync_target'])
    
    # From each scan we need:
    # 1. Date scan started
    results['scandates'] = [pretty_time(sourcescan['key'][2]),pretty_time(targetscan['key'][2])]
    
    # 2. If the scan is complete
    if (sourcescan['doc']['ended'] > 0):
        sourcescan_ended = "Yes"
    else:
        sourcescan_ended = "No"
    if (targetscan['doc']['ended'] > 0):
        targetscan_ended = "Yes"
    else:
        targetscan_ended = "No"
    results['scancomplete'] = [sourcescan_ended,targetscan_ended]
    
    # 3. the scan DB each host is using
    results['scandbs'] = [re.sub('scandb-','',sourcescan['value']),re.sub('scandb-','',targetscan['value'])]
    
    # From each scandb for each host:
    source_files_so_far = files_scanned(sourcescan['value'], sourcescan['id'], config['rsync_source'])
    target_files_so_far = files_scanned(targetscan['value'], targetscan['id'], config['rsync_target'])
    # number of files scanned
    results['filecount'] = ["{:,}".format(source_files_so_far['count']),"{:,}".format(target_files_so_far['count'])]
    
    # number of errors in scan
    results['errors'] = [scanning_errors(sourcescan['value'],sourcescan['id']),scanning_errors(targetscan['value'],targetscan['id'])]
    
    # total size of scanned files (directory size)
    results['dirsize'] = [data_size_pretty(source_files_so_far['sum']),data_size_pretty(target_files_so_far['sum'])]
    
    # For summary stats:
    # missingfiles = sourcefiles - targetfiles from above
    results['missing'] = "{:,}".format(source_files_so_far['count'] - target_files_so_far['count'])
    # orphaned files = from view
    results['orphaned'] = "{:,}".format(orphan_view(targetscan['value'],targetscan['id']))
    # stale files = from view
    results['stale'] = "{:,}".format(stale_view(targetscan['value'],targetscan['id']))
    # send back a results dictionary the printer can parse
    return(results)

def stale_view(scan_db, scan_id):
    stale_files = 0
    url = "https://{0}.cloudant.com/{1}/{2}/_view/{3}".format(
        config['cloudant_account'],
        scan_db,
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
    if len(jsondata['rows']) > 0:
        for row in jsondata['rows']:
            if row['key'][2] == True:
                stale_files = stale_files + row['value']['count']
    return(stale_files)

def orphan_view(scan_db,scan_id):
    orphaned_files = 0
    url = "https://{0}.cloudant.com/{1}/{2}/_view/{3}".format(
        config['cloudant_account'],
        scan_db,
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
    if len(jsondata['rows']) > 0:
        orphaned_files = jsondata['rows'][0]['value']['count']
    return(orphaned_files)

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

def files_scanned(scan_database, scan_id, host_id):
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
    if len(jsondata['rows']) > 0:
        return (jsondata['rows'][0]['value'])
    else:
        zeroes = dict(
            sum = 0,
            count = 0,
            min = 0,
            max = 0,
            sumsqr = 0
        )
        return (zeroes)

def scanning_errors(scan_db, scan_id):
    errors = 0
    url = "https://{0}.cloudant.com/{1}/{2}/_view/{3}".format(
        config['cloudant_account'],
        scan_db,
        scandb_views['problem_files'][0],
        scandb_views['problem_files'][1]
    )
    payload = {
        "startkey": '["'+scan_id+'",null,null]',
        "endkey": '["'+scan_id+'",{},{}]',
        "group_level": 1,
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
    if len(jsondata['rows']) > 0:
        errors = jsondata['rows'][0]['value']
    return(errors)

def data_size_pretty(size):
    measure = 0
    while (size > 1024):
        size = size / 1024
        measure = measure + 1
    codes = ['',' KB',' MB',' GB',' TB',' PB']
    formattedsize = "{:,}".format(size)
    return (formattedsize + codes[measure])

# BROKEN due to Cloudant-Python bug on "group_level"
def stale_view_cp(scandb,scan_id):
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
def orphan_view_cp(scandb,scan_id):
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