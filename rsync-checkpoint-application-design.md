# rsync-checkpoint Application Design
## NoSQL Database Structure
#### Single operations database
* Host documents (describe individual hosts using the system)
* Relationship documents (describe the nature of the synchronization of two host filesystems)
* Scan documents (describe a batch-oriented scan job, either full or incremental)

#### Multiple "temporal" scan databases
* File documents with a custom ID for utilizing the primary index

#### Document formats
###### Host document

 
    {
      "_id": <GUID set by database>,
      "hostname": "user-set_friendly_name",
      "ip4": "ipv4_address",
      "ip6": "ipv6_address",
      "type": "host"
    }
    
###### Relationship document:

    {
    	"_id": <GUID set by database>,
    	"name": "friendly name of relationship between two hosts",
    	"sourcehost": <_id of host sync is coming "from">,
    	"targethost": <_id>,
    	"sourcedir": "/path/of/directory/being/syncd/to/target/",
    	"targetdir": "/path/synced/from/source/",
    	"active": (true/false),
    	"type": "relationship",
    	"rsyncflags": ["a","z","--delete","etc..."],
    	"excludedfiles": ["any files","or paths","to ignore"]
    }
  
###### Scan document:

    {
    	"_id": <GUID set by database
        "filecount": number of files scanned,
        "errorcount": number of errors encountered during scan,
        "type": "scan",
        "previousscanID": "",
        "directory": "/home/brad/Pictures",
        "database": "scandb-1450216439",
        "ended": UTC Timestamp of when scan ended (zero if unfinished),
        "firstscan": (true/false),
        "hostID": <_id of host being scanned by this task>,
        "relationship": <_id of the associated relationship>,
        "success": (true/false),  # Whether the scan completed correctly or not
        "source": (true/false), # Whether this scan is running on the source or destination of the filesystem sync relationship
        "started": UTC Timestamp of when scan began,
        "directorysize": Total size of scanned files in the directory in bytes
     }
  
###### File document:
     {
        "_id": <hash_of_host,relative_path,name><timestamp>,
        "scanID": <ID_of_scan_that_found_it>,
        "IDprefix": <hash_portion_of_ID>,
        "group": <local_host_ownership_group>,
        "name": "filename.jpg",
        "relationship": <GUID of relationship>,
        "sourcemodified": <date file modified on source host>,
        "orphaned": (yes, no, unknown),
        "goodscan": (true/false),
        "source": (true/false),
        "host": <Host GUID>,
        "datescanned": 1453483319,
        "permissionsUNIX": 33188,
        "owner": <local host ownership user>,
        "path": "/home/brad/Pictures/",
        "sourceIDPrefix": <hash portion of source file ID> (if on target),
        "type": "file",
        "datemodified": <date of modification on filesystem>,
        "size": <file size in bytes>
      }


### Map-Reduce indexes

