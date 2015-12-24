# rsync-checkpoint
When setting up two systems to have a replica filesystem using `rsync`, I often find it hard to get a reliable view of how well-synchronized the two systems are.  

Rsync will happily continue going in whatever operation you set up, but if it's only putting placeholders or skipping over files it can't read, you won't know until you need those copied files or manually go through and check the integrity of them all from time to time.

This is a combination python scanning script, command line tool, and eventually will include a Node.js visualization program to show how closely up-to-date two directories are to one another.  The scanner script runs independently on each host, and uses Cloudant DBaaS  as the means by which each host provide updates about their local filesystem's contents.

The python scripts all utilize the cloudant-python beta (2.0.0a4) library, available from:

	pip install --pre cloudant
	
The deprecated (0.5.10) cloudant python library will not work with these scripts.

## Files:
* dirscan.py - script that runs on each local system, also contains procedures to setup first configuration file
* synccheck.py - script to view the status of an rsync relationship, either during or after scans by dirscan.py


#### Example local configuration file (JSON format)

	{
		‘cloudant_auth’: <Cloudant password>,
		‘cloudant_user': <Cloudant account name>,
		‘relationship': <ID of host relationship>,
		‘host_id’: <ID of host this file is for>,
		‘threshold’: <number of docs per bulk post>,
		‘maindbname’: <name of central sync database> # Currently not used
	}

## How to set up the scanner:
* Port 443 must be open for HTTPS traffic from scanning hosts
* Go to [www.cloudant.com](http://www.cloudant.com) to create a free Cloudant account.  This system is designed to minimize the amount of activity on the database, so depending on the size of your filesystem and the frequency with which you scan, it should stay under the $50/month fee trigger and keep your usage of the tool free forever.
* Get the new official Cloudant python library either using `pip install --pre cloudant` or [download it from github](https://github.com/cloudant/python-cloudant)
* Execute `dirscan.py -v` on each host in the rsync relationship. You can also include `-x <filename>` to have it read the file containing a list of path entries for the scanner to skip. This is useful if you're ignoring some files/dirs through rsync `--exclude`.  You can also enter these manually during setup.
* Follow prompts to set up the configuration file for the host and to define the relationship between them
* Create a cron task (or manually execute) the scan using `dirscan.py -c dirscansync.json` as a user which has full local read access to directory being scanned

## How to use the command-line tool
* Once scanning is configured, run synccheck.py either in the same directory as the configuration file the scanner uses, or point it to the scanner using `python synccheck.py -c <configfile> -r <minutes>`
* The output will show the current state of the two replica filesystems with one another, accounting for any ignored files or paths. Passing `-r` causes the script to continuously update the status every `<minutes>`.
    
## Known Issues/Limitations:
* Currently only supports one relationship per host pair per direction. Each relationship will be for two hosts and one direction between them
* An existing relationship cannot be modified using the script. For now, delete the configuration file on each host and create new ones.
* Input validation needed for numerous user-entry fields
* Currently only 10 relationships are supported per account
* IPv6 not supported yet
* Non-unicode character path names are not supported at this time.
* I recommend using a lock file wrapper on the cron task until one is implemented in-script to avoid concurrent local scans
