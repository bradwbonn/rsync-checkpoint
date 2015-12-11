# rsync-checkpoint
A python scanning tool and Node.js visualization program to show how closely up-to-date two directories are to one another.  Uses Cloudant as the database backend.  Cloudant DBaaS functions as the means by which each host will provide updates re: their filesystem contents.
## Files:
* dirscan.py - script that runs on each local system, also contains procedures to setup first configuration file
** Utilizes the new Cloudant Python library.
* dirsync.js - Webpage that reads from Cloudant DB to obtain current sync state between the two hosts

## To-Do:
* Finish dirscan.py - Config portion complete; Working on scan algorithm
* Create visualization system 

## How to set up:
* Port 443 must be open for HTTPS traffic from scanning hosts
* Execute `dirscan.py -v` on each host in the rsync relationship. You can also include `-x <filename>` to have it read the file containing a list of path entries for the scanner to skip. This is useful if you're ignoring some files/dirs through rsync `--exclude`.  You can also enter these manually during setup.
* Follow prompts to set up the configuration file for the host and to define the relationship between them
* Create a cron task (or manually execute) the scan using `dirscan.py -c dirscansync.json` as a user which has full local read access to directory being scanned

## Known Issues/Limitations:
* Running more than one scanner concurrently can be a serious performance drain.  Recommend using a lock file wrapper on cron task until one is implemented in-script.
* Currently only supports one relationship per host pair per direction. Each relationship will be for two hosts and one direction between them
* An existing relationship cannot be modified using the script, it would have to be deleted and re-created manually by deleting the associated Cloudant docs from 'rsynccheckpoint' and per-diem database(s)
* Input validation needed for numerous user-entry fields
* Currently only 10 relationships are supported per account
* IPv6 not supported yet
