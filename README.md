# rsync-checkpoint
A python scanning tool and Node.js visualization program to show how closely up-to-date two directories are to one another.  Uses Cloudant as the database backend.  Cloudant DBaaS functions as the means by which each host will provide updates re: their filesystem contents.  (Port 443 must be open for HTTPS traffic)
## Files:
* dirscan.py - script that runs on each local system, also contains procedures to setup first configuration file
** Utilizes the new Cloudant Python library.
* dirsync.js - Webpage that reads from Cloudant DB to obtain current sync state between the two hosts

## To-Do:
* Finish dirscan.py - host init nearly complete, then moving on to scan process
* Create visualization system 

## How to set up:
* Port 443 must be open for HTTPS traffic from scanning hosts
* Execute `dirscan.py -v` on each host in the rsync relationship
* Follow prompts to set up the configuration file for the host and to define the relationship between them
* Create a cron task (or manually execute) the scan using `dirscan.py -c dirscansync.json` as a user which has full local read access to directory being scanned

## Known Issues:
* Admin account required to create database and populate views. API keys not yet implemented.
* Currently only supports one relationship per host pair. (only one directory sync per host pair)
* An existing relationship cannot be modified using the script, it would have to be deleted and re-created manually by deleting the associated Cloudant docs from 'rsynccheckpoint' and per-diem database(s)
* Input validation needed for numerous user-entry fields
* Currently only 10 relationships are supported per account
