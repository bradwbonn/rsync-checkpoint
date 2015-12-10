# rsync-checkpoint
A python scanning tool and Node.js visualization program to show how closely up-to-date two directories are to one another.  Uses Cloudant as the database backend.  Cloudant DBaaS functions as the means by which each host will provide updates re: their filesystem contents.  (Port 443 must be open for HTTPS traffic)
## Files:
* dirscan.py - script that runs on each local system, also contains procedures to setup first configuration file
** Utilizes the new Cloudant Python library.
* dirsync.js - Webpage that reads from Cloudant DB to obtain current sync state between the two hosts

## To-Do:
* Finish dirscan.py - host init nearly complete, then moving on to scan process
* Create visualization system

## Known Issues:
* Admin account required to create database and populate views. API keys not yet implemented.
* Currently only supports one relationship per host pair. (only one directory sync per host pair)
