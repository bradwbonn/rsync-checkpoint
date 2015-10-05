# rsync-checkpoint
A python scanning tool and Node.js visualization program to show how closely up-to-date two directories are to one another.  Uses Cloudant as the database backend.  Cloudant DBaaS functions as the means by which each host will provide updates re: their filesystem contents.  (Port 443 must be open for HTTPS traffic)
## Files:
* dirscan.py - script that runs on each local system, also contains procedures to setup first configuration file
* dirsync.js - Webpage that reads from Cloudant DB to obtain current sync state between the two hosts
## To-Do:
* Finish dirscan.py
* Create page for visualization
