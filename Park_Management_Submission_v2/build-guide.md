# Build Guide for parkmanagement 

## Status

**NTP**: Off  
**Firewall**: On  
**Updates**: Off  
**ICMP**: On  
**IPv6**: Off  
**AV or Security**: Off

## Overview

**OS**: Ubuntu Server 20.04.6 LTS  
**Hostname**: parkmanagement  
**Vulnerability 1**: T1190 - Exploit Public-Facing Application
**Vulnerability 2**: T1552 - Unsecured Credentials 
**Admin Username**: root  
**Admin Password**: AGreatDaytobeaParkRangerMay2023  
**Low Priv Username**: brandon  
**Low Priv Password**: ILoveParkandRecreation2024  
**Location of local.txt**: /home/brandon/local.txt  
**Value of local.txt**: d76e00fe6ea1d81112622c6bd1cb88ce  
**Location of proof.txt**: /root/proof.txt  
**Value of proof.txt**: 3f56c60fd4f0315a4de12a8870f6f2d7

## Required Settings

**CPU**: 1 CPU  
**Memory**: 2GB  
**Disk**: 10GB

## Build Guide

1. Install Ubuntu Server 20.04.6 LTS
2. Enable network connectivity
3. Ensure machine is fully updated by running `apt-get update`
4. Upload the following files to `/root`
    - `build.sh`
    - `getsimplecms.tar.gz`
    - `parklogs.zip`
5. Change to `/root` and run `build.sh`
