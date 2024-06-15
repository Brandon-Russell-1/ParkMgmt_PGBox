# Park Management TryHackMe, a Linux CTF

https://tryhackme.com/jr/parkmanagement

In this Capture The Flag (CTF) challenge, you will learn key cybersecurity skills, including network and web application enumeration, hash cracking, and vulnerability identification. You'll practice remote code execution (RCE) to gain system access, privilege escalation, and post-exploitation techniques. This hands-on experience covers the entire penetration testing process, from initial scanning to gaining and maintaining root access.

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