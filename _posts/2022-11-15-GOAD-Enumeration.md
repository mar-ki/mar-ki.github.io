---
title: GOAD - Enumeration 
date: 2022-11-15 12:00:00
categories: [AD,GOAD]
tags: [goad]
---

# Description

In this section we will go over some basic active directory enumeration methods which are also documented in the famous [Pentesting Active Directory Mind Map](https://orange-cyberdefense.github.io/ocd-mindmaps/img/pentest_ad_dark_2022_11.svg)

# Target

Let's assume we are assigned to perform a security evaluation of our target organization called **GOT**

The only data the client provided was that we are allowed to target the ip address space **192.168.56.0/24** and that they are using active directory

| IP              | Details            |
| --------------- | ------------------ |
| 192.168.56.0/24 | Prob. Windows + AD |

# Gathering Basic Infos

I'll run through the commands and diplay a summary of what we got in the end and how it could be useful for our fictional engagement

## What's on the network

```bash
cme smb 192.168.56.0/24                  
```

## Password Policy

```bash
cme smb 192.168.56.0/24 --pass-pol
```

## Find Users

```bash
cme smb 192.168.56.11 --users
```

## Find Shares

```bash
# Enum Null Session
cme smb ./hosts.txt -u '' -p '' --shares
# Enum Anonymous Access
cme smb ./hosts.txt -u 'Guest' -p '' --shares
```

## SMB Relay List

```bash
# Generate List of hosts than can be used for smb relaying attacks 
cme smb ./hosts.txt --gen-relay-list ./smb_relay.txt
```

> Consider to generate the list based on infos we got at the **What's on the network** step.  
> Just to save some events that could trigger detection.  
> We're looking for: SMB Signing Disabled  

## DC IPs

```bash
# Get the DC IP for sevenkingdoms.local
nslookup -type=srv _ldap._tcp.dc._msdcs.sevenkingdoms.local 192.168.56.10
# Get the DC IP for north.sevenkingdoms.local
nslookup -type=srv _ldap._tcp.dc._msdcs.north.sevenkingdoms.local 192.168.56.10
# Get the DC IP for essos.local
nslookup -type=srv _ldap._tcp.dc._msdcs.essos.local 192.168.56.10
```

## Quick Wins

### Zero Logon

```bash
cme smb ./hosts.txt -u '' -p '' -M zerologon
```

### PetitPotam

```bash
cme smb ./hosts.txt -u '' -p '' -M PetitPotam
```

### noPac

```bash
# User needed
crackmapexec smb ./hosts.txt -u 'user' -p 'pass' -M nopac
```

# Port & Service Scan

Skip this part if it isn't interesting for you. It's a lot of text as nmap is verbose as always. I removed some lines to make it more readable

```bash
sudo rustscan -t 1500 -b 1500 --ulimit 65000 -a ./hosts.txt -- -sV -sC -oA ./loot/rust/{{ip}}
```

## Open Ports

```bash
# kingslanding.sevenkingdoms.local
Open 192.168.56.10:135
Open 192.168.56.10:139
Open 192.168.56.10:3268
Open 192.168.56.10:3269
Open 192.168.56.10:3389
Open 192.168.56.10:389
Open 192.168.56.10:445
Open 192.168.56.10:464
Open 192.168.56.10:53
Open 192.168.56.10:593
Open 192.168.56.10:5985
Open 192.168.56.10:5986
Open 192.168.56.10:636
Open 192.168.56.10:88
Open 192.168.56.10:9389

# winterfell.north.sevenkingdoms.local
Open 192.168.56.11:135
Open 192.168.56.11:139
Open 192.168.56.11:3268
Open 192.168.56.11:3269
Open 192.168.56.11:3389
Open 192.168.56.11:389
Open 192.168.56.11:445
Open 192.168.56.11:464
Open 192.168.56.11:53
Open 192.168.56.11:593
Open 192.168.56.11:5985
Open 192.168.56.11:5986
Open 192.168.56.11:636
Open 192.168.56.11:88
Open 192.168.56.11:9389

# meereen.essos.local
Open 192.168.56.12:135
Open 192.168.56.12:139
Open 192.168.56.12:3268
Open 192.168.56.12:3269
Open 192.168.56.12:3389
Open 192.168.56.12:389
Open 192.168.56.12:445
Open 192.168.56.12:464
Open 192.168.56.12:53
Open 192.168.56.12:593
Open 192.168.56.12:5985
Open 192.168.56.12:5986
Open 192.168.56.12:636
Open 192.168.56.12:88
Open 192.168.56.12:9389

# castelblack.north.sevenkingdoms.local
Open 192.168.56.22:135
Open 192.168.56.22:139
Open 192.168.56.22:1433
Open 192.168.56.22:3389
Open 192.168.56.22:445
Open 192.168.56.22:5985
Open 192.168.56.22:5986
Open 192.168.56.22:80

# braavos.essos.local
Open 192.168.56.23:135
Open 192.168.56.23:139
Open 192.168.56.23:1433
Open 192.168.56.23:3389
Open 192.168.56.23:445
Open 192.168.56.23:5985
Open 192.168.56.23:5986
Open 192.168.56.23:80
```

## Services

### 192.168.56.10

```bash
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain?       syn-ack ttl 128
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp    open  kerberos-sec  syn-ack ttl 128 Microsoft Windows Kerberos (server time: 2022-11-15 22:19:27Z)
135/tcp   open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 128 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 128 Microsoft Windows Active Directory LDAP (Domain: sevenkingdoms.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 128
464/tcp   open  kpasswd5?     syn-ack ttl 128
593/tcp   open  ncacn_http    syn-ack ttl 128 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 128
3268/tcp  open  ldap          syn-ack ttl 128 Microsoft Windows Active Directory LDAP (Domain: sevenkingdoms.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 128
3389/tcp  open  ms-wbt-server syn-ack ttl 128 Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: SEVENKINGDOMS
|   NetBIOS_Domain_Name: SEVENKINGDOMS
|   NetBIOS_Computer_Name: KINGSLANDING
|   DNS_Domain_Name: sevenkingdoms.local
|   DNS_Computer_Name: kingslanding.sevenkingdoms.local
|   DNS_Tree_Name: sevenkingdoms.local
|   Product_Version: 10.0.17763
|_  System_Time: 2022-11-15T22:21:43+00:00
| ssl-cert: Subject: commonName=kingslanding.sevenkingdoms.local
| Issuer: commonName=kingslanding.sevenkingdoms.local
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-11-13T23:31:11
| Not valid after:  2023-05-15T23:31:11
| MD5:   54c4 7b3b 1705 9f7e ba03 1101 696d 85bb
| SHA-1: a03b cbe2 d89b 672c 5676 c89b 874f 6870 984d 9ffc
|_ssl-date: 2022-11-15T22:22:22+00:00; 0s from scanner time.
5985/tcp  open  http          syn-ack ttl 128 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
5986/tcp  open  ssl/http      syn-ack ttl 128 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
| ssl-cert: Subject: commonName=VAGRANT
| Subject Alternative Name: DNS:VAGRANT, DNS:vagrant
| Issuer: commonName=VAGRANT
| Public Key type: rsa
| Public Key bits: 4096
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-11-13T14:35:11
| Not valid after:  2025-11-12T14:35:11
| MD5:   f97b 5742 8c7a 9aa8 7b04 9a9e 7b97 341c
| SHA-1: 74a9 6154 7c74 177b 353b db08 839b b53d b54e 64e5
|_ssl-date: 2022-11-15T22:22:22+00:00; 0s from scanner time.
| tls-alpn: 
|_  http/1.1
9389/tcp  open  mc-nmf        syn-ack ttl 128 .NET Message Framing
49666/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49672/tcp open  ncacn_http    syn-ack ttl 128 Microsoft Windows RPC over HTTP 1.0
49673/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49676/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49728/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49756/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=11/15%Time=63741074%P=x86_64-pc-linux-gnu%r(DNS
SF:VersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version
SF:\x04bind\0\0\x10\0\x03");
MAC Address: 08:00:27:12:E1:71 (Oracle VirtualBox virtual NIC)
Service Info: Host: KINGSLANDING; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 0s, deviation: 0s, median: 0s
| nbstat: NetBIOS name: KINGSLANDING, NetBIOS user: <unknown>, NetBIOS MAC: 08:00:27:12:e1:71 (Oracle VirtualBox virtual NIC)
| Names:
|   KINGSLANDING<00>     Flags: <unique><active>
|   SEVENKINGDOMS<00>    Flags: <group><active>
|   SEVENKINGDOMS<1c>    Flags: <group><active>
|   KINGSLANDING<20>     Flags: <unique><active>
|   SEVENKINGDOMS<1b>    Flags: <unique><active>
| Statistics:
|   08 00 27 12 e1 71 00 00 00 00 00 00 00 00 00 00 00
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|_  00 00 00 00 00 00 00 00 00 00 00 00 00 00
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 41826/tcp): CLEAN (Timeout)
|   Check 2 (port 62115/tcp): CLEAN (Timeout)
|   Check 3 (port 39390/udp): CLEAN (Timeout)
|   Check 4 (port 61517/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2022-11-15T22:21:43
|_  start_date: N/A
```

### 192.168.56.11

```bash
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain?       syn-ack ttl 128
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp    open  kerberos-sec  syn-ack ttl 128 Microsoft Windows Kerberos (server time: 2022-11-15 22:24:11Z)
135/tcp   open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 128 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 128 Microsoft Windows Active Directory LDAP (Domain: sevenkingdoms.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 128
464/tcp   open  kpasswd5?     syn-ack ttl 128
593/tcp   open  ncacn_http    syn-ack ttl 128 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 128
3268/tcp  open  ldap          syn-ack ttl 128 Microsoft Windows Active Directory LDAP (Domain: sevenkingdoms.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 128
3389/tcp  open  ms-wbt-server syn-ack ttl 128 Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: NORTH
|   NetBIOS_Domain_Name: NORTH
|   NetBIOS_Computer_Name: WINTERFELL
|   DNS_Domain_Name: north.sevenkingdoms.local
|   DNS_Computer_Name: winterfell.north.sevenkingdoms.local
|   DNS_Tree_Name: sevenkingdoms.local
|   Product_Version: 10.0.17763
|_  System_Time: 2022-11-15T22:26:27+00:00
| ssl-cert: Subject: commonName=winterfell.north.sevenkingdoms.local
| Issuer: commonName=winterfell.north.sevenkingdoms.local
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-11-13T23:40:52
| Not valid after:  2023-05-15T23:40:52
| MD5:   d07c 42a0 b403 bb2d 9c12 be51 6c4f a994
| SHA-1: 422d 9d49 f721 c5cc 67c6 1188 3146 0e40 eb90 acd9
|_ssl-date: 2022-11-15T22:27:06+00:00; 0s from scanner time.
5985/tcp  open  http          syn-ack ttl 128 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
5986/tcp  open  ssl/http      syn-ack ttl 128 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
| ssl-cert: Subject: commonName=VAGRANT
| Subject Alternative Name: DNS:VAGRANT, DNS:vagrant
| Issuer: commonName=VAGRANT
| Public Key type: rsa
| Public Key bits: 4096
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-11-13T14:38:15
| Not valid after:  2025-11-12T14:38:15
| MD5:   b6c4 673e fe75 84c0 a4e4 015e 528c 9d24
| SHA-1: 5a49 4ec8 1610 2032 56ce dcb4 2cb8 54de e0ef d39c
|_ssl-date: 2022-11-15T22:27:06+00:00; 0s from scanner time.
| tls-alpn: 
|_  http/1.1
9389/tcp  open  mc-nmf        syn-ack ttl 128 .NET Message Framing
49666/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49672/tcp open  ncacn_http    syn-ack ttl 128 Microsoft Windows RPC over HTTP 1.0
49673/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49678/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49719/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
64738/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=11/15%Time=63741190%P=x86_64-pc-linux-gnu%r(DNS
SF:VersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version
SF:\x04bind\0\0\x10\0\x03");
MAC Address: 08:00:27:B1:FA:7C (Oracle VirtualBox virtual NIC)
Service Info: Host: WINTERFELL; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 0s, deviation: 0s, median: 0s
| nbstat: NetBIOS name: WINTERFELL, NetBIOS user: <unknown>, NetBIOS MAC: 08:00:27:b1:fa:7c (Oracle VirtualBox virtual NIC)
| Names:
|   WINTERFELL<00>       Flags: <unique><active>
|   NORTH<00>            Flags: <group><active>
|   NORTH<1c>            Flags: <group><active>
|   WINTERFELL<20>       Flags: <unique><active>
|   NORTH<1b>            Flags: <unique><active>
| Statistics:
|   08 00 27 b1 fa 7c 00 00 00 00 00 00 00 00 00 00 00
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|_  00 00 00 00 00 00 00 00 00 00 00 00 00 00
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 50298/tcp): CLEAN (Timeout)
|   Check 2 (port 37282/tcp): CLEAN (Timeout)
|   Check 3 (port 38986/udp): CLEAN (Timeout)
|   Check 4 (port 46743/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2022-11-15T22:26:26
|_  start_date: N/A
```

### 192.168.56.12

```bash
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain?       syn-ack ttl 128
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp    open  kerberos-sec  syn-ack ttl 128 Microsoft Windows Kerberos (server time: 2022-11-15 22:27:54Z)
135/tcp   open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 128 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 128 Microsoft Windows Active Directory LDAP (Domain: essos.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds  syn-ack ttl 128 Windows Server 2016 Standard Evaluation 14393 microsoft-ds (workgroup: ESSOS)
464/tcp   open  kpasswd5?     syn-ack ttl 128
593/tcp   open  ncacn_http    syn-ack ttl 128 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 128
3268/tcp  open  ldap          syn-ack ttl 128 Microsoft Windows Active Directory LDAP (Domain: essos.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 128
3389/tcp  open  ms-wbt-server syn-ack ttl 128 Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: ESSOS
|   NetBIOS_Domain_Name: ESSOS
|   NetBIOS_Computer_Name: MEEREEN
|   DNS_Domain_Name: essos.local
|   DNS_Computer_Name: meereen.essos.local
|   DNS_Tree_Name: essos.local
|   Product_Version: 10.0.14393
|_  System_Time: 2022-11-15T22:30:10+00:00
| ssl-cert: Subject: commonName=meereen.essos.local
| Issuer: commonName=meereen.essos.local
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-11-13T23:31:11
| Not valid after:  2023-05-15T23:31:11
| MD5:   64dc a3a2 1f93 c985 0502 450f 3940 4853
| SHA-1: 933c c38d 947d 7817 1316 efba e695 a798 875d 470a
|_ssl-date: 2022-11-15T22:30:49+00:00; 0s from scanner time.
5985/tcp  open  http          syn-ack ttl 128 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
5986/tcp  open  ssl/http      syn-ack ttl 128 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
| ssl-cert: Subject: commonName=VAGRANT
| Subject Alternative Name: DNS:VAGRANT, DNS:vagrant
| Issuer: commonName=VAGRANT
| Public Key type: rsa
| Public Key bits: 4096
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-11-13T14:49:34
| Not valid after:  2025-11-12T14:49:34
| MD5:   cd47 0aa7 1f2e 33d6 e2fa 611f a5b6 49f2
| SHA-1: 6d67 e78f 2a71 0529 5544 3e31 3510 41b3 0b62 16d9
|_ssl-date: 2022-11-15T22:30:49+00:00; 0s from scanner time.
| tls-alpn: 
|   h2
|_  http/1.1
9389/tcp  open  mc-nmf        syn-ack ttl 128 .NET Message Framing
49666/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49672/tcp open  ncacn_http    syn-ack ttl 128 Microsoft Windows RPC over HTTP 1.0
49673/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49676/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49698/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49705/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=11/15%Time=6374126F%P=x86_64-pc-linux-gnu%r(DNS
SF:VersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version
SF:\x04bind\0\0\x10\0\x03");
MAC Address: 08:00:27:52:1E:6D (Oracle VirtualBox virtual NIC)
Service Info: Host: MEEREEN; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1h20m00s, deviation: 3h15m57s, median: 0s
| nbstat: NetBIOS name: MEEREEN, NetBIOS user: <unknown>, NetBIOS MAC: 08:00:27:52:1e:6d (Oracle VirtualBox virtual NIC)
| Names:
|   ESSOS<00>            Flags: <group><active>
|   MEEREEN<00>          Flags: <unique><active>
|   ESSOS<1c>            Flags: <group><active>
|   MEEREEN<20>          Flags: <unique><active>
|   ESSOS<1b>            Flags: <unique><active>
| Statistics:
|   08 00 27 52 1e 6d 00 00 00 00 00 00 00 00 00 00 00
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|_  00 00 00 00 00 00 00 00 00 00 00 00 00 00
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 56698/tcp): CLEAN (Timeout)
|   Check 2 (port 12168/tcp): CLEAN (Timeout)
|   Check 3 (port 32496/udp): CLEAN (Timeout)
|   Check 4 (port 48602/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard Evaluation 14393 (Windows Server 2016 Standard Evaluation 6.3)
|   Computer name: meereen
|   NetBIOS computer name: MEEREEN\x00
|   Domain name: essos.local
|   Forest name: essos.local
|   FQDN: meereen.essos.local
|_  System time: 2022-11-15T14:30:10-08:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2022-11-15T22:30:09
|_  start_date: 2022-11-15T19:06:4
```

### 192.168.56.22

```bash
PORT      STATE SERVICE       REASON          VERSION
80/tcp    open  http          syn-ack ttl 128 Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Site doesn't have a title (text/html).
135/tcp   open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 128 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack ttl 128
1433/tcp  open  ms-sql-s      syn-ack ttl 128 Microsoft SQL Server  15.00.2000.00
| ms-sql-ntlm-info: 
|   Target_Name: NORTH
|   NetBIOS_Domain_Name: NORTH
|   NetBIOS_Computer_Name: CASTELBLACK
|   DNS_Domain_Name: north.sevenkingdoms.local
|   DNS_Computer_Name: castelblack.north.sevenkingdoms.local
|   DNS_Tree_Name: sevenkingdoms.local
|_  Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-11-15T19:07:57
| Not valid after:  2052-11-15T19:07:57
| MD5:   05e2 9995 7a78 5a7b 4f0a 9ddd a41b efa3
| SHA-1: 0d8e b7b8 614e 287c 4510 d582 12a5 b477 5f9c 07a2
|_ssl-date: 2022-11-15T22:19:20+00:00; 0s from scanner time.
3389/tcp  open  ms-wbt-server syn-ack ttl 128 Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: NORTH
|   NetBIOS_Domain_Name: NORTH
|   NetBIOS_Computer_Name: CASTELBLACK
|   DNS_Domain_Name: north.sevenkingdoms.local
|   DNS_Computer_Name: castelblack.north.sevenkingdoms.local
|   DNS_Tree_Name: sevenkingdoms.local
|   Product_Version: 10.0.17763
|_  System_Time: 2022-11-15T22:18:41+00:00
| ssl-cert: Subject: commonName=castelblack.north.sevenkingdoms.local
| Issuer: commonName=castelblack.north.sevenkingdoms.local
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-11-13T23:48:01
| Not valid after:  2023-05-15T23:48:01
| MD5:   16ac a35c 07a7 3e68 bbca da2b 35de e44b
| SHA-1: ad8d b459 20d5 9828 b52c df33 b0fd cc6f 7139 48a7
|_ssl-date: 2022-11-15T22:19:20+00:00; 0s from scanner time.
5985/tcp  open  http          syn-ack ttl 128 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
5986/tcp  open  ssl/http      syn-ack ttl 128 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
| ssl-cert: Subject: commonName=VAGRANT
| Subject Alternative Name: DNS:VAGRANT, DNS:vagrant
| Issuer: commonName=VAGRANT
| Public Key type: rsa
| Public Key bits: 4096
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-11-13T15:01:56
| Not valid after:  2025-11-12T15:01:56
| MD5:   3452 70ea a847 5b16 e449 bfb2 90cb 8995
| SHA-1: e215 f32f 58ec 2884 caa7 586b f7a3 f6e5 6d7b 824d
|_ssl-date: 2022-11-15T22:19:20+00:00; 0s from scanner time.
| tls-alpn: 
|_  http/1.1
49666/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
MAC Address: 08:00:27:B2:9B:F2 (Oracle VirtualBox virtual NIC)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 0s, deviation: 0s, median: 0s
| ms-sql-info: 
|   192.168.56.22:1433: 
|     Version: 
|       name: Microsoft SQL Server 
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 
|_    TCP port: 1433
| nbstat: NetBIOS name: CASTELBLACK, NetBIOS user: <unknown>, NetBIOS MAC: 08:00:27:b2:9b:f2 (Oracle VirtualBox virtual NIC)
| Names:
|   CASTELBLACK<00>      Flags: <unique><active>
|   NORTH<00>            Flags: <group><active>
|   CASTELBLACK<20>      Flags: <unique><active>
| Statistics:
|   08 00 27 b2 9b f2 00 00 00 00 00 00 00 00 00 00 00
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|_  00 00 00 00 00 00 00 00 00 00 00 00 00 00
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 14258/tcp): CLEAN (Timeout)
|   Check 2 (port 63105/tcp): CLEAN (Timeout)
|   Check 3 (port 27598/udp): CLEAN (Timeout)
|   Check 4 (port 4709/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2022-11-15T22:18:41
|_  start_date: N/A
```

### 192.168.56.23

```bash
PORT      STATE SERVICE       REASON          VERSION
80/tcp    open  http          syn-ack ttl 128 Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
135/tcp   open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 128 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds  syn-ack ttl 128 Windows Server 2016 Standard Evaluation 14393 microsoft-ds
1433/tcp  open  ms-sql-s      syn-ack ttl 128 Microsoft SQL Server  15.00.2000.00
| ms-sql-ntlm-info: 
|   Target_Name: ESSOS
|   NetBIOS_Domain_Name: ESSOS
|   NetBIOS_Computer_Name: BRAAVOS
|   DNS_Domain_Name: essos.local
|   DNS_Computer_Name: braavos.essos.local
|   DNS_Tree_Name: essos.local
|_  Product_Version: 10.0.14393
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-11-15T19:08:28
| Not valid after:  2052-11-15T19:08:28
| MD5:   e0d8 6ef8 7ee3 8c51 cca3 e192 52d2 dd1c
| SHA-1: 08af 5a95 9354 4bc0 c884 3115 f573 9d29 d137 5b18
|_ssl-date: 2022-11-15T22:17:46+00:00; 0s from scanner time.
3389/tcp  open  ms-wbt-server syn-ack ttl 128 Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: ESSOS
|   NetBIOS_Domain_Name: ESSOS
|   NetBIOS_Computer_Name: BRAAVOS
|   DNS_Domain_Name: essos.local
|   DNS_Computer_Name: braavos.essos.local
|   DNS_Tree_Name: essos.local
|   Product_Version: 10.0.14393
|_  System_Time: 2022-11-15T22:17:06+00:00
| ssl-cert: Subject: commonName=braavos.essos.local
| Issuer: commonName=braavos.essos.local
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-11-13T23:47:59
| Not valid after:  2023-05-15T23:47:59
| MD5:   2150 783c f954 1990 8250 403f 8c3f 82c6
| SHA-1: 4dc2 b581 3180 44f9 e9bb 27e7 0c8b 5132 9a11 5792
|_ssl-date: 2022-11-15T22:17:46+00:00; 0s from scanner time.
5985/tcp  open  http          syn-ack ttl 128 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
5986/tcp  open  ssl/http      syn-ack ttl 128 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
| ssl-cert: Subject: commonName=VAGRANT
| Subject Alternative Name: DNS:VAGRANT, DNS:vagrant
| Issuer: commonName=VAGRANT
| Public Key type: rsa
| Public Key bits: 4096
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-11-13T15:16:40
| Not valid after:  2025-11-12T15:16:40
| MD5:   be50 23a6 828e 075c 740b df88 6adf affe
| SHA-1: 3ec0 c0b6 62b8 1c28 4eee 4cf2 4a23 4012 b2e2 2feb
|_ssl-date: 2022-11-15T22:17:46+00:00; 0s from scanner time.
| tls-alpn: 
|   h2
|_  http/1.1
49668/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
49705/tcp open  msrpc         syn-ack ttl 128 Microsoft Windows RPC
MAC Address: 08:00:27:23:C6:CE (Oracle VirtualBox virtual NIC)
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 59m59s, deviation: 2h49m42s, median: 0s
| ms-sql-info: 
|   192.168.56.23:1433: 
|     Version: 
|       name: Microsoft SQL Server 
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 
|_    TCP port: 1433
| nbstat: NetBIOS name: BRAAVOS, NetBIOS user: <unknown>, NetBIOS MAC: 08:00:27:23:c6:ce (Oracle VirtualBox virtual NIC)
| Names:
|   BRAAVOS<00>          Flags: <unique><active>
|   ESSOS<00>            Flags: <group><active>
|   BRAAVOS<20>          Flags: <unique><active>
| Statistics:
|   08 00 27 23 c6 ce 00 00 00 00 00 00 00 00 00 00 00
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|_  00 00 00 00 00 00 00 00 00 00 00 00 00 00
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 29164/tcp): CLEAN (Timeout)
|   Check 2 (port 17189/tcp): CLEAN (Timeout)
|   Check 3 (port 63738/udp): CLEAN (Timeout)
|   Check 4 (port 23793/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard Evaluation 14393 (Windows Server 2016 Standard Evaluation 6.3)
|   Computer name: braavos
|   NetBIOS computer name: BRAAVOS\x00
|   Domain name: essos.local
|   Forest name: essos.local
|   FQDN: braavos.essos.local
|_  System time: 2022-11-15T14:17:06-08:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2022-11-15T22:17:06
|_  start_date: 2022-11-15T19:08:23
```

# Summary

We used different techniques to enumerate some basic details about the environment we are currently in. There are maybe a couple more that you could try out but those that I used yield enough infos for me to jump deeper into the active directory part that will be covered in my next blog post

## Loot?!

What to we have so far?

- Identified all live hosts and their names
- Identified all Domain Controllers
- Identified two web services
- Identified two mssql services
- Identified a ADCS host
- A couple of shares that are accessible for anonymous users
- User Accounts of Domain North
- Password Policy of Domain North
- A password for the user `north.sevenkingdoms.local/samwell.tarly`
- Identified systems that are vulnerable to zerologon and petitpotam

###  Live Windows Hosts

Identified during the step **What's on the network**

```bash
192.168.56.10
192.168.56.11
192.168.56.12
192.168.56.22
192.168.56.23
```

### Domain Controllers and associated domains

Identified during the step **DC IPs** 

```bash
192.168.56.10   sevenkingdoms.local
192.168.56.11   north.sevenkingdoms.local 
192.168.56.12   essos.local 
```

### Hosts and associated names

List was created by merging data collected during steps **DC IPs** and **What's on the network**

```bash
192.168.56.10   kingslanding.sevenkingdoms.local sevenkingdoms.local kingslanding
192.168.56.11   winterfell.north.sevenkingdoms.local north.sevenkingdoms.local winterfell
192.168.56.12   meereen.essos.local essos.local meereen
192.168.56.22   castelblack.north.sevenkingdoms.local castelblack
192.168.56.23   braavos.essos.local braavos
```

### Users - Domain North (and a Password)

Identiefied during **Find Users** Step

```
north.sevenkingdoms.local\Guest                          
Built-in account for guest access to the computer/domain  

north.sevenkingdoms.local\arya.stark                     
Arya Stark

north.sevenkingdoms.local\sansa.stark
Sansa Stark

north.sevenkingdoms.local\brandon.stark
Brandon Stark

north.sevenkingdoms.local\rickon.stark
Rickon Stark

north.sevenkingdoms.local\hodor
Brainless Giant

north.sevenkingdoms.local\jon.snow
Jon Snow

north.sevenkingdoms.local\samwell.tarly
Samwell Tarly (Password : Heartsbane)    

north.sevenkingdoms.local\jeor.mormont
Jeor Mormont

north.sevenkingdoms.local\sql_svc
sql service
```

> Passwords in descriptions or custom fields are pretty usual. Always worth to check for them

### Password Policy - Domain North

```bash
[+] Dumping password info for domain: NORTH
Minimum password length: 5
Password history length: 24
Maximum password age: 311 days 2 minutes 

Password Complexity Flags: 000000
Domain Refuse Password Change: 0
Domain Password Store Cleartext: 0
Domain Password Lockout Admins: 0
Domain Password No Clear Change: 0
Domain Password No Anon Change: 0
Domain Password Complex: 0
     
Minimum password age: 1 day 4 minutes 
Reset Account Lockout Counter: 5 minutes 
Locked Account Duration: 5 minutes 
Account Lockout Threshold: 5
Forced Log off Time: Not Set
```

### Accessible Shares

We discovered some shares that are accessible as anonymous user.
Also helped to identify which system is running ADCS

```bash
192.168.56.22 [+] Enumerated shares
192.168.56.22 Share           Permissions     Remark
192.168.56.22 -----           -----------     ------
192.168.56.22 ADMIN$                          Remote Admin
192.168.56.22 all             READ,WRITE      Basic RW share for all
192.168.56.23 [+] Enumerated shares
192.168.56.22 C$                              Default share
192.168.56.22 IPC$            READ            Remote IPC
192.168.56.23 Share           Permissions     Remark
192.168.56.23 -----           -----------     ------
192.168.56.22 public                          Basic Read share for all domain users
192.168.56.23 ADMIN$                          Remote Admin
192.168.56.23 all             READ,WRITE      Basic RW share for all
192.168.56.23 C$                              Default share
192.168.56.23 CertEnroll                      Active Directory Certificate Services share
192.168.56.23 IPC$                            Remote IPC
192.168.56.23 public                          Basic Read share for all domain users
```

### Quick Wins

I probably won't use them in later blog posts as they normally result in a complete domain takeover 

```bash
# Zerologon
ZEROLOGO... 192.168.56.12   445    MEEREEN          VULNERABLE
ZEROLOGO... 192.168.56.12   445    MEEREEN          Next step: https://github.com/dirkjanm/CVE-2020-1472
# PetitPotam
PETITPOT... 192.168.56.10   445    KINGSLANDING     VULNERABLE
PETITPOT... 192.168.56.10   445    KINGSLANDING     Next step: https://github.com/topotam/PetitPotam
PETITPOT... 192.168.56.11   445    WINTERFELL       VULNERABLE
PETITPOT... 192.168.56.11   445    WINTERFELL       Next step: https://github.com/topotam/PetitPotam
PETITPOT... 192.168.56.12   445    MEEREEN          VULNERABLE
PETITPOT... 192.168.56.12   445    MEEREEN          Next step: https://github.com/topotam/PetitPotam
```