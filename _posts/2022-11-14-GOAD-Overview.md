---
title: GOAD - Overview 
date: 2022-11-14 18:00:00
categories: [AD,GOAD]
tags: [goad]
---
![PWNING](https://raw.githubusercontent.com/Orange-Cyberdefense/GOAD/main/docs/img/GOAD.png)

[GOAD](https://github.com/Orange-Cyberdefense/GOAD) is a pentest active directory LAB project. The purpose of this lab is to give pentesters a vulnerable Active directory environment ready to use to practice usual attack techniques.  

# Setup

Setting up [GOAD](https://github.com/Orange-Cyberdefense/GOAD) is pretty straightforward as long as you have enough ressources and fulfill some basic prerequisites

## Prerequisites

**Prerequisites - Software**
* VirtualBox
* Vagrant
* Docker

**Prerequisites - Hardware**
* Space Required: 115GB (more if you want to take snapshots)
* Memory:  ~11GB RAM (1GB per Machine)

## Startup

There are a couple of ways you can launch the environment from your command line. I will only showcase one of them. For more details visit [GOAD](https://github.com/Orange-Cyberdefense/GOAD)

* Default Domain: sevenkingdoms.local
* Default Subnet: 192.168.56.1/24

```bash
# Clone the Repo
git clone https://github.com/Orange-Cyberdefense/GOAD.git
# Switch to the Repo
cd GOAD
# Provide infrastructure
vagrant up
# Provision the hosts
sudo docker build -t goadansible .
sudo docker run -ti --rm --network host -h goadansible -v $(pwd):/goad -w /goad/ansible goadansible ansible-playbook main.yml
```

Grab a coffee and wait till your systems are up and running.

## Some Blueteam?

If you are interessted in following along the lab events you can enable the ELK stack.
Btw. could also be used to check how noisy your methods are ;)

* Elk will be deployed on [192.168.56.50](http://192.168.56.50:5601)
* Log Encyclopedia can be found on [Ultimate Windows Security](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)

Uncomment the ELK Part in Vagrantfile

```
# { :name => "elk", :ip => "192.168.56.50", :box => "bento/ubuntu-18.04", :os => "linux",
#   :forwarded_port => [
#     {:guest => 22, :host => 2210, :id => "ssh"}
#   ]
# }
```

Uncomment the ELK Part in  ansible/hosts file

```
[elk:vars]
ansible_connection=ssh
ansible_ssh_user=vagrant
ansible_ssh_private_key_file=./.vagrant/machines/elk/virtualbox/private_key
ansible_ssh_port=22
host_key_checking = false

[elk]
192.168.56.50
```

Install using docker

```bash
sudo docker run -ti --rm --network host -h goadansible -v $(pwd):/goad -w /goad/ansible goadansible ansible-playbook elk.yml
```

# Lab Overview

![OVERVIEW](https://raw.githubusercontent.com/Orange-Cyberdefense/GOAD/main/docs/img/v2_overview.png)

## Server

The Lab is running five virtual machines

-   **kingslanding** : DC01 running on Windows Server 2019 (with windefender enabled by default)
-   **winterfell** : DC02 running on Windows Server 2019 (with windefender enabled by default)
-   **castelblack** : SRV02 running on Windows Server 2019 (with windefender **disabled** by default)
-   **meereen** : DC03 running on Windows Server 2016 (with windefender enabled by default)
-   **braavos** : SRV03 running on Windows Server 2016 (with windefender enabled by default)

### Domain : north.sevenkingdoms.local

-   **winterfell** : DC01
-   **castelblack** : SRV02 : MSSQL / IIS

### Domain : sevenkingdoms.local

-   **kingslanding** : DC02
-   **castelrock** : SRV01 (disabled due to resources reasons)

### Domain : essos.local

-   **braavos** : DC03
-   **meeren** : SRV03 : MSSQL / ADCS

# Vulnerabilities & Scenarios

## Users/Groups and associated vulnerabilites/scenarios

**NORTH.SEVENKINGDOMS.LOCAL**

-   **STARKS**
    -   arya.stark: Execute as user on mssql
    -   eddard.stark: DOMAIN ADMIN NORTH/ (bot 5min) LLMRN request to do NTLM relay with responder
    -   catelyn.stark:
    -   robb.stark: bot (3min) RESPONDER LLMR
    -   sansa.stark:
    -   brandon.stark: ASREP_ROASTING
    -   rickon.stark: GPO abuse (Edit Settings on "ChangeWallpaperInBlue" GPO)
    -   theon.greyjoy:
    -   jon.snow: mssql admin / KERBEROASTING / group cross domain / mssql trusted link
    -   hodor: PASSWORD SPRAY (user=password)
-   **NIGHT WATCH**
    -   samwell.tarly: Password in ldap description / mssql execute as login
    -   jon.snow: (see starks)
    -   jeor.mormont: (see mormont)
-   **MORMONT**
    -   jeor.mormont: ACL writedacl-writeowner on group Night Watch
-   AcrossTheSea : cross forest group

**SEVENKINGDOMS.LOCAL**

-   **LANISTERS**
    -   tywin.lannister: ACL genericall-on-user cersei.lannister / ACL forcechangepassword on jaime.lanister
    -   jaime.lannister: ACL genericwrite-on-user cersei.lannister
    -   tyron.lannister: ACL self-self-membership-on-group Domain Admins
    -   cersei.lannister: DOMAIN ADMIN SEVENKINGDOMS
-   **BARATHEON**
    -   robert.baratheon: DOMAIN ADMIN SEVENKINGDOMS
    -   joffrey.baratheon:
    -   renly.baratheon:
    -   stannis.baratheon: ACL genericall-on-computer kingslanding / ACL writeproperty-self-membership Domain Admins
-   **SMALL COUNCIL**
    -   petyer.baelish: ACL writeproperty-on-group Domain Admins
    -   lord.varys: ACL genericall-on-group Domain Admins
    -   maester.pycelle: ACL write owner on group Domain Admins

**ESSOS.LOCAL**

-   **TARGERYEN**
    -   daenerys.targaryen: DOMAIN ADMIN ESSOS
    -   viserys.targaryen:
    -   jorah.mormont: mssql trusted link
-   **DOTHRAKI**
    -   khal.drogo: mssql admin / GenericAll on viserys (shadow credentials) / GenericAll on ECS4
-   **DragonsFriends**: cross forest group
-   **Spys**: cross forest group

## Computers Users and group permissions

-   **SEVENKINGDOMS**
    -   DC01 : kingslanding.sevenkingdoms.local (Windows Server 2019) (SEVENKINGDOMS DC)
        -   Admins : robert.baratheon (U), cersei.lannister (U)
        -   RDP: Small Council (G)
        
-   **NORTH**
    -   DC02 : winterfell.north.sevenkingdoms.local (Windows Server 2019) (NORTH DC)
        -   Admins : eddard.stark (U), catelyn.stark (U), robb.stark (U)
        -   RDP: Stark(G)
        
    -   SRV02 : castelblack.essos.local (Windows Server 2019) (IIS, MSSQL, SMB share)
        -   Admins: jeor.mormont (U)
        -   RDP: Night Watch (G), Mormont (G), Stark (G)
        -   IIS : allow asp upload, run as NT Authority/network
        -   MSSQL:
            -   admin : jon.snow
            -   impersonate :
                -   execute as login : samwel.tarlly -> sa
                -   execute as user : arya.stark -> dbo
            -   link :
                -   to braavos : jon.snow -> sa
                
-   **ESSOS**
    -   DC03 : meereen.essos.local (Windows Server 2016) (ESSOS DC)
        -   Admins: daenerys.targaryen (U)
        -   RDP: Targaryen (G)
        
    -   SRV03 : braavos.essos.local (Windows Server 2016) (MSSQL, SMB share)
        -   Admins: khal.drogo (U)
        -   RDP: Dothraki (G)
        -   MSSQL :
            -   admin : khal.drogo
            -   impersonate :
                -   execute as login : jorah.mormont -> sa
            -   link:
                -   to castelblack: jorah.mormont -> sa