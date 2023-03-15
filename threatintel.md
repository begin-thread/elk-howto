# Very helpful links!

[https://github.com/deviantony/docker-elk] Thanks you so much!

[https://www.elastic.co/fr/blog/establish-robust-threat-intelligence-with-elastic-security]

[https://www.elastic.co/guide/en/beats/winlogbeat/current/configuration-winlogbeat-options.html]

<!---
*******************************************************************************
-->
# INSTALL UBUNTU to host ELK and Filebeat to send IOC to ELK
Download link here: [https://ubuntu.com/download/desktop]

## INSTALL DOCKER ON UBUNTU

Reference: [https://docs.docker.com/engine/install/ubuntu/]

```
sudo apt-get remove docker docker-engine docker.io containerd runc

sudo apt-get update

sudo apt-get install \
	ca-certificates \
	curl \
	gnupg \
	lsb-release
	
sudo mkdir -p /etc/apt/keyrings

curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
  
sudo apt-get update

sudo apt-get install docker-ce docker-ce-cli containerd.io docker-compose-plugin

sudo docker run hello-world

sudo docker compose version
```

## GET ELK STACK (DOCKER)
```
git clone https://github.com/deviantony/docker-elk.git
cd docker-elk

# Ref. :  https://docs.docker.com/compose/install/linux/#install-the-plugin-manually
# It seems that in Ubuntu Azure, docker compose v2 is installed (instead of v1) (2023-02-08)
# v1 = docker-compose
# v2 = docker compose

sudo docker compose up

# ufw deny 5601
# service ufw restart
```

## LOGIN TO ELK
Link here: [http://localhost:5601/app/home#/]

> elastic / yourpassword

<!---
*******************************************************************************
-->

# KIBANA SECURITY PANEL

## Error will occur
API integration key required
> A new encryption key is generated for saved objects each time you start Kibana. Without a persistent key, you cannot delete or modify rules after Kibana restarts. To set a persistent key, add the xpack.encryptedSavedObjects.encryptionKey setting with any text value of 32 or more characters to the kibana.yml file.

## Edit 
```
vi docker-elk/kibana/config/kibana.yml
```

## Add to the beginning of the file a generated key
```
xpack.encryptedSavedObjects:
  encryptionKey: "min-32-byte-long-strong-encryption-key"
```

## Also add
Reference: [https://www.elastic.co/guide/en/kibana/current/using-kibana-with-security.html#security-configure-settings]
```
xpack.security.encryptionKey: "something_at_least_32_characters"
```

## There are 2 goals with the current setup you are installing
> - Threat Matched Detected: This section is solely reserved for threat indicator matches identified by an indicator match rule. Threat indicator matches are produced whenever event data matches a threat indicator field value in your indicator index. If indicator threat matches are not discovered, the section displays a message that none are available.
> - Enriched with Threat Intelligence: This section shows indicator matches that Elastic Security found when querying the alert for fields with threat intelligence. You can use the date time picker to modify the query time frame, which looks at the past 30 days by default. Click the Inspect button, located on the far right of the threat label, to view more information on the query. If threat matches are not discovered within the selected time frame, the section displays a message that none are available.


# FILEBEAT INSTALLATION ON UBUNTU
Reference [https://www.elastic.co/fr/security-labs/ingesting-threat-data-with-the-threat-intel-filebeat-module]
```
curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-8.6.1-amd64.deb
sudo dpkg -i filebeat-8.6.1-amd64.deb
```

## Uncomment HOST / USER / PASS for elasticsearch
```
sudo vi /etc/filebeat/filebeat.yml
```

If you want to send syslog, enable this module
```
sudo filebeat modules enable system
```

```
sudo vi /etc/filebeat/modules.d/system.yml 
```

Enable the 2 modules ->->->

```
- module: system
  # Syslog
  syslog:
->->->    enabled: true

    # Set custom paths for the log files. If left empty,
    # Filebeat will choose the paths depending on your OS.
    #var.paths:

  # Authorization logs
  auth:
->->->    enabled: false
```

## Enable the Filebeat Kibana dashboard
```
sudo filebeat setup
sudo filebeat test output
```

## Make it permanent
```
# Enable at boot
sudo systemctl enable filebeat

# Make it permanent
sudo service filebeat start
```

<!---
*******************************************************************************
-->

# AUDITBEAT (for Linux AuditD / Better than the auditd module of FILEBEAT)

## Install

```
curl -L -O https://artifacts.elastic.co/downloads/beats/auditbeat/auditbeat-8.6.2-amd64.deb
sudo dpkg -i auditbeat-8.6.2-amd64.deb
```

## Uncomment HOST / USER / PASS for elasticsearch
```
sudo vi /etc/auditbeat/auditbeat.yml
```

## Enable the auditbeat Kibana dashboard
```
sudo filebeat setup
sudo filebeat test output
```

## Make it permanent
```
# Enable at boot
sudo systemctl enable auditbeat

# Make it permanent
sudo service auditbeat start
```


<!---
*******************************************************************************
-->

# FILEBEAT THREATINTEL MODULE ACTIVATION (TO SEND IOC TO ELK)

## Activate the threatintel module
```
sudo filebeat modules enable threatintel
```

## Activate your feeds
```
sudo vi /etc/filebeat/modules.d/threatintel.yml 
```

Example :
	- module: threatintel
	  abuseurl:
		enabled: true

## For AlienVault, get your API key here and add it to threatintel.yml
Link here: [https://otx.alienvault.com/api]

## The authentication token used to contact the OTX API, can be found on the OTX UI.
```
var.api_token: put-your-key-here
```

## Test to connectivity
```
sudo filebeat test output
```

## Launch filebeat
```
sudo filebeat -e
```

## Validate if you have this error (not quite easy to see)
```
{"log.level":"error","@timestamp":"2023-01-26T20:48:07.041-0800","log.logger":"publisher_pipeline_output","log.origin":{"file.name":"pipeline/client_worker.go","file.line":150},"message":"Failed to connect to backoff
(elasticsearch(http://192.168.2.41:9200)): Connection marked as failed because the onConnect callback failed: 
```

## Sanitized error is
> Elasticsearch is too old. Please upgrade the instance. 
> If you would like to connect to older instances set output.elasticsearch.allow_older_versions to true. ES=8.5.3, Beat=8.6.1","service.name":"filebeat","ecs.version":"1.6.0"}

## The solution is to add allow_older_versions : "true" in the output.elasticsearch section
```
output.elasticsearch:
  # Array of hosts to connect to.
  hosts: ["localhost:9200"]

  # Protocol - either `http` (default) or `https`.
  #protocol: "https"

  # Authentication credentials - either API key or username/password.
  #api_key: "id:api_key"
  username: "**********"
  password: "**********"
  allow_older_versions : "true"
```

## If you have this error "no enable fileset error"
You need to activate some modules as specified in my threatintel.yml section up here

<!---
*******************************************************************************
-->
# KIBANA INDICATORS

## Add the threatintel integration
```
# Not useful, works with the intel integration in Kibana? [http://localhost:5601/app/integrations/detail/ti_util-1.1.0/overview] (2023-02-08)
```

## Validate the ingestion here
```
[http://localhost:5601/app/security/threat_intelligence/indicators]

# I cannot publish the URL directly as it use a token in the URL
Look at this dashboard too : [Filebeat Threat Intel] AlienVault OTX
```

<!---
*******************************************************************************
-->

# FILEBEAT *** UBUNTU *** SYSLOG TO MAKE SOME RULES DETECTION

## SYSTEM
```
sudo filebeat modules enable system
```

## Enable modules in the module.d/system.yml
```
enabled: true
```

## AUDITD - ENABLE AND ACTIVATE
```
sudo apt-get install auditd
sudo filebeat modules enable auditd
```

## Enable modules in the module.d/auditd.yml
```
enabled: true
```

## Activate
```
sudo filebeat setup -e
```

## Activate the endpoint module
Reference: [http://localhost:5601/app/integrations/detail/endpoint-8.2.0/overview]


## Could make ip indicator works???
```
sudo filebeat modules enable iptables
sudo gedit /etc/filebeat/modules.d/iptables.yml 
		enabled: true
```

## No logs, so I try 
```
sudo service ufw enable
```
kern.log instead of iptables.log


<!---
*******************************************************************************
-->
# WINLOGBEAT ON *** WINDOWS *** TO SEND EVENTS TO ELK

## Setup Kibana in the winlogbeat config to allow the activation of Kibana dashboard
Uncomment and the the kibana host for the winlogbeat setup
```
setup.kibana:

  # Kibana Host
  # Scheme and port can be left out and will be set to the default (http and 5601)
  # In case you specify and additional path, the scheme is required: http://localhost:5601/path
  # IPv6 addresses should always be defined as: https://[2001:db8::1]:5601
  host: "192.168.206.131:5601"
```

## New proposed winlogbeat config! (2023-02-18)

Other good reference :
- 'https://github.com/jhochwald/Universal-Winlogbeat-configuration'
- 'https://github.com/jhochwald/Universal-Winlogbeat-configuration/issues/4'


My personal version is based on 'https://github.com/Cyb3rWard0g/HELK/blob/master/configs/winlogbeat/winlogbeat.yml'

```
#-------------------------- Windows Logs To Collect -----------------------------
winlogbeat.event_logs:
  - name: Application
    ignore_older: 30m
    provider:
      - TCP/IP
  - name: Security
    ignore_older: 30m
  - name: System
    ignore_older: 30m
  - name: Microsoft-Windows-Sysmon/Operational
    ignore_older: 30m
  - name: Microsoft-Windows-PowerShell/Operational
    ignore_older: 30m
    #event_id: 4103, 4104
    event_id: 4103, 4104, 4105, 4106
  - name: Windows PowerShell
    #event_id: 400,600
    event_id: 400, 403, 600, 800
    ignore_older: 30m
  - name: Microsoft-Windows-WMI-Activity/Operational
    event_id: 5857,5858,5859,5860,5861
  - name: ForwardedEvents
    tags: [forwarded]
  - name: Internet Explorer
    ignore_older: 30m
```

## Download sysmon
Link here: [https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon]

## Activate sysmon network connection
By default, tcp disabled by default, we need to activate it to have indicator match

```
The screenshot [-n] configures Sysmon to Log network connections as well. 
```

## SYSMON - Use the SwiftOnSecurity sysmon configuration https://github.com/SwiftOnSecurity/sysmon-config (2023-02-18)
```
sysmon.exe -accepteula -n -i sysmonconfig-export.xml
```

## SYSMON - Use a simple version (2023-02-18)
```
sysmon -i -accepteula -h md5,sha256,imphash -l -n
```

## Make sure to test the config  (2023-02-18)
```
winlogbeat.exe test config -e
```

## Setup
```
winlogbeat.exe setup -e
```

## Test
```
winlogbeat.exe test output -e
```

## Run winlogbeat in a *** privileged *** cmd.exe windows (to allow registry access, sysmon is a good example)

Be careful to start winlogbeat with Admin right!!! 
Otherwise a small error message will be hidden in the console saying that without admin rights, sysmon will not be ingested...

Thanks to kifarunix.com for the admin reminder! 'https://kifarunix.com/send-windows-logs-to-elastic-stack-using-winlogbeat-and-sysmon/'

```
winlogbeat.exe run -c winlogbeat.yml -e
```

## If you have this error in winlogbeat output
> {"log.level":"error","@timestamp":"2023-01-27T23:21:48.261-0500","log.logger":"publisher_pipeline_output","log.origin":
> {"file.name":"pipeline/client_worker.go","file.line":150},"message":"Failed to connect to backoff(elasticsearch(http://192.168.206.131:9200)): 
> Connection marked as failed because the onConnect callback failed: Elasticsearch is too old. Please upgrade the instance. 
> If you would like to connect to older instances set output.elasticsearch.allow_older_versions to true. ES=8.5.3, Beat=8.6.1","service.name":"winlogbeat","ecs.version":"1.6.0"}

The solution is here
```
output.elasticsearch.allow_older_versions to true
```

<!---
*******************************************************************************
-->
# TEST A THREAT INTELLIGENCE IOC DETECTION BY A KIBANA RULE

## Rule to activate, by default not all rules are activated
```
Rule = Threat Intel Filebeat Module (v8.x) Indicator Match
```

## Way to test
Test the IOC with MSEDGE or TELNET on the port
Ping or Tracert do no generate tcp/udp traffic (was a simple not working)

## Filebeat config
```
Update the securitySolution:defaultThreatIndex advanced setting by adding the appropriate index pattern name after the default Fleet threat intelligence index pattern (logs-ti*):
```

It is important to read the rules, and make sure it match your tests
Make sure the index is the right one
```
For this rule : Threat Intel Indicator Match
The dataset "event.dataset: ti_*" does not match the filebeat one
```

## Now we have a rule that match

> For this rule : Threat Intel Filebeat Module (v8.x) Indicator Match


## Look at the rule, all the fields are matching (the one from the windows event, and the one from the IOC feed)
```
(destination.ip MATCHES threat.indicator.ip)
threat.indicator.ip: * -> come from abuse.ch, not alienvault
```

## Test one IOC
Use Powershell to simulate a c2 connection (for fun)

> x.x.x.x = pick one from alienvault, but be careful...

```
Invoke-WebRequest x.x.x.x -OutFile out.txt  -v
```

Expected results are :

> "Potential Process Injection via PowerShell" rule triggered


<!---
*******************************************************************************
-->
# ATOMIC RED TEAM TO TEST MITRE ATTACK WITH ELK

## Installation
It needs to be done everytime you start powershell
```
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing); Install-AtomicRedTeam -getAtomics -Force

Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser -Force
```

## Launch a test
The list of available tests are documented here 

'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/Indexes/Indexes-Markdown/index.md'

'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1055.012/T1055.012.md'


<!---
*******************************************************************************
-->
# Testing

## TEST T1055.012 - Process Injection: Process Hollowing
'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1055.012/T1055.012.md'

```
Invoke-AtomicTest T1055.012 -ShowDetailsBrief​ -v
Invoke-AtomicTest T1055.012 -CheckPrereqs -v
Invoke-AtomicTest T1055.012 -GetPrereqs -v
​Invoke-AtomicTest T1055.012 -v
```

Expected results are :
> "Potential Process Injection via PowerShell" rule triggered

> "Potential Antimalware Scan Interface Bypass via PowerShell" rule triggered

<!---
*******************************************************************************
-->
# TEST T1037.001 - Boot or Logon Initialization Scripts: Logon Script
'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1037.001/T1037.001.md'

```
Invoke-AtomicTest T1037.001 -v
```

Expected results are :

> In progress...


<!---
*******************************************************************************
-->
# TEST T1071.001 - Application Layer Protocol: Web Protocols
'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.001/T1071.001.md'

*** Your need to start IE first so the test can call IE (yep)

```
Invoke-AtomicTest T1071.001 -v
```

Expected results are :

> Nothing... We need to create a custom rule! More to come...

<!---
*******************************************************************************
-->
## TEST T1059.001 - Command and Scripting Interpreter: PowerShell
'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md'

Thanks to 'https://systemweakness.com/atomic-red-team-3-detecting-bloodhound-using-the-download-cradle-in-elk-siem-bc6960cb4066'

```
Invoke-AtomicTest T1059.001 -v
```

Expected results are :

> KQL = message: (SharpHound or BloodHound)

> More to come...

<!---
*******************************************************************************
-->
## TEST Bruteforce ssh
```
nmap -p 22 --script ssh-brute x.x.x.x
```

<!---
*******************************************************************************
-->
# MISP Threat Intelligence Platform (TIP)

## Installation
Here is the installation command. Please note that it will take a while to install...

```
git clone https://github.com/MISP/misp-docker

cd misp-docker

cp template.env .env 
```

## Change the base URL for your MISP IP

In the .env file 

```
#MISP_BASEURL=https://localhost
MISP_BASEURL=https://192.168.206.131/
```

## Change the timezone. To find yours, type this command

```
timedatectl
```

Replace with your timezone in the .env file 

> Time zone: America/Toronto (EST, -0500)

```
#TIMEZONE=Europe/Brussels
TIMEZONE=America/Toronto
```

## Start Docker
```
sudo docker compose up
```

## Activate feeds

'https://localhost/feeds/index'

> "Enable selected"

> "Enable caching for selected" 

> "Fetch and store all feed data"

## Refresh and wait

'https://localhost/'

Wait a couple of minutes and go back to the main page, the feeds are loading


<!---
*******************************************************************************
-->

# 99 - Install xRDP on Ubuntu

'https://linuxize.com/post/how-to-install-xrdp-on-ubuntu-20-04/'

```
sudo apt install xrdp 
sudo systemctl status xrdp

sudo adduser xrdp ssl-cert  

#20230314 sudo systemctl restart xrdp

sudo service xrdp restart
```

<!---
*******************************************************************************
-->
# 99 - Install xfce4 on Ubuntu 

Less intensive on the graphical side. Good with old hardware.

```
sudo apt install xfce4
```

At login, choose "Xfce session" as the display manager.

<!---
*******************************************************************************
-->
# 99 UFW - Some useful commands 

> Beware that Docker will use iptables directly, so everything you do to close some ports will not work.

```
sudo ufw allow 22
sudo ufw allow 3389
sudo ufw deny 5601

sudo ufw default deny incoming
sudo ufw default allow outgoing

sudo ufw enable
service ufw restart

apt-get install gufw
```


<!---
*******************************************************************************
-->
# 666 - RANDOM

'https://communities.vmware.com/t5/VMware-Workstation-Player/VMware-Player-has-paused-this-virtual-machine/td-p/1192117'

> For security reasons, VMware doesn't allow VM's to start/run if there is not enough free disk space available. This is a percentage of the partition size.
> You can override this with mainMem.freeSpaceCheck = "FALSE" (see http://sanbarrow.com/vmx/vmx-advanced.html#vmx)
> Personally, I wouldn't take the risk and rather clean up the disk or move the VM to a larger disk.
> André

# 666 - RANDOM

Ref.: 'https://packages.ubuntu.com/bionic/x-session-manager'

```
sudo apt install gnome-session-flashback
sudo apt install gnome-session gdm3
sudo apt install cinnamon-session
 
 
# Select the right one
sudo update-alternatives --config x-session-manager

# Another option
sudo update-alternatives --install /usr/bin/x-session-manager x-session-manager /usr/lib/gnome-flashback/gnome-flashback-metacity 60

# Always restart that way
sudo service xrdp restart

#20230314 sudo systemctl restart xrdp



#
sudo reboot
```
