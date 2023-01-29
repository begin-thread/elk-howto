# Very helpful links!
[https://www.elastic.co/fr/blog/establish-robust-threat-intelligence-with-elastic-security]

[https://www.elastic.co/guide/en/beats/winlogbeat/current/configuration-winlogbeat-options.html]

# 1- INSTALL Ubuntu to host ELK and Filebeat to send IOC to ELK
Download link here: [https://ubuntu.com/download/desktop]

## INSTALL DOCKER-DESKTOP ON UBUNTU

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
```

## GET ELK STACK (DOCKER)
```
git clone https://github.com/deviantony/docker-elk.git
cd docker-elk
sudo docker-compose up
```

## LOGON TO ELK
Link here: [http://localhost:5601/app/home#/]

> elastic / yourpassword


# 2- FILEBEAT INSTALLATION ON UBUNTU (TO SEND IOC)
Reference [https://www.elastic.co/fr/security-labs/ingesting-threat-data-with-the-threat-intel-filebeat-module]
```
curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-8.6.1-amd64.deb
sudo dpkg -i filebeat-8.6.1-amd64.deb
```

## Uncomment user and pass for elasticsearch
```
sudo vi /etc/filebeat/filebeat.yml
```

## Enable the Filebeat Kibana dashboard
```
sudo filebeat setup -e
```

# 3- FILEBEAT THREATINTEL MODULE ACTIVATION

## Activate the threatintel module
```
sudo filebeat modules enable threatintel
```

## Activate your feeds
```
sudo vi /etc/filebeat/modules.d/threatintel.yml 
OR
sudo gedit /etc/filebeat/modules.d/threatintel.yml 
```

Example :
	- module: threatintel
	  abuseurl:
		enabled: true

## For AlienVault, get your API key here and add it to threatintel.yml
Link here: [https://otx.alienvault.com/api]

## The authentication token used to contact the OTX API, can be found on the OTX UI.
```
var.api_token: put-you-key-here
```

## Test to connectivity
```
sudo filebeat test ouput
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

# 3- KIBANA INDICATORS

## Add the threatintel integration
```
[http://localhost:5601/app/integrations/detail/ti_util-1.1.0/overview]
```

## Validate the ingestion here
```
[http://localhost:5601/app/security/threat_intelligence/indicators]
```


# 4- KIBANA SECURITY PANEL

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

## 2 goals with the current setup you are installing
> - Threat Matched Detected: This section is solely reserved for threat indicator matches identified by an indicator match rule. Threat indicator matches are produced whenever event data matches a threat indicator field value in your indicator index. If indicator threat matches are not discovered, the section displays a message that none are available.
> - Enriched with Threat Intelligence: This section shows indicator matches that Elastic Security found when querying the alert for fields with threat intelligence. You can use the date time picker to modify the query time frame, which looks at the past 30 days by default. Click the Inspect button, located on the far right of the threat label, to view more information on the query. If threat matches are not discovered within the selected time frame, the section displays a message that none are available.

# 5- FILEBEAT *** UBUNTU *** SYSLOG TO MAKE SOME RULES DETECTION

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


# 6- WINLOGBEAT ON *** WINDOWS *** TO GENERATE EVENTS

## If you have this error
> {"log.level":"error","@timestamp":"2023-01-27T23:21:48.261-0500","log.logger":"publisher_pipeline_output","log.origin":
> {"file.name":"pipeline/client_worker.go","file.line":150},"message":"Failed to connect to backoff(elasticsearch(http://192.168.206.131:9200)): 
> Connection marked as failed because the onConnect callback failed: Elasticsearch is too old. Please upgrade the instance. 
> If you would like to connect to older instances set output.elasticsearch.allow_older_versions to true. ES=8.5.3, Beat=8.6.1","service.name":"winlogbeat","ecs.version":"1.6.0"}

## Solution
```
output.elasticsearch.allow_older_versions to true
```

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

## Add more sysmon events, will allow to get Virus detection
```
- name: Internet Explorer
- name: Microsoft-Windows-Windows Firewall With Advanced Security/Firewall
- name: Microsoft-Windows-Windows Defender/Operational
  include_xml: true
```

## Setup
```
winlogbeat.exe setup -e
```

## Test
```
winlogbeat.exe test output
```

## Run winlogbeat in a privileged cmd.exe windows (to allow registry access, sysmon is a good example)
```
winlogbeat run -e
```

## Download sysmon
Link here: [https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon]

## Activate sysmon network connection
By default, tcp disabled by default, we need to activate it to have indicator match
```
The screenshot [-n] configures Sysmon to Log network connections as well. 
```
```
sysmon -i -n -accepteula
```


# 7- TEST A DETECTION BY A KIBANA RULE

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


## It is important to read the rules, and make sure it match your tests
Make sure the index is the right one
```
For this rule : Threat Intel Indicator Match
The dataset "event.dataset: ti_*" does not match the filebeat one
```

## Now we have a rule that match
```
For this rule : Threat Intel Filebeat Module (v8.x) Indicator Match
```

## Look at the rule, all the fields are matching (the one from the windows event, and the one from the IOC feed.
```
(destination.ip MATCHES threat.indicator.ip)
threat.indicator.ip: * -> come from abuse.ch, not alienvault
```

## Test one IOC
Use Powershell to simulate a c2 connection (for fun)

x.x.x.x = pick one from alienvault, but be careful...
```
Invoke-WebRequest x.x.x.x -OutFile out.txt
```

## The rule is working ;)







