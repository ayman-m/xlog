[![made-with](https://img.shields.io/badge/Built%20with-grey)]()
[![made-with-Python](https://img.shields.io/badge/Python-blue)](https://www.python.org/)
[![made-with-FastAPI](https://img.shields.io/badge/FastAPI-green)](https://fastapi.tiangolo.com/)
[![made-with-GraphQL](https://img.shields.io/badge/GraphQL-red)](https://graphql.org/)
[![Docker Pulls](https://img.shields.io/docker/pulls/aymanam/rosetta)](https://hub.docker.com/repository/docker/aymanam/rosetta)
[![scanned-with](https://img.shields.io/badge/Scanned%20with-gree)]()
[![snyk](https://snyk.io/test/github/my-soc/Rosetta/badge.svg)](https://snyk.io/test/github/my-soc/Rosetta)
![codeql](https://github.com/my-soc/Rosetta/actions/workflows/github-code-scanning/codeql/badge.svg)
[![slack-community](https://img.shields.io/badge/Slack-4A154C?logo=slack&logoColor=white)](https://go-rosetta.slack.com)

<img  align="left" src="img/logo.png" width="30%" alt="Xlog"> 

# XLog
XLog is a tool to help you generate synthetic log messages. The main interface to the tool is a GraphQL API service with query capabilities to automate the following:
- Fake log messages in different formats.
- Group different logs in scenarios representing different attack techniques.
- Run a worker to send those messages to your detection tools.
***
<img  align="left" src="img/logo.png" width="100%" alt="Xlog"> 

## Usage
If you are planning to use Xlog with XSIAM, you need to create an XSIAM API Key and store the key id in an env file, example:
```bash
XSIAM_URL=https://api-xsiam-sandbox-emea.xdr.eu.paloaltonetworks.com
XSIAM_ID=10
XSIAM_KEY=AbCxYz
```

You can run XLog in several ways:

### Option (1) - Installation
- Clone the repository.
- Install the required packages using `pip install -r requirements.txt`. 
- Start the server using  `uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload.`

### Option (2) - Run Your Container
- Build the image `docker build -t xlog`
- Run the image `docker run --name xlog -p 8000:8000 -d rosetta`

### Option (3) - Run a Ready Container
- You can run a ready container: `docker run --env-file .env -dp 8000:8000 -it aymanam/xlog:latest`
***
## Available Queries
You can use the built-in GraphiQL in-browser tool `http://[xlog-address]:[port]` for writing, validating, and
testing your GraphQL queries. Type queries into this side of the screen, and you will see intelligent typeaheads aware of the current GraphQL type schema and live syntax and  validation errors highlighted within the text.
You can also click on the Explorer page to view a list of the available queries.

With all the queries, you can pass a dict of observables if you want Xlog to use those observables in the synthetic log messages, you can include the following observables in your dict:

```csv
local_ip, remote_ip, local_ip_v6, remote_ip_v6, src_host, dst_host, src_domain, dst_domain, sender_email, 
recipient_email, email_subject, email_body, url, source_port, remote_port, protocol, inbound_bytes, 
outbound_bytes, app, os, user, cve, file_name, file_hash, win_cmd, unix_cmd, win_process, win_child_process,
 unix_process, unix_child_process, technique, entry_type, severity, sensor, action, event_id, error_code, terms,
  alert_types, alert_name, incident_types, analysts, action_status
```

### Synthetic Log Generator
`generateFakeData` query can be used to generate fake logs in different log formats.

The simplest query to generate random syslog message, the message represent a fake risky command execution on a unix server.

**A curl example:**
```bash
curl --location 'http://localhost:8000' \
--header 'Content-Type: application/json' \
--data '{"query":"query MyQuery ($type: FakerTypeEnum!) {\n  generateFakeData(requestInput: {type: $type}) {\n    count\n    data\n    type\n  }\n}","variables":{"type":"SYSLOG"}}'
```
Example output:
```json
{
    "data": {
        "generateFakeData": {
            "count": 1,
            "data": [
                "Jan 05 18:29:25 41538 perform evansrandy sudo find / -name '*.log' -exec rm -f {} \\;"
            ],
            "type": "FakerTypeEnum.SYSLOG"
        }
    }
}
```
You can use specific type of logs to be generated , the following types are currenlty supported: CEF, LEEF, JSON, WINEVENT and Incident , examples of responses for each type , using the above the CURL Query with just changing the "type" variable:

- **CEF**
```json
{
    "data": {
        "generateFakeData": {
            "count": 1,
            "data": [
                "CEF:0|XLog|chance|1.0.9|3f2eda60-d8b7-4ad5-b1b2-ea582d262903|2025-01-05T17:55:35.155577Z|low|local_ip=184.170.19.42 local_port=18380 remote_ip=118.33.231.7 remote_port=4717 protocol=RTP rule_id=75 action=Log"
            ],
            "type": "FakerTypeEnum.CEF"
        }
    }
}
```
- **LEEF**
```json
{
    "data": {
        "generateFakeData": {
            "count": 1,
            "data": [
                "LEEF:1.0|XLog|None|1.0.9|deviceEventDate=2023-07-01 07:35:12.066061|212.152.209.198|email-22.smith-hansen.com|src_ip=58.244.8.75 src_port=28926 request_url=https://example.com/user/profile.php?id=1234' OR 1=1 --&password=pass protocol=RTP status=403 action=Deny severity=3"
            ],
            "type": "FakerTypeEnum.LEEF"
        }
    }
}
```
- **JSON**
```json
{
    "data": {
        "generateFakeData": {
            "count": 1,
            "data": [
                {
                    "vendor": "XLog",
                    "product": "UnknownProduct",
                    "version": "1.0.9",
                    "datetime_iso": "2025-01-05 17:55:58",
                    "severity": "Critical",
                    "user": "castillotimothy",
                    "host": "discover"
                }
            ],
            "type": "FakerTypeEnum.JSON"
        }
    }
}
```
- **WINEVENT**
```json
{
    "data": {
        "generateFakeData": {
            "count": 1,
            "data": [
                "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><Provider Name=\"Microsoft-Windows-Security-Auditing\" Guid=\"e1f724ed-3b5e-42a1-a0fc-88b0248c670a\"/><EventID>4688</EventID><Version>0</Version><Level>0</Level><Task>13312</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime=\"2025-01-06 11:30:03\"/><EventRecordID>53824087</EventRecordID><Correlation/><Execution ProcessID=\"7483\" ThreadID=\"1524\" Channel=\"Security\"/><Computer>email-30.clark-donaldson.com</Computer><Security UserID=\"bsmith\"/><EventData><Data Name=\"SubjectUserSid\">bsmith</Data><Data Name=\"SubjectUserName\">bsmith</Data><Data Name=\"SubjectDomainName\">klein-anthony.com</Data><Data Name=\"SubjectLogonId\">bsmith</Data><Data Name=\"NewProcessId\">5803</Data><Data Name=\"CreatorProcessId\">7483</Data><Data Name=\"TokenElevationType\">TokenElevationTypeLimited (3)</Data><Data Name=\"ProcessCommandLine\">Import-Module DSInternals; Get-SamDomainInformation</Data>"
            ],
            "type": "FakerTypeEnum.WINEVENT"
        }
    }
}
```
- **Incident**
```json
{
    "data": {
        "generateFakeData": {
            "count": 1,
            "data": [
                {
                    "id": 1,
                    "duration": 3,
                    "type": "Malware",
                    "analyst": "Christy",
                    "severity": 4,
                    "description": "Thought scientist institution prepare particular movement tax professional determine.",
                    "events": [
                        {
                            "event": "Jan 06 10:59:33 8636 quickly markmcfarland sudo dd if=/dev/zero of=/dev/sda"
                        },
                        {
                            "event": "CEF:0|XLog|edge|1.0.0|7b7d2cb4-481d-412e-8049-d6b7105a62a2|2025-01-06T10:59:32.720148Z|low|local_ip=104.37.149.239 local_port=23250 remote_ip=184.105.247.244 remote_port=53113 protocol=RTP rule_id=134 action=Wait"
                        },
                        {
                            "event": "LEEF:1.0|XLog|discuss|1.0.7|959894936|severity=Low  devTime=Jan 06 10:59:32  local_ip=47.118.44.83  local_port=31123  host=page  url=https://example.com/user/profile.php?id=1234' OR 1=1 --&password=pass  protocol=SQL  response_code=200  action=Drop"
                        },
                        {
                            "event": "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><Provider Name=\"Microsoft-Windows-Security-Auditing\" Guid=\"ba4c6e7a-da4c-468d-9018-d8d3f7622ede\"/><EventID>4624</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime=\"2025-01-06 10:59:33\"/><EventRecordID>74630238</EventRecordID><Correlation/><Execution ProcessID=\"973\" ThreadID=\"6819\" Channel=\"Security\"/><Computer>laptop-08.hanson.org</Computer><Security UserID=\"kimberly70\"/><EventData><Data Name=\"SubjectUserSid\">kimberly70</Data><Data Name=\"SubjectUserName\">kimberly70</Data><Data Name=\"SubjectDomainName\">logan.com</Data><Data Name=\"SubjectLogonId\">kimberly70</Data><Data Name=\"LogonType\">3</Data><Data Name=\"TargetUserSid\">kimberly70</Data><Data Name=\"TargetUserName\">kimberly70</Data><Data Name=\"TargetDomainName\">logan.com</Data><Data Name=\"ProcessName\">spoolsv.exe</Data><Data Name=\"ProcessId\">973</Data><Data Name=\"DestinationLogonId\">5609</Data><Data Name=\"SourceNetworkAddress\">172.16.15.13</Data><Data Name=\"SourcePort\">16409</Data><Data Name=\"LogonGuid\">ba4c6e7a-da4c-468d-9018-d8d3f7622ede</Data><Data Name=\"TransmittedServices\">Half these attention big particular order.</Data></EventData></Event>"
                        },
                        {
                            "event": {
                                "vendor": "XLog",
                                "product": "UnknownProduct",
                                "version": "1.0.0",
                                "datetime_iso": "2025-01-06 10:59:32",
                                "severity": "Low",
                                "user": "janice21",
                                "host": "way"
                            }
                        }
                    ]
                }
            ],
            "type": "FakerTypeEnum.Incident"
        }
    }
}
```
#### Using _vendor_ Input
***
You can use the "vendor" input with CEF, LEEF and JSON types of logs.

**A curl example:**

```bash
curl --location 'http://localhost:8000' \
--header 'Content-Type: application/json' \
--data '{"query":"query MyQuery ($type: FakerTypeEnum!, $vendor: String!) {\n  generateFakeData(requestInput: {type: $type, vendor: $vendor}) {\n    count\n    data\n    type\n  }\n}","variables":{"type":"JSON","vendor":"TestVendor"}}'
```
Example output:
```json
{
    "data": {
        "generateFakeData": {
            "count": 1,
            "data": [
                {
                    "vendor": "TestVendor",
                    "product": "UnknownProduct",
                    "version": "1.0.4",
                    "datetime_iso": "2025-01-05 17:57:00",
                    "severity": "Low",
                    "user": "renee84",
                    "host": "seat"
                }
            ],
            "type": "FakerTypeEnum.JSON"
        }
    }
}
```
#### Using _product_ Input
***
You can use the "product" input with CEF, LEEF and JSON.

**A curl example:**

```bash
curl --location 'http://localhost:8000' \
--header 'Content-Type: application/json' \
--data '{"query":"query MyQuery ($type: FakerTypeEnum!, $product: String!) {\n  generateFakeData(requestInput: {type: $type, product: $product}) {\n    count\n    data\n    type\n  }\n}","variables":{"type":"LEEF","product":"TestProduct"}}'
```
Example output:
```json
{
    "data": {
        "generateFakeData": {
            "count": 1,
            "data": [
                "LEEF:1.0|XLog|TestProduct|1.0.5|1020050003|severity=High  devTime=Jan 05 17:58:03  local_ip=115.124.80.129  local_port=36969  host=model  url=http://example.com/login.php  protocol=TCP  response_code=200  action=Allow"
            ],
            "type": "FakerTypeEnum.LEEF"
        }
    }
}
```
#### Using _version_ Input
***
You can use the "version" input with CEF, LEEF, JSON and Incident.

**A curl example:**

```bash
curl --location 'http://localhost:8000' \
--header 'Content-Type: application/json' \
--data '{"query":"query MyQuery ($type: FakerTypeEnum!, $version: String!) {\n  generateFakeData(requestInput: {type: $type, version: $version}) {\n    count\n    data\n    type\n  }\n}","variables":{"type":"LEEF","version":"5.0"}}'
```
Example output:
```json
{
    "data": {
        "generateFakeData": {
            "count": 1,
            "data": [
                "LEEF:1.0|XLog|decade|5.0|127089161|severity=High  devTime=Jan 05 17:59:36  local_ip=221.218.25.129  local_port=9480  host=Republican  url=https://example.com/login.php?username=admin&password=pass  protocol=RDP  response_code=200  action=Allow"
            ],
            "type": "FakerTypeEnum.LEEF"
        }
    }
}
```
#### Using _timestamp_ Input
***
If you want to set a "timestamp" to start from, you can set the timestamp input to a datatime formatted string, example "2022-01-01 12:00:00". You can use the timestamp input with Syslog, CEF, LEEF, and JSON.

**A curl example:**

```bash
curl --location 'http://localhost:8000' \
--header 'Content-Type: application/json' \
--data '{"query":"query MyQuery ($type: FakerTypeEnum!, $timestamp: String!) {\n  generateFakeData(requestInput: {type: $type, datetimeIso: $timestamp}) {\n    count\n    data\n    type\n  }\n}","variables":{"type":"CEF","timestamp":"2022-01-01 12:00:00"}}'
```
Example output:
```json
{
    "data": {
        "generateFakeData": {
            "count": 1,
            "data": [
                "CEF:0|XLog|blue|1.0.4|6b91e46d-20a1-41a5-afd5-d0446ea4fb68|2022-01-01T12:00:00.000000Z|low|local_ip=146.61.255.44 local_port=50324 remote_ip=35.192.149.89 remote_port=50251 protocol=RTP rule_id=60 action=Log"
            ],
            "type": "FakerTypeEnum.CEF"
        }
    }
}
```
#### Using _count_ Input
***
If you want to fake multiple log entries, you can set the count input to an int. You can use the count input with Syslog, CEF, LEEF, and JSON.
** A curl example:**
```bash
curl --location 'http://localhost:8000' \
--header 'Content-Type: application/json' \
--data '{"query":"query MyQuery ($type: FakerTypeEnum!, $count: Int!) {\n  generateFakeData(requestInput: {type: $type, count: $count}) {\n    count\n    data\n    type\n  }\n}","variables":{"type":"CEF","count":3}}'
```
Example output:
```json
{
    "data": {
        "generateFakeData": {
            "count": 3,
            "data": [
                "CEF:0|XLog|leader|1.0.2|a3fd0c40-09f6-4480-9039-2b509ad50d13|2025-01-05T18:00:57.482255Z|low|local_ip=183.92.252.208 local_port=64886 remote_ip=47.93.115.100 remote_port=34985 protocol=SQL rule_id=176 action=Drop",
                "CEF:0|XLog|leader|1.0.2|fbbb4f9b-cbf3-4258-99ac-521405f141f5|2025-01-05T18:00:58.482255Z|low|local_ip=162.142.89.61 local_port=40927 remote_ip=184.105.247.238 remote_port=56098 protocol=SSL rule_id=144 action=Log",
                "CEF:0|XLog|leader|1.0.2|73af72e4-afd6-43a1-9dfc-c49c8848493c|2025-01-05T18:00:59.482255Z|low|local_ip=63.170.29.219 local_port=42437 remote_ip=198.199.112.81 remote_port=56569 protocol=TCP rule_id=79 action=Allow"
            ],
            "type": "FakerTypeEnum.CEF"
        }
    }
}
```
#### Using _requiredFields_ Input
***
If you want to set a requiredFields list for those fields to be present in the logs. You can use this input with SYSLOG, CEF, LEEF and JSON, you can select one or more of those fields:
- ACTION
- ACTION_STATUS
- ALERT_NAME
- ALERT_TYPES
- ANALYSTS
- APP
- ATTACHMENT_HASH
- ATTACK_TYPE
- COOKIES
- CVE
- DATABASE_NAME
- DESTINATION_LOGIN_ID
- DURATION
- DST_DOMAIN
- DST_HOST
- DST_URL
- EMAIL_BODY
- EMAIL_SUBJECT
- ENTRY_TYPE
- ERROR_CODE
- EVENT_ID
- EVENT_RECORD_ID
- FILE_HASH
- FILE_NAME
- GUID
- INCIDENT_TYPES
- INBOUND_BYTES
- LOCAL_IP
- LOCAL_IP_V6
- LOCAL_PORT
- LOG_ID
- METHOD
- NEW_PROCESS_ID
- OS
- OUTBOUND_BYTES
- PID
- PRIVILEGE_LIST
- PROCESS_ID
- PROTOCOL
- QUERY
- QUERY_TYPE
- RECIPIENT_EMAIL
- REFERER
- REMOTE_IP
- REMOTE_IP_V6
- REMOTE_PORT
- RESPONSE_CODE
- RESPONSE_SIZE
- RULE_ID
- SEVERITY
- SENDER_EMAIL
- SENSOR
- SOURCE_NETWORK_ADDRESS
- SPAM_SCORE
- SRC_DOMAIN"
- SRC_HOST
- SUBJECT_LOGIN_ID
- TARGET_PID
- TECHNIQUE
- TERMS
- THREAD_ID
- TRANSMITTED_SERVICES
- URL
- USER
- USER_AGENT
- WIN_CHILD_PROCESS
- WIN_CMD
- WIN_PROCESS
- WIN_USER_ID
- UNIX_CHILD_PROCESS
- UNIX_CMD
- UNIX_PROCESS
** A curl example:**
```bash
curl --location 'http://localhost:8000' \
--header 'Content-Type: application/json' \
--data '{"query":"query MyQuery ($type: FakerTypeEnum!, $requiredFields: [RequiredFieldEnum!]) {\n  generateFakeData(requestInput: {type: $type, requiredFields:$requiredFields}) {\n    count\n    data\n    type\n  }\n}","variables":{"type":"CEF","requiredFields":["REMOTE_IP","REMOTE_PORT","LOCAL_PORT","URL","USER","OS"]}}'
```
Example output:
```json
{
    "data": {
        "generateFakeData": {
            "count": 1,
            "data": [
                "CEF:0|XLog|alone|1.0.4|b0796571-4938-44ca-ac80-24cc05133926|2025-01-05T18:41:22.017094Z|low|remote_ip=194.195.249.215 remote_port=13310 local_port=20860 url=https://example.com/login.php?username=admin&password=pass user=christensenjonathan os=Arch Linux 2024.09"
            ],
            "type": "FakerTypeEnum.CEF"
        }
    }
}
```
#### Using _Observables_ Input
***
If you want to set an Observables list to pick from. You can use this input with SYSLOG, CEF, LEEF and JSON. 
- local_ip
- remote_ip
- local_ip_v6
- remote_ip_v6
- src_host
- dst_host
- src_domain
- dst_domain
- sender_email
- recipient_email
- email_subject
- email_body
- url
- local_port
- remote_port
- protocol
- inbound_bytes
- outbound_bytes
- app
- os
- user
- cve
- file_name
- file_hash
- win_cmd
- unix_cmd
- win_process
- win_child_process
- unix_process
- unix_child_process
- technique
- entry_type
- severity
- sensor
- action
- event_id
- error_code
- terms
- incident_types
- analysts
- alert_types
- alert_name
- action_status
- query_type
- database_name
- query

**A curl example:**
```bash
curl --location 'http://localhost:8000' \
--header 'Content-Type: application/json' \
--data '{"query":"query MyQuery ($type: FakerTypeEnum!, $observablesDict: JSON!) {\n  generateFakeData(requestInput: {type: $type, observablesDict: $observablesDict}) {\n    count\n    data\n    type\n  }\n}","variables":{"type":"LEEF","observablesDict":{"src_ip":["1.1.1.1","2.2.2.2"],"error_code":["200"],"technique":[{"indicator":"https://www.example.org/auth","mechanism":"POST"}]}}}'
```
Example output:
```json
{
    "data": {
        "generateFakeData": {
            "count": 1,
            "data": [
                "LEEF:1.0|XLog|None|1.0.1|deviceEventDate=2023-07-01 08:11:03.339443|95.1.218.82|email-19.logan.info|src_ip=1.1.1.1 src_port=10018 request_url=https://www.example.org/auth protocol=UDP status=200 action=Deny severity=1 src_ip=1.1.1.1 technique={'indicator': 'https://www.example.org/auth', 'mechanism': 'POST'} error_code=200"
            ],
            "type": "FakerTypeEnum.LEEF"
        }
    }
}
```
#### Using _Fields_ Input
***
The Fields input is only available with the Incident type. The following fields are supported:
- id
- duration
- type
- analyst
- severity
- description
- events

The events field will allow you to include all different types of logs with the generated incident.

- ** A curl example:**
```bash
curl --location 'http://localhost:8000' \
--header 'Content-Type: application/json' \
--data '{"query":"query MyQuery ($type: FakerTypeEnum!, $observablesDict: JSON!, $fields: String!, $timestamp: String!) {\n  generateFakeData(requestInput: {type: $type, observablesDict: $observablesDict, fields:$fields, timestamp: $timestamp}) {\n    count\n    data\n    type\n  }\n}","variables":{"type":"Incident","observablesDict":{"incident_types":["phishing","malware"],"src_host":["host1","host2"]},"fields":"id,type,duration,analyst,severity,description,events","timestamp":"2022-01-01 12:00:00"}}'
```
Example output:
```json
{
    "data": {
        "generateFakeData": {
            "count": 1,
            "data": [
                {
                    "id": 1,
                    "duration": 2,
                    "type": "malware",
                    "analyst": "Margaret",
                    "severity": 5,
                    "description": "Event Triggered Execution: Windows Management Instrumentation Event Subscription Hide Artifacts: Process Argument Spoofing System Binary Proxy Execution: Rundll32 Phishing for Information: Spearphishing Service Create or Modify System Process: Windows Service Acquire Infrastructure: Botnet.",
                    "events": [
                        {
                            "event": "2022-01-01 12:00:01 host2 sudo[47191]: kararogers : COMMAND ; dd if=/dev/zero of=/dev/sda"
                        },
                        {
                            "event": "CEF:0|XLog|None|1.0.3|05a4f070-4aae-4b29-8729-c3422a24076e|2022-01-01 12:00:01|3|src_ip=163.62.103.47 src_port=23158 dst_ip=['122.116.230.172'] dst_port=43234 proto=RTP rule=157 act=Deny src_host=host2 incident_types=malware"
                        },
                        {
                            "event": "LEEF:1.0|XLog|None|1.0.3|deviceEventDate=2022-01-01 12:00:01|60.64.201.117|host1|src_ip=158.143.53.183 src_port=10339 request_url=https://example.com/assets/jquery-1.11.1.js protocol=RTP status=500 action=Wait severity=3 src_host=host2 incident_types=malware"
                        },
                        {
                            "event": "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><Provider Name=\"Microsoft-Windows-Security-Auditing\" Guid=\"8cf17663-830d-4495-a237-440b3c619548\"/><EventID>4688</EventID><Version>0</Version><Level>0</Level><Task>13312</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime=\"2022-01-01 12:00:01\"/><EventRecordID>122</EventRecordID><Correlation/><Execution ProcessID=\"5613\" ThreadID=\"6919\" Channel=\"Security\"/><Computer>host1</Computer><Security UserID=\"S-1-5970\"/><EventData><Data Name=\"SubjectUserSid\">S-1-5970</Data><Data Name=\"SubjectUserName\">megangill</Data><Data Name=\"SubjectDomainName\">richards.org</Data><Data Name=\"SubjectLogonId\">S-1-5970</Data><Data Name=\"NewProcessId\">9692</Data><Data Name=\"CreatorProcessId\">5613</Data><Data Name=\"TokenElevationType\">TokenElevationTypeLimited (3)</Data><Data Name=\"ProcessCommandLine\">Import-Module PowerSploit; Get-GPPPassword</Data>"
                        },
                        {
                            "event": {
                                "vendor": "XLog",
                                "product": null,
                                "version": "1.0.5",
                                "timestamp": "2022-01-01 12:00:01",
                                "severity": 4,
                                "host": "host2",
                                "user": "lozanojerry",
                                "src_host": "host1",
                                "incident_types": "phishing"
                            }
                        }
                    ]
                }
            ],
            "type": "FakerTypeEnum.Incident"
        }
    }
}
```


***

### Synthetic Log Sender
`createDataWorker` query can be used to create a new worker to send the faked logs to a destination detection tool.

#### Create a UDP Worker 

You can use the UDP worker for sending generic Syslog, CEF and LEEF Messages.

**A curl example:**
```bash
curl --location 'http://localhost:8000' \
--header 'Content-Type: application/json' \
--data '{"query":"query MyQuery($type: WorkerTypeEnum!, $destination: String!, $count: Int!, $interval: Int!) {\n    createDataWorker(requestInput: {type: $type, destination: $destination, count: $count, interval: $interval}) {\n        worker\n        type\n        status\n        count\n        interval\n        destination\n        createdAt\n  }\n}","variables":{"type":"SYSLOG","destination":"udp:127.0.0.1:514","count":5,"interval":2}}'
```
Example output:
```json
{
    "data": {
        "createDataWorker": {
            "worker": "worker_20230629095100",
            "type": "SYSLOG",
            "status": "Running",
            "count": "4",
            "interval": "2",
            "destination": "udp:127.0.0.1:514",
            "createdAt": "2023-06-29 09:51:00.626856"
        }
    }
}
```
PCAP:
<img  align="left" src="img/worker-simple.png" width="100%" alt="Worker Simple">
***

If you want to fake multiple log entries, you can set the count input to an int.
##### A curl example:

```bash
curl --location 'http://localhost:8000' \
--header 'Content-Type: application/json' \
--data '{"query":"query MyQuery($type: WorkerTypeEnum!, $destination: String!, $count: Int!) {\n    createDataWorker(requestInput: {type: $type, destination: $destination, count: $count}) {\n        worker\n        type\n        status\n        count\n        interval\n        destination\n        createdAt\n  }\n}","variables":{"type":"SYSLOG","destination":"udp:127.0.0.1:514","count":2}}'
```
Example output:
```json
{
    "data": {
        "createDataWorker": {
            "worker": "worker_20230629134154",
            "type": "SYSLOG",
            "status": "Running",
            "count": "1",
            "interval": "2",
            "destination": "udp:127.0.0.1:514",
            "createdAt": "2023-06-29 13:41:54.660233"
        }
    }
}
```
PCAP:
<img  align="left" src="img/worker-count-1.png" width="100%" alt="Worker Count 1">
<img  align="left" src="img/worker-count-2.png" width="100%" alt="Worker Count 2">
***
***
If you want to fake set the interval between sent log entries, you can set the interval input to an int.
##### A curl example:

```bash
curl --location 'http://localhost:8000' \
--header 'Content-Type: application/json' \
--data '{"query":"query MyQuery($type: WorkerTypeEnum!, $destination: String!, $interval: Int!, $count: Int!) {\n    createDataWorker(requestInput: {type: $type, destination: $destination, count: $count, interval: $interval}) {\n        worker\n        type\n        status\n        count\n        interval\n        destination\n        createdAt\n  }\n}","variables":{"type":"SYSLOG","destination":"udp:127.0.0.1:514","count":2,"interval":5}}'
```
Example output:
```json
{
    "data": {
        "createDataWorker": {
            "worker": "worker_20230629135734",
            "type": "SYSLOG",
            "status": "Running",
            "count": "1",
            "interval": "5",
            "destination": "udp:127.0.0.1:514",
            "createdAt": "2023-06-29 13:57:34.940563"
        }
    }
}
```
PCAP:
<img  align="left" src="img/worker-interval-1.png" width="100%" alt="Worker Interval 1">
<img  align="left" src="img/worker-interval-2.png" width="100%" alt="Worker Interval 2">
***
***
If you want to set a timestamp to start from, you can set the timestamp input to a datatime formatted string, example "2022-01-01 12:00:00".
##### A curl example:

```bash
curl --location 'http://localhost:8000' \
--header 'Content-Type: application/json' \
--data '{"query":"query MyQuery($type: WorkerTypeEnum!, $destination: String!, $timestamp: String!) {\n    createDataWorker(requestInput: {type: $type, destination: $destination, timestamp: $timestamp}) {\n        worker\n        type\n        status\n        count\n        interval\n        destination\n        createdAt\n  }\n}","variables":{"type":"SYSLOG","destination":"udp:127.0.0.1:514","timestamp":"2022-01-01 12:00:00"}}'
```
Example output:
```json
{
    "data": {
        "createDataWorker": {
            "worker": "worker_20230629140330",
            "type": "SYSLOG",
            "status": "Running",
            "count": "0",
            "interval": "2",
            "destination": "udp:127.0.0.1:514",
            "createdAt": "2023-06-29 14:03:30.748572"
        }
    }
}
```
PCAP:
<img  align="left" src="img/worker-timestamp.png" width="100%" alt="Worker Timestamp">
***
***
If you want to set an observables object, you can use the observablesDict input, below are all the types of observables that you can use in your dict, please review the supported observables for each log type:
```csv
local_ip, remote_ip, local_ip_v6, remote_ip_v6, src_host, dst_host, src_domain, dst_domain, sender_email, 
recipient_email, email_subject, email_body, url, source_port, remote_port, protocol, inbound_bytes, 
outbound_bytes, app, os, user, cve, file_name, file_hash, win_cmd, unix_cmd, win_process, win_child_process,
 unix_process, unix_child_process, technique, entry_type, severity, sensor, action, event_id, error_code, terms,
  alert_types, alert_name, incident_types, analysts, action_status
```
##### A curl example:

```bash
curl --location 'http://localhost:8000' \
--header 'Content-Type: application/json' \
--data '{"query":"query MyQuery($type: WorkerTypeEnum!, $destination: String!, $observablesDict: JSON!) {\n    createDataWorker(requestInput: {type: $type, destination: $destination, observablesDict: $observablesDict}) {\n        worker\n        type\n        status\n        count\n        interval\n        destination\n        createdAt\n  }\n}","variables":{"type":"SYSLOG","destination":"udp:127.0.0.1:514","observablesDict":{"src_host":["test12","test32"]}}}'
```
Example output:
```json
{
    "data": {
        "createDataWorker": {
            "worker": "worker_20230629141531",
            "type": "SYSLOG",
            "status": "Running",
            "count": "0",
            "interval": "2",
            "destination": "udp:127.0.0.1:514",
            "createdAt": "2023-06-29 14:15:31.069035"
        }
    }
}
```
PCAP:
<img  align="left" src="img/worker-observables.png" width="100%" alt="Worker Observables">
***
***
#### Create a TCP Worker 
You can use the TCP worker for sending generic Syslog, CEF and LEEF Messages.
***
You can use same query options that include count, interval, timestamp and observables; Please refer to the above examples.
##### A curl example:

```bash
curl --location 'http://localhost:8000' \
--header 'Content-Type: application/json' \
--data '{"query":"query MyQuery($type: WorkerTypeEnum!, $destination: String!, $count: Int!, $interval: Int!) {\n    createDataWorker(requestInput: {type: $type, destination: $destination, count: $count, interval: $interval}) {\n        worker\n        type\n        status\n        count\n        interval\n        destination\n        createdAt\n  }\n}","variables":{"type":"SYSLOG","destination":"tcp:127.0.0.1:514","count":5,"interval":2}}'
```
Example output:
```json
{
    "data": {
        "createDataWorker": {
            "worker": "worker_20230629140642",
            "type": "SYSLOG",
            "status": "Running",
            "count": "4",
            "interval": "2",
            "destination": "tcp:127.0.0.1:514",
            "createdAt": "2023-06-29 14:06:42.089409"
        }
    }
}
```
***
#### Create a Webhook Worker 
You can use the Webhook worker for sending JSON and Incident Messages.
***
You can use same query options that include count, interval, timestamp, observables, fields and verify_ssl; Please refer to the above examples.
##### A curl example:

```bash
curl --location 'http://localhost:8000' \
--header 'Content-Type: application/json' \
--data '{"query":"query MyQuery($type: WorkerTypeEnum!, $destination: String!, $count: Int!, $interval: Int!,$fields: String!) {\n    createDataWorker(requestInput: {type: $type, destination: $destination, count: $count, interval: $interval, fields: $fields}) {\n        worker\n        type\n        status\n        count\n        interval\n        destination\n        verifySsl\n        createdAt\n  }\n}","variables":{"type":"JSON","destination":"https://webhook-service.local","count":3,"interval":2,"fields":"id,type,duration,analyst,severity,description,events"}}'
```
Example output:
```json
{
    "data": {
        "createDataWorker": {
            "worker": "worker_20230629144632",
            "type": "JSON",
            "status": "Running",
            "count": "2",
            "interval": "2",
            "destination": "https://webhook-service.local",
            "verifySsl": "False",
            "createdAt": "2023-06-29 14:46:32.622369"
        }
    }
}
```
***

#### Create an XSIAM Worker to Send Alerts
You can use the XSIAM worker for sending JSON Alerts.

##### A curl example:

```bash
curl --location 'http://localhost:8000' \
--header 'Content-Type: application/json' \
--data '{"query":"query MyQuery($type: WorkerTypeEnum!, $destination: String!, $count: Int!, $interval: Int!, $vendor: String!, $product: String!) {\n    createDataWorker(requestInput: {type: $type, destination: $destination, count: $count, interval: $interval, vendor: $vendor, product: $product}) {\n        worker\n        type\n        status\n        count\n        interval\n        destination\n        verifySsl\n        createdAt\n  }\n}","variables":{"type":"JSON","destination":"XSIAM","count":2,"interval":2,"vendor":"Xlog","product":"ABC"}}'
```
Example output:
```json
{
    "data": {
        "createDataWorker": {
            "worker": "worker_20230717160020",
            "type": "JSON",
            "status": "Running",
            "count": "0",
            "interval": "1",
            "destination": "https://api-xsiam-sandbox-emea.xdr.eu.paloaltonetworks.com/public_api/v1/alerts/insert_cef_alerts",
            "verifySsl": "False",
            "createdAt": "2023-07-17 16:00:22.424259"
        }
    }
}
```
***
You can use the XSIAM worker for sending CEF Alerts.

##### A curl example:

```bash
curl --location 'http://localhost:8000' \
--header 'Content-Type: application/json' \
--data '{"query":"query MyQuery($type: WorkerTypeEnum!, $destination: String!, $count: Int!, $interval: Int!, $vendor: String!, $product: String!) {\n    createDataWorker(requestInput: {type: $type, destination: $destination, count: $count, interval: $interval, vendor: $vendor, product: $product}) {\n        worker\n        type\n        status\n        count\n        interval\n        destination\n        verifySsl\n        createdAt\n  }\n}","variables":{"type":"CEF","destination":"XSIAM","count":2,"interval":2,"vendor":"Xlog","product":"ABC"}}'
```
Example output:
```json
{
    "data": {
        "createDataWorker": {
            "worker": "worker_20230717160156",
            "type": "JSON",
            "status": "Running",
            "count": "0",
            "interval": "1",
            "destination": "https://api-xsiam-sandbox-emea.xdr.eu.paloaltonetworks.com/public_api/v1/alerts/insert_cef_alerts",
            "verifySsl": "False",
            "createdAt": "2023-07-17 16:01:58.823652"
        }
    }
}
```
***
### Synthetic Scenario Sender
You can create and use Scenario log files to contain multiple log entries to represent different attack techniques.

##### A curl example:

```bash
curl --location 'http://localhost:8000' \
--header 'Content-Type: application/json' \
--data '{"query":"query MyQuery($scenario: String!, $destination: String!) {\n    createScenarioWorker(requestInput: {scenario: $scenario, destination: $destination}) {\n        count\n        createdAt\n        destination\n        type\n        worker\n        status\n  }\n}","variables":{"scenario":"dark_secrets","destination":"udp:192.168.70.165:514"}}'
```
Example output:
```json
{
    "data": {
        "createScenarioWorker": [
            {
                "count": "0",
                "createdAt": "2023-07-17 15:11:01.586093",
                "destination": "udp:192.168.70.165:514",
                "type": "CEF",
                "worker": "worker_20230717151101",
                "status": "Running"
            },
            {
                "count": "0",
                "createdAt": "2023-07-17 15:11:01.587538",
                "destination": "udp:192.168.70.165:514",
                "type": "LEEF",
                "worker": "worker_20230717151101",
                "status": "Running"
            },
            {
                "count": "0",
                "createdAt": "2023-07-17 15:11:01.587847",
                "destination": "udp:192.168.70.165:514",
                "type": "LEEF",
                "worker": "worker_20230717151101",
                "status": "Running"
            },
            {
                "count": "19",
                "createdAt": "2023-07-17 15:11:01.588045",
                "destination": "udp:192.168.70.165:514",
                "type": "CEF",
                "worker": "worker_20230717151101",
                "status": "Running"
            },
            {
                "count": "0",
                "createdAt": "2023-07-17 15:11:01.588257",
                "destination": "udp:192.168.70.165:514",
                "type": "SYSLOG",
                "worker": "worker_20230717151101",
                "status": "Running"
            }
        ]
    }
}
```
***
#### List Sender Workers
You can query Xlog to list current workers.

##### A curl example:

```bash
curl --location 'http://localhost:8000' \
--header 'Content-Type: application/json' \
--data '{"query":"query MyQuery {\n  listWorkers {\n    destination\n    status\n    type\n    count\n    interval\n    worker\n    createdAt\n  }\n}","variables":{}}'
```
Example output:
```json
{
    "data": {
        "listWorkers": [
            {
                "destination": "https://api-xsiam-sandbox-emea.xdr.eu.paloaltonetworks.com/public_api/v1/alerts/insert_cef_alerts",
                "status": "Stopped",
                "type": "JSON",
                "count": "0",
                "interval": "1",
                "worker": "worker_20230717160156",
                "createdAt": "2023-07-17 16:01:58.823652"
            }
        ]
    }
}
```
***
