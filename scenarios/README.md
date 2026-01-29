# Attack Scenarios

This directory contains pre-built attack scenarios that simulate multi-step attacks following the MITRE ATT&CK framework.

## Overview

Scenarios are JSON files that define complete attack chains, from initial access through exfiltration. Each scenario contains multiple tactics/techniques with corresponding log templates, allowing you to generate realistic security telemetry for testing detection rules, SIEM correlation, and security operations workflows.

## Directory Structure

```
scenarios/
├── drafts/              # Scenarios under development (placeholder files)
│   ├── alpha_and_omega.json
│   ├── crossroads.json
│   ├── dark_lies.json
│   ├── dark_truths.json
│   ├── double_lives.json
│   ├── everything_is_now.json
│   ├── past_and_present.json
│   ├── sic_mundus_creatus_est.json
│   └── you_will_reap.json
└── ready/               # Production-ready scenarios
    └── dark_secrets.json
```

## Scenario Structure

Each scenario JSON file follows this schema:

```json
{
  "name": "scenario_name",
  "tactics": [
    {
      "tactic": "Initial Access",
      "tactic_id": "TA0001",
      "technique": "Phishing: Spearphishing Attachment",
      "technique_id": "T1566.001",
      "count": 10,
      "interval": 2,
      "type": "CEF|LEEF|SYSLOG|JSON|WINEVENT",
      "log": {
        "product": "Email-GW",
        "observables": {
          "sender_email": "attacker@example.com",
          "recipient_email": "user@example.com",
          "file_name": "malware.xls",
          "file_hash": "a4c21e34a12f...",
          "action": "quarantine"
        }
      }
    }
  ]
}
```

### Field Definitions

| Field | Description | Example |
|-------|-------------|---------|
| `name` | Scenario identifier | `"dark_secrets"` |
| `tactic` | MITRE ATT&CK tactic name | `"Initial Access"` |
| `tactic_id` | MITRE ATT&CK tactic ID | `"TA0001"` |
| `technique` | MITRE ATT&CK technique name | `"Phishing"` |
| `technique_id` | MITRE ATT&CK technique ID | `"T1566.001"` |
| `count` | Number of logs to generate | `10` |
| `interval` | Delay between log batches (seconds) | `2` |
| `type` | Log format | `CEF`, `LEEF`, `SYSLOG`, `JSON`, `WINEVENT` |
| `product` | Product/vendor name in logs | `"Firewall"`, `"Windows"` |
| `observables` | Field values for the logs | See Observable Fields below |

## Observable Fields

Observables define the specific field values that appear in generated logs. Common observables include:

### Network Observables
- `local_ip` / `remote_ip` - IP addresses
- `local_port` / `remote_port` - Port numbers
- `host` / `src_host` / `dst_host` - Hostnames
- `url` - URLs
- `domain` - Domain names

### Email Observables
- `sender_email` / `recipient_email` - Email addresses
- `email_subject` / `email_body` - Email content
- `file_name` / `file_hash` - Attachment details

### Process Observables
- `win_process` / `unix_process` - Process names
- `win_child_process` - Child processes
- `win_cmd` - Command line arguments
- `user` - Username

### File Observables
- `file_name` - File name
- `file_path` - File path
- `file_hash` - File hash (MD5, SHA256)

### Action Observables
- `action` - Action taken (`allow`, `deny`, `quarantine`, `execution`)
- `severity` - Event severity

## Example Scenario: dark_secrets.json

The **dark_secrets** scenario simulates a complete attack chain:

### 1. Initial Access (TA0001)
**Technique**: Spearphishing Attachment (T1566.001)
- Generates Email Gateway CEF logs showing phishing email with malicious attachment
- Observable: Quarantined email with suspicious Excel file

### 2. Execution (TA0002)
**Technique**: Exploitation for Client Execution (T1566.001)
- Generates Windows LEEF logs showing Excel spawning cmd.exe
- Observable: PowerShell download command for malicious DLL

### 3. Persistence (TA0003)
**Technique**: Account Manipulation (T1098)
- Generates Windows LEEF logs showing new local user creation
- Observable: PowerShell New-LocalUser command

### 4. Lateral Movement (TA0008)
**Technique**: SMB/Windows Admin Shares (T1021.002)
- Generates Firewall CEF logs showing SMB connections
- Observable: Multiple internal IPs on ports 135, 445

### 5. Exfiltration (TA0010)
**Technique**: Exfiltration Over Alternative Protocol (T1048)
- Generates Linux SYSLOG showing DNS tunneling via curl
- Observable: Suspicious DNS queries to external domain

## Using Scenarios

### Via MCP Server

```python
# Using the MCP tool
await xlog_create_scenario_worker(
    name="dark_secrets",
    destination="XSIAM_WEBHOOK",
    tags=["apt", "phishing"]
)
```

### Via GraphQL API

```graphql
mutation {
  runScenario(
    name: "dark_secrets"
    destination: "udp:127.0.0.1:514"
  ) {
    success
    workerId
    message
  }
}
```

### Via REST API

```bash
curl -X POST http://localhost:8000/scenarios/dark_secrets \
  -H "Content-Type: application/json" \
  -d '{
    "destination": "tcp:siem.example.com:514"
  }'
```

## Creating Custom Scenarios

1. **Plan the Attack Chain**: Map out the MITRE ATT&CK tactics and techniques
2. **Define Log Sources**: Choose appropriate log formats for each step
3. **Set Observables**: Define realistic field values that create a coherent story
4. **Test**: Run the scenario and verify logs are generated correctly
5. **Validate**: Confirm detection rules trigger as expected

### Example: Creating a New Scenario

```json
{
  "name": "ransomware_attack",
  "tactics": [
    {
      "tactic": "Initial Access",
      "tactic_id": "TA0001",
      "technique": "Drive-by Compromise",
      "technique_id": "T1189",
      "count": 1,
      "type": "CEF",
      "log": {
        "product": "Proxy",
        "observables": {
          "url": ["http://malicious-site.com/exploit"],
          "user": ["john.doe"],
          "action": ["blocked"]
        }
      }
    },
    {
      "tactic": "Impact",
      "tactic_id": "TA0040",
      "technique": "Data Encrypted for Impact",
      "technique_id": "T1486",
      "count": 100,
      "interval": 1,
      "type": "WINEVENT",
      "log": {
        "product": "Windows",
        "observables": {
          "win_process": ["ransomware.exe"],
          "file_path": ["C:\\Users\\*\\Documents\\*.encrypted"],
          "action": ["file_modified"]
        }
      }
    }
  ]
}
```

## Best Practices

1. **Realistic Timing**: Use appropriate intervals between tactics (initial access → execution → persistence)
2. **Consistent Observables**: Use the same IPs, hostnames, and usernames throughout the attack chain
3. **Appropriate Log Formats**: Match log formats to realistic sources (CEF for firewalls, LEEF for QRadar sources, WINEVENT for Windows)
4. **MITRE ATT&CK Alignment**: Always map to official MITRE ATT&CK tactics and techniques
5. **Test Detection**: Validate that your SIEM/EDR detects the scenario as expected

## Use Cases

### Detection Engineering
Generate scenarios to test and validate detection rules:
```bash
# Test phishing detection
xlog run dark_secrets --destination XSIAM
# Verify alerts in XSIAM
xsiam query "dataset=alerts | filter alert_name contains 'phishing'"
```

### Purple Team Exercises
Combine scenarios with CALDERA operations:
```python
# Generate synthetic logs
await xlog_create_scenario_worker("dark_secrets", "XSIAM_WEBHOOK")

# Run parallel CALDERA operation
operation = await caldera_create_operation("Purple Team Exercise", "Hunter")
await caldera_update_operation(operation["id"], {"state": "running"})
```

### SIEM Testing
Validate log parsing and correlation:
```bash
# Send to SIEM
xlog run dark_secrets --destination tcp:siem.company.com:514

# Check if all steps were ingested correctly
# Verify correlation rules triggered
```

## Troubleshooting

**Scenario Not Found**: Ensure the scenario file exists in `scenarios/ready/`

**Invalid JSON**: Validate JSON syntax using `json.tool` or online validators

**Missing Observables**: Check that all required fields for the log format are provided

**No Logs Generated**: Verify the destination is reachable and XLog server is running

## See Also

- [App README](../app/README.md) - Core log generation engine
- [MCP Server README](../mcp/server/README.md) - AI-orchestrated scenario execution
- [MITRE ATT&CK Framework](https://attack.mitre.org/) - Tactic and technique reference
