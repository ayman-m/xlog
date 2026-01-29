# Skill: Crossroads Scenario

## Category
scenarios

## Attack Type
Credential Access / Lateral Movement

## MITRE ATT&CK Tactics
- TA0006: Credential Access
- TA0008: Lateral Movement
- TA0001: Initial Access

## High-Level Guidance

Keep this scenario minimal:

1. Start with one compromised user account and a single attacker source IP.
2. Show two diverging access paths from that account (e.g., VPN login + cloud console login) within a short window.
3. Include one failed login attempt before the successful one.
4. End with a single lateral movement event to a second host.
