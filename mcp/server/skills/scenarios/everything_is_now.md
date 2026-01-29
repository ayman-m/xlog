# Skill: Everything Is Now Scenario

## Category
scenarios

## Attack Type
Full-Spectrum Attack Chain (Logs + CALDERA)

## MITRE ATT&CK Tactics
- TA0001: Initial Access
- TA0002: Execution
- TA0007: Discovery
- TA0008: Lateral Movement
- TA0005: Defense Evasion
- TA0011: Command and Control
- TA0006: Credential Access
- TA0040: Impact

## High-Level Guidance

Create a complete chain that mixes log simulation and CALDERA actions:

1. **Initial Access (logs)**: A single external IP triggers a phishing or VPN login with one failed attempt followed by success.
2. **Execution (CALDERA)**: Run a single scripted execution ability on the initial host.
3. **Discovery (logs)**: Emit host and network discovery logs within a short window.
4. **Credential Access (CALDERA)**: Execute one credential access ability and record a follow-on auth log.
5. **Lateral Movement (logs)**: Generate one lateral movement log (e.g., SMB or RDP) to a second host.
6. **Defense Evasion (CALDERA)**: Run one obfuscation or security tooling tamper ability.
7. **Command & Control (logs)**: High-frequency beaconing to one C2 domain from the initial host.
8. **Impact (logs)**: Conclude with a single impact log (data wipe or service outage).
