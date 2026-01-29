# Skill: Ink and Foil Scenario

## Category
scenarios

## Attack Type
Sophisticated Log-Only Attack Chain

## MITRE ATT&CK Tactics
- TA0001: Initial Access
- TA0002: Execution
- TA0003: Persistence
- TA0007: Discovery
- TA0008: Lateral Movement
- TA0006: Credential Access
- TA0011: Command and Control
- TA0040: Impact

## High-Level Guidance

Create a multi-step, log-only attack chain with consistent IoCs and clear sequencing:

1. **Initial Access (Phish + Login)**  
   - Emit one phishing email log: `sender_email`, `recipient_email`, `subject`, `url`.  
   - Follow with a VPN or web login: one failed auth, then success from the same `remoteIp`.  
2. **Execution (User Context)**  
   - Log a suspicious script or command execution on the initial host (`win_cmd` or `unix_cmd`).  
   - Include `user`, `src_host`, `process_name`, `parent_process` where available.  
3. **Persistence (Scheduled Task/Service)**  
   - Create a new scheduled task or service log with a plausible name (e.g., `UpdateService`).  
   - Tie it to the same host and user from step 2.  
4. **Discovery (Host + Network)**  
   - Host discovery: process listing or system info command log.  
   - Network discovery: multiple connection attempts to common ports from the initial host.  
5. **Credential Access (Access Artifacts)**  
   - Emit one credential access indicator (e.g., LSASS read, registry access).  
   - Follow with an anomalous authentication event (new device or new geo).  
6. **Lateral Movement (Second Host)**  
   - SMB/RDP/WinRM session log to `dst_host` with `remote_port` 445 or 3389.  
   - Keep `remoteIp` consistent with initial access.  
7. **Command & Control (Beaconing)**  
   - Regular outbound connections to a single `dst_domain` or IP every few seconds.  
   - Include `protocol`, `remote_port`, and `user_agent` if available.  
8. **Impact (Data + Service)**  
   - File modification/encryption logs on the second host.  
   - End with a service outage or critical error log tied to the same asset.

## Consistency Rules

- Reuse the same attacker `remoteIp`, C2 `dst_domain`, and phishing `url` across steps.  
- Keep hostnames consistent: `src_host` for initial host, `dst_host` for lateral movement.  
- Use a short, realistic timeline (minutes, not days).  
