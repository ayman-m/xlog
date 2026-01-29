# XQL Query Examples

### Arista Cloud Vision Wireless Alerts (automatically generated)

```sql
dataset = arista_cloud_vision_wireless_generic_alert_raw
| filter _alert_data != null
| alter alert_severity = json_extract_scalar(_alert_data, "$.severity")
| alter alert_category = json_extract_scalar(_alert_data, "$.alert_category")
| alter alert_name = json_extract_scalar(_alert_data, "$.alert_name")
| alter alert_description = json_extract_scalar(_alert_data, "$.alert_description")
```

---

### Arista Cloud Vision Wireless_ Alerts (automatically generated)

```sql
dataset = arista_cloud_vision_wireless_blackgeneric_alert_raw
| filter _alert_data != null
| alter alert_severity = json_extract_scalar(_alert_data, "$.severity")
| alter alert_category = json_extract_scalar(_alert_data, "$.alert_category")
| alter alert_name = json_extract_scalar(_alert_data, "$.alert_name")
| alter alert_description = json_extract_scalar(_alert_data, "$.alert_description")
```

---

### jira-v2 Alerts (automatically generated)

```sql
dataset = jira_v2_generic_alert_raw
| filter _alert_data != null
| alter alert_severity = json_extract_scalar(_alert_data, "$.severity")
| alter alert_category = json_extract_scalar(_alert_data, "$.alert_category")
| alter alert_name = json_extract_scalar(_alert_data, "$.alert_name")
| alter alert_description = json_extract_scalar(_alert_data, "$.alert_description")
```

---

### Jira V3 Alerts (automatically generated)

```sql
dataset = jira_v3_generic_alert_raw
| filter _alert_data != null
| alter alert_severity = json_extract_scalar(_alert_data, "$.severity")
| alter alert_category = json_extract_scalar(_alert_data, "$.alert_category")
| alter alert_name = json_extract_scalar(_alert_data, "$.alert_name")
| alter alert_description = json_extract_scalar(_alert_data, "$.alert_description")
```

---

### AzureDevOps Alerts (automatically generated)

```sql
dataset = azuredevops_generic_alert_raw
| filter _alert_data != null
| alter alert_severity = json_extract_scalar(_alert_data, "$.severity")
| alter alert_category = json_extract_scalar(_alert_data, "$.alert_category")
| alter alert_name = json_extract_scalar(_alert_data, "$.alert_name")
| alter alert_description = json_extract_scalar(_alert_data, "$.alert_description")
```

---

### Possible Attacks against AP/Security Cameras

```sql
dataset = panw_ngfw_traffic_raw 
| fields app,from_zone,source_ip,source_port,dest_ip, dest_port, to_zone, action, sub_type, dest_device_host, log_source_name, rule_matched, sub_type, log_type
//severity, pcap_id, pcap, threat_name, file_name, url_domain, source_user_info_name, threat_category, sub_type, threat_id
| filter incidr(dest_ip, "10.220.10.0/24, 10.220.11.0/24") = True
| filter (from_zone not in ("security_cameras", "noc_wifi", "switch-ap_mgmt", "TAP-FW-1")) 
| comp count(dest_ip) as number_of_attempts by source_ip, dest_ip, dest_port, app, from_zone, to_zone, action, rule_matched, log_type
| filter  number_of_attempts > 50 AND action != "drop"
```

---

### IoT Security - New Raspberry Device Found

```sql
dataset = panw_iot_security_devices_raw 
| filter profile contains "Raspberry Pi Device"
| alter duration_time = timestamp_diff(_insert_time,first_seen_date,"MINUTE") 
| filter duration_time <= 30 and duration_time  >= 0
//| dedup mac_address
```

---

### Possible Attacks against AP/Security Cameras (THREAT LOGS)

```sql
dataset = panw_ngfw_threat_raw 
| fields app,from_zone,source_ip,source_port,dest_ip, dest_port, to_zone, action, sub_type, dest_device_host, log_source_name, rule_matched, sub_type, log_type, severity, pcap_id, pcap, threat_name, file_name, url_domain, source_user_info_name, threat_category, sub_type, threat_id
| filter incidr(dest_ip, "10.220.10.0/24, 10.220.11.0/24") = True
| filter (from_zone not in ("security_cameras", "noc_wifi", "switch-ap_mgmt", "TAP-FW-1")) 
| filter from_zone != "dns" and to_zone != "dns"
//| comp count(dest_ip) as number_of_attempts by source_ip, dest_ip, dest_port, app, from_zone, to_zone, action, rule_matched, log_type
//| filter  number_of_attempts > 50
```

---

### Interzone Class Threat Detected

```sql
dataset = panw_ngfw_threat_raw 
| fields app,from_zone,source_ip,source_port,dest_ip, dest_port, to_zone, action,
    file_sha_256, sub_type,
    dest_device_host,
    cloud_hostname, log_source_name,
    rule_matched,
    severity,
    pcap_id,
    pcap,
    session_id,
    threat_name,
    file_name, url_domain,
    source_user_info_name,
    threat_category, sub_type, threat_id 
| filter rule_matched not contains "Allow Tap"
| filter to_zone != "internet" and from_zone != "internet"
| filter (rule_matched != """RDNS Outbound DNS""") 
| filter from_zone != to_zone
| filter app not contains "dns" and to_zone != "dns"
| filter from_zone not contains "noc_" and to_zone != "reg_web"
| filter rule_matched not contains "nate_joel_laptop_to_reg"
| filter to_zone != "tools_mgmt"
```

---

### Corelight AI Classroom Triage Alert

```sql
dataset = corelight_ai_triage_raw 
| filter IR_recommendation = "ESCALATE"
| fields First_ts, Source_IP,Source_IP_range, Destination_IP, Destination_Range, alert_name, Criticality, Criticality_explanation, Source_subnet, Curriculum_question, Curriculum_explanation, IR_explanation, IR_recommendation, Traffic_direction
```

---

### Wildfire Malware Detected

```sql
dataset = panw_ngfw_threat_raw 
//| fields dest_ip, app_category, threat_*, source_ip, to_zone, from_zone, action
|filter sub_type ~= ".*wildfire-virus.*|.*virus.*|.*wildfire.*|.*virus.*"
|filter verdict != "benign"and verdict != null
| fields app, verdict,
    to_zone,
    dest_device_host as dest_hostname,
    dest_ip, dest_port,
    file_sha_256 as file_hash,
    cloud_hostname, log_source_name as firewall_name,
    action,
    rule_matched as rule,
    severity,
    pcap_id as pcap_id,
    pcap,
    session_id,
    from_zone,
    source_ip as src_ip,
    source_port as src_port,
    threat_name as threat,
    file_name as url_filename,
    users 
//| iploc  src_ip loc_city, loc_region, loc_country, loc_continent, loc_latlon, loc_timezone 
//| comp count(dest_ip) as count_dest by threat_category
```

---

### Outbound C2 Spyware

```sql
dataset = panw_ngfw_threat_raw 
| fields app,from_zone,source_ip,source_port,dest_ip, dest_port, to_zone, action,
    file_sha_256, sub_type,
    dest_device_host,
    cloud_hostname, log_source_name,
    rule_matched,
    severity,
    pcap_id,
    pcap,
    session_id,
    threat_name,
    file_name, url_domain,
    source_user_info_name,
    threat_category, sub_type, threat_id, users
| alter threat = threat_name + " (" + to_string(threat_id) + ")"
//| filter threat_id != 14978 and threat_id != 14984
//| filter severity != "Informational" and severity != "Low" and severity != "Medium" and severity != null
| filter app not contains "dns"
| filter sub_type = "spyware"
| filter incidr(dest_ip, "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16") = false and from_zone not in("internet")
| filter rule_matched != "Allow TAP"
| filter file_name contains ".oast."
//| filter to_zone = "internet" and from_zone != "internet"
```

---

### Captive Portal Continue Click

```sql
dataset = panw_ngfw_url_raw 
| filter action = "continue"
| fields source_user, action
```

---

### Generic Webhook Alerts (automatically generated)

```sql
dataset = generic_webhook_generic_alert_raw
| filter _alert_data != null
| alter alert_severity = json_extract_scalar(_alert_data, "$.severity")
| alter alert_category = json_extract_scalar(_alert_data, "$.alert_category")
| alter alert_name = json_extract_scalar(_alert_data, "$.alert_name")
| alter alert_description = json_extract_scalar(_alert_data, "$.alert_description")
```

---

### GitHub Alerts (automatically generated)

```sql
dataset = github_generic_alert_raw
| filter _alert_data != null
| alter alert_severity = json_extract_scalar(_alert_data, "$.severity")
| alter alert_category = json_extract_scalar(_alert_data, "$.alert_category")
| alter alert_name = json_extract_scalar(_alert_data, "$.alert_name")
| alter alert_description = json_extract_scalar(_alert_data, "$.alert_description")
```

---

### Gitlab - User Permission Changed

```sql
datamodel dataset = gitlab_gitlab_raw 
| fields _time
,xdm.event.id 
,xdm.source.user.identifier 
,xdm.target.resource.id 
,xdm.target.resource.type 
,xdm.source.user.username 
,xdm.target.resource.sub_type 
,xdm.target.resource.name 
,xdm.event.description 
,xdm.source.ipv4 
,xdm.target.resource_before.value 
,xdm.target.resource.value 
,xdm.event.operation 
,xdm.event.type 
,xdm.event.operation_sub_type 
| filter xdm.event.operation = "change_access_level" and xdm.target.resource_before.value = "Guest" and xdm.target.resource.value = "Owner"
```

---

### GoogleThreatIntelligenceDTMAlerts Alerts (automatically generated)

```sql
dataset = googlethreatintelligencedtmalerts_generic_alert_raw
| filter _alert_data != null
| alter alert_severity = json_extract_scalar(_alert_data, "$.severity")
| alter alert_category = json_extract_scalar(_alert_data, "$.alert_category")
| alter alert_name = json_extract_scalar(_alert_data, "$.alert_name")
| alter alert_description = json_extract_scalar(_alert_data, "$.alert_description")
```

---

### GoogleThreatIntelligenceASMIssues Alerts (automatically generated)

```sql
dataset = googlethreatintelligenceasmissues_generic_alert_raw
| filter _alert_data != null
| alter alert_severity = json_extract_scalar(_alert_data, "$.severity")
| alter alert_category = json_extract_scalar(_alert_data, "$.alert_category")
| alter alert_name = json_extract_scalar(_alert_data, "$.alert_name")
| alter alert_description = json_extract_scalar(_alert_data, "$.alert_description")
```

---

### HelloWorld Alerts (automatically generated)

```sql
dataset = helloworld_generic_alert_raw
| filter _alert_data != null
| alter alert_severity = json_extract_scalar(_alert_data, "$.severity")
| alter alert_category = json_extract_scalar(_alert_data, "$.alert_category")
| alter alert_name = json_extract_scalar(_alert_data, "$.alert_name")
| alter alert_description = json_extract_scalar(_alert_data, "$.alert_description")
```

---

### NUC Agent Update Script

```sql
dataset = endpoints
| filter group_names in ("NUCs") and last_upgrade_status = "COMPLETED_SUCCESSFULLY" and endpoint_status = ENUM.CONNECTED  
| alter ct = current_time()
| alter diff_in_mins = timestamp_diff(ct, last_upgrade_status_time, "MINUTE")
| filter diff_in_mins < 59
| fields diff_in_mins, endpoint_status, endpoint_id, endpoint_name, group_names, agent_version, ip_address , mac_address, last_upgrade_status_time
```

---

### Palo Alto Networks IoT Alerts (automatically generated)

```sql
dataset = palo_alto_networks_iot_generic_alert_raw
| filter _alert_data != null
| alter alert_severity = json_extract_scalar(_alert_data, "$.severity")
| alter alert_category = json_extract_scalar(_alert_data, "$.alert_category")
| alter alert_name = json_extract_scalar(_alert_data, "$.alert_name")
| alter alert_description = json_extract_scalar(_alert_data, "$.alert_description")
```

---

### 1000 eyes - uncleared alert

```sql
dataset = cisco_1000_raw 
| filter alert_id != null
| comp min(_time) as _time ,count() as c , values(eventId)as event_ids , values(cleared_time) as cleared_time, values(devices_names) as devices_names, values(details) as details by alert_id, testId, signature, test_type, test_name , alert_type, triggered_time, itsiDrilldownURI, vendor_severity addrawdata = true 
// | filter c = 1 and cleared_time = null
| alter vendor_severity = if(vendor_severity = "MINOR", "Low", if(vendor_severity = "CIRTICAL", "Critical", vendor_severity ))
| alter details = arraymerge(details )
| alter devices_names = arraymerge(devices_names)
```

---

### Health - Strong deviation in ingestion rate using Z score

```sql
preset = metrics_view 
|filter last_seen > to_timestamp(1754146800000, "MILLIS") and timestamp_diff(current_time(), _time ,"minute") >= 6
| alter unique_id = concat(_collector_id, _collector_ip, _collector_name, _collector_type, _collector_internal_ip_address, _final_reporting_device_ip, _final_reporting_device_name, _reporting_device_name, _collector_hostname, _broker_device_id, _device_id, _log_type, _vendor, _product)
| alter t = _time 
| bin t span = 1h
| comp sum(total_event_count) as total_event_count by unique_id, t
| comp avg(total_event_count) as total_event_count_avg , var(total_event_count) as total_event_count_var by unique_id addrawdata = true as raw_stat //, _collector_id, _collector_ip, _collector_name, _collector_type , _final_reporting_device_ip ,_final_reporting_device_name , _broker_device_id ,_vendor , _product
| join conflict_strategy = both  (
    preset = metrics_view |filter timestamp_diff(current_time(), _time ,"minute") >= 6 and timestamp_diff(current_time(), _time ,"minute") <= 65 
    | alter unique_id = concat(_collector_id, _collector_ip, _collector_name, _collector_type, _collector_internal_ip_address, _final_reporting_device_ip, _final_reporting_device_name, _reporting_device_name, _collector_hostname, _broker_device_id, _device_id, _log_type, _vendor, _product)
    | alter t = _time 
    | bin t span = 1h
    | comp sum(total_event_count) as total_event_count, values(_time) as v by unique_id, t addrawdata = true as jonined_raw
       ) as last_ten_m last_ten_m.unique_id = unique_id 
| alter distance_to_average  =  subtract(total_event_count_avg, total_event_count)
| alter total_event_count_std = pow(total_event_count_var, 0.5)
| alter distance_to_average = if(distance_to_average <0 , multiply(distance_to_average , -1), distance_to_average )
| alter anom = divide(distance_to_average ,total_event_count_std)
| filter anom > 3
```

---

### Health - Ingestion is absolute zero

```sql
preset = metrics_view  
|filter last_seen > to_timestamp(1754146800000, "MILLIS") //start of reg handoff - 0800,2-AUG
| comp sum(total_event_count) as total_event_count_sum by _collector_id, _collector_ip, _collector_name, _collector_type, _collector_internal_ip_address, _final_reporting_device_ip, _final_reporting_device_name, _reporting_device_name, _collector_hostname, _broker_device_id, _device_id, _log_type, _vendor, _product
| filter total_event_count_sum = 0
```

---

### Microsoft Teams Alerts (automatically generated)

```sql
dataset = microsoft_teams_generic_alert_raw
| filter _alert_data != null
| alter alert_severity = json_extract_scalar(_alert_data, "$.severity")
| alter alert_category = json_extract_scalar(_alert_data, "$.alert_category")
| alter alert_name = json_extract_scalar(_alert_data, "$.alert_name")
| alter alert_description = json_extract_scalar(_alert_data, "$.alert_description")
```

---

### NGFW Vuln or Spyware trigger and allowed connections to reg_web

```sql
dataset = panw_ngfw_threat_raw 
/*
| fields app, from_zone, source_ip, source_port, dest_ip, dest_port, to_zone, action,
    file_sha_256, sub_type,
    dest_device_host,
    cloud_hostname, log_source_name,
    rule_matched,
    severity,
    pcap_id,
    pcap,
    session_id,
    threat_name,
    file_name, url_domain,
    source_user_info_name,
    threat_category, sub_type, threat_id, _reporting_device_ip, source_device_host, dest_device_host  */
| alter threat = threat_name + " (" + to_string(threat_id) + ")"
| filter app not contains "dns"
| filter lowercase(severity) != "informational" and lowercase(severity) != "low"
| filter 
    threat_id != 40073     // PowerDNS Authoritative Server Long qname Denial-of-Service Vulnerability
    and threat_id != 57955 // ZGrab Application Layer Scanner Detection
// | filter incidr(dest_ip, "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16") = false
| filter to_zone = "reg_web"
//| filter lowercase(rule_matched) != "allow tap"
| filter lowercase(action) != "reset-both" and lowercase(action) != "reset-server" and lowercase(action) != "reset-client"
| filter threat_name != "Inline Cloud Analyzed CMD Injection Traffic Detection" // the TAP was removed so we are excluding the inline C2 since it is allowed in
```

---

### Corelight Suricata Alert

```sql
dataset = corelight_zeek_raw
| fields _path, uid, id_orig_h as source_ip, id_resp_h as dest_ip, id_orig_p as source_port, id_resp_p as dest_port, id_resp_l2_addr as dest_mac, id_orig_l2_addr as source_mac, payload, payload_printable, alert_signature, alert_signature_id, alert_action, alert_category, alert_action, alert_metadata, alert_severity, alert_rule, service, enrichment_orig_network_name, enrichment_orig_network_ssid, enrichment_orig_room_name, enrichment_resp_network_name, enrichment_resp_network_ssid, enrichment_resp_room_name, conn_state, spcap_url, id_orig_chaddr
| filter _path = "suricata_corelight" and ((payload != null and payload != "") or (payload_printable != null and payload_printable != "")) and (alert_metadata contains "signature_severity:medium" or alert_metadata contains "signature_severity:high" or alert_metadata contains "signature_severity:critical")
```

---

### NGFW Inline/ATP Alerts on TAP

```sql
dataset = panw_ngfw_threat_raw | 
fields app, from_zone, source_ip, source_port, dest_ip, dest_port, to_zone, action,
    file_sha_256, sub_type,
    dest_device_host,
    cloud_hostname, log_source_name,
    rule_matched,
    severity,
    pcap_id,
    pcap,
    session_id,
    threat_name,
    file_name, url_domain,
    source_user_info_name,
    threat_category, sub_type, threat_id
| alter threat = threat_name + " (" + to_string(threat_id) + ")"
// | filter incidr(dest_ip, "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16") = false
// | filter to_zone = "reg_web"                    // Irrelevant on TAP as the to_zone is TAP-FW-1
| filter lowercase(rule_matched) = "allow tap"     // Inline C2 / ATP alerts are only enabled on TAP NGFWs
| filter lowercase(threat_name) contains "inline"  // Inline C2
// | filter lowercase(action) != "reset-both" and lowercase(action) != "reset-server" and lowercase(action) != "reset-client"
```

---

### Panorama Alerts (automatically generated)

```sql
dataset = panorama_generic_alert_raw
| filter _alert_data != null
| alter alert_severity = json_extract_scalar(_alert_data, "$.severity")
| alter alert_category = json_extract_scalar(_alert_data, "$.alert_category")
| alter alert_name = json_extract_scalar(_alert_data, "$.alert_name")
| alter alert_description = json_extract_scalar(_alert_data, "$.alert_description")
```

---

### RedLock Alerts (automatically generated)

```sql
dataset = redlock_generic_alert_raw
| filter _alert_data != null
| alter alert_severity = json_extract_scalar(_alert_data, "$.severity")
| alter alert_category = json_extract_scalar(_alert_data, "$.alert_category")
| alter alert_name = json_extract_scalar(_alert_data, "$.alert_name")
| alter alert_description = json_extract_scalar(_alert_data, "$.alert_description")
```

---

### PrismaCloud v2 Alerts (automatically generated)

```sql
dataset = prismacloud_v2_generic_alert_raw
| filter _alert_data != null
| alter alert_severity = json_extract_scalar(_alert_data, "$.severity")
| alter alert_category = json_extract_scalar(_alert_data, "$.alert_category")
| alter alert_name = json_extract_scalar(_alert_data, "$.alert_name")
| alter alert_description = json_extract_scalar(_alert_data, "$.alert_description")
```

---

### Proofpoint TAP v2 Alerts (automatically generated)

```sql
dataset = proofpoint_tap_v2_generic_alert_raw
| filter _alert_data != null
| alter alert_severity = json_extract_scalar(_alert_data, "$.severity")
| alter alert_category = json_extract_scalar(_alert_data, "$.alert_category")
| alter alert_name = json_extract_scalar(_alert_data, "$.alert_name")
| alter alert_description = json_extract_scalar(_alert_data, "$.alert_description")
```

---

### Create alert for new/unassigned IT incidents

```sql
dataset = incidents 
| filter incident_domain = "DOMAIN_IT"
| filter status = ENUM.NEW
```

---

### Malleable C2 Attacks Inet Bourne

```sql
dataset = panw_ngfw_threat_raw  
| filter (threat_id = 9950 or threat_id = 89951 or threat_id = 89952 or threat_id = 89953 or threat_id = 89954 or threat_id = 89955 or threat_id = 89956 or threat_id = 89957 or threat_id = 89958 or threat_id = 99951 or threat_id = 99950 )  and ( from_zone  = "Internet" or to_zone  = "Internet")
```

---

### Arista Wireless

```sql
config case_sensitive = false 
| dataset = arista_cloudvision_raw 
| alter client_mac = json_extract(radio, "$.macaddress")
| alter client_mac = replace(client_mac,"\"","")
| alter userName = replace(userName, "--","")
| filter active = true
```

---

### Arista Wireless Misbehaving

```sql
config case_sensitive = false 
| dataset = arista_cloudvision_raw 
| alter client_mac = json_extract(radio, "$.macaddress")
| alter client_mac = replace(client_mac,"\"","")
| alter userName = replace(userName, "--","")
| filter active = true and misbehaving = "YES"
```

---

### Reg Servers Critical

```sql
config case_sensitive = false 
| dataset = panw_ngfw_threat_raw 
| filter ((dest_ip = "66.77.37.5") or (source_ip = "66.77.37.5") or (dest_ip = "10.220.153.11") or (source_ip = "10.220.153.11")) and (severity != "informational") and (severity != "low" and rule_matched = "Registration Web Server")
```

---

### ServiceNow Alerts (automatically generated)

```sql
dataset = servicenow_generic_alert_raw
| filter _alert_data != null
| alter alert_severity = json_extract_scalar(_alert_data, "$.severity")
| alter alert_category = json_extract_scalar(_alert_data, "$.alert_category")
| alter alert_name = json_extract_scalar(_alert_data, "$.alert_name")
| alter alert_description = json_extract_scalar(_alert_data, "$.alert_description")
```

---

### ServiceNow v2 Alerts (automatically generated)

```sql
dataset = servicenow_v2_generic_alert_raw
| filter _alert_data != null
| alter alert_severity = json_extract_scalar(_alert_data, "$.severity")
| alter alert_category = json_extract_scalar(_alert_data, "$.alert_category")
| alter alert_name = json_extract_scalar(_alert_data, "$.alert_name")
| alter alert_description = json_extract_scalar(_alert_data, "$.alert_description")
```

---

### SlackV3 Alerts (automatically generated)

```sql
dataset = slackv3_generic_alert_raw
| filter _alert_data != null
| alter alert_severity = json_extract_scalar(_alert_data, "$.severity")
| alter alert_category = json_extract_scalar(_alert_data, "$.alert_category")
| alter alert_name = json_extract_scalar(_alert_data, "$.alert_name")
| alter alert_description = json_extract_scalar(_alert_data, "$.alert_description")
```

---

### Palo Alto Networks Threat Vault v2 Alerts (automatically generated)

```sql
dataset = palo_alto_networks_threat_vault_v2_generic_alert_raw
| filter _alert_data != null
| alter alert_severity = json_extract_scalar(_alert_data, "$.severity")
| alter alert_category = json_extract_scalar(_alert_data, "$.alert_category")
| alter alert_name = json_extract_scalar(_alert_data, "$.alert_name")
| alter alert_description = json_extract_scalar(_alert_data, "$.alert_description")
```

---

### Twinwave Alerts (automatically generated)

```sql
dataset = twinwave_generic_alert_raw
| filter _alert_data != null
| alter alert_severity = json_extract_scalar(_alert_data, "$.severity")
| alter alert_category = json_extract_scalar(_alert_data, "$.alert_category")
| alter alert_name = json_extract_scalar(_alert_data, "$.alert_name")
| alter alert_description = json_extract_scalar(_alert_data, "$.alert_description")
```

---

### Spike DNS Malware Traffic

```sql
dataset = panw_ngfw_threat_raw 
|filter sub_type = "spyware"
|filter threat_category ~= "dns-malware" 
| fields _time,_id,users as user,threat_category,threat_name as threat,
    file_name as url_filename, app,tunneled_app, rule_matched as rule,
to_zone, from_zone,
    source_ip as src_ip,
    source_port as src_port,protocol,
    dest_ip, dest_port,
    action,
    dest_device_host as dest_hostname,
    cloud_hostname, log_source_name as firewall_name,
    severity,
    pcap_id as pcap_id,
    pcap,
    session_id,
    customer_id
//Counting activity by 24h
|bin _time span = 1d //count 
|comp count() as event_count , values(rule ) as rule , values(app) as app,values(tunneled_app) as tunneled_app, values(threat_category) as threat_category, values(url_filename ) as url_filename, values(from_zone) as from_zone, values(src_ip )as src_ip,values(src_port) as src_port, values(dest_port) as dest_port, values(protocol)as protocol, values(to_zone) as to_zone, values(dest_ip ) as dest_ip, values(action) as action, values(firewall_name) as log_source_name,values(pcap) as pcap,values(dest_hostname) as dest_device_host,values(cloud_hostname) as cloud_hostname,values(severity) as severity,values(pcap_id) as pcap_id,values(session_id) as session_id by user,threat,_time
|filter if((url_filename  ~= ".*epicunitscan.info.*" and event_count >= 300) or (event_count >= 100 and url_filename  !~= ".*epicunitscan.info.*"), "True", "False") = "True" 
|sort desc event_count
```

---

### Testing Suricata

```sql
dataset = corelight_zeek_raw  
| filter _path = "suricata_corelight" 
| fields alert_category, id_orig_h , id_resp_h, alert_rule , alert_metadata   
//| comp count() as t by id_orig_h addrawdata = true
```

---

### VirusTotal - Premium (API v3) Alerts (automatically generated)

```sql
dataset = virustotal_premium_api_v3__generic_alert_raw
| filter _alert_data != null
| alter alert_severity = json_extract_scalar(_alert_data, "$.severity")
| alter alert_category = json_extract_scalar(_alert_data, "$.alert_category")
| alter alert_name = json_extract_scalar(_alert_data, "$.alert_name")
| alter alert_description = json_extract_scalar(_alert_data, "$.alert_description")
```

---

### Cortex XSIAM Troy Security Incidents - Custom XQL Widget

```sql
dataset = incidents 
| filter assigned_user = NULL and status = ENUM.NEW
| comp count_distinct(incident_id)
| alter from_time = parse_timestamp("%Y-%m-%d %H:%M:%S ", "2025-04-01 00:00:00")
| alter to_time = parse_timestamp("%Y-%m-%d %H:%M:%S ", "2025-04-04 00:00:00")
 //view graph type = single subtype = standard yaxis = count_distinct_1 scale_threshold("#00ff00","#ffff00","20","#ff0000","30")
| view graph type = single subtype = standard yaxis = count_distinct_1
```

---

### Cortex XSIAM Troy Security Incidents - Active Incidents

```sql
dataset = incidents 
| filter (status = ENUM.NEW or status = ENUM.UNDER_INVESTIGATION)
| filter starred = 1
| comp count_distinct(incident_id)
| alter from_time = parse_timestamp("%Y-%m-%d %H:%M:%S ", "2024-12-06 00:00:00")
| alter to_time = parse_timestamp("%Y-%m-%d %H:%M:%S ", "2024-12-09 00:00:00")
| view graph type = single subtype = standard yaxis = count_distinct_1
```

---

### Cortex XSIAM Troy Security Incidents - Custom XQL Widget

```sql
dataset = incidents
| filter starred = 1
| fields _time as modified_time, creation_time, resolved_ts, assigned_user, incident_id, status, assigned_user, description, resolve_comment, severity, starring_ts, first_assignment_ts 
| filter status = ENUM.RESOLVED_TRUE_POSITIVE or status = ENUM.RESOLVED_SECURITY_TESTING or status = ENUM.RESOLVED_OTHER  or status = ENUM.RESOLVED_FALSE_POSITIVE or status = ENUM.RESOLVED_KNOWN_ISSUE or status = ENUM.RESOLVED_HANDLED_THREAT or status contains "BH_POSITIVE"
// THE JOINING OF THE ALERT TABLE
| join conflict_strategy = left  type = left 
(dataset = alerts 
//| filter starred = TRUE
| fields _time as alert_time, event_timestamp, incident_id, alert_id, alert_source, alert_name, alert_type, 
        description, user_name, resolution_status, resolution_comment, 
        host_name, host_os, action, severity, rule_id, module
        | alter user_name = arrayindex(arraydistinct(user_name), 0) 
        | comp values(user_name) as affected_users, values(alert_id) as alert_id, values(alert_name) as alert_name, values(alert_time) as alert_time, values(severity) as alert_severity, values(alert_source) as               alert_type, values(host_os) as host_os by incident_id
        ) as alert_table alert_table.incident_id = incident_id
//FORMAT TIME
| alter first_alert_time = arrayindex(alert_time, 0)
| alter first_alert_timestamp = format_timestamp("%Y-%m-%d %H:%M:%S", arrayindex(alert_time, 0))
| alter modified_timestamp = format_timestamp("%Y-%m-%d %H:%M:%S", modified_time)
| alter resolved_timestamp = format_timestamp("%Y-%m-%d %H:%M:%S", resolved_ts)
| alter creation_timestamp = format_timestamp("%Y-%m-%d %H:%M:%S", creation_time)
| alter starring_timestamp = format_timestamp("%Y-%m-%d %H:%M:%S", starring_ts)
| alter assignment_timestamp = format_timestamp("%Y-%m-%d %H:%M:%S", first_assignment_ts)
//TIME DIFFERENCE
| alter time_to_resolve = timestamp_diff(resolved_ts, creation_time, "MINUTE") 
| alter time_to_detect = timestamp_diff(creation_time, first_alert_time, "MINUTE") 
| alter time_to_detect = 
    if(to_integer(time_to_detect) < 0, 0, time_to_detect)
| alter close_code = status
| alter close_code = replace(close_code, "STATUS_070_RESOLVED_OTHER", "Benign")
| alter close_code = replace(close_code, "STATUS_040_RESOLVED_KNOWN_ISSUE", "No Operation (NOP)")
| alter close_code = replace(close_code, "STATUS_060_RESOLVED_FALSE_POSITIVE", "False Positive")
| alter close_code = replace(close_code, "STATUS_090_TRUE_POSITIVE", "True Positive")
| alter close_code = replace(close_code, "STATUS_100_SECURITY_TESTING", "Bad Practice")
| alter close_code = replace(close_code, "STATUS_RESOLVED_BH_POSITIVE", "Troy Postive")
| fields incident_id, status, assigned_user, description, resolve_comment, close_code, time_to_detect, time_to_resolve, creation_timestamp, resolved_timestamp, starring_timestamp,  assignment_timestamp, modified_timestamp, first_alert_timestamp, affected_users, alert_id, alert_name, alert_severity, alert_type, host_os, severity 
| comp count(incident_id) as starred_incident_count by close_code 
| sort desc starred_incident_count
| view graph type = line show_callouts = `true` show_callouts_names = `true` xaxis = close_code yaxis = starred_incident_count seriescolor("starred_incident_count","#479ca2") xvaluesfontsize = 0
```

---

### Cortex XSIAM Troy Security Incidents - Custom XQL Widget

```sql
config timeframe = 4d|
dataset = incidents
//get created incidents by day
| bin creation_time span = 1d
| alter day = format_timestamp("%b %d", creation_time)
| comp count_distinct(incident_id) as new by day
//union resolved incidents by day
| union (
dataset = incidents 
| bin resolved_ts span = 1d
| alter day = format_timestamp("%b %d", resolved_ts)
| comp count_distinct(incident_id) as resolved by day
)
//display in grouped vertical columns
| sort asc day
| filter day contains "Aug"
| view graph type = column subtype = grouped layout = horizontal show_callouts = `true` xaxis = day yaxis = new,resolved seriescolor("new","#479ca2") seriescolor("resolved","#7575a6") seriestitle("new","New Incidents") seriestitle("resolved","Resolved Incidents")
```

---

### Cortex XSIAM Troy Security Incidents - Custom XQL Widget

```sql
dataset = panw_ngfw_url_raw 
| filter url_category_list contains "command-and-control" or url_category_list contains "malware" or url_category_list contains "phishing" or url_category_list contains "greyware"
//| filter url_category not in ("catch-all", "computer-and-internet-info")
| alter test = arrayindex(split(url_category_list, ","), 1)
| fields source_ip, from_zone, dest_ip, to_zone, url_*, app, to_zone, test
| comp count(url_domain) as hits, values(app) as application_id, values(arrayindex(split(url_category_list, ","), 1)) as url_categories by url_domain 
| sort desc hits 
| limit 10
```

---

### Cortex XSIAM Troy Security Incidents - XQL Query

```sql
dataset = panw_ngfw_threat_raw 
| filter app contains "dns" and threat_category contains "dns-malware" or threat_category contains "dns-phishing"
| filter threat_id != 93031
| fields threat_category, threat_name, url*, sub_type
| comp count(threat_name) as hits, values(threat_category) as dns_type by threat_name
| sort desc hits
| limit 10
```

---

### Cortex XSIAM Troy Security Incidents - Custom XQL Widget

```sql
dataset = panw_ngfw_*
| fields dest_ip, app_category, threat_*, source_ip, to_zone, from_zone, action
| filter from_zone = "internet"
//| filter threat_category contains "spyware"
| filter action contains "reset"
| iploc  source_ip loc_city, loc_region, loc_country, loc_continent, loc_latlon, loc_timezone 
//| comp count(dest_ip) as count_dest by threat_category 
| comp count(dest_ip) as hit_count by source_ip 
| iploc  source_ip loc_country
| sort desc hit_count
```

---

### Cortex XSIAM Troy Security Incidents - Custom XQL Widget

```sql
dataset = panw_ngfw_*
| fields dest_ip, app_category, threat_*, source_ip, to_zone, from_zone, action
| filter from_zone = "internet"
//| filter threat_category contains "spyware"
| filter action contains "reset"
| iploc  source_ip loc_city, loc_region, loc_country, loc_continent, loc_latlon, loc_timezone 
//| comp count(dest_ip) as count_dest by threat_category 
| comp count(dest_ip) as hit_count by source_ip 
| iploc  source_ip loc_country
| sort desc hit_count
|
 view graph type = map xaxis = loc_country yaxis = hit_count
```

---

### Cortex XSIAM Troy Security Incidents - Custom XQL Widget

```sql
dataset = incidents 
| fields description, alert_categories, severity, incident_id
| comp count(incident_id) as incidents by severity 
| alter from_time = parse_timestamp("%Y-%m-%d %H:%M:%S ", "2024-12-06 00:00:00")
| alter to_time = parse_timestamp("%Y-%m-%d %H:%M:%S ", "2024-12-09 00:00:00")
// view graph type = pie subtype = semi_donut xaxis = severity yaxis = incidents
| view graph type = pie xaxis = severity yaxis = incidents
```

---

### Cortex XSIAM Troy Security Incidents - Custom XQL Widget

```sql
dataset = alerts 
| fields alert_name, app_id, app_subcategory, category, fw_name, source_zone_name, destination_zone_name 
//| fields alert_name, source_zone_name
| filter source_zone_name != null and source_zone_name != "internet"
| comp count(alert_name) as alert_count, values(arrayindex(source_zone_name,0)) as room, values(category) as category by alert_name 
| sort desc alert_count
```

---

### Cortex XSIAM Troy NGFW 24h - Custom XQL Widget

```sql
dataset = panw_ngfw_traffic_raw 
| filter app not contains "xdr" and app not contains "paloalto" and app not contains "traps" and app not contains "traps" and app not contains "panos" and action = "allow"
| comp count(action)
| view graph type = single subtype = standard header = "Allow" yaxis = count_1 headcolor = "#12ff00" headerfontsize = 60
```

---

### Cortex XSIAM Troy NGFW 24h - Custom XQL Widget

```sql
dataset = panw_ngfw_traffic_raw 
| filter app not contains "xdr" and app not contains "paloalto" and app not contains "traps" and app not contains "traps" and app not contains "panos" and action = "drop"
| comp count(action)
| view graph type = single subtype = standard header = "Drop" yaxis = count_1 headcolor = "#ffba00" headerfontsize = 60
```

---

### Cortex XSIAM Troy NGFW 24h - Custom XQL Widget

```sql
dataset = incidents
| filter status = ENUM.RESOLVED_AUTO_RESOLVE and alert_sources = "FW"
| comp count(status)
| view graph type = single subtype = standard header = "Auto Closed 24h" yaxis = count_1 headcolor = "#08ff4b" headerfontsize = 60
```

---

### Cortex XSIAM Troy NGFW 24h - Custom XQL Widget

```sql
dataset = panw_ngfw_traffic_raw 
| filter app not contains "xdr" and app not contains "paloalto" and app not contains "traps" and app not contains "traps" and app not contains "panos" and action = "allow"
| comp count(app ) as counter by app
| sort desc counter 
| limit 10
| view graph type = pie subtype = full xaxis = app yaxis = counter
```

---

### Cortex XSIAM Troy NGFW 24h - Custom XQL Widget

```sql
dataset = panw_ngfw_traffic_raw 
| filter app not contains "xdr" and app not contains "paloalto" and app not contains "traps" and app not contains "traps" and app not contains "panos" and action = "drop"
| comp count(app ) as counter by app
| sort desc counter 
| limit 10
| view graph type = pie subtype = full xaxis = app yaxis = counter
```

---

### Cortex XSIAM Troy NGFW Threat Hunting - Custom XQL Widget

```sql
dataset = panw_ngfw_traffic_raw | filter app contains "unknown" | comp count(dest_ip) as dest_count by dest_ip
| view graph type = column subtype = grouped header = "Unknown App Traffic by IP" xaxis = dest_ip yaxis = dest_count
```

---

### Cortex XSIAM Troy NGFW Threat Hunting - Custom XQL Widget

```sql
dataset = panw_ngfw_traffic_raw | filter app contains "unknown" | comp count(app) as app_count by app
| view graph type = pie header = "Unkown UDP and TCP" xaxis = app yaxis = app_count
```

---

### Cortex XSIAM Troy NGFW Threat Hunting - Custom XQL Widget

```sql
dataset = panw_ngfw_traffic_raw 
| filter app not contains "not-applicable" and app not contains "incomplete"
| fields app 
| comp count(app) as app_num by app
| sort desc app_num 
| view graph type = pie xaxis = app yaxis = app_num
```

---

### Cortex XSIAM Troy NGFW Threat Hunting - Custom XQL Widget

```sql
dataset = panw_ngfw_traffic_raw | comp count()
| view graph type = single subtype = standard header = "Total Traffic Logs" yaxis = count_1
```

---

### Cortex XSIAM Troy NGFW Remote Access Activity [Front] - Custom XQL Widget

```sql
dataset = panw_ngfw_traffic_raw
//Filter for remote access applications
| filter app_sub_category = "remote-access"
//Count total events by app, zone, ip and port 
| alter Zone_Direction = concat(to_string(from_zone), " to ", to_string(to_zone))
| comp values(source_ip) as source_ips, values(dest_ip) as dest_ips, sum(bytes_received) as total_bytes_in, sum(bytes_sent) as total_bytes_out, sum(bytes_total) as total_bytes, count(_id) as total_sessions by app, action, zone_direction 
| alter TotalGB_sent = divide(total_bytes_out ,1048576), TotalGB_recieved = divide(total_bytes_in, 1048576), TotalGB = divide(total_bytes, 1048576) 
| alter Sent_TotalGB = round(TotalGB_sent)
| alter Received_TotalGB = round(TotalGB_recieved)
| alter Total_GB = round(TotalGB)
| fields app, action, Zone_Direction, source_ips, dest_ips, total_sessions , Sent_TotalGB , Received_TotalGB , Total_GB 
| sort desc Total_GB
| fields app, total_sessions
| comp count() as counter by app
| limit 5
| sort desc counter
| view graph type = column subtype = grouped layout = horizontal xaxis = app yaxis = counter headerfontsize = 20
```

---

### Cortex XSIAM Troy NGFW Remote Access Activity [Front] - Custom XQL Widget

```sql
dataset = panw_ngfw_traffic_raw
| filter app_sub_category = "remote-access"
| fields app, app_sub_category, from_zone
| comp count(app) as hits by app, app_sub_category, from_zone
| sort desc hits
| filter (from_zone != """noc_wifi""") 
| filter (from_zone != """noc_wired""")
| filter (from_zone != """TAP-FW-1""")
```

---

### Cortex XSIAM Troy NGFW Remote Access Activity [Front] - Custom XQL Widget

```sql
dataset = panw_ngfw_traffic_raw
//Filter for remote access applications
| filter url_category = "proxy-avoidance-and-anonymizers" and (app not in("""ssl""", """web-browsing""", """incomplete""")) 
//Count total events by app, zone, ip and port 
| alter Zone_Direction = concat(to_string(from_zone), " to ", to_string(to_zone))
| comp values(source_ip) as source_ips, values(dest_ip) as dest_ips, sum(bytes_received) as total_bytes_in, sum(bytes_sent) as total_bytes_out, sum(bytes_total) as total_bytes, count(_id) as total_sessions by app, action, zone_direction 
| alter TotalGB_sent = divide(total_bytes_out ,1048576), TotalGB_recieved = divide(total_bytes_in, 1048576), TotalGB = divide(total_bytes, 1048576) 
| alter Sent_TotalGB = round(TotalGB_sent)
| alter Received_TotalGB = round(TotalGB_recieved)
| alter Total_GB = round(TotalGB)
| fields app, action, Zone_Direction, source_ips, dest_ips, total_sessions , Sent_TotalGB , Received_TotalGB , Total_GB 
| sort desc Total_GB
| fields app, total_sessions
| comp count() as counter by app
| sort desc counter
| limit 5
| view graph type = column subtype = grouped layout = horizontal xaxis = app yaxis = counter
```

---

### Cortex XSIAM Troy NGFW Remote Access Activity [Front] - Custom XQL Widget

```sql
dataset = panw_ngfw_traffic_raw
| filter url_category = "proxy-avoidance-and-anonymizers"
| fields app, app_sub_category, from_zone
| comp count(app) as hits by app, app_sub_category, from_zone
| sort desc hits
| filter (from_zone != """noc_wifi""") 
| filter (from_zone != """noc_wired""")
| filter (from_zone != """TAP-FW-1""")
| filter (app != """ssl""")
```

---

### Cortex XSIAM Troy Traffic Overview - Custom XQL Widget

```sql
config timeframe between "4d" and "now"
| dataset = panw_ngfw*
| bin _time span =1h
| sort asc  _time 
| comp sum(bytes_sent) as sent, sum(bytes_received ) as received by _time
| alter sent_GB = divide(sent, 1073741824), received_GB = divide(received, 1073741824) // 1073741824 = 1024^3
| view graph type = area subtype = stacked show_percentage = `false` xaxis = _time yaxis = sent_GB,received_GB
```

---

### Cortex XSIAM Troy Traffic Overview - Custom XQL Widget

```sql
preset = network_story 
| alter app = arrayindex(action_app_id_transitions ,2)
| comp count(event_id ) as traffic_count by app
| sort desc traffic_count 
| limit 12
| view graph type = column subtype = grouped layout = horizontal show_callouts = `true` xaxis = app yaxis = traffic_count seriescolor("traffic_count","#4384c2") xvaluesfontsize = 12 legend = `false`
```

---

### Cortex XSIAM Troy Traffic Overview - Custom XQL Widget

```sql
dataset = panw*
| fields action 
| comp count(_id ) as traffic_count by action
| sort desc traffic_count 
| view graph type = column subtype = grouped layout = horizontal show_callouts = `true` xaxis = action yaxis = traffic_count seriescolor("traffic_count","#4384c2") xvaluesfontsize = 15 calloutfontsize = 15 legend = `false`
```

---

### Cortex XSIAM Troy Traffic Overview - Custom XQL Widget

```sql
preset = network_story
| alter proto = to_string(action_network_protocol )
| alter proto = if(proto = "1", "ICMP",proto = "6", "TCP",proto = "17", "UDP", proto = "47", "GRE", proto = "4", "IP-in-IP")
| comp count(event_id ) as traffic_count by proto
| sort desc traffic_count 
| view graph type = pie subtype = semi_donut xaxis = proto yaxis = traffic_count
```

---

### Daily Check Report - Custom XQL Widget

```sql
config timeframe = 30M
| dataset = panw_ngfw_traffic_raw 
| comp count(_time ) by _reporting_device_name
```

---

### Daily Check Report - Custom XQL Widget

```sql
dataset = panw_ngfw_system_raw
| filter severity in ("high", "critical") and _reporting_device_name in ("BH_ASIA_*")
| fields _reporting_device_name, log_type, severity, event_name, event_description
| sort desc _time
```

---

### Daily Check Report - Custom XQL Widget

```sql
dataset = panw_ngfw_system_raw
| filter sub_type = "ha"
| fields _time, log_source_name, severity, event_name, event_description 
| sort desc _time
```

---

### Daily Check Report - Custom XQL Widget

```sql
dataset = panw_ngfw_threat_raw 
| filter severity in ("high", "critical")
| fields log_type, threat_name, from_zone, to_zone, source_ip, source_user, dest_ip, dest_port, app, action, severity, file_name, file_url 
| sort desc _time
```

---

### Daily Check Report - Custom XQL Widget

```sql
dataset = management_auditing 
| filter (`management_auditing_type` = MANAGEMENT_AUDIT_BROKER_VMS) 
| fields _time, description, subtype
| sort desc _time
```

---

### Daily Check Report - Custom XQL Widget

```sql
dataset = endpoints 
| filter operational_status != ENUM.PROTECTED or endpoint_status = ENUM.DISCONNECTED 
| fields operational_status_description, endpoint_name, endpoint_status, operational_status, group_names, operating_system, agent_version, mac_address, os_version, ip_address, ipv6_address, user, last_seen, content_version, assigned_prevention_policy, assigned_extensions_policy
```

---

### Daily Check Report - Last Ingestion by Device, Collector Type

```sql
preset = metrics_view
| filter _collector_type in ("*")
| alter 90th_percentile_latency_seconds = round(data_freshness_ninetieth_percentile), ven_prod = concat(_vendor, " ", _product), device = trim(concat(_reporting_device_name, " ", " " , _reporting_device_ip, " ", _final_reporting_device_name), " "), source = trim(concat(_broker_device_name, " ", _collector_name), " "), tz_corrected = parse_timestamp("%Y-%m-%d %H:%M:%S+00", to_string(last_seen), "+7:00")
| alter last_received = to_string(tz_corrected), last_seen_ = to_string(last_seen), latency_in_seconds = to_string(90th_percentile_latency_seconds)
| fields ven_prod, device, last_received as last_received_local_time, source, _collector_type, latency_in_seconds
| dedup device 
| filter not device contains "ASIA"
| sort asc _vendor
```

---

### Cortex XSIAM Troy SOC Value Metrics - Custom XQL Widget

```sql
dataset = xsiam_playbookmetrics_raw
| alter Tasks = Tasks->[]
| arrayexpand Tasks
// TODO apply a datamodel to these two objects instead (Tasks and Alert)
| alter
taskState = tasks->state,
taskType = tasks->type,
taskId = tasks->id,
taskName = tasks->name,
scriptID = tasks->scriptId,
incidentID = alert->parentXDRIncident,
alertID = alert->id,
alertName = alert->name,
alertType = alert->type,
playbookId = alert->playbookId
| filter taskType not in ("start", "title", "condition")
| filter playbookId != ""
// Since the job which posts this data runs every 15 min there may be duplicate data the more frequent it is run
| alter dedupkey = concat(incidentID,taskId, alertID )
| dedup dedupkey
// Filter for just automation
//| filter alerttype != "Unclassified"
| filter taskState = "Completed"
| filter tasktype = "regular"
| alter ScriptID  =  if ( scriptID  ~= "^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89abAB][0-9a-f]{3}-[0-9a-f]{12}$", "Custom", ScriptID )
//TODO make this a lookup table and join instead to make it scalable
| join type = inner (dataset = value_tags
| fields Category as value_category, ScriptID as value_scriptid, `Tag` as value_tag, TaskName as value_taskname, Time as value_time, Product as product, Vendor as vendor
) as vt (scriptID contains vt.value_scriptid)
| fields value_category, value_scriptid, product, value_taskname, value_time, vendor
| filter ((value_time != null and value_time != """""")) 
| filter ((value_scriptid != null and value_scriptid != """""")) 
| alter soc_event_minutes = to_integer(value_time)
| comp sum(soc_event_minutes) as total_soc_minutes by product, vendor
| alter total_soc_hours = round(divide(total_soc_minutes , 60))
| fields product, vendor, total_soc_minutes  , total_soc_hours
| sort desc total_soc_hours
| view graph type = area subtype = standard header = "Most Used Vendors" show_callouts = `true` show_callouts_names = `true` show_percentage = `false` xaxis = vendor yaxis = total_soc_hours seriescolor("total_soc_hours","#c047d7")
```

---

### Cortex XSIAM Troy SOC Value Metrics - Custom XQL Widget

```sql
dataset = xsiam_playbookmetrics_raw
| alter Tasks = Tasks->[]
| arrayexpand Tasks
// TODO apply a datamodel to these two objects instead (Tasks and Alert)
| alter
taskState = tasks->state,
taskType = tasks->type,
taskId = tasks->id,
taskName = tasks->name,
scriptID = tasks->scriptId,
incidentID = alert->parentXDRIncident,
alertID = alert->id,
alertName = alert->name,
alertType = alert->type,
playbookId = alert->playbookId
| filter taskType not in ("start", "title", "condition")
| filter playbookId != ""
// Since the job which posts this data runs every 15 min there may be duplicate data the more frequent it is run
| alter dedupkey = concat(incidentID,taskId)
| dedup dedupkey
// Filter for just automation
//| filter alerttype != "Unclassified"
| filter taskState = "Completed"
| filter tasktype = "regular"
//TODO make this a lookup table and join instead to make it scalable
| join type = inner (dataset = value_tags 
| fields Category as value_category, ScriptID as value_scriptid, `Tag` as value_tag, TaskName as value_taskname, Time as value_time, PlaybookID as playbook_id
) as vt (scriptID contains vt.value_scriptid)
| fields value_category, value_scriptid, value_tag, value_taskname, value_time, _time, playbook_id 
| filter ((value_time != null and value_time != """""")) 
| filter ((value_scriptid != null and value_scriptid != """""")) 
| alter soc_event_mintutes = to_integer(value_time)
| comp sum(soc_event_mintutes) as total_soc_minutes
| alter total_soc_hours = round(divide(total_soc_minutes,60))
| view graph type = single subtype = standard header = "Hours Saved by XSIAM" yaxis = total_soc_hours dataunit = "Hours" headcolor = "#f1f7f0" font = "Arial" headerfontsize = 6
```

---

### Cortex XSIAM Troy SOC Value Metrics - Custom XQL Widget

```sql
dataset = xsiam_playbookmetrics_raw 
| alter Tasks = Tasks->[]
| arrayexpand Tasks
// TODO apply a datamodel to these two objects instead (Tasks and Alert)
| alter 
taskState = tasks->state,
taskType = tasks->type,
taskId = tasks->id,
taskName = tasks->name,
scriptID = tasks->scriptId,
incidentID = alert->parentXDRIncident,
alertID = alert->id,
alertName = alert->name,
alertType = alert->type,
playbookId = alert->playbookId
| filter taskType not in ("start", "title", "condition")
| filter playbookId != ""
// Since the job which posts this data runs every 15 min there may be duplicate data the more frequent it is run
| alter dedupkey = concat(incidentID,taskId, alertID )
| dedup dedupkey
// Filter for just automation
//| filter alerttype != "Unclassified"
| filter taskState = "Completed"
| filter tasktype = "regular"
//TODO make this a lookup table and join instead to make it scalable
| join type = inner (dataset = value_tags 
| fields Category as value_category, ScriptID as value_scriptid, `Tag` as value_tag, TaskName as value_taskname, Time as value_time, PlaybookID as playbook_id
) as vt (scriptID contains vt.value_scriptid)
| fields value_category, value_scriptid, value_tag, value_taskname, value_time, _time, playbook_id 
| filter ((value_time != null and value_time != """""")) 
| filter ((value_scriptid != null and value_scriptid != """""")) 
| alter soc_event_minutes = to_integer(value_time )
| comp sum(soc_event_minutes) as total_soc_minutes, first(_time) as TimeFrameBegin
| alter TimeFrameEnds = time_frame_end()
| alter TimeFrameWeeks = divide(timestamp_diff(TimeFrameEnds  , TimeFrameBegin  ,"DAY"),7)
| alter TimeFrameWeeks = if(TimeFrameWeeks < 1, 1, TimeFrameWeeks )
| alter TimeFrameHours = multiply(TimeFrameWeeks, 40)
| alter total_soc_hours = divide(total_soc_minutes,60)
| alter total_fte_saved = round(divide(total_soc_hours, TimeFrameHours))
| view graph type = single subtype = standard header = "Total FTEs Saved" yaxis = total_fte_saved dataunit = "FTEs"
```

---

### Cortex XSIAM Troy SOC Value Metrics - Custom XQL Widget

```sql
dataset = alerts 
| arrayexpand original_tags
| filter original_tags contains "DS:"
//| filter original_tags contains "Proofpoint"  
| filter resolution_status = ENUM.RESOLVED_OTHER or resolution_status = ENUM.RESOLVED_AUTO_RESOLVE or resolution_status = ENUM.RESOLVED_AUTO_RESOLVE 
| comp count_distinct(alert_id) as total_alerts by original_tags  
| sort desc total_alerts 
//| view column order = populated
| view graph type = column subtype = grouped layout = horizontal header = "Total Auto Resolved Alerts" xaxis = original_tags yaxis = total_alerts seriescolor("total_alerts","#aaec7c") xaxistitle = "Alerts" yaxistitle = "Data Sources" seriestitle("total_alerts","Alerts by Data Source")
```

---

### Cortex XSIAM Troy SOC Value Metrics - Custom XQL Widget

```sql
dataset = xsiam_playbookmetrics_raw
| alter Tasks = Tasks->[]
| arrayexpand Tasks
// TODO apply a datamodel to these two objects instead (Tasks and Alert)
| alter
taskState = tasks->state,
taskType = tasks->type,
taskId = tasks->id,
taskName = tasks->name,
scriptID = tasks->scriptId,
incidentID = alert->parentXDRIncident,
alertID = alert->id,
alertName = alert->name,
alertType = alert->type,
playbookId = alert->playbookId
| filter taskType not in ("start", "title", "condition")
| filter playbookId != ""
// Since the job which posts this data runs every 15 min there may be duplicate data the more frequent it is run
| alter dedupkey = concat(incidentID,taskId, alertID )
| dedup dedupkey
// Filter for just automation
//| filter alerttype != "Unclassified"
| filter taskState = "Completed"
| filter tasktype = "regular"
| alter ScriptID  =  if ( scriptID  ~= "^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89abAB][0-9a-f]{3}-[0-9a-f]{12}$", "Custom", ScriptID )
//TODO make this a lookup table and join instead to make it scalable
| join type = inner (dataset = value_tags 
| fields Category as value_category, ScriptID as value_scriptid, `Tag` as value_tag, TaskName as value_taskname, Time as value_time, PlaybookID as playbook_id
) as vt (scriptID contains vt.value_scriptid)
| fields value_category, value_scriptid, value_tag, value_taskname, value_time, _time, playbook_id 
| filter ((value_time != null and value_time != """""")) 
| filter ((value_scriptid != null and value_scriptid != """""")) 
| fields value_time , value_category
| alter soc_event_mintutes = to_integer(value_time )
| comp sum(soc_event_mintutes) as total_soc_minutes by value_category
| alter total_soc_hours = round(divide(total_soc_minutes,60))
| sort desc total_soc_minutes
| view graph type = column subtype = grouped layout = horizontal show_callouts = `true` xaxis = value_category yaxis = total_soc_minutes,total_soc_hours seriescolor("total_soc_minutes","#c1ce17") seriescolor("total_soc_hours","#ca79e4") xaxistitle = "Time" yaxistitle = "Category" seriestitle("total_soc_minutes","Total SOC Minutes") seriestitle("total_soc_hours","Total SOC Hours")
```

---

### Cortex XSIAM Troy SOC Value Metrics - Custom XQL Widget

```sql
dataset = incidents 
| fields incident_id, creation_time, description , severity  
//| filter timestamp_diff(current_time(),creation_time, "DAY") <= 1 
| filter severity  in (ENUM.CRITICAL,ENUM.HIGH,ENUM.MEDIUM )
| join (
    dataset = alerts
    | fields _time , incident_id as inc_id
    ) as alert_table
    alert_table.inc_id = incident_id 
| comp max(_time ) as event_time by incident_id, creation_time
| alter MTTD = divide(timestamp_diff(creation_time,event_time,"MILLISECOND"),60000) //1000 * 60 = 1000 milliseconds and 60 seconds per minute
| alter MTTD = if(MTTD<0, 0, MTTD)
| comp avg(MTTD) as MTTD
| view graph type = gauge subtype = radial header = "MTTD" yaxis = MTTD maxscalerange = 20 scale_threshold("#8ad036","#e5832c","7","#df3016","10") dataunit = "minutes" headcolor = "rgba(245,243,243,0.99)" headerfontsize = 30 legendfontsize = 30
```

---

### Cortex XSIAM Troy SOC Value Metrics - Custom XQL Widget

```sql
config timeframe = 1D
| dataset = cases 
| fields xdm.case.id , _time, xdm.case.description    //, creation_time, description 
| filter timestamp_diff(current_time(),_time, "DAY") <= 7 
| join type=left (config timeframe = 7D
    |dataset = alerts
    | fields alert_arrival_timestamp, incident_id as inc_id, alert_id, resolution_status 
    ) as alert_table
    alert_table.inc_id = xdm.case.id
| comp min(alert_id) as first_alert_id, earliest(_time) as incident_creation_time by xdm.case.id, resolution_status 
| filter first_alert_id != null
| join type = left (config timeframe = 7D
    | dataset = management_auditing  
    | fields management_auditing_type, subtype, description, email
    | filter management_auditing_type = ENUM.MANAGEMENT_AUDIT_ISSUE_MANAGEMENT and subtype in ("Update Issue") and description contains "to In Progress"
    | alter alert_id = to_integer(arrayindex(regextract(description,"Changed issue with id ([0-9]+) status to In Progress"),0))
    | fields _time as under_investigation_timestamp_alert, alert_id, email as email_alert) as management_auditing_table
    management_auditing_table.alert_id = first_alert_id 
| join type = left (config timeframe = 7D
    |dataset = management_auditing 
    | fields management_auditing_type, subtype, description, email
    | filter management_auditing_type = ENUM.MANAGEMENT_AUDIT_CASE_MANAGEMENT and subtype in ("Change Case Status") and description contains "to In Progress"
    | alter inc_id = to_integer(arrayindex(regextract(description,"Changed case ([0-9]+) status to In Progress"),0))
    | fields _time as under_investigation_timestamp_incident, inc_id, email as email_incident) as management_auditing_table
    management_auditing_table.inc_id = xdm.case.id 
| fields xdm.case.id , incident_creation_time, first_alert_id, under_investigation_timestamp_alert, under_investigation_timestamp_incident, email_alert, email_incident, resolution_status 
| alter under_investigation_timestamp = if(under_investigation_timestamp_alert!=null, under_investigation_timestamp_alert, under_investigation_timestamp_incident),
    email = if(email_alert!=null, email_alert, email_incident)
| filter under_investigation_timestamp_incident != null
| alter MTTA = divide(timestamp_diff(under_investigation_timestamp_incident,incident_creation_time,"MILLISECOND"),6000000)//1000 * 60 = 1000 milliseconds and 60 seconds per minute (60000)
| alter MTTA = if(MTTA<0,0,MTTA)
| comp avg(MTTA) as MTTA
| alter MTTA = round(MTTA)
| view graph type = gauge subtype = radial header = "MTTA" yaxis = MTTA maxscalerange = 100 scale_threshold("#15e612") dataunit = "minutes" default_limit = `false` headerfontsize = 30 legendfontsize = 30
```

---

### Cortex XSIAM Troy SOC Value Metrics - Custom XQL Widget

```sql
config timeframe = 7D
| dataset = incidents 
| fields incident_id, creation_time, description, resolved_ts, status 
| filter timestamp_diff(current_time(),creation_time, "DAY") <= 7 and status not in (ENUM.NEW, 
ENUM.UNDER_INVESTIGATION, "STATUS_HOLD")
| alter MTTR = divide(timestamp_diff(resolved_ts,creation_time,"MILLISECOND"),600000)//1000 * 60 = 1000 milliseconds and 60 seconds per minute
| comp avg(MTTR) as MTTR  
| alter MTTR = round(MTTR)
| view graph type = gauge subtype = radial header = "MTTR" yaxis = MTTR maxscalerange = 192 scale_threshold("#12e6e6") dataunit = "minutes" default_limit = `false` headerfontsize = 30 legendfontsize = 30
```

---

### Cortex XSIAM Troy SOC Value Metrics - Custom XQL Widget

```sql
dataset = alerts 
| arrayexpand original_tags
| filter original_tags contains "DS:"
// Total Alerts
| comp count_distinct(alert_id) as total_alerts by original_tags 
| sort desc total_alerts
| view graph type = column subtype = grouped layout = horizontal header = "Total Alerts" xaxis = original_tags yaxis = total_alerts seriescolor("total_alerts","#a6ec7c") xaxistitle = "Alerts" yaxistitle = "Data Sources" seriestitle("total_alerts","Alerts by Data Source")
```

---

### Cortex XSIAM Troy SOC Value Metrics - Custom XQL Widget

```sql
dataset = alerts 
// Total Alerts
| comp count_distinct(alert_id) as total_alerts by alert_source 
| sort desc total_alerts
| view graph type = pie show_callouts = `true` show_callouts_names = `true` xaxis = alert_source yaxis = total_alerts
```

---

### Cortex XSIAM Troy SOC Value Metrics - Custom XQL Widget

```sql
dataset = alerts 
| arrayexpand original_tags
| filter original_tags contains "DS:"
// Total Incidents
| comp count_distinct(incident_id) as total_incidents by original_tags  
| sort desc total_incidents 
| view graph type = pie header = "Total Incidents" xaxis = original_tags yaxis = total_incidents
```

---

### Cortex XSIAM Troy SOC Value Metrics - Custom XQL Widget

```sql
dataset = alerts 
| arrayexpand original_tags
| filter original_tags contains "DS:"
// Open manual alerts
| filter resolution_status = ENUM.NEW or resolution_status = ENUM.UNDER_INVESTIGATION 
| comp count_distinct(incident_id) as total_incidents by original_tags    
| sort desc total_incidents 
| view graph type = pie header = "Total Manual Incidents" xaxis = original_tags yaxis = total_incidents
```

---

### Cortex XSIAM Troy Threats - Custom XQL Widget

```sql
dataset = panw_ngfw_threat_raw 
| filter severity != "Informational"
| bin _time span = 1h
| sort asc _time 
| comp count(_id ) as counter by _time
| view graph type = area subtype = stacked show_percentage = `false` xaxis = _time yaxis = counter seriescolor("counter","#32c262") seriestitle("counter","Threats")
```

---

### Cortex XSIAM Troy Threats - Custom XQL Widget

```sql
dataset = panw_ngfw_threat_raw 
| filter severity != "Informational"
| comp count(_id ) as no_of_traffic by from_zone  
| sort desc no_of_traffic
| limit 10
| view graph type = column subtype = grouped layout = horizontal show_callouts = `true` xaxis = from_zone yaxis = no_of_traffic seriescolor("no_of_traffic","#32c262") legend = `false`
```

---

### Cortex XSIAM Troy Threats - Custom XQL Widget

```sql
dataset = panw_ngfw_threat_raw 
| filter severity != "Informational"
| comp count(_id ) as counter by severity  
| sort desc counter 
| limit 10
| view graph type = pie subtype = semi_donut xaxis = severity yaxis = counter
```

---

### Cortex XSIAM Troy Threats - Custom XQL Widget

```sql
dataset = panw_ngfw_threat_raw 
| filter severity != "Informational"
| filter threat_category != "unknown"
| comp count(_id ) as traffic_count by threat_category 
| sort desc traffic_count 
| limit 10
| view graph type = column subtype = grouped layout = horizontal show_callouts = `true` xaxis = threat_category yaxis = traffic_count seriescolor("traffic_count","#32c262") calloutfontsize = 13 legend = `false`
```

---

### Cortex XSIAM Troy Threats - Custom XQL Widget

```sql
dataset = panw_ngfw_threat_raw 
| filter severity not in ("informational", "low") 
| filter from_zone != "TAP"
| comp count(_id) as hits by from_zone, to_zone,threat_name, threat_category,severity
| fields from_zone, to_zone, threat_name, threat_category,severity, hits
| sort desc hits 
| limit 50
```

---

### Cortex XSIAM Troy Network Zones - Custom XQL Widget

```sql
dataset = panw*
| comp count(_id) as counter by from_zone, to_zone 
| alter zones = concat(from_zone, "-->", to_zone )
| filter zones != "TAP-->TAP"
| sort desc counter
| limit 10
| view graph type = area subtype = standard show_callouts = `true` show_percentage = `false` xaxis = zones yaxis = counter seriescolor("counter","#9b5e19") legend = `false`
```

---

### Cortex XSIAM Troy Network Zones - Custom XQL Widget

```sql
dataset = panw*
| comp count(_id) as counter by to_zone  
| filter to_zone != "TAP"
| sort desc counter 
| limit 10
| view graph type = column subtype = grouped layout = horizontal show_callouts = `true` xaxis = to_zone yaxis = counter seriescolor("counter","#9b5e19") xvaluesfontsize = 15 calloutfontsize = 15 legend = `false`
```

---

### Cortex XSIAM Troy Network Zones - Custom XQL Widget

```sql
dataset = panw*
| comp count(_id) as traffic_count by from_zone 
| filter from_zone != "TAP"
| sort desc traffic_count 
| limit 10
| view graph type = column subtype = grouped layout = horizontal show_callouts = `true` xaxis = from_zone yaxis = traffic_count seriescolor("counter","#9b5e19") seriescolor("traffic_count","#9b5e19") xvaluesfontsize = 15 calloutfontsize = 15 legend = `false` seriestitle("counter","traffic_count")
```

---

### Cortex XSIAM Troy HTTP Activity - Custom XQL Widget

```sql
dataset = xdr_data 
| filter event_type = ENUM.STORY
| fields http_data, event_id 
| filter http_data != null
| alter http_method  = arrayindex(regextract(to_json_string(http_data), "http_req_before_method.*?(\w+)"),0)
| alter http_method = if(http_method = "null","", http_method )
| filter http_method != null
| union (dataset = panw*| fields _id as event_id, http_method  | alter http_method = if(http_method = "unknown","", http_method )| alter http_method = uppercase(http_method ) | filter http_method != "" and http_method != null)
| comp count(event_id) as counter by http_method | filter http_method != ""
| sort desc counter | limit 10
| view graph type = area subtype = standard show_callouts = `true` show_percentage = `false` xaxis = http_method yaxis = counter seriescolor("counter","#5dae44") xvaluesfontsize = 15 calloutfontsize = 15 seriestitle("counter","traffic_count")
```

---

### Cortex XSIAM Troy HTTP Activity - Custom XQL Widget

```sql
dataset = xdr_data 
| filter event_type = ENUM.STORY
| fields http_data, event_id 
| alter responsecode  = arrayindex(regextract(to_json_string(http_data), "http_rsp_code\"\:(\d+)"),0)
| filter responsecode  != null
| comp count(event_id) as traffic_count by responsecode
| sort desc traffic_count 
| limit 10
| view graph type = column subtype = grouped layout = horizontal show_callouts = `true` xaxis = responsecode yaxis = traffic_count seriescolor("traffic_count","#5dae44") xvaluesfontsize = 15 calloutfontsize = 15
```

---

### Cortex XSIAM Troy HTTP Activity - Custom XQL Widget

```sql
dataset = xdr_data 
| filter event_type = ENUM.STORY
| fields http_data, event_id 
| alter a = to_json_string(http_data)
| alter content_type_header = arrayindex(regextract(to_json_string(http_data), "http_req_content_type_header\"\:\"(.*?)\""),0)
| alter content_type_header = if(content_type_header contains ";", arrayindex(regextract(to_json_string(content_type_header), "(.*?);"),0), content_type_header)
| alter content_type_header = replace(content_type_header, "\"", "")
| filter content_type_header  != null
| comp count(event_id) as traffic_count by content_type_header
| sort desc traffic_count 
| limit 10
| view graph type = column subtype = grouped layout = horizontal show_callouts = `true` xaxis = content_type_header yaxis = traffic_count seriescolor("traffic_count","#5dae44") xvaluesfontsize = 15 calloutfontsize = 15
```

---

### Cortex XSIAM Troy HTTP Activity - Custom XQL Widget

```sql
dataset = xdr_data 
| filter event_type = ENUM.STORY
| fields http_data, event_id 
| alter a = to_json_string(http_data)
| alter user_agent  = arrayindex(regextract(to_json_string(http_data), "http_req_user_agent_header\"\:\"(.*?)\""),0)
| filter user_agent  != null
| comp count(event_id) as traffic_count by user_agent
| sort desc traffic_count 
| limit 10
| view graph type = column subtype = grouped layout = horizontal show_callouts = `true` xaxis = user_agent yaxis = traffic_count seriescolor("traffic_count","#5dae44") xvaluesfontsize = 15 calloutfontsize = 15
```

---

### Cortex XSIAM Troy DNS Activity - Custom XQL Widget

```sql
preset = network_story 
| alter app = lowercase(arraystring(action_app_id_transitions,","))
| filter app contains "dns"
| comp count(event_id ) as counter by dns_reply_code
| sort desc counter 
| view graph type = column subtype = grouped layout = horizontal show_callouts = `true` xaxis = dns_reply_code yaxis = counter seriescolor("counter","#ec9d7c") xvaluesfontsize = 15 calloutfontsize = 15 legend = `false`
```

---

### Cortex XSIAM Troy DNS Activity - Custom XQL Widget

```sql
preset = network_story 
| bin _time span =1h
| sort asc  _time 
| alter app = lowercase(arraystring(action_app_id_transitions,","))
| filter app contains "dns"
| comp count(event_id ) as counter by _time
| view graph type = line xaxis = _time yaxis = counter default_limit = `false` seriescolor("counter","#ec9d7c") seriestitle("counter","DNS Queries")
```

---

### Cortex XSIAM Troy Geo Locations - Custom XQL Widget

```sql
preset = network_story 
| iploc action_remote_ip loc_country
| filter loc_country != null
| union (preset = network_story| iploc action_local_ip loc_country | filter loc_country != null) 
| comp count(event_id) as counter by loc_country 
| sort desc counter 
| limit 10
| view graph type = pie subtype = semi_donut xaxis = loc_country yaxis = counter
```

---

### Cortex XSIAM Troy Geo Locations - Custom XQL Widget

```sql
preset = network_story 
| iploc action_remote_ip loc_country
| filter loc_country != null
| union (preset = network_story| iploc action_local_ip loc_country | filter loc_country != null) 
| comp count(event_id) as counter by loc_country
| view graph type = map xaxis = loc_country yaxis = counter default_limit = `false` seriestitle("counter","Volume")
```

---

### Cortex XSIAM Troy URL Activity - Custom XQL Widget

```sql
dataset = panw*
| filter risk_of_app != "Informational"
| comp count(_id) as traffic_count by risk_of_app 
| sort  desc traffic_count 
| limit 10
| view graph type = pie subtype = semi_donut xaxis = risk_of_app yaxis = traffic_count
```

---

### Cortex XSIAM Troy URL Activity - Custom XQL Widget

```sql
dataset = panw_ngfw_*
| filter risk_of_app != "Informational"
| comp count(_id) as counter by url_category
| filter url_category != "catch-all"
| filter url_category != "any"
| filter url_category != "private-ip-addresses"
| filter url_category != "panw*"
| sort  desc counter 
| limit 20
| view graph type = wordcloud xaxis = url_category yaxis = counter word_color = "#5ae9d2"
```

---

### Cortex XSIAM Troy URL Activity - Custom XQL Widget

```sql
dataset = panw_ngfw_url_raw
| filter to_zone = "internet" and from_zone = "general_wifi" and url_category = "artificial-intelligence"
| filter url_category_list contains "AI-conversational"
| filter app contains "chatgpt" or app contains "openai" or app contains "perplexity" or app contains "deepseek" or app contains "gemini" or app contains "claude"
| comp count(app) as counter by app
| sort desc counter
| view graph type = wordcloud header = "- Popular LLMs" xaxis = app yaxis = counter word_color = "#5ae9d2" headerfontsize = 20
```

---

### Cortex XSIAM Troy Threat Hunting - Custom XQL Widget

```sql
config case_sensitive = false 
| dataset = corelight_zeek_raw 
| filter (`_path` = """conn""") 
| fields uid  , id_orig_p , id_orig_chaddr , id_resp_l2_addr , id_orig_l2_addr , id, id_orig_h , id_resp_h , enrichment_orig_network_name, enrichment_orig_network_ssid, enrichment_orig_room_name, enrichment_resp_network_name, enrichment_resp_network_ssid, enrichment_resp_room_name, conn_state, spcap_url, id_orig_chaddr
| join type = right (dataset = corelight_zeek_raw 
| filter (`_path` = """yara_corelight""") | fields match_meta,match_rule,md5,mime_type,sha1,sha256,uid) as a a.uid=uid
| join type = right (dataset = corelight_zeek_raw
| fields _path, uid, id_orig_h as source_ip, id_resp_h as dest_ip, id_orig_p as source_port, id_resp_p as dest_port, id_resp_l2_addr as dest_mac, id_orig_l2_addr as source_mac, payload, payload_printable, alert_signature, alert_signature_id, alert_action, alert_category, alert_action, alert_metadata, alert_severity, alert_rule, service
| filter _path = "suricata_corelight") as t t.uid = uid 
| filter (`conn_state` not in (null, """""")) 
| filter source_ip  ~= arrayindex(split($source_ip, "@"),0)
```

---

### Cortex XSIAM Troy Threat Hunting - Custom XQL Widget

```sql
dataset = corelight_zeek_raw
| fields _path, uid, id_orig_h as source_ip, id_resp_h as dest_ip, id_orig_p as source_port, id_resp_p as dest_port, id_resp_l2_addr as dest_mac, id_orig_l2_addr as source_mac, payload, payload_printable, alert_signature, alert_signature_id, alert_action, alert_category, alert_action, alert_metadata, alert_severity, alert_rule, service
| filter _path = "suricata_corelight" and alert_signature contains "ETPRO HUNTING"
| comp count () by alert_signature 
| view graph type = pie xaxis = alert_signature yaxis = count_1 seriestitle("count_1","Total")
```

---

### Cortex XSIAM Troy Threat Hunting - Custom XQL Widget

```sql
config case_sensitive = false 
| dataset = corelight_zeek_raw 
| filter (`_path` = """conn""") 
| fields uid  , id_orig_p , id_orig_chaddr , id_resp_l2_addr , id_orig_l2_addr , id, id_orig_h , id_resp_h , enrichment_orig_network_name, enrichment_orig_network_ssid, enrichment_orig_room_name, enrichment_resp_network_name, enrichment_resp_network_ssid, enrichment_resp_room_name, conn_state, spcap_url, id_orig_chaddr
| join type = right (dataset = corelight_zeek_raw 
| filter (`_path` = """yara_corelight""") | fields match_meta,match_rule,md5,mime_type,sha1,sha256,uid) as a a.uid=uid
| join type = right (dataset = corelight_zeek_raw
| fields _path, uid, id_orig_h as source_ip, id_resp_h as dest_ip, id_orig_p as source_port, id_resp_p as dest_port, id_resp_l2_addr as dest_mac, id_orig_l2_addr as source_mac, payload, payload_printable, alert_signature, alert_signature_id, alert_action, alert_category, alert_action, alert_metadata, alert_severity, alert_rule, service
| filter _path = "suricata_corelight") as t t.uid = uid 
| filter (`conn_state` not in (null, """""")) 
| comp count() by match_rule
| view graph type = column subtype = grouped layout = horizontal header = "Match Rule" xaxis = match_rule yaxis = count_1 seriescolor("count_1","#e9ec7c") seriestitle("count_1","Total")
```

---

### Cortex XSIAM Troy Threat Hunting - Custom XQL Widget

```sql
dataset = corelight_zeek_raw
| fields _path, uid, id_orig_h as source_ip, id_resp_h as dest_ip, id_orig_p as source_port, id_resp_p as dest_port, id_resp_l2_addr as dest_mac, id_orig_l2_addr as source_mac, payload, payload_printable, alert_signature, alert_signature_id, alert_action, alert_category, alert_action, alert_metadata, alert_severity, alert_rule, service
| filter _path = "suricata_corelight" 
| comp count () by alert_category  
| view graph type = pie header = "Suricata Alert Category" xaxis = alert_category yaxis = count_1 seriestitle("count_1","Total")
```

---

### 1000 eyes - Custom XQL Widget

```sql
dataset = cisco_1000_raw 
| filter alert_id != null
// | alter details = arraystring(details -> [], ",")
| comp min(_time) as _time ,count() as c , values(eventId)as event_ids , values(cleared_time) as cleared_time, values(devices_names) as devices_names, values(details) as details by alert_id, testId, signature, test_type , alert_type, triggered_time, itsiDrilldownURI, vendor_severity, test_name  addrawdata = true 
| filter c < 2 and cleared_time = null
| alter details = arraymerge(details )
| alter devices_names = arraymerge(devices_names)
| fields vendor_severity ,alert*, test*, signature  , devices_names, details , cleared_time
```

---

### Cortex XSIAM Troy Network Security Incidents - XQL Query

```sql
dataset = panw_ngfw_threat_raw 
| filter app contains "dns" and threat_category contains "dns-malware" or threat_category contains "dns-phishing"
| filter threat_id != 93031
| fields threat_category, threat_name, url*, sub_type
| comp count(threat_name) as hits, values(threat_category) as dns_type by threat_name
| sort desc hits
| limit 10
```

---

### Cortex XSIAM Troy Network Security Incidents - Custom XQL Widget

```sql
dataset = panw_ngfw_*
| fields dest_ip, app_category, threat_*, source_ip, to_zone, from_zone, action
| filter from_zone = "internet"
//| filter threat_category contains "spyware"
| filter action contains "reset"
| iploc  source_ip loc_city, loc_region, loc_country, loc_continent, loc_latlon, loc_timezone 
//| comp count(dest_ip) as count_dest by threat_category 
| comp count(dest_ip) as hit_count by source_ip 
| iploc  source_ip loc_country
| sort desc hit_count
|
 view graph type = map xaxis = loc_country yaxis = hit_count
```

---

### Cortex XSIAM Troy Network Security Incidents - Custom XQL Widget

```sql
dataset = panw_ngfw_*
| fields dest_ip, app_category, threat_*, source_ip, to_zone, from_zone, action
| filter from_zone = "internet"
//| filter threat_category contains "spyware"
| filter action contains "reset"
| iploc  source_ip loc_city, loc_region, loc_country, loc_continent, loc_latlon, loc_timezone 
//| comp count(dest_ip) as count_dest by threat_category 
| comp count(dest_ip) as hit_count by source_ip 
| iploc  source_ip loc_country
| sort desc hit_count
```

---

### Cortex XSIAM Troy Network Security Incidents - Custom XQL Widget

```sql
dataset = incidents 
| fields description, alert_categories, severity, incident_id
| comp count(incident_id) as incidents by severity 
| alter from_time = parse_timestamp("%Y-%m-%d %H:%M:%S ", "2024-12-06 00:00:00")
| alter to_time = parse_timestamp("%Y-%m-%d %H:%M:%S ", "2024-12-09 00:00:00")
// view graph type = pie subtype = semi_donut xaxis = severity yaxis = incidents
| view graph type = pie xaxis = severity yaxis = incidents
```

---

### - Swapcard - Custom XQL Widget

```sql
preset = metrics_view 
| filter (`_product` = """swapcard""" and `_vendor` = """bh""") 
| bin _time span = 1h
| comp sum(total_event_count) by _time 
| sort asc _time
| view graph type = line xaxis = _time yaxis = sum_1 default_limit = `false` seriescolor("sum_1","#01ec45") gridcolor = "#d9f2db" legend = `false` xaxistitle = "Time" yaxistitle = "Count"
```

---

### - Swapcard - Custom XQL Widget

```sql
dataset = bh_swapcard_raw // | fields suspected*
| filter (`SUSPECTED_BOT` not in (null, """"""))
| alter Platform = arrayindex(regextract(userAgent ,"(Windows NT [^;)\s]+|Mac OS X [^;)\s]+|iPhone OS [^;)\s]+|CPU OS [^;)\s]+|Android [^;)\s]+|iPad; CPU OS [^;)\s]+|CrOS [^;\)]+|Darwin/[0-9._]+|Linux|node|CFNetwork|NetworkingExtension|com\.apple\.WebKit\.Networking|symbolicator|Microsoft-WebDAV-MiniRedir|SkypeUriPreview)"),0)
| alter Browser = arrayindex(regextract(userAgent ,"(Chrome|Safari|Firefox|Edg|Opera|CriOS|MobileSafari|LinkedInBot|AhrefsBot|DuckDuckBot|DuckDuckGo|AdsBot-Google|Googlebot|YandexBot|PetalBot|Troy%20Events|curl|Go-http-client|undici|node|okhttp|symbolicator|NetworkingExtension|CFNetwork|com\.apple\.WebKit\.Networking|python-requests|Slackbot|Slackbot-LinkExpanding|axios|AASA-Bot|meta-externalagent|SkypeUriPreview|coccocbot-web|Microsoft-WebDAV-MiniRedir)"),0)
| alter useragent_short = if(concat(Platform , " ", Browser) = null, userAgent , concat(Platform , " ", Browser))
| alter SUSPECTED_BOT_value = SUSPECTED_BOT -> value
| comp count() as counter by SUSPECTED_BOT_value , useragent_short 
| sort desc counter 
// | view column order = populated
| view graph type = column subtype = stacked layout = horizontal show_callouts_names = `true` xaxis = SUSPECTED_BOT_value yaxis = counter series = useragent_short seriescolor("Other","#01ec45")
```

---

### - Swapcard - Custom XQL Widget

```sql
dataset = bh_swapcard_raw | filter to_string(responseCode) ~= "\b[013456789]\d*\b" and responseCode != 0
| comp count() as counter by responseCode 
| sort desc counter 
| view graph type = pie subtype = full show_callouts = `true` show_callouts_names = `true` xaxis = responseCode yaxis = counter
```

---

### - Swapcard - Custom XQL Widget

```sql
dataset = bh_swapcard_raw 
| alter Platform = arrayindex(regextract(userAgent ,"(Windows NT [^;)\s]+|Mac OS X [^;)\s]+|iPhone OS [^;)\s]+|CPU OS [^;)\s]+|Android [^;)\s]+|iPad; CPU OS [^;)\s]+|CrOS [^;\)]+|Darwin/[0-9._]+|Linux|node|CFNetwork|NetworkingExtension|com\.apple\.WebKit\.Networking|symbolicator|Microsoft-WebDAV-MiniRedir|SkypeUriPreview)"),0)
| alter Browser = arrayindex(regextract(userAgent ,"(Chrome|Safari|Firefox|Edg|Opera|CriOS|MobileSafari|LinkedInBot|AhrefsBot|DuckDuckBot|DuckDuckGo|AdsBot-Google|Googlebot|YandexBot|PetalBot|Troy%20Events|curl|Go-http-client|undici|node|okhttp|symbolicator|NetworkingExtension|CFNetwork|com\.apple\.WebKit\.Networking|python-requests|Slackbot|Slackbot-LinkExpanding|axios|AASA-Bot|meta-externalagent|SkypeUriPreview|coccocbot-web|Microsoft-WebDAV-MiniRedir)"),0)
| alter useragent_short = if(concat(Platform , " ", Browser) = null, userAgent , concat(Platform , " ", Browser))
| comp count() as Counter by useragent_short 
| sort desc Counter 
| limit 20
| view graph type = column subtype = grouped layout = horizontal xaxis = useragent_short yaxis = Counter default_limit = `false` seriescolor("Counter","#01ec45")
```

---

### - Swapcard - Custom XQL Widget

```sql
dataset = bh_swapcard_raw  | comp count() as counter, avg(responseSize) as avgsize by remoteCountryCode | sort desc counter  | limit 20  //| fields - _*| view column order = populated
| view graph type = bubble subtype = standard xaxis = remoteCountryCode yaxis = counter series = avgsize bubblerad = avgsize default_limit = `false` seriescolor("counter","#01ec45")
```

---

### - Swapcard - Custom XQL Widget

```sql
dataset = bh_swapcard_raw | fields serverName , responseCode  | comp count() as c by servername, responseCode  | sort desc c | limit 100   //filter  responseCode = 0
| view graph type = bubble subtype = grouppacked show_callouts = `true` show_callouts_names = `true` xaxis = responseCode yaxis = c series = servername default_limit = `false` headcolor = "#dedede" gridcolor = "#d9e4f2"
```

---

### Cortex XSIAM Troy Corelight Alerts - Custom XQL Widget

```sql
dataset = corelight_http_raw 
|fields _path , _raw_log
|filter _path in("yara_corelight") //"notice", "yara_corelight", "intel*"
|alter match_rule = _raw_log -> match_rule, match_meta = json_extract_scalar_array(_raw_log, "$.match_meta")
|filter match_rule not in("DELIVRTO_SUSP_ZIP_Smuggling_Jun01")
|alter match_desc = arrayindex(arrayfilter(match_meta, "@element" contains "description="),0)
|alter match_desc = arrayindex(split(match_desc,"="), 1)
|comp count() as counter by match_desc
|sort desc counter 
| view graph type = column subtype = stacked layout = horizontal xaxis = match_desc yaxis = counter series = match_desc default_limit = `false` legend = `false`
```

---

### Cortex XSIAM Troy Corelight Alerts - Custom XQL Widget

```sql
dataset = corelight_http_raw 
|fields _path, alert_signature 
|filter _path in("suricata_corelight", "notice", "yara_corelight", "intel*") and alert_signature not in("INFO*","POLICY*","DNS*","ICMP*") 
|alter topic = arrayindex(regextract(alert_signature, "^\w+\s([A-Z0-9_]*)"),0), sig_name = arrayindex(regextract(alert_signature, "^[A-Z]{2,5}\s.+?\s(.+)$") , 0)
|alter sig_name = replex(sig_name, "\sgroup\s\d+$","")
|filter topic not in("SNMP","ICMP","USER_AGENTS","DROP","HUNTING","SCAN","ADWARE_PUP","FILE_SHARING") and sig_name not in("syncthing*")
//|view column order = populated 
|comp count() as counter by sig_name
|sort desc counter 
| view graph type = pie xaxis = sig_name yaxis = counter
```

---

### Cortex XSIAM Troy Corelight Alerts - Custom XQL Widget

```sql
dataset = corelight_http_raw 
|fields _path, alert_signature 
|filter _path in("suricata_corelight", "notice", "yara_corelight", "intel*") and alert_signature not in("INFO*","POLICY*","DNS*","ICMP*") 
|alter topic = arrayindex(regextract(alert_signature, "^\w+\s([A-Z0-9_]*)"),0), sig_name = arrayindex(regextract(alert_signature, "^[A-Z]{2,5}\s.+?\s(.+)$") , 0)
|alter sig_name = replex(sig_name, "\sgroup\s\d+$","")
|filter topic not in("SNMP","ICMP","USER_AGENTS","DROP","HUNTING","SCAN","ADWARE_PUP","FILE_SHARING") and sig_name not in("syncthing*","Jabber*")
//|view column order = populated 
|comp count() as counter by sig_name
|sort asc counter 
| view graph type = pie xaxis = sig_name yaxis = counter
```

---

### Cortex XSIAM Troy NGFW/Corelight - Custom XQL Widget

```sql
dataset = panw_ngfw_traffic_raw 
| filter app not contains "not-applicable" and app not contains "incomplete"
| fields app 
| comp count(app) as app_num by app
| sort desc app_num 
| view graph type = pie xaxis = app yaxis = app_num
```

---

### Cortex XSIAM Troy NGFW/Corelight - Custom XQL Widget

```sql
//Title: NGFW Threats Over Time
//Description: Intended to be used as an XDR Widget to highlight threats over time derived from Pan_Threat logs. 
//Author: Raymond DePalma
//Technical QC: Anthony Galiette 
//Date: April 22, 2022
//Dataset: panw_ngfw_threat_raw 
//Requirements: PA NGFW Threat Logs, PRO enabled
//Tags: graph,NGFW,noAPI,PANWOpen
//Disable case sensitivity, last 30 days
 dataset = panw_ngfw_threat_raw
|fields _id , _time 
| bin _time span = 1d
| comp count(_id) by _time
| alter date = format_timestamp("%b %d", _time)
| sort asc _time
| view graph type = area subtype = standard show_percentage = `false` xaxis = date yaxis = count_1 headerfontsize = 16 legend = `false`
```

---

### Cortex XSIAM Troy NGFW/Corelight - Custom XQL Widget

```sql
dataset = corelight_http_raw 
|fields _path, _raw_log 
|filter _path in("notice") 
|alter msg = _raw_log -> msg, note =_raw_log -> note, subject = _raw_log -> sub, src_ip = _raw_log -> src 
|filter note in("SSH*")
|comp count() as counter by note // addrawdata = true as rawdata 
|sort desc counter
| view graph type = column subtype = grouped layout = horizontal show_callouts_names = `true` xaxis = note yaxis = counter series = note default_limit = `false` legend = `false`
```

---

### Cortex XSIAM Troy NGFW/Corelight - Custom XQL Widget

```sql
dataset = corelight_http_raw 
|fields _path, _raw_log 
|filter _path in("notice") 
|alter msg = _raw_log -> msg, note =_raw_log -> note, subject = _raw_log -> sub, src_ip = _raw_log -> src 
|filter note not in("SSH*","CaptureLoss*","CorelightML*","SSL*")
|comp count() as counter by note // addrawdata = true as rawdata 
|sort desc counter
| view graph type = column subtype = grouped layout = horizontal show_callouts_names = `true` xaxis = note yaxis = counter series = note default_limit = `false` legend = `false`
```

---

### Cortex XSIAM Troy NUC Monitoring - Custom XQL Widget

```sql
dataset = endpoints
|filter endpoint_name contains "SOC"
| comp count(endpoint_id) as agent_count by agent_version
| sort desc agent_count
| view graph type = pie xaxis = agent_version yaxis = agent_count
```

---

### Cortex XSIAM Troy NUC Monitoring - Custom XQL Widget

```sql
dataset = endpoints
|filter endpoint_name contains "SOC"
| filter endpoint_status in (CONNECTED, CONNECTION_LOST)
| comp count(endpoint_id) as total by endpoint_status
| view graph type = pie xaxis = endpoint_status yaxis = total
```

---

### Cortex XSIAM Troy NUC Monitoring - Custom XQL Widget

```sql
dataset = alerts
| filter host_name contains "SOC"
| comp count(alert_id) as alert_count by host_name 
| sort desc alert_count
| limit 20
```

---

### Cortex XSIAM Troy JAMF Monitoring - Custom XQL Widget

```sql
dataset = jamf_pro_raw
| filter device_udid != null
| bin _time span = 10m
| comp count(device_udid) as number_devices by _time
| view graph type = line xaxis = _time yaxis = number_devices
```

---

### Cortex XSIAM Troy JAMF Monitoring - Custom XQL Widget

```sql
dataset = jamf_pro_raw 
| comp count(device_name) as device_count by device_model
| sort desc device_model
| view graph type = pie xaxis = device_model yaxis = device_count
```

---

### Cortex XSIAM Troy JAMF Monitoring - Custom XQL Widget

```sql
dataset = jamf_pro_raw 
| comp count(device_name) as model_count by model_display
| sort desc model_display
| view graph type = pie xaxis = model_display yaxis = model_count
```

---

### Cortex XSIAM Troy JAMF Monitoring - Custom XQL Widget

```sql
dataset = jamf_pro_raw
|alter webhookEvent = json_extract_scalar(webhook, "$.webhookEvent")
| comp count(webhookEvent) as webhook_event_type by webhookEvent
| view graph type = pie xaxis = webhookEvent yaxis = webhook_event_type
```

---

### broken_widgets - Custom XQL Widget

```sql
config timeframe = 7D
| dataset = incidents 
| fields incident_id, creation_time, description 
| filter timestamp_diff(current_time(),creation_time, "DAY") <= 7 
| join type=left (config timeframe = 7D
    |dataset = alerts
    | fields alert_arrival_timestamp, incident_id as inc_id, alert_id, resolution_status 
    ) as alert_table
    alert_table.inc_id = incident_id
| comp min(alert_id) as first_alert_id, earliest(creation_time) as incident_creation_time by incident_id, resolution_status 
| filter first_alert_id != null
| join type = left (config timeframe = 7D
    | dataset = management_auditing  
    | fields management_auditing_type, subtype, description, email
    | filter management_auditing_type = ENUM.MANAGEMENT_AUDIT_ISSUE_MANAGEMENT and subtype in ("Update Issue") and description contains "to In Progress"
    | alter alert_id = to_integer(arrayindex(regextract(description,"Changed issue with id ([0-9]+) status to In Progress"),0))
    | fields _time as under_investigation_timestamp_alert, alert_id, email as email_alert) as management_auditing_table
    management_auditing_table.alert_id = first_alert_id 
| join type = left (config timeframe = 7D
    |dataset = management_auditing 
    | fields management_auditing_type, subtype, description, email
    | filter management_auditing_type = ENUM.MANAGEMENT_AUDIT_CASE_MANAGEMENT and subtype in ("Change Case Status") and description contains "to In Progress"
    | alter inc_id = to_integer(arrayindex(regextract(description,"Changed case ([0-9]+) status to In Progress"),0))
    | fields _time as under_investigation_timestamp_incident, inc_id, email as email_incident) as management_auditing_table
    management_auditing_table.inc_id = incident_id
| fields incident_id, incident_creation_time, first_alert_id, under_investigation_timestamp_alert, under_investigation_timestamp_incident, email_alert, email_incident, resolution_status 
| alter under_investigation_timestamp = if(under_investigation_timestamp_alert!=null, under_investigation_timestamp_alert, under_investigation_timestamp_incident),
    email = if(email_alert!=null, email_alert, email_incident)
| filter under_investigation_timestamp_incident != null
| alter MTTA = divide(timestamp_diff(under_investigation_timestamp_incident,incident_creation_time,"MILLISECOND"),60000)//1000 * 60 = 1000 milliseconds and 60 seconds per minute
| alter MTTA = if(MTTA<0,0,MTTA)
| comp avg(MTTA) as MTTA
| alter MTTA = round(MTTA)
| view graph type = gauge subtype = radial header = "MTTA" yaxis = MTTA maxscalerange = 12 scale_threshold("#d7e612") dataunit = "minutes" default_limit = `false` headerfontsize = 30 legendfontsize = 30
```

---

### broken_widgets - Custom XQL Widget

```sql
dataset = incidents 
| filter (status = ENUM.NEW or status = ENUM.UNDER_INVESTIGATION)
| alter starred = to_boolean(starred)
| filter starred = true
| comp count_distinct(incident_id)
| alter from_time = parse_timestamp("%Y-%m-%d %H:%M:%S ", "2024-12-06 00:00:00")
| alter to_time = parse_timestamp("%Y-%m-%d %H:%M:%S ", "2024-12-09 00:00:00")
| view graph type = single subtype = standard yaxis = count_distinct_1
```

---

### broken_widgets - Custom XQL Widget

```sql
dataset = alerts 
| fields alert_name, app_id, app_subcategory, category, fw_name, source_zone_name, destination_zone_name 
| alter source_zone_name = arrayindex(source_zone_name, 0), destination_zone_name = arrayindex(destination_zone_name, 0)
| filter source_zone_name != null and source_zone_name != "internet"
| join type = left (
    dataset = troy_subnets_lookup 
    |filter Name not in("OpenDNS/Umbrella DNS Virtual Appliances", "Tool Mgmt", "", null)
    |fields Name , Location , FirewallZoneName 
) as subnets subnets.FirewallZoneName = source_zone_name or subnets.FirewallZoneName = destination_zone_name 
//| alter Name = if(Name in(null,""), "General WiFi", Name)
| comp count(alert_name) as alert_count by Name  
| sort desc alert_count
| limit 10
| view graph type = column subtype = grouped layout = horizontal xaxis = Name yaxis = alert_count default_limit = `false`
```

---

### broken_widgets - Custom XQL Widget

```sql
dataset = alerts  
| alter Room = 
if (incidr(endpoint_id , "192.168.120.0/24"),"Suite 03",
if (incidr(endpoint_id , "192.168.121.0/24"),"Suite 04",
if (incidr(endpoint_id , "192.168.122.0/24"),"Suite 07",
if (incidr(endpoint_id , "192.168.123.0/24"),"Suite 09",
if (incidr(endpoint_id , "192.168.124.0/24"),"Suite 10",
if (incidr(endpoint_id , "192.168.125.0/24"),"Suite 12",
if (incidr(endpoint_id , "192.168.126.0/24"),"Suite 13",
if (incidr(endpoint_id , "192.168.127.0/24"),"Suite 14",
if (incidr(endpoint_id , "192.168.128.0/24"),"Suite 15",
if (incidr(endpoint_id , "192.168.129.0/24"),"Suite 16",
if (incidr(endpoint_id , "192.168.130.0/24"),"Suite 17",
if (incidr(endpoint_id , "192.168.131.0/24"),"Suite 14",
if (incidr(endpoint_id , "192.168.132.0/24"),"Suite 15",
if (incidr(endpoint_id , "192.168.133.0/24"),"Suite 16",
if (incidr(endpoint_id , "192.168.240.0/24"),"General Wifi",
if (incidr(endpoint_id , "192.168.101.0/24"),"Sales Suite",
if (incidr(endpoint_id , "192.168.197.0/24"),"Arsenal",
if (incidr(endpoint_id , "192.168.131.0/24"),"PSuite02",
if (incidr(endpoint_id , "192.168.132.0/24"),"PSuite03",
"Other")))))))))))))))))))
| comp count(alert_id) as Occurences by Room 
| sort desc Occurences 
|
 view graph type = pie subtype = full show_callouts = `true` show_callouts_names = `true` xaxis = Room yaxis = Occurences valuecolor("Suite 17","#e362aa") font = "Arial"
```

---

### broken_widgets - Custom XQL Widget

```sql
dataset = alerts  
| alter localip = arraystring(local_ip, ", ")
| alter Room = 
if (incidr(localip, "10.220.32.0/24"),"Suite 03",
if (incidr(localip , "10.220.33.0/24"),"Suite 04",
if (incidr(localip , "10.220.34.0/24"),"Suite 07",
if (incidr(localip , "10.220.35.0/24"),"Suite 09",
if (incidr(localip , "10.220.36.0/24"),"Suite 10",
if (incidr(localip , "10.220.37.0/24"),"Suite 12",
if (incidr(localip , "10.220.38.0/24"),"Suite 13",
if (incidr(localip , "10.220.39.0/24"),"Suite 14",
if (incidr(localip , "10.220.40.0/24"),"Suite 15",
if (incidr(localip , "10.220.41.0/24"),"Suite 16",
if (incidr(localip , "10.220.42.0/24"),"Suite 17",
if (incidr(localip , "10.220.43.0/24"),"South Gallery 15",
if (incidr(localip , "10.220.44.0/24"),"South Gallery 19",
if (incidr(localip , "10.220.45.0/24"),"South Gallery 17",
if (incidr(localip , "10.220.46.0/24"),"South Gallery 20",
if (incidr(localip , "10.220.47.0/24"),"South Gallery 22",
if (incidr(localip , "192.168.128.0/18"),"General Wifi",
if (incidr(localip , "10.220.27.0/24"),"Arsenal",
if (incidr(localip , "10.220.251.0/24"),"SOC",
"Other")))))))))))))))))))
| filter Room != "Other"
| comp count(alert_id) as Occurences by Room 
| sort desc Occurences 
| view graph type = pie subtype = full show_callouts = `true` show_callouts_names = `true` xaxis = Room yaxis = Occurences valuecolor("Suite 17","#e362aa") font = "Arial"
```

---

### broken_widgets - Custom XQL Widget

```sql
dataset = alerts  
| filter category != "IP"
| filter category != "Domain Name"
| alter Room = 
if (incidr(endpoint_id , "192.168.120.0/24"),"Suite 03",
if (incidr(endpoint_id , "192.168.121.0/24"),"Suite 04",
if (incidr(endpoint_id , "192.168.122.0/24"),"Suite 07",
if (incidr(endpoint_id , "192.168.123.0/24"),"Suite 09",
if (incidr(endpoint_id , "192.168.124.0/24"),"Suite 10",
if (incidr(endpoint_id , "192.168.125.0/24"),"Suite 12",
if (incidr(endpoint_id , "192.168.126.0/24"),"Suite 13",
if (incidr(endpoint_id , "192.168.127.0/24"),"Suite 14",
if (incidr(endpoint_id , "192.168.128.0/24"),"Suite 15",
if (incidr(endpoint_id , "192.168.129.0/24"),"Suite 16",
if (incidr(endpoint_id , "192.168.130.0/24"),"Suite 17",
if (incidr(endpoint_id , "192.168.131.0/24"),"Suite 14",
if (incidr(endpoint_id , "192.168.132.0/24"),"Suite 15",
if (incidr(endpoint_id , "192.168.133.0/24"),"Suite 16",
if (incidr(endpoint_id , "192.168.240.0/24"),"General Wifi",
if (incidr(endpoint_id , "192.168.101.0/24"),"Sales Suite",
if (incidr(endpoint_id , "192.168.197.0/24"),"Arsenal",
if (incidr(endpoint_id , "192.168.131.0/24"),"PSuite02",
if (incidr(endpoint_id , "192.168.132.0/24"),"PSuite03",
"Other")))))))))))))))))))
| comp count(alert_id) as Occurences by Room 
| sort desc Occurences 
|
 view graph type = pie subtype = full show_callouts = `true` show_callouts_names = `true` xaxis = Room yaxis = Occurences valuecolor("Suite 17","#e362aa") font = "Arial"
```

---

### broken_widgets - Custom XQL Widget

```sql
dataset = incidents
| alter starred = to_boolean(starred )
| filter starred = true
| fields _time as modified_time, creation_time, resolved_ts, assigned_user, incident_id, status, assigned_user, description, resolve_comment, severity, starring_ts, first_assignment_ts 
| filter status = ENUM.RESOLVED_TRUE_POSITIVE or status = ENUM.RESOLVED_SECURITY_TESTING or status = ENUM.RESOLVED_OTHER  or status = ENUM.RESOLVED_FALSE_POSITIVE or status = ENUM.RESOLVED_KNOWN_ISSUE or status = ENUM.RESOLVED_HANDLED_THREAT or status contains "BH_POSITIVE"
// THE JOINING OF THE ALERT TABLE
| join conflict_strategy = left  type = left 
(dataset = alerts 
//| filter starred = TRUE
| fields _time as alert_time, event_timestamp, incident_id, alert_id, alert_source, alert_name, alert_type, 
        description, user_name, resolution_status, resolution_comment, 
        host_name, host_os, action, severity, rule_id, module
        | alter user_name = arrayindex(arraydistinct(user_name), 0) 
        | comp values(user_name) as affected_users, values(alert_id) as alert_id, values(alert_name) as alert_name, values(alert_time) as alert_time, values(severity) as alert_severity, values(alert_source) as               alert_type, values(host_os) as host_os by incident_id
        ) as alert_table alert_table.incident_id = incident_id
//FORMAT TIME
| alter first_alert_time = arrayindex(alert_time, 0)
| alter first_alert_timestamp = format_timestamp("%Y-%m-%d %H:%M:%S", arrayindex(alert_time, 0))
| alter modified_timestamp = format_timestamp("%Y-%m-%d %H:%M:%S", modified_time)
| alter resolved_timestamp = format_timestamp("%Y-%m-%d %H:%M:%S", resolved_ts)
| alter creation_timestamp = format_timestamp("%Y-%m-%d %H:%M:%S", creation_time)
| alter starring_timestamp = format_timestamp("%Y-%m-%d %H:%M:%S", starring_ts)
| alter assignment_timestamp = format_timestamp("%Y-%m-%d %H:%M:%S", first_assignment_ts)
//TIME DIFFERENCE
| alter time_to_resolve = timestamp_diff(resolved_ts, creation_time, "MINUTE") 
| alter time_to_detect = timestamp_diff(creation_time, first_alert_time, "MINUTE") 
| alter time_to_detect = 
    if(to_integer(time_to_detect) < 0, 0, time_to_detect)
| alter close_code = status
| alter close_code = replace(close_code, "STATUS_070_RESOLVED_OTHER", "Benign")
| alter close_code = replace(close_code, "STATUS_040_RESOLVED_KNOWN_ISSUE", "No Operation (NOP)")
| alter close_code = replace(close_code, "STATUS_060_RESOLVED_FALSE_POSITIVE", "False Positive")
| alter close_code = replace(close_code, "STATUS_090_TRUE_POSITIVE", "True Positive")
| alter close_code = replace(close_code, "STATUS_100_SECURITY_TESTING", "Bad Practice")
| alter close_code = replace(close_code, "STATUS_RESOLVED_BH_POSITIVE", "Troy Postive")
| fields incident_id, status, assigned_user, description, resolve_comment, close_code, time_to_detect, time_to_resolve, creation_timestamp, resolved_timestamp, starring_timestamp,  assignment_timestamp, modified_timestamp, first_alert_timestamp, affected_users, alert_id, alert_name, alert_severity, alert_type, host_os, severity 
| comp count(incident_id) as starred_incident_count by close_code 
| sort desc starred_incident_count
| view graph type = line show_callouts = `true` show_callouts_names = `true` xaxis = close_code yaxis = starred_incident_count seriescolor("starred_incident_count","#479ca2") xvaluesfontsize = 0
```

---

### broken_widgets - Custom XQL Widget

```sql
config case_sensitive = false 
| dataset = corelight_zeek_raw 
| filter (`_path` = """conn""") 
| fields uid  , id_orig_p , id_orig_chaddr , id_resp_l2_addr , id_orig_l2_addr , id, id_orig_h , id_resp_h , enrichment_orig_network_name, enrichment_orig_network_ssid, enrichment_orig_room_name, enrichment_resp_network_name, enrichment_resp_network_ssid, enrichment_resp_room_name, conn_state, spcap_url, id_orig_chaddr
| join type = right (dataset = corelight_zeek_raw 
| filter (`_path` = """yara_corelight""") | fields match_meta,match_rule,md5,mime_type,sha1,sha256,uid) as a a.uid=uid
| join type = right (dataset = corelight_zeek_raw
| fields _path, uid, id_orig_h as source_ip, id_resp_h as dest_ip, id_orig_p as source_port, id_resp_p as dest_port, id_resp_l2_addr as dest_mac, id_orig_l2_addr as source_mac, payload, payload_printable, alert_signature, alert_signature_id, alert_action, alert_category, alert_action, alert_metadata, alert_severity, alert_rule, service
| filter _path = "suricata_corelight") as t t.uid = uid 
| filter (`conn_state` not in (null, """""")) 
| filter source_ip  ~= arrayindex(split($source_ip, "@"),0)
```

---

### broken_widgets - Custom XQL Widget

```sql
dataset = corelight_zeek_raw
| fields _path, uid, id_orig_h as source_ip, id_resp_h as dest_ip, id_orig_p as source_port, id_resp_p as dest_port, id_resp_l2_addr as dest_mac, id_orig_l2_addr as source_mac, payload, payload_printable, alert_signature, alert_signature_id, alert_action, alert_category, alert_action, alert_metadata, alert_severity, alert_rule, service
| filter _path = "suricata_corelight" and alert_signature contains "ETPRO HUNTING"
| comp count () by alert_signature 
| view graph type = pie xaxis = alert_signature yaxis = count_1 seriestitle("count_1","Total")
```

---

### broken_widgets - Custom XQL Widget

```sql
config case_sensitive = false 
| dataset = corelight_zeek_raw 
| filter (`_path` = """conn""") 
| fields uid  , id_orig_p , id_orig_chaddr , id_resp_l2_addr , id_orig_l2_addr , id, id_orig_h , id_resp_h , enrichment_orig_network_name, enrichment_orig_network_ssid, enrichment_orig_room_name, enrichment_resp_network_name, enrichment_resp_network_ssid, enrichment_resp_room_name, conn_state, spcap_url, id_orig_chaddr
| join type = right (dataset = corelight_zeek_raw 
| filter (`_path` = """yara_corelight""") | fields match_meta,match_rule,md5,mime_type,sha1,sha256,uid) as a a.uid=uid
| join type = right (dataset = corelight_zeek_raw
| fields _path, uid, id_orig_h as source_ip, id_resp_h as dest_ip, id_orig_p as source_port, id_resp_p as dest_port, id_resp_l2_addr as dest_mac, id_orig_l2_addr as source_mac, payload, payload_printable, alert_signature, alert_signature_id, alert_action, alert_category, alert_action, alert_metadata, alert_severity, alert_rule, service
| filter _path = "suricata_corelight") as t t.uid = uid 
| filter (`conn_state` not in (null, """""")) 
| comp count() by match_rule
| view graph type = column subtype = grouped layout = horizontal header = "Match Rule" xaxis = match_rule yaxis = count_1 seriescolor("count_1","#e9ec7c") seriestitle("count_1","Total")
```

---

### Troy Playbook Automation - Custom XQL Widget

```sql
dataset = xsiam_playbookmetrics_raw
| alter playbookId = alert->playbookId
| alter alertId = alert->id
| dedup alertId
| comp count(playbookId)
| view graph type = single subtype = standard header = "Playbook Runs" yaxis = count_1
```

---

### Troy Playbook Automation - Custom XQL Widget

```sql
dataset = xsiam_playbookmetrics_raw
| alter
incidentID = alert->parentXDRIncident,
alertID = alert->id,
alertName = alert->name,
alertType = alert->type,
playbookId = alert->playbookId
| dedup alertID 
| filter playbookId != ""
| join (dataset = playbook_mapping) as playbook_mapping playbook_mapping.PlaybookID = playbookId 
| bin _time span = 10m
| alter dedupKey = concat(PlaybookName,"|",_time)
| comp count(_time) as PlaybookTotalRuns by _time
// | windowcomp count(PlaybookName) by dedupKey as PlaybookRuns
// | comp count(PlaybookName ) as PlaybookCount by PlaybookName
// | view graph type = pie xaxis = PlaybookName yaxis = PlaybookCount
| view graph type = line header = "Total Playbook Runs" xaxis = _time yaxis = PlaybookTotalRuns
```

---

### Troy Playbook Automation - Custom XQL Widget

```sql
dataset = xsiam_playbookmetrics_raw
| alter
incidentID = alert->parentXDRIncident,
alertID = alert->id,
alertName = alert->name,
alertType = alert->type,
playbookId = alert->playbookId
| dedup alertID 
| filter playbookId != ""
| join (dataset = playbook_mapping) as playbook_mapping playbook_mapping.PlaybookID = playbookId 
| comp count(PlaybookName ) as PlaybookCount by PlaybookName
| view graph type = pie xaxis = PlaybookName yaxis = PlaybookCount
```

---

### Troy Playbook Automation - Custom XQL Widget

```sql
dataset = xsiam_playbookmetrics_raw
| alter
incidentID = alert->parentXDRIncident,
alertID = alert->id,
alertName = alert->name,
alertType = alert->type,
playbookId = alert->playbookId
| dedup alertID 
| filter playbookId != ""
| join (dataset = playbook_mapping) as playbook_mapping playbook_mapping.PlaybookID = playbookId 
| bin _time span = 10m
| alter dedupKey = concat(PlaybookName,"|",_time)
| windowcomp count(PlaybookName) by dedupKey as PlaybookRuns
// | comp count(PlaybookName ) as PlaybookCount by PlaybookName
// | view graph type = pie xaxis = PlaybookName yaxis = PlaybookCount
| view graph type = line header = "Playbook Runs" xaxis = _time yaxis = PlaybookRuns series = PlaybookName
```

---

### Cortex XSIAM Troy Cisco Umbrella DNS - Custom XQL Widget

```sql
dataset = cisco_umbrella_raw  
|filter action contains "blocked"
| bin _time span =1h
| sort asc  _time 
| comp count(_collection_timestamp ) as counter by _time
| view graph type = line xaxis = _time yaxis = counter seriescolor("counter","#ec0101") legend = `false`
```

---

### Cortex XSIAM Troy Cisco Umbrella DNS - Custom XQL Widget

```sql
dataset = cisco_umbrella_raw 
| filter (action not contains """Allowed""") 
| comp count(domain) as domain_count by domain
| limit 50
| view graph type = wordcloud xaxis = domain yaxis = domain_count word_color = "#00ff5b"
```

---

### Cortex XSIAM Troy Cisco Umbrella DNS - Custom XQL Widget

```sql
dataset = cisco_umbrella_raw  
| bin _time span =1h
| sort asc  _time 
| comp count(_collection_timestamp ) as counter by _time
| view graph type = line xaxis = _time yaxis = counter seriescolor("counter","#30ec01") legend = `false`
```

---

### Cortex XSIAM Troy Cisco Umbrella DNS - Custom XQL Widget

```sql
dataset = cisco_umbrella_raw  
|filter action contains "blocked"
| comp count(catagories) as counter by catagories 
|sort desc counter 
|limit 5
| view graph type = pie xaxis = catagories yaxis = counter seriestitle("counter","Blocked DNS")
```

---

###  Alerts by Subnets - Custom XQL Widget

```sql
dataset = alerts
| fields alert_name , action , action_process_causality_id , action_process_instance_id , actor_causality_id , actor_process_causality_id , action_process_instance_id , agent_data_collection_status , agent_host_boot_time , agent_install_type , agent_os_sub_type , agent_version , alert_arrival_timestamp , alert_domain , alert_domain ,  alert_id , alert_source , alert_type , app_category , app_id , app_subcategory , app_technology , category , causality_actor_process_execution_time , cgo_cmd , cgo_md5 , cgo_name , cgo_path , cgo_sha256 , cgo_signature , cgo_signer , cid , cloud_identity_sub_type , cloud_identity_type , cloud_operation_type , cloud_project , cloud_provider , cloud_referenced_resource , cloud_resource_sub_type , cloud_resource_type , cluster_name , cloud_identity_sub_type , container_id , container_name , contains_featured_host , contains_featured_ip_address , contains_featured_user , country , description , destination_agent_id , destination_causality_actor_process_execution_time , destination_zone_name , dst_action_external_hostname , dst_action_external_port , dns_query_name , domain , dst_action_country , dst_action_external_hostname , dst_action_external_port , email_recipient , email_sender , email_subject , endpoint_id , event_id , event_timestamp , excluded , external_id , externally_detected_provider , file_macro_sha256 , file_md5 , file_name , file_path , file_sha256 , fw_name , fw_rule_id , fw_rule_name , fw_serial_number , host_fqdn , host_ipv6 , host_ip , host_mac_address , host_name , host_os , image_id , image_name , incident_id , initiated_by , initiator_cmd , initiator_md5 , initiator_path , initiator_pid , initiator_sha256 , initiator_signature , initiator_signer , initiator_tid , is_npcap , is_phishing , local_ip , local_ipv6 , local_port , malicious_urls , misc , mitre_attack_tactic , mitre_attack_technique , module , namespace , ngfw_vsys_name , original_tags , os_actor_causality_id , os_actor_process_causality_id , os_actor_process_instance_id , os_parent_cmd , os_parent_name , os_parent_path , os_parent_pid , os_parent_sha256 , os_parent_signature , os_parent_signer , os_parent_tid , os_parent_user_name , process_execution_signature , process_execution_signer , registry_data , registry_full_key , registry_key_name , registry_value_name , remote_host , remote_ip , remote_ipv6 , remote_port , resolution_comment , resolution_status , rule_id , severity , source_zone_name , starred , target_process_cmd , target_process_name , target_process_sha256 , url , user_agent , user_name 
| alter localip = arraystring(local_ip, ", ")
| join conflict_strategy = right type = left
    (
      dataset = agentic_subnet_lookup
      | fields DHCP , FirewallZoneName , FirewallZoneType , Gateway , Location , Name , SSID , Subnet , VLAN  
    )
  as subnet_lkp incidr(localip, subnet_lkp.subnet) 
  | comp count () as alerts_by_location by Location | sort desc alerts_by_location
| view graph type = pie header = "Alerts by Location" xaxis = Location yaxis = alerts_by_location seriestitle("alerts_by_location","Alerts")
```

---

###  Alerts by Subnets - Custom XQL Widget

```sql
dataset = alerts
| fields alert_name , action , action_process_causality_id , action_process_instance_id , actor_causality_id , actor_process_causality_id , action_process_instance_id , agent_data_collection_status , agent_host_boot_time , agent_install_type , agent_os_sub_type , agent_version , alert_arrival_timestamp , alert_domain , alert_domain ,  alert_id , alert_source , alert_type , app_category , app_id , app_subcategory , app_technology , category , causality_actor_process_execution_time , cgo_cmd , cgo_md5 , cgo_name , cgo_path , cgo_sha256 , cgo_signature , cgo_signer , cid , cloud_identity_sub_type , cloud_identity_type , cloud_operation_type , cloud_project , cloud_provider , cloud_referenced_resource , cloud_resource_sub_type , cloud_resource_type , cluster_name , cloud_identity_sub_type , container_id , container_name , contains_featured_host , contains_featured_ip_address , contains_featured_user , country , description , destination_agent_id , destination_causality_actor_process_execution_time , destination_zone_name , dst_action_external_hostname , dst_action_external_port , dns_query_name , domain , dst_action_country , dst_action_external_hostname , dst_action_external_port , email_recipient , email_sender , email_subject , endpoint_id , event_id , event_timestamp , excluded , external_id , externally_detected_provider , file_macro_sha256 , file_md5 , file_name , file_path , file_sha256 , fw_name , fw_rule_id , fw_rule_name , fw_serial_number , host_fqdn , host_ipv6 , host_ip , host_mac_address , host_name , host_os , image_id , image_name , incident_id , initiated_by , initiator_cmd , initiator_md5 , initiator_path , initiator_pid , initiator_sha256 , initiator_signature , initiator_signer , initiator_tid , is_npcap , is_phishing , local_ip , local_ipv6 , local_port , malicious_urls , misc , mitre_attack_tactic , mitre_attack_technique , module , namespace , ngfw_vsys_name , original_tags , os_actor_causality_id , os_actor_process_causality_id , os_actor_process_instance_id , os_parent_cmd , os_parent_name , os_parent_path , os_parent_pid , os_parent_sha256 , os_parent_signature , os_parent_signer , os_parent_tid , os_parent_user_name , process_execution_signature , process_execution_signer , registry_data , registry_full_key , registry_key_name , registry_value_name , remote_host , remote_ip , remote_ipv6 , remote_port , resolution_comment , resolution_status , rule_id , severity , source_zone_name , starred , target_process_cmd , target_process_name , target_process_sha256 , url , user_agent , user_name 
| alter localip = arraystring(local_ip, ", ")
| join conflict_strategy = right type = left
    (
      dataset = agentic_subnet_lookup
      | fields DHCP , FirewallZoneName , FirewallZoneType , Gateway , Location , Name , SSID , Subnet , VLAN  
    )
  as subnet_lkp incidr(localip, subnet_lkp.subnet) 
  | comp count () as alerts_by_ssid by SSID | sort desc alerts_by_ssid
| view graph type = pie header = "Alerts by SSID" xaxis = SSID yaxis = alerts_by_ssid seriestitle("alerts_by_ssid","Alerts")
```

---

###  Alerts by Subnets - Custom XQL Widget

```sql
dataset = alerts
| fields alert_name , action , action_process_causality_id , action_process_instance_id , actor_causality_id , actor_process_causality_id , action_process_instance_id , agent_data_collection_status , agent_host_boot_time , agent_install_type , agent_os_sub_type , agent_version , alert_arrival_timestamp , alert_domain , alert_domain ,  alert_id , alert_source , alert_type , app_category , app_id , app_subcategory , app_technology , category , causality_actor_process_execution_time , cgo_cmd , cgo_md5 , cgo_name , cgo_path , cgo_sha256 , cgo_signature , cgo_signer , cid , cloud_identity_sub_type , cloud_identity_type , cloud_operation_type , cloud_project , cloud_provider , cloud_referenced_resource , cloud_resource_sub_type , cloud_resource_type , cluster_name , cloud_identity_sub_type , container_id , container_name , contains_featured_host , contains_featured_ip_address , contains_featured_user , country , description , destination_agent_id , destination_causality_actor_process_execution_time , destination_zone_name , dst_action_external_hostname , dst_action_external_port , dns_query_name , domain , dst_action_country , dst_action_external_hostname , dst_action_external_port , email_recipient , email_sender , email_subject , endpoint_id , event_id , event_timestamp , excluded , external_id , externally_detected_provider , file_macro_sha256 , file_md5 , file_name , file_path , file_sha256 , fw_name , fw_rule_id , fw_rule_name , fw_serial_number , host_fqdn , host_ipv6 , host_ip , host_mac_address , host_name , host_os , image_id , image_name , incident_id , initiated_by , initiator_cmd , initiator_md5 , initiator_path , initiator_pid , initiator_sha256 , initiator_signature , initiator_signer , initiator_tid , is_npcap , is_phishing , local_ip , local_ipv6 , local_port , malicious_urls , misc , mitre_attack_tactic , mitre_attack_technique , module , namespace , ngfw_vsys_name , original_tags , os_actor_causality_id , os_actor_process_causality_id , os_actor_process_instance_id , os_parent_cmd , os_parent_name , os_parent_path , os_parent_pid , os_parent_sha256 , os_parent_signature , os_parent_signer , os_parent_tid , os_parent_user_name , process_execution_signature , process_execution_signer , registry_data , registry_full_key , registry_key_name , registry_value_name , remote_host , remote_ip , remote_ipv6 , remote_port , resolution_comment , resolution_status , rule_id , severity , source_zone_name , starred , target_process_cmd , target_process_name , target_process_sha256 , url , user_agent , user_name 
| alter localip = arraystring(local_ip, ", ")
| join conflict_strategy = right type = left
    (
      dataset = agentic_subnet_lookup
      | fields DHCP , FirewallZoneName , FirewallZoneType , Gateway , Location , Name , SSID , Subnet , VLAN  
    )
  as subnet_lkp incidr(localip, subnet_lkp.subnet) 
  | comp count () as alerts_by_room by Name | sort desc alerts_by_room
| view graph type = pie header = "Alerts by Subnet" xaxis = Name yaxis = alerts_by_room seriestitle("alerts_by_room","Alerts")
```

---

###  Alerts by Subnets - Custom XQL Widget

```sql
dataset = alerts
| fields alert_name , action , action_process_causality_id , action_process_instance_id , actor_causality_id , actor_process_causality_id , action_process_instance_id , agent_data_collection_status , agent_host_boot_time , agent_install_type , agent_os_sub_type , agent_version , alert_arrival_timestamp , alert_domain , alert_domain ,  alert_id , alert_source , alert_type , app_category , app_id , app_subcategory , app_technology , category , causality_actor_process_execution_time , cgo_cmd , cgo_md5 , cgo_name , cgo_path , cgo_sha256 , cgo_signature , cgo_signer , cid , cloud_identity_sub_type , cloud_identity_type , cloud_operation_type , cloud_project , cloud_provider , cloud_referenced_resource , cloud_resource_sub_type , cloud_resource_type , cluster_name , cloud_identity_sub_type , container_id , container_name , contains_featured_host , contains_featured_ip_address , contains_featured_user , country , description , destination_agent_id , destination_causality_actor_process_execution_time , destination_zone_name , dst_action_external_hostname , dst_action_external_port , dns_query_name , domain , dst_action_country , dst_action_external_hostname , dst_action_external_port , email_recipient , email_sender , email_subject , endpoint_id , event_id , event_timestamp , excluded , external_id , externally_detected_provider , file_macro_sha256 , file_md5 , file_name , file_path , file_sha256 , fw_name , fw_rule_id , fw_rule_name , fw_serial_number , host_fqdn , host_ipv6 , host_ip , host_mac_address , host_name , host_os , image_id , image_name , incident_id , initiated_by , initiator_cmd , initiator_md5 , initiator_path , initiator_pid , initiator_sha256 , initiator_signature , initiator_signer , initiator_tid , is_npcap , is_phishing , local_ip , local_ipv6 , local_port , malicious_urls , misc , mitre_attack_tactic , mitre_attack_technique , module , namespace , ngfw_vsys_name , original_tags , os_actor_causality_id , os_actor_process_causality_id , os_actor_process_instance_id , os_parent_cmd , os_parent_name , os_parent_path , os_parent_pid , os_parent_sha256 , os_parent_signature , os_parent_signer , os_parent_tid , os_parent_user_name , process_execution_signature , process_execution_signer , registry_data , registry_full_key , registry_key_name , registry_value_name , remote_host , remote_ip , remote_ipv6 , remote_port , resolution_comment , resolution_status , rule_id , severity , source_zone_name , starred , target_process_cmd , target_process_name , target_process_sha256 , url , user_agent , user_name 
| alter localip = arraystring(local_ip, ", ")
| join conflict_strategy = right type = left
    (
      dataset = agentic_subnet_lookup
      | fields DHCP , FirewallZoneName , FirewallZoneType , Gateway , Location , Name , SSID , Subnet , VLAN  
    )
  as subnet_lkp incidr(localip, subnet_lkp.subnet) 
  | comp count () as alerts_by_firewallzone by FirewallZoneName | sort desc alerts_by_firewallzone
| view graph type = pie header = "Alerts by Zone Name" xaxis = FirewallZoneName yaxis = alerts_by_firewallzone seriestitle("alerts_by_firewallzone","Alerts")
```

---

