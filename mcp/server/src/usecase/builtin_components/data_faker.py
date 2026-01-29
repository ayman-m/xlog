"""MCP tools for generating fake data using XLog."""

import ast
import json
import logging
from typing import Any, Dict, List, Optional, Union

from fastmcp import Context
from pydantic import BaseModel, Field, field_validator

from pkg.graphql_client import XLogGraphQLClient

logger = logging.getLogger("XLog MCP")


class ObservablesDict(BaseModel):
    """
    Observables dictionary for injecting specific values into fake log data.

    All fields accept lists of strings that will be randomly selected during log generation.
    Use camelCase field names (e.g., 'remoteIP', not 'remote_ip').
    """

    # Original Network observables
    local_ip: Optional[List[str]] = Field(default=None, description="Local IP addresses (IPv4). Example: ['192.168.1.10', '10.0.0.5']")
    remote_ip: Optional[List[str]] = Field(default=None, description="Remote IP addresses (IPv4). Example: ['8.8.8.8', '1.1.1.1']")
    local_ip_v6: Optional[List[str]] = Field(default=None, description="Local IPv6 addresses. Example: ['::1', 'fe80::1']")
    remote_ip_v6: Optional[List[str]] = Field(default=None, description="Remote IPv6 addresses. Example: ['2001:4860:4860::8888']")
    source_port: Optional[List[str]] = Field(default=None, description="Source port numbers. Example: ['443', '8080', '22']")
    remote_port: Optional[List[str]] = Field(default=None, description="Remote port numbers. Example: ['80', '443', '3389']")
    protocol: Optional[List[str]] = Field(default=None, description="Network protocols. Example: ['TCP', 'UDP', 'ICMP']")

    # Host observables
    src_host: Optional[List[str]] = Field(default=None, description="Source hostnames. Example: ['workstation01', 'server-web-01']")
    dst_host: Optional[List[str]] = Field(default=None, description="Destination hostnames. Example: ['mail-server', 'db-server']")
    src_domain: Optional[List[str]] = Field(default=None, description="Source domains. Example: ['example.com', 'corp.local']")
    dst_domain: Optional[List[str]] = Field(default=None, description="Destination domains. Example: ['google.com', 'github.com']")

    # Email observables
    sender_email: Optional[List[str]] = Field(default=None, description="Sender email addresses. Example: ['admin@example.com']")
    recipient_email: Optional[List[str]] = Field(default=None, description="Recipient email addresses. Example: ['user@example.com']")
    email_subject: Optional[List[str]] = Field(default=None, description="Email subject lines. Example: ['Security Alert', 'Invoice']")
    email_body: Optional[List[str]] = Field(default=None, description="Email body content. Example: ['Click here to verify']")

    # Web observables
    url: Optional[List[str]] = Field(default=None, description="URLs. Example: ['https://example.com/login']")

    # Traffic observables
    inbound_bytes: Optional[List[str]] = Field(default=None, description="Inbound bytes transferred. Example: ['1024', '2048576']")
    outbound_bytes: Optional[List[str]] = Field(default=None, description="Outbound bytes transferred. Example: ['512', '1048576']")

    # System observables
    app: Optional[List[str]] = Field(default=None, description="Application names. Example: ['Chrome', 'Outlook', 'ssh']")
    os: Optional[List[str]] = Field(default=None, description="Operating systems. Example: ['Windows 10', 'Ubuntu 20.04']")
    user: Optional[List[str]] = Field(default=None, description="Usernames. Example: ['admin', 'john.doe']")

    # Threat observables
    cve: Optional[List[str]] = Field(default=None, description="CVE identifiers. Example: ['CVE-2021-44228']")
    file_name: Optional[List[str]] = Field(default=None, description="File names. Example: ['malware.exe', 'invoice.pdf']")
    file_hash: Optional[List[str]] = Field(default=None, description="File hashes (MD5/SHA). Example: ['d41d8cd98f00b204e9800998ecf8427e']")

    # Process observables
    win_cmd: Optional[List[str]] = Field(default=None, description="Windows commands. Example: ['powershell.exe -enc']")
    unix_cmd: Optional[List[str]] = Field(default=None, description="Unix/Linux commands. Example: ['bash -c']")
    win_process: Optional[List[str]] = Field(default=None, description="Windows processes. Example: ['explorer.exe', 'svchost.exe']")
    win_child_process: Optional[List[str]] = Field(default=None, description="Windows child processes. Example: ['cmd.exe']")
    unix_process: Optional[List[str]] = Field(default=None, description="Unix/Linux processes. Example: ['bash', 'python3']")
    unix_child_process: Optional[List[str]] = Field(default=None, description="Unix/Linux child processes. Example: ['sh', 'perl']")

    # Security observables
    technique: Optional[List[str]] = Field(default=None, description="MITRE ATT&CK techniques. Example: ['T1059.001']")
    entry_type: Optional[List[str]] = Field(default=None, description="Log entry types. Example: ['Error', 'Warning']")
    severity: Optional[List[str]] = Field(default=None, description="Severity levels. Example: ['Critical', 'High', 'Medium', 'Low']")
    sensor: Optional[List[str]] = Field(default=None, description="Sensor names. Example: ['IDS-01', 'Firewall-DMZ']")
    action: Optional[List[str]] = Field(default=None, description="Actions taken. Example: ['blocked', 'allowed']")
    event_id: Optional[List[str]] = Field(default=None, description="Event IDs. Example: ['4624', '4625', '7045']")
    error_code: Optional[List[str]] = Field(default=None, description="Error codes. Example: ['200', '404', '500']")

    # Incident observables
    terms: Optional[List[str]] = Field(default=None, description="Search terms. Example: ['malware', 'phishing']")
    incident_types: Optional[List[str]] = Field(default=None, description="Incident types. Example: ['Malware', 'Phishing']")
    analysts: Optional[List[str]] = Field(default=None, description="Analyst names. Example: ['John Smith', 'Jane Doe']")
    alert_types: Optional[List[str]] = Field(default=None, description="Alert types. Example: ['Brute Force']")
    alert_name: Optional[List[str]] = Field(default=None, description="Alert names. Example: ['Suspicious PowerShell']")
    action_status: Optional[List[str]] = Field(default=None, description="Action statuses. Example: ['pending', 'completed']")

    # Database observables
    query_type: Optional[List[str]] = Field(default=None, description="SQL query types. Example: ['SELECT', 'INSERT']")
    database_name: Optional[List[str]] = Field(default=None, description="Database names. Example: ['users_db']")
    query: Optional[List[str]] = Field(default=None, description="SQL queries. Example: ['SELECT * FROM users']")

    # Network Extended
    client_ip: Optional[List[str]] = Field(default=None, description="Client IP addresses. Example: ['192.168.1.50']")
    server_ip: Optional[List[str]] = Field(default=None, description="Server IP addresses. Example: ['10.0.0.1']")
    destination_ip: Optional[List[str]] = Field(default=None, description="Destination IP addresses. Example: ['8.8.8.8']")
    source_ip: Optional[List[str]] = Field(default=None, description="Source IP addresses. Example: ['192.168.1.100']")
    public_ip: Optional[List[str]] = Field(default=None, description="Public IP addresses. Example: ['203.0.113.10']")
    private_ip: Optional[List[str]] = Field(default=None, description="Private IP addresses. Example: ['10.0.0.5']")
    nat_source_ip: Optional[List[str]] = Field(default=None, description="NAT source IP addresses")
    nat_destination_ip: Optional[List[str]] = Field(default=None, description="NAT destination IP addresses")
    client_port: Optional[List[str]] = Field(default=None, description="Client port numbers")
    server_port: Optional[List[str]] = Field(default=None, description="Server port numbers")
    destination_port: Optional[List[str]] = Field(default=None, description="Destination port numbers")
    local_port: Optional[List[str]] = Field(default=None, description="Local port numbers")

    # HTTP/API
    http_method: Optional[List[str]] = Field(default=None, description="HTTP methods. Example: ['GET', 'POST', 'PUT']")
    http_uri: Optional[List[str]] = Field(default=None, description="HTTP URIs. Example: ['/api/v1/users']")
    http_status_code: Optional[List[str]] = Field(default=None, description="HTTP status codes. Example: ['200', '404', '500']")
    http_user_agent: Optional[List[str]] = Field(default=None, description="HTTP user agents")
    http_host: Optional[List[str]] = Field(default=None, description="HTTP host headers")
    http_referer: Optional[List[str]] = Field(default=None, description="HTTP referer headers")
    api_endpoint: Optional[List[str]] = Field(default=None, description="API endpoints. Example: ['/api/login']")
    api_key: Optional[List[str]] = Field(default=None, description="API keys")
    api_name: Optional[List[str]] = Field(default=None, description="API names")
    request_id: Optional[List[str]] = Field(default=None, description="Request IDs")
    response_time_ms: Optional[List[str]] = Field(default=None, description="Response times in milliseconds")
    content_type: Optional[List[str]] = Field(default=None, description="Content types. Example: ['application/json']")

    # DNS/DHCP
    dns_query: Optional[List[str]] = Field(default=None, description="DNS queries. Example: ['example.com']")
    dns_response: Optional[List[str]] = Field(default=None, description="DNS responses. Example: ['93.184.216.34']")
    dns_server: Optional[List[str]] = Field(default=None, description="DNS server addresses")
    query_time_ms: Optional[List[str]] = Field(default=None, description="Query times in milliseconds")
    lease_duration: Optional[List[str]] = Field(default=None, description="DHCP lease duration")

    # Kubernetes/Containers
    container_id: Optional[List[str]] = Field(default=None, description="Container IDs")
    container_name: Optional[List[str]] = Field(default=None, description="Container names. Example: ['nginx', 'redis']")
    container_image: Optional[List[str]] = Field(default=None, description="Container images. Example: ['nginx:latest']")
    pod_name: Optional[List[str]] = Field(default=None, description="Kubernetes pod names")
    pod_uid: Optional[List[str]] = Field(default=None, description="Kubernetes pod UIDs")
    namespace: Optional[List[str]] = Field(default=None, description="Kubernetes namespaces. Example: ['default', 'prod']")
    cluster: Optional[List[str]] = Field(default=None, description="Kubernetes cluster names")
    node_name: Optional[List[str]] = Field(default=None, description="Kubernetes node names")
    service_account: Optional[List[str]] = Field(default=None, description="Kubernetes service accounts")
    labels: Optional[List[str]] = Field(default=None, description="Kubernetes labels")
    annotations: Optional[List[str]] = Field(default=None, description="Kubernetes annotations")

    # Cloud Infrastructure
    cloud_provider: Optional[List[str]] = Field(default=None, description="Cloud providers. Example: ['AWS', 'Azure', 'GCP']")
    region: Optional[List[str]] = Field(default=None, description="Cloud regions. Example: ['us-east-1']")
    instance_id: Optional[List[str]] = Field(default=None, description="Cloud instance IDs")
    instance_type: Optional[List[str]] = Field(default=None, description="Cloud instance types. Example: ['t2.micro']")
    vpc_id: Optional[List[str]] = Field(default=None, description="VPC IDs")
    subnet_id: Optional[List[str]] = Field(default=None, description="Subnet IDs")
    security_groups: Optional[List[str]] = Field(default=None, description="Security group names")
    iam_role: Optional[List[str]] = Field(default=None, description="IAM roles")
    bucket_name: Optional[List[str]] = Field(default=None, description="S3/Storage bucket names")
    resource_id: Optional[List[str]] = Field(default=None, description="Cloud resource IDs")
    resource_type: Optional[List[str]] = Field(default=None, description="Cloud resource types")
    resource_arn: Optional[List[str]] = Field(default=None, description="AWS resource ARNs")

    # SSL/TLS
    ssl_cipher: Optional[List[str]] = Field(default=None, description="SSL ciphers. Example: ['AES256-SHA']")
    ssl_version: Optional[List[str]] = Field(default=None, description="SSL versions")
    tls_version: Optional[List[str]] = Field(default=None, description="TLS versions. Example: ['TLSv1.2', 'TLSv1.3']")
    certificate_cn: Optional[List[str]] = Field(default=None, description="Certificate common names")
    certificate_issuer: Optional[List[str]] = Field(default=None, description="Certificate issuers")
    ja3_hash: Optional[List[str]] = Field(default=None, description="JA3 fingerprint hashes")
    ja3s_hash: Optional[List[str]] = Field(default=None, description="JA3S fingerprint hashes")

    # Threat Detection
    mitre_tactic: Optional[List[str]] = Field(default=None, description="MITRE ATT&CK tactics. Example: ['TA0001', 'TA0002']")
    mitre_technique: Optional[List[str]] = Field(default=None, description="MITRE ATT&CK techniques. Example: ['T1059', 'T1105']")
    threat_score: Optional[List[str]] = Field(default=None, description="Threat scores. Example: ['85', '92']")
    threat_level: Optional[List[str]] = Field(default=None, description="Threat levels. Example: ['high', 'critical']")
    threat_name: Optional[List[str]] = Field(default=None, description="Threat names")
    threat_type: Optional[List[str]] = Field(default=None, description="Threat types. Example: ['malware', 'ransomware']")
    signature_id: Optional[List[str]] = Field(default=None, description="Signature IDs")
    signature_name: Optional[List[str]] = Field(default=None, description="Signature names")
    cve_id: Optional[List[str]] = Field(default=None, description="CVE IDs. Example: ['CVE-2021-44228']")
    cvss_score: Optional[List[str]] = Field(default=None, description="CVSS scores. Example: ['9.8', '7.5']")
    ioc_type: Optional[List[str]] = Field(default=None, description="IOC types. Example: ['ip', 'domain', 'hash']")
    ioc_value: Optional[List[str]] = Field(default=None, description="IOC values")

    # Process Extended
    parent_process_name: Optional[List[str]] = Field(default=None, description="Parent process names")
    command_line: Optional[List[str]] = Field(default=None, description="Command lines")
    executable_path: Optional[List[str]] = Field(default=None, description="Executable paths")
    working_directory: Optional[List[str]] = Field(default=None, description="Working directories")
    process_name: Optional[List[str]] = Field(default=None, description="Process names")
    process_guid: Optional[List[str]] = Field(default=None, description="Process GUIDs")
    ppid: Optional[List[str]] = Field(default=None, description="Parent process IDs")

    # File Extended
    file_path: Optional[List[str]] = Field(default=None, description="File paths")
    file_size: Optional[List[str]] = Field(default=None, description="File sizes in bytes")
    file_type: Optional[List[str]] = Field(default=None, description="File types. Example: ['exe', 'pdf', 'dll']")
    file_hash_sha256: Optional[List[str]] = Field(default=None, description="SHA256 file hashes")
    file_hash_md5: Optional[List[str]] = Field(default=None, description="MD5 file hashes")
    file_hash_sha1: Optional[List[str]] = Field(default=None, description="SHA1 file hashes")
    file_owner: Optional[List[str]] = Field(default=None, description="File owners")

    # Email Extended
    sender: Optional[List[str]] = Field(default=None, description="Email senders")
    recipient: Optional[List[str]] = Field(default=None, description="Email recipients")
    subject: Optional[List[str]] = Field(default=None, description="Email subjects")
    message_id: Optional[List[str]] = Field(default=None, description="Email message IDs")
    attachment_name: Optional[List[str]] = Field(default=None, description="Attachment names")
    attachment_hash: Optional[List[str]] = Field(default=None, description="Attachment hashes")
    spf_result: Optional[List[str]] = Field(default=None, description="SPF results. Example: ['pass', 'fail']")
    dkim_result: Optional[List[str]] = Field(default=None, description="DKIM results. Example: ['pass', 'fail']")
    dmarc_result: Optional[List[str]] = Field(default=None, description="DMARC results. Example: ['pass', 'fail']")

    # Authentication
    authentication_method: Optional[List[str]] = Field(default=None, description="Auth methods. Example: ['password', 'mfa']")
    authentication_result: Optional[List[str]] = Field(default=None, description="Auth results. Example: ['success', 'failure']")
    mfa_method: Optional[List[str]] = Field(default=None, description="MFA methods. Example: ['totp', 'push']")
    mfa_result: Optional[List[str]] = Field(default=None, description="MFA results")
    logon_type: Optional[List[str]] = Field(default=None, description="Logon types. Example: ['2', '3', '10']")
    session_id: Optional[List[str]] = Field(default=None, description="Session IDs")
    username: Optional[List[str]] = Field(default=None, description="Usernames")
    account_name: Optional[List[str]] = Field(default=None, description="Account names")

    # Firewall/IDS
    firewall_name: Optional[List[str]] = Field(default=None, description="Firewall names")
    rule_name: Optional[List[str]] = Field(default=None, description="Rule names")
    rule_action: Optional[List[str]] = Field(default=None, description="Rule actions. Example: ['allow', 'deny']")
    zone_source: Optional[List[str]] = Field(default=None, description="Source zones")
    zone_destination: Optional[List[str]] = Field(default=None, description="Destination zones")
    tcp_flags: Optional[List[str]] = Field(default=None, description="TCP flags")
    packets: Optional[List[str]] = Field(default=None, description="Packet counts")
    bytes_sent: Optional[List[str]] = Field(default=None, description="Bytes sent")
    bytes_received: Optional[List[str]] = Field(default=None, description="Bytes received")

    # Virtual Machines
    vm_id: Optional[List[str]] = Field(default=None, description="VM IDs")
    vm_name: Optional[List[str]] = Field(default=None, description="VM names")
    hypervisor_type: Optional[List[str]] = Field(default=None, description="Hypervisor types. Example: ['ESXi', 'Hyper-V']")
    cpu_usage: Optional[List[str]] = Field(default=None, description="CPU usage percentages")
    memory_usage: Optional[List[str]] = Field(default=None, description="Memory usage percentages")

    # Database Extended
    query_text: Optional[List[str]] = Field(default=None, description="Database query text")
    execution_time_ms: Optional[List[str]] = Field(default=None, description="Query execution times in ms")
    transaction_id: Optional[List[str]] = Field(default=None, description="Transaction IDs")
    affected_rows: Optional[List[str]] = Field(default=None, description="Rows affected by query")
    schema_name: Optional[List[str]] = Field(default=None, description="Database schema names")

    # Vulnerability/Compliance
    vulnerability_id: Optional[List[str]] = Field(default=None, description="Vulnerability IDs")
    vulnerability_name: Optional[List[str]] = Field(default=None, description="Vulnerability names")
    scan_result: Optional[List[str]] = Field(default=None, description="Scan results. Example: ['pass', 'fail']")
    scan_type: Optional[List[str]] = Field(default=None, description="Scan types")
    compliance_status: Optional[List[str]] = Field(default=None, description="Compliance statuses")

    # Incident Response
    incident_id: Optional[List[str]] = Field(default=None, description="Incident IDs")
    incident_severity: Optional[List[str]] = Field(default=None, description="Incident severities")
    incident_status: Optional[List[str]] = Field(default=None, description="Incident statuses")
    playbook_id: Optional[List[str]] = Field(default=None, description="Playbook IDs")
    alert_id: Optional[List[str]] = Field(default=None, description="Alert IDs")

    # Additional commonly used
    hostname: Optional[List[str]] = Field(default=None, description="Hostnames")
    host: Optional[List[str]] = Field(default=None, description="Host identifiers")
    domain: Optional[List[str]] = Field(default=None, description="Domain names")
    status: Optional[List[str]] = Field(default=None, description="Status values")
    result: Optional[List[str]] = Field(default=None, description="Result values")
    message: Optional[List[str]] = Field(default=None, description="Log messages")
    description: Optional[List[str]] = Field(default=None, description="Descriptions")
    timestamp: Optional[List[str]] = Field(default=None, description="Timestamps")
    risk_score: Optional[List[str]] = Field(default=None, description="Risk scores")
    priority: Optional[List[str]] = Field(default=None, description="Priority levels")
    category: Optional[List[str]] = Field(default=None, description="Categories")
    tags: Optional[List[str]] = Field(default=None, description="Tags")
    malware_name: Optional[List[str]] = Field(default=None, description="Malware names")
    malware_type: Optional[List[str]] = Field(default=None, description="Malware types")
    direction: Optional[List[str]] = Field(default=None, description="Traffic direction. Example: ['inbound', 'outbound']")
    geo_location: Optional[List[str]] = Field(default=None, description="Geographic locations")
    country: Optional[List[str]] = Field(default=None, description="Country names")


_OBSERVABLE_SNAKE_KEYS = [
    # Original fields
    "local_ip", "remote_ip", "local_ip_v6", "remote_ip_v6", "source_port", "remote_port", "protocol",
    "src_host", "dst_host", "src_domain", "dst_domain",
    "sender_email", "recipient_email", "email_subject", "email_body",
    "url", "inbound_bytes", "outbound_bytes",
    "app", "os", "user",
    "cve", "file_name", "file_hash",
    "win_cmd", "unix_cmd", "win_process", "win_child_process", "unix_process", "unix_child_process",
    "technique", "entry_type", "severity", "sensor", "action", "event_id", "error_code",
    "terms", "incident_types", "analysts", "alert_types", "alert_name", "action_status",
    "query_type", "database_name", "query",
    # Network Extended
    "client_ip", "server_ip", "destination_ip", "source_ip", "public_ip", "private_ip",
    "nat_source_ip", "nat_destination_ip", "client_port", "server_port", "destination_port", "local_port",
    "client_mac", "server_hostname", "client_hostname", "destination_hostname", "source_hostname",
    # HTTP/API
    "http_method", "http_uri", "http_status_code", "http_user_agent", "http_host", "http_referer",
    "api_endpoint", "api_key", "api_name", "request_id", "response_time_ms", "content_type",
    # DNS/DHCP
    "dns_query", "dns_response", "dns_server", "query_time_ms", "lease_duration",
    # Kubernetes/Containers
    "container_id", "container_name", "container_image", "pod_name", "pod_uid",
    "namespace", "cluster", "node_name", "service_account", "labels", "annotations",
    # Cloud Infrastructure
    "cloud_provider", "region", "instance_id", "instance_type", "vpc_id", "subnet_id",
    "security_groups", "iam_role", "bucket_name", "resource_id", "resource_type", "resource_arn",
    # SSL/TLS
    "ssl_cipher", "ssl_version", "tls_version", "certificate_cn", "certificate_issuer", "ja3_hash", "ja3s_hash",
    # Threat Detection
    "mitre_tactic", "mitre_technique", "threat_score", "threat_level", "threat_name", "threat_type",
    "signature_id", "signature_name", "cve_id", "cvss_score", "ioc_type", "ioc_value",
    # Process Extended
    "parent_process_name", "command_line", "executable_path", "working_directory",
    "process_name", "process_guid", "ppid",
    # File Extended
    "file_path", "file_size", "file_type", "file_hash_sha256", "file_hash_md5", "file_hash_sha1", "file_owner",
    # Email Extended
    "sender", "recipient", "subject", "message_id", "attachment_name", "attachment_hash",
    "spf_result", "dkim_result", "dmarc_result",
    # Authentication
    "authentication_method", "authentication_result", "mfa_method", "mfa_result",
    "logon_type", "session_id", "username", "account_name",
    # Firewall/IDS
    "firewall_name", "rule_name", "rule_action", "zone_source", "zone_destination",
    "tcp_flags", "packets", "bytes_sent", "bytes_received",
    # Virtual Machines
    "vm_id", "vm_name", "hypervisor_type", "cpu_usage", "memory_usage",
    # Database Extended
    "query_text", "execution_time_ms", "transaction_id", "affected_rows", "schema_name",
    # Vulnerability/Compliance
    "vulnerability_id", "vulnerability_name", "scan_result", "scan_type", "compliance_status",
    # Incident Response
    "incident_id", "incident_severity", "incident_status", "playbook_id", "alert_id",
    # Additional commonly used
    "hostname", "host", "domain", "status", "result", "message", "description", "timestamp",
    "risk_score", "priority", "category", "tags", "malware_name", "malware_type",
    "direction", "geo_location", "country",
]


def _snake_to_camel(value: str, upper_ip: bool) -> str:
    parts = value.split("_")
    if not parts:
        return value
    converted = [parts[0]]
    for token in parts[1:]:
        if token == "ip":
            converted.append("IP" if upper_ip else "Ip")
        elif token in {"v6", "v4"}:
            converted.append(token.upper())
        else:
            converted.append(token.capitalize())
    return "".join(converted)


_OBSERVABLE_KEY_MAP = {
    _snake_to_camel(key, upper_ip=True): key for key in _OBSERVABLE_SNAKE_KEYS
}
_OBSERVABLE_KEY_MAP.update(
    {_snake_to_camel(key, upper_ip=False): key for key in _OBSERVABLE_SNAKE_KEYS}
)
_OBSERVABLE_KEY_MAP["remorePort"] = "remote_port"


def _normalize_observable_keys(values: Dict[str, Any]) -> Dict[str, Any]:
    normalized: Dict[str, Any] = {}
    for key, value in values.items():
        mapped_key = _OBSERVABLE_KEY_MAP.get(key, key)
        normalized[mapped_key] = value
    return normalized


class FakeDataRequest(BaseModel):
    """Request model for generating fake data."""

    type: str = Field(
        description=(
            "Type of fake log data to generate. Must be one of the following (case-insensitive):\n\n"
            "- SYSLOG: Standard syslog format (RFC 3164/5424) - Traditional Unix/Linux system logs\n"
            "- CEF: Common Event Format - ArcSight compatible format\n"
            "- LEEF: Log Event Extended Format - IBM QRadar compatible format\n"
            "- WINEVENT: Windows Event logs in JSON format - Windows security/system events\n"
            "- JSON: Generic JSON formatted security logs\n"
            "- Incident: XSIAM incident records with full context\n"
            "- XSIAM_Parsed: Pre-parsed logs ready for XSIAM ingestion\n"
            "- XSIAM_CEF: CEF format optimized for XSIAM\n\n"
            "Examples: 'SYSLOG', 'CEF', 'WINEVENT', 'Incident'. "
            "Use xlog_get_field_info to check which parameters and fields are supported per log type."
        )
    )
    count: int = Field(
        default=1,
        description=(
            "Number of fake log entries to generate in a single request. "
            "Must be a positive integer. Example: 5 to generate 5 log entries"
        )
    )
    vendor: Optional[str] = Field(
        default=None,
        description=(
            "Vendor name to include in the logs (primarily for CEF/LEEF formats). "
            "Example: 'Palo Alto Networks', 'Cisco', 'Microsoft'"
        )
    )
    product: Optional[str] = Field(
        default=None,
        description=(
            "Product name to include in the logs (primarily for CEF/LEEF formats). "
            "Example: 'Firewall', 'WAF', 'EmailGW', 'IDS'"
        )
    )
    version: Optional[str] = Field(
        default=None,
        description=(
            "Version string to include in the logs (primarily for CEF/LEEF formats). "
            "Example: '1.0', '5.0', '2.3.1'"
        )
    )
    datetime_iso: Optional[str] = Field(
        default=None,
        description=(
            "Override the timestamp for generated logs with a specific datetime in ISO format. "
            "Format: 'YYYY-MM-DD HH:MM:SS'. Example: '2024-01-15 14:30:00'"
        )
    )
    fields: Optional[Union[str, List[str]]] = Field(
        default=None,
        description=(
            "Custom field names to include in the logs. Accepts a comma-separated string or JSON list. "
            "Example (string): 'custom_field1,custom_field2,user_action'. "
            "Example (JSON list): [\"custom_field1\", \"custom_field2\", \"user_action\"]"
        )
    )
    required_fields: Optional[Union[List[str], str]] = Field(
        default=None,
        description=(
            "Required field enums that MUST be present in generated logs. "
            "Accepts a JSON list or a comma-separated string; values are uppercased before sending. "
            "Use UPPERCASE enum values exactly as shown. Available field enums (~270 total):\n\n"
            "Network Fields:\n"
            "  LOCAL_IP, REMOTE_IP, LOCAL_IP_V6, REMOTE_IP_V6, LOCAL_PORT, REMOTE_PORT, PROTOCOL, "
            "  SOURCE_NETWORK_ADDRESS, INBOUND_BYTES, OUTBOUND_BYTES, CLIENT_IP, SERVER_IP, "
            "  DESTINATION_IP, SOURCE_IP, PUBLIC_IP, PRIVATE_IP, NAT_SOURCE_IP, NAT_DESTINATION_IP\n\n"
            "Host/Domain Fields:\n"
            "  SRC_HOST, DST_HOST, SRC_DOMAIN, DST_DOMAIN, DST_URL, URL, HOSTNAME, HOST, DOMAIN\n\n"
            "HTTP/API Fields:\n"
            "  HTTP_METHOD, HTTP_URI, HTTP_STATUS_CODE, HTTP_USER_AGENT, HTTP_HOST, HTTP_REFERER, "
            "  API_ENDPOINT, API_KEY, API_NAME, REQUEST_ID, RESPONSE_TIME_MS, CONTENT_TYPE\n\n"
            "DNS/DHCP Fields:\n"
            "  DNS_QUERY, DNS_RESPONSE, DNS_SERVER, QUERY_TIME_MS, LEASE_DURATION\n\n"
            "Email Fields:\n"
            "  SENDER_EMAIL, RECIPIENT_EMAIL, EMAIL_SUBJECT, EMAIL_BODY, SPAM_SCORE, ATTACHMENT_HASH, "
            "  SENDER, RECIPIENT, SUBJECT, MESSAGE_ID, ATTACHMENT_NAME, SPF_RESULT, DKIM_RESULT, DMARC_RESULT\n\n"
            "Kubernetes/Container Fields:\n"
            "  CONTAINER_ID, CONTAINER_NAME, CONTAINER_IMAGE, POD_NAME, POD_UID, NAMESPACE, "
            "  CLUSTER, NODE_NAME, SERVICE_ACCOUNT, LABELS, ANNOTATIONS\n\n"
            "Cloud Infrastructure Fields:\n"
            "  CLOUD_PROVIDER, REGION, INSTANCE_ID, INSTANCE_TYPE, VPC_ID, SUBNET_ID, "
            "  SECURITY_GROUPS, IAM_ROLE, BUCKET_NAME, RESOURCE_ID, RESOURCE_TYPE, RESOURCE_ARN\n\n"
            "SSL/TLS Fields:\n"
            "  SSL_CIPHER, SSL_VERSION, TLS_VERSION, CERTIFICATE_CN, CERTIFICATE_ISSUER, JA3_HASH, JA3S_HASH\n\n"
            "Threat Detection Fields:\n"
            "  MITRE_TACTIC, MITRE_TECHNIQUE, THREAT_SCORE, THREAT_LEVEL, THREAT_NAME, THREAT_TYPE, "
            "  SIGNATURE_ID, SIGNATURE_NAME, CVE_ID, CVSS_SCORE, IOC_TYPE, IOC_VALUE, MALWARE_NAME, MALWARE_TYPE\n\n"
            "Security Fields:\n"
            "  ALERT_NAME, ALERT_TYPES, SEVERITY, CVE, TECHNIQUE, SENSOR, ACTION, ATTACK_TYPE, RISK_SCORE\n\n"
            "Process Fields:\n"
            "  WIN_PROCESS, WIN_CHILD_PROCESS, WIN_CMD, WIN_USER_ID, PROCESS_ID, NEW_PROCESS_ID, "
            "  THREAD_ID, TARGET_PID, PID, UNIX_PROCESS, UNIX_CHILD_PROCESS, UNIX_CMD, "
            "  PARENT_PROCESS_NAME, COMMAND_LINE, EXECUTABLE_PATH, WORKING_DIRECTORY, PROCESS_NAME, PROCESS_GUID, PPID\n\n"
            "File Fields:\n"
            "  FILE_NAME, FILE_HASH, FILE_PATH, FILE_SIZE, FILE_TYPE, FILE_HASH_SHA256, "
            "  FILE_HASH_MD5, FILE_HASH_SHA1, FILE_OWNER, APP, OS\n\n"
            "Authentication Fields:\n"
            "  AUTHENTICATION_METHOD, AUTHENTICATION_RESULT, MFA_METHOD, MFA_RESULT, "
            "  LOGON_TYPE, SESSION_ID, USERNAME, ACCOUNT_NAME\n\n"
            "Firewall/IDS Fields:\n"
            "  FIREWALL_NAME, RULE_NAME, RULE_ACTION, ZONE_SOURCE, ZONE_DESTINATION, "
            "  TCP_FLAGS, PACKETS, BYTES_SENT, BYTES_RECEIVED\n\n"
            "VM Fields:\n"
            "  VM_ID, VM_NAME, HYPERVISOR_TYPE, CPU_USAGE, MEMORY_USAGE\n\n"
            "Database Fields:\n"
            "  DATABASE_NAME, QUERY, QUERY_TYPE, QUERY_TEXT, EXECUTION_TIME_MS, "
            "  TRANSACTION_ID, AFFECTED_ROWS, SCHEMA_NAME\n\n"
            "Vulnerability/Compliance Fields:\n"
            "  VULNERABILITY_ID, VULNERABILITY_NAME, SCAN_RESULT, SCAN_TYPE, COMPLIANCE_STATUS\n\n"
            "Incident Response Fields:\n"
            "  INCIDENT_ID, INCIDENT_SEVERITY, INCIDENT_STATUS, PLAYBOOK_ID, ALERT_ID, "
            "  INCIDENT_TYPES, ANALYSTS, ACTION_STATUS, TERMS\n\n"
            "Event Fields:\n"
            "  EVENT_ID, EVENT_RECORD_ID, ENTRY_TYPE, ERROR_CODE, RESPONSE_CODE, RESPONSE_SIZE, RULE_ID, LOG_ID\n\n"
            "User/Identity Fields:\n"
            "  USER, SUBJECT_LOGIN_ID, DESTINATION_LOGIN_ID, PRIVILEGE_LIST, TRANSMITTED_SERVICES\n\n"
            "Web Fields:\n"
            "  METHOD, USER_AGENT, REFERER, COOKIES, DURATION\n\n"
            "Example (JSON list): [\"REMOTE_IP\", \"ALERT_NAME\", \"SEVERITY\", \"MITRE_TECHNIQUE\"]\n"
            "Example (string): \"CONTAINER_ID, POD_NAME, NAMESPACE, CLOUD_PROVIDER\"\n"
            "Example (string): \"THREAT_SCORE, CVE_ID, CVSS_SCORE, IOC_TYPE\""
        )
    )
    observables_dict: Optional[Union[ObservablesDict, Dict[str, Any], str]] = Field(
        default=None,
        description=(
            "Dictionary of specific observable values to inject into the generated logs. "
            "Accepts a JSON object (string) or a dict. Each field accepts a list of values that will be "
            "randomly selected during generation. Use camelCase field names (e.g., 'remoteIP', 'alertName'). "
            "Use xlog_get_field_info to retrieve the full observable catalog.\n\n"
            "Example (dict): {'remoteIP': ['192.168.1.100', '10.0.0.50'], 'alertName': ['Malware Detected']}\n"
            "Example (JSON string): \"{\\\"srcHost\\\": [\\\"web-server-01\\\"], \\\"remoteIP\\\": [\\\"8.8.8.8\\\"], \\\"remotePort\\\": [\\\"443\\\"]}\"\n"
            "Example (Windows): {'eventId': ['4624', '4625'], 'user': ['admin', 'john.doe']}"
        )
    )


    @field_validator("required_fields", mode="before")
    @classmethod
    def normalize_required_fields(cls, value: Any) -> Any:
        if value is None:
            return value
        if isinstance(value, list):
            return [str(item).strip().upper() for item in value if str(item).strip()]
        if isinstance(value, str):
            loaded = _load_string_value(value)
            if isinstance(loaded, list):
                return [str(item).strip().upper() for item in loaded if str(item).strip()]
            if isinstance(loaded, str):
                parts = [item.strip().upper() for item in loaded.split(",") if item.strip()]
                return parts or None
        return value

    @field_validator("fields", mode="before")
    @classmethod
    def normalize_fields(cls, value: Any) -> Any:
        if value is None:
            return value
        if isinstance(value, list):
            parts = [str(item).strip() for item in value if str(item).strip()]
            return ",".join(parts) if parts else None
        if isinstance(value, str):
            loaded = _load_string_value(value)
            if isinstance(loaded, list):
                parts = [str(item).strip() for item in loaded if str(item).strip()]
                return ",".join(parts) if parts else None
            if isinstance(loaded, str):
                return loaded.strip() or None
        return value

    @field_validator("observables_dict", mode="before")
    @classmethod
    def normalize_observables_dict(cls, value: Any) -> Any:
        if value is None:
            return value
        if isinstance(value, (ObservablesDict, dict)):
            return value
        if isinstance(value, str):
            loaded = _load_string_value(value)
            if isinstance(loaded, dict):
                return loaded
        return value


def _load_string_value(raw: str) -> Any:
    value = raw.strip()
    if not value:
        return None
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        try:
            return ast.literal_eval(value)
        except (ValueError, SyntaxError):
            return value


def _parse_required_fields(value: Optional[Union[List[str], str]]) -> Optional[List[str]]:
    if value is None:
        return None
    if isinstance(value, list):
        return [str(item).strip().upper() for item in value if str(item).strip()]
    if isinstance(value, str):
        loaded = _load_string_value(value)
        if loaded is None:
            return None
        if isinstance(loaded, list):
            return [str(item).strip().upper() for item in loaded if str(item).strip()]
        if isinstance(loaded, str):
            parts = [item.strip().upper() for item in loaded.split(",") if item.strip()]
            return parts or None
    raise ValueError("required_fields must be a JSON list or comma-separated string")


def _parse_fields(value: Optional[Union[str, List[str]]]) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, list):
        parts = [str(item).strip() for item in value if str(item).strip()]
        return ",".join(parts) if parts else None
    if isinstance(value, str):
        loaded = _load_string_value(value)
        if loaded is None:
            return None
        if isinstance(loaded, list):
            parts = [str(item).strip() for item in loaded if str(item).strip()]
            return ",".join(parts) if parts else None
        if isinstance(loaded, str):
            return loaded.strip() or None
    raise ValueError("fields must be a JSON list or comma-separated string")


def _parse_observables_dict(
    value: Optional[Union[ObservablesDict, Dict[str, Any], str]],
) -> Optional[Dict[str, Any]]:
    if value is None:
        return None
    if isinstance(value, ObservablesDict):
        return value.model_dump(exclude_none=True)
    if isinstance(value, dict):
        return _normalize_observable_keys(value)
    if isinstance(value, str):
        loaded = _load_string_value(value)
        if loaded is None:
            return None
        if isinstance(loaded, dict):
            return _normalize_observable_keys(loaded)
    raise ValueError("observables_dict must be a JSON object string or dict")


async def xlog_generate_fake_data(request: FakeDataRequest, ctx: Context) -> Dict[str, Any]:
    """
    Generate synthetic fake log data in various security log formats for testing, development, and demonstration purposes.

    Before calling this tool, use xlog_get_field_info to check which parameters are supported for the
    requested log type and to fetch the full observable catalog if needed.

    This tool creates realistic-looking security logs that can be used for:
    - Testing log ingestion pipelines and SIEM systems
    - Developing and testing security analytics queries
    - Creating demonstrations and proof-of-concepts
    - Training and education on log analysis
    - Populating test environments with sample data

    Supported log formats:
    - SYSLOG: RFC 3164/5424 compliant syslog messages
    - CEF: Common Event Format (ArcSight)
    - LEEF: Log Event Extended Format (IBM QRadar)
    - WINEVENT: Windows Event Logs in JSON format
    - JSON: Generic JSON-formatted security logs
    - Incident: XSIAM incident records
    - XSIAM_Parsed: Pre-parsed XSIAM-compatible logs

    Usage Examples:

    1. Generate 5 basic syslog entries:
       {
         "type": "SYSLOG",
         "count": 5
       }

    2. Generate CEF logs with specific vendor/product:
       {
         "type": "CEF",
         "count": 3,
         "vendor": "Palo Alto Networks",
         "product": "Firewall"
       }

    3. Generate logs with specific required fields:
       {
         "type": "SYSLOG",
         "count": 10,
         "required_fields": ["REMOTE_IP", "ALERT_NAME", "SEVERITY"]
       }

    4. Generate logs with specific observable values (use camelCase):
       {
         "type": "WINEVENT",
         "count": 5,
         "observables_dict": {
           "remoteIP": ["192.168.1.100", "10.0.0.50"],
           "eventId": ["4624", "4625"],
           "user": ["admin", "john.doe"]
         }
       }

    5. Generate logs with custom timestamp:
       {
         "type": "JSON",
         "count": 2,
         "datetime_iso": "2024-01-15 14:30:00"
       }

    6. Use string inputs for list/dict arguments:
       {
         "type": "CEF",
         "count": 3,
         "required_fields": "REMOTE_IP, ALERT_NAME, SEVERITY",
         "observables_dict": "{\"remoteIP\": [\"192.168.1.100\"], \"user\": [\"admin\"]}"
       }

    Example MCP tool call:
       {
         "method": "tools/call",
         "params": {
           "name": "xlog_generate_fake_data",
           "arguments": {
             "request": {
               "type": "CEF",
               "count": 1,
               "vendor": "Cisco",
               "product": "IDS",
               "observables_dict": {
                 "srcHost": ["web-server-01"],
                 "remoteIP": ["8.8.8.8"],
                 "remotePort": ["443"]
               },
               "required_fields": ["SRC_HOST", "REMOTE_IP", "REMOTE_PORT"]
             }
           }
         }
       }

    Args:
        request: The fake data generation request parameters
        ctx: MCP context containing XLog URL

    Returns:
        Dictionary containing:
        - data: List of generated log entries (strings)
        - type: The log type that was generated
        - count: Number of logs generated

    Example Response:
        {
          "data": [
            "Jan 07 12:01:50 2257 smile yorkchelsea sudo dd if=/dev/zero of=/dev/sda",
            "Jan 07 12:01:51 2258 cloud database-server nginx access /var/log/nginx"
          ],
          "type": "FakerTypeEnum.SYSLOG",
          "count": 2
        }
    """
    lifespan_context = ctx.request_context.lifespan_context
    client = XLogGraphQLClient(lifespan_context["xlog_url"])

    query = """
    query GenerateFakeData($type: FakerTypeEnum!, $count: Int, $vendor: String, $product: String,
                          $version: String, $datetimeIso: String, $fields: String,
                          $requiredFields: [RequiredFieldEnum!], $observablesDict: ObservablesInput) {
      generateFakeData(requestInput: {
        type: $type
        count: $count
        vendor: $vendor
        product: $product
        version: $version
        datetimeIso: $datetimeIso
        fields: $fields
        requiredFields: $requiredFields
        observablesDict: $observablesDict
      }) {
        data
        type
        count
      }
    }
    """

    required_fields = _parse_required_fields(request.required_fields)
    observables_dict = _parse_observables_dict(request.observables_dict)
    fields = _parse_fields(request.fields)

    variables = {
        "type": request.type.upper(),
        "count": request.count,
        "vendor": request.vendor,
        "product": request.product,
        "version": request.version,
        "datetimeIso": request.datetime_iso,
        "fields": fields,
        "requiredFields": required_fields,
        "observablesDict": observables_dict,
    }

    # Remove None values
    variables = {k: v for k, v in variables.items() if v is not None}

    result = await client.execute_query(query, variables)
    return result.get("generateFakeData", {})
