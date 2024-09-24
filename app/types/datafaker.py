import strawberry
from enum import Enum
from typing import Optional, List
from strawberry.scalars import JSON


@strawberry.enum(description="Enum representing the types of fake data.")
class FakerTypeEnum(Enum):
    SYSLOG = 'syslog'
    CEF = 'cef'
    LEEF = 'leef'
    WINEVENT = 'winevent'
    JSON = 'json'
    Incident = 'incident'
    XSIAM_Parsed = 'xsiam_parsed'
    XSIAM_CEF = 'xsiam_cef'


@strawberry.input(description="Data observables dictionary.")
class ObservablesInput:
    local_ip: Optional[List[str]] = None
    remote_ip: Optional[List[str]] = None
    local_ip_v6: Optional[List[str]] = None
    remote_ip_v6: Optional[List[str]] = None
    src_host: Optional[List[str]] = None
    dst_host: Optional[List[str]] = None
    src_domain: Optional[List[str]] = None
    dst_domain: Optional[List[str]] = None
    sender_email: Optional[List[str]] = None
    recipient_email: Optional[List[str]] = None
    email_subject: Optional[List[str]] = None
    email_body: Optional[List[str]] = None
    url: Optional[List[str]] = None
    source_port: Optional[List[str]] = None
    remote_port: Optional[List[str]] = None
    protocol: Optional[List[str]] = None
    inbound_bytes: Optional[List[str]] = None
    outbound_bytes: Optional[List[str]] = None
    app: Optional[List[str]] = None
    os: Optional[List[str]] = None
    user: Optional[List[str]] = None
    cve: Optional[List[str]] = None
    file_name: Optional[List[str]] = None
    file_hash: Optional[List[str]] = None
    win_cmd: Optional[List[str]] = None
    unix_cmd: Optional[List[str]] = None
    win_process: Optional[List[str]] = None
    win_child_process: Optional[List[str]] = None
    unix_process: Optional[List[str]] = None
    unix_child_process: Optional[List[str]] = None
    technique: Optional[List[str]] = None
    entry_type: Optional[List[str]] = None
    severity: Optional[List[str]] = None
    sensor: Optional[List[str]] = None
    action: Optional[List[str]] = None
    event_id: Optional[List[str]] = None
    error_code: Optional[List[str]] = None
    terms: Optional[List[str]] = None
    incident_types: Optional[List[str]] = None
    analysts: Optional[List[str]] = None
    alert_types: Optional[List[str]] = None
    alert_name: Optional[List[str]] = None
    action_status: Optional[List[str]] = None
    query_type: Optional[List[str]] = None
    database_name: Optional[List[str]] = None
    query: Optional[List[str]] = None


@strawberry.input(description="Input object for generating fake data.")
class DataFakerInput:
    type: FakerTypeEnum
    vendor: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    count: Optional[int] = 1
    datetime_iso: Optional[str] = None
    fields: Optional[str] = None
    observables_dict: Optional[ObservablesInput] = None
    required_fields: Optional[str] = None


@strawberry.type(description="Output object containing the generated fake data.")
class DataFakerOutput:
    data: List[JSON]
    type: str
    count: int
