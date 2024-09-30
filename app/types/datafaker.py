import strawberry
from enum import Enum
from typing import Optional, List
from strawberry.scalars import JSON

@strawberry.enum(description="Enum representing the types of required fields.")
class RequiredFieldEnum(Enum):
    LOCAL_IP = "local_ip"
    REMOTE_IP = "remote_ip"
    SRC_HOST = "src_host"
    DST_HOST = "dst_host"
    SENDER_EMAIL = "sender_email"
    RECIPIENT_EMAIL = "recipient_email"
    LOCAL_IP_V6 = "local_ip_v6"
    REMOTE_IP_V6 = "remote_ip_v6"
    SRC_DOMAIN = "src_domain"
    DST_DOMAIN = "dst_domain"
    EMAIL_SUBJECT = "email_subject"
    EMAIL_BODY = "email_body"
    URL = "url"
    LOCAL_PORT = "local_port"
    REMOTE_PORT = "remote_port"
    PROTOCOL = "protocol"
    INBOUND_BYTES = "inbound_bytes"
    OUTBOUND_BYTES = "outbound_bytes"
    APP = "app"
    OS = "os"
    USER = "user"
    CVE = "cve"
    FILE_NAME = "file_name"
    FILE_HASH = "file_hash"
    WIN_CMD = "win_cmd"
    UNIX_CMD = "unix_cmd"
    WIN_PROCESS = "win_process"
    WIN_CHILD_PROCESS = "win_child_process"
    UNIX_PROCESS = "unix_process"
    UNIX_CHILD_PROCESS = "unix_child_process"
    TECHNIQUE = "technique"
    ENTRY_TYPE = "entry_type"
    SEVERITY = "severity"
    SENSOR = "sensor"
    ACTION = "action"
    EVENT_ID = "event_id"
    ERROR_CODE = "error_code"
    TERMS = "terms"
    INCIDENT_TYPES = "incident_types"
    ANALYSTS = "analysts"
    ALERT_TYPES = "alert_types"
    ALERT_NAME = "alert_name"
    ACTION_STATUS = "action_status"
    QUERY_TYPE = "query_type"
    DATABASE_NAME = "database_name"
    QUERY = "query"
    USER_AGENT = "user_agent"
    REFERER = "referer"
    RESPONSE_CODE = "response_code"
    RESPONSE_SIZE = "response_size"
    ATTACK_TYPE = "attack_type"
    COOKIES = "cookies"
    GUID = "guid"
    TRANSMITTED_SERVICES = "transmitted_services"
    PROCESS_ID = "process_id"
    NEW_PROCESS_ID = "new_process_id"
    THREAD_ID = "thread_id"
    TARGET_PID = "target_pid"
    SUBJECT_LOGIN_ID = "subject_login_id"
    WIN_USER_ID = "win_user_id"
    DESTINATION_LOGIN_ID = "destination_login_id"
    PRIVILEGE_LIST = "privilege_list"
    EVENT_RECORD_ID = "event_record_id"
    SPAM_SCORE = "spam_score"
    SOURCE_NETWORK_ADDRESS = "source_network_address"
    ATTACHMENT_HASH = "attachment_hash"
    DURATION = "duration"
    LOG_ID = "log_id"
    PID = "pid"
    RULE_ID = "rule_id"
    DST_URL = "dst_url"
    METHOD = "method"

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
    required_fields: Optional[List[RequiredFieldEnum]] = None


@strawberry.type(description="Output object containing the generated fake data.")
class DataFakerOutput:
    data: List[JSON]
    type: str
    count: int


@strawberry.input(description="Scenario step object for generating fake scenario data.")
class DetailedScenarioStep:
    tactic: Optional[str] = None
    tactic_id: Optional[str] = None
    technique: Optional[str] = None
    technique_id:Optional[str] = None
    type: Optional[str] = None
    logs: List[DataFakerInput]


@strawberry.input(description="Scenario input object for generating fake scenario data.")
class DetailedScenarioInput:
    name: str
    tags:  Optional[List[str]] = None
    steps: List[DetailedScenarioStep]


@strawberry.type(description="Output object containing the generated fake data.")
class DetailedScenarioOutput:
    steps: List[JSON]
    name: str
    tags: Optional[List[str]] = None