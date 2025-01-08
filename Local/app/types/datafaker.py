import strawberry
from enum import Enum
from typing import Optional, List
from strawberry.scalars import JSON

@strawberry.enum(description="Enum representing the types of required fields.")
class RequiredFieldEnum(Enum):
    ACTION = "action"
    ACTION_STATUS = "action_status"
    ALERT_NAME = "alert_name"
    ALERT_TYPES = "alert_types"
    ANALYSTS = "analysts"
    APP = "app"
    ATTACHMENT_HASH = "attachment_hash"
    ATTACK_TYPE = "attack_type"
    COOKIES = "cookies"
    CVE = "cve"
    DATABASE_NAME = "database_name"
    DESTINATION_LOGIN_ID = "destination_login_id"
    DURATION = "duration"
    DST_DOMAIN = "dst_domain"
    DST_HOST = "dst_host"
    DST_URL = "dst_url"
    EMAIL_BODY = "email_body"
    EMAIL_SUBJECT = "email_subject"
    ENTRY_TYPE = "entry_type"
    ERROR_CODE = "error_code"
    EVENT_ID = "event_id"
    EVENT_RECORD_ID = "event_record_id"
    FILE_HASH = "file_hash"
    FILE_NAME = "file_name"
    GUID = "guid"
    INCIDENT_TYPES = "incident_types"
    INBOUND_BYTES = "inbound_bytes"
    LOCAL_IP = "local_ip"
    LOCAL_IP_V6 = "local_ip_v6"
    LOCAL_PORT = "local_port"
    LOG_ID = "log_id"
    METHOD = "method"
    NEW_PROCESS_ID = "new_process_id"
    OS = "os"
    OUTBOUND_BYTES = "outbound_bytes"
    PID = "pid"
    PRIVILEGE_LIST = "privilege_list"
    PROCESS_ID = "process_id"
    PROTOCOL = "protocol"
    QUERY = "query"
    QUERY_TYPE = "query_type"
    RECIPIENT_EMAIL = "recipient_email"
    REFERER = "referer"
    REMOTE_IP = "remote_ip"
    REMOTE_IP_V6 = "remote_ip_v6"
    REMOTE_PORT = "remote_port"
    RESPONSE_CODE = "response_code"
    RESPONSE_SIZE = "response_size"
    RULE_ID = "rule_id"
    SEVERITY = "severity"
    SENDER_EMAIL = "sender_email"
    SENSOR = "sensor"
    SOURCE_NETWORK_ADDRESS = "source_network_address"
    SPAM_SCORE = "spam_score"
    SRC_DOMAIN = "src_domain"
    SRC_HOST = "src_host"
    SUBJECT_LOGIN_ID = "subject_login_id"
    TARGET_PID = "target_pid"
    TECHNIQUE = "technique"
    TERMS = "terms"
    THREAD_ID = "thread_id"
    TRANSMITTED_SERVICES = "transmitted_services"
    URL = "url"
    USER = "user"
    USER_AGENT = "user_agent"
    WIN_CHILD_PROCESS = "win_child_process"
    WIN_CMD = "win_cmd"
    WIN_PROCESS = "win_process"
    WIN_USER_ID = "win_user_id"
    UNIX_CHILD_PROCESS = "unix_child_process"
    UNIX_CMD = "unix_cmd"
    UNIX_PROCESS = "unix_process"


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
    procedure:Optional[str] = None
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