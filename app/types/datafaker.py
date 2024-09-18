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


@strawberry.input(description="Input object for generating fake data.")
class DataFakerInput:
    type: FakerTypeEnum
    vendor: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    count: Optional[int] = 1
    datetime_iso: Optional[str] = None
    fields: Optional[str] = None
    observables_dict: Optional[JSON] = None
    required_fields: Optional[str] = None


@strawberry.type(description="Output object containing the generated fake data.")
class DataFakerOutput:
    data: List[JSON]
    type: str
    count: int

@strawberry.input(description="Data observables dictionary.")
class ObservablesInput:
    sender_email: Optional[str] = None
    recipient_email: Optional[str] = None
    email_subject: Optional[str] = None
    email_body: Optional[str] = None
    file_name: Optional[str] = None
    file_hash: Optional[str] = None
    action: Optional[str] = None
    host: Optional[List[str]] = None
    local_ip: Optional[List[str]] = None
    win_process: Optional[List[str]] = None
    win_child_process: Optional[List[str]] = None
    win_cmd: Optional[List[str]] = None
    user: Optional[List[str]] = None
    remote_ip: Optional[List[str]] = None
    remote_port: Optional[List[str]] = None
    unix_process: Optional[List[str]] = None
    src_host: Optional[List[str]] = None
    # Add any other observables as needed
