import strawberry
from enum import Enum
from typing import Optional, List
from strawberry.scalars import JSON

from app.schema_loader import build_enum, build_input_class, load_supported_fields


_SUPPORTED_FIELDS = load_supported_fields()
WorkerObservablesInput = build_input_class(
    "WorkerObservablesInput",
    _SUPPORTED_FIELDS,
    description="Data observables dictionary.",
)

WorkerRequiredFieldEnum = build_enum(
    "WorkerRequiredFieldEnum",
    _SUPPORTED_FIELDS,
    description="Enum representing the types of required fields.",
)

@strawberry.enum(description="Enum representing the types of workers.")
class WorkerTypeEnum(Enum):
    SYSLOG = 'syslog'
    CEF = 'cef'
    LEEF = 'leef'
    WINEVENT = 'winevent'
    JSON = 'json'
    Incident = 'incident'
    XSIAM_Parsed = 'xsiam_parsed'
    XSIAM_CEF = 'xsiam_cef'


@strawberry.enum(description="Enum representing the actions for a worker.")
class WorkerActionEnum(Enum):
    STOP = 'stop'
    STATUS = 'status'


@strawberry.input(description="Input object for creating a data worker. Destination supports XSIAM_WEBHOOK.")
class DataWorkerCreateInput:
    type: WorkerTypeEnum
    count: int = 1
    interval: int = 2
    destination: str
    fields: Optional[str] = None
    vendor: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    observables_dict: Optional[JSON] = None
    required_fields: Optional[str] = None
    datetime_iso: Optional[str] = None
    verify_ssl: Optional[bool] = False


@strawberry.input(description="Input object for creating a scenario worker. Destination supports XSIAM_WEBHOOK.")
class ScenarioWorkerCreateInput:
    count: int = 1
    interval: int = 2
    scenario: str
    destination: str
    vendor: Optional[str] = None
    datetime_iso: Optional[str] = None
    verify_ssl: Optional[bool] = False


@strawberry.input(description="Input object for performing an action on a data worker.")
class DataWorkerActionInput:
    worker: str
    action: WorkerActionEnum


@strawberry.type(description="Output object containing information about a data worker.")
class WorkerOutput:
    type: str
    worker: str
    status: str
    count: str
    interval: str
    verifySsl: str
    destination: str
    createdAt: str


@strawberry.type(description="Output object containing status information about a data worker.")
class WorkerStatusOutput:
    worker: str
    status: str

@strawberry.input(description="Input object for generating fake data.")
class WorkerFakerInput:
    type: WorkerTypeEnum
    vendor: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    count: int = 1
    interval: int = 2
    datetime_iso: Optional[str] = None
    fields: Optional[str] = None
    observables_dict: Optional[WorkerObservablesInput] = None
    required_fields: Optional[List[WorkerRequiredFieldEnum]] = None
    verify_ssl: Optional[bool] = False

@strawberry.input(description="Scenario step object for generating fake scenario data.")
class DetailedQueryScenarioStep:
    tactic: Optional[str] = None
    tactic_id: Optional[str] = None
    technique: Optional[str] = None
    technique_id:Optional[str] = None
    procedure:Optional[str] = None
    type: Optional[str] = None
    logs: List[WorkerFakerInput]


@strawberry.input(description="Input object for creating a scenario worker from a query. Destination supports XSIAM_WEBHOOK.")
class ScenarioQueryWorkerCreateInput:
    name: str
    destination: str
    tags:  Optional[List[str]] = None
    steps: List[DetailedQueryScenarioStep]
