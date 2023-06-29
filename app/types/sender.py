import strawberry
from enum import Enum
from typing import Optional, List
from strawberry.scalars import JSON


@strawberry.enum(description="Enum representing the types of workers.")
class WorkerTypeEnum(Enum):
    SYSLOG = 'syslog'
    CEF = 'cef'
    LEEF = 'leef'
    WINEVENT = 'winevent'
    JSON = 'json'
    INCIDENT = 'incident'


@strawberry.enum(description="Enum representing the actions for a worker.")
class WorkerActionEnum(Enum):
    STOP = 'stop'
    STATUS = 'status'


@strawberry.input(description="Input object for creating a data worker.")
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
    timestamp: Optional[str] = None
    verify_ssl: Optional[bool] = False


@strawberry.input(description="Input object for performing an action on a data worker.")
class DataWorkerActionInput:
    worker: str
    action: WorkerActionEnum


@strawberry.type(description="Output object containing information about a data worker.")
class DataWorkerOutput:
    type: str
    worker: str
    status: str
    count: str
    interval: str
    verifySsl: str
    destination: str
    createdAt: str


@strawberry.type(description="Output object containing status information about a data worker.")
class DataWorkerStatusOutput:
    worker: str
    status: str
