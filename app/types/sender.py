import strawberry
from enum import Enum
from typing import Optional, List


@strawberry.enum(description="Enum representing the types of workers.")
class WorkerTypeEnum(Enum):
    SYSLOG = 'syslog'
    CEF = 'cef'
    LEEF = 'leef'
    WINEVENT = 'winevent'
    JSON = 'json'


@strawberry.enum(description="Enum representing the actions for a worker.")
class WorkerActionEnum(Enum):
    STOP = 'stop'
    STATUS = 'status'


@strawberry.input(description="Input object for creating a data worker.")
class DataWorkerCreateInput:
    type: WorkerTypeEnum
    count: int = 1
    destination: str
    fields: Optional[List[str]] = None
    observables_list: Optional[List[str]] = None
    interval: int = 2


@strawberry.input(description="Input object for performing an action on a data worker.")
class DataWorkerActionInput:
    worker: str
    action: WorkerActionEnum


@strawberry.type(description="Output object containing information about a data worker.")
class DataWorkerOutput:
    type: WorkerTypeEnum
    worker: str
    status: str
    destination: str
    createdAt: str


@strawberry.type(description="Output object containing status information about a data worker.")
class DataWorkerStatusOutput:
    worker: str
    status: str
