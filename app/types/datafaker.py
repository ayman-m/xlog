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


@strawberry.input(description="Input object for generating fake data.")
class DataFakerInput:
    type: FakerTypeEnum
    vendor: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    count: Optional[int] = 1
    timestamp: Optional[str] = None
    fields: Optional[str] = None
    observables_dict: Optional[JSON] = None


@strawberry.type(description="Output object containing the generated fake data.")
class DataFakerOutput:
    data: List[JSON]
    type: str
    count: int
