import strawberry
from enum import Enum
from typing import Optional, List
from strawberry.scalars import JSON

from app.schema_loader import build_enum, build_input_class, load_supported_fields

@strawberry.enum(description="Enum representing the type of observable to generate.")
class ObservableTypeEnum(Enum):
    IP = "ip"
    URL = "url"
    SHA256 = "sha256"
    CVE = "cve"
    TERMS = "terms"


@strawberry.enum(description="Enum representing whether the observable is known malicious or benign.")
class ObservableKnownEnum(Enum):
    BAD = "bad"
    GOOD = "good"

_SUPPORTED_FIELDS = load_supported_fields()
RequiredFieldEnum = build_enum(
    "RequiredFieldEnum",
    _SUPPORTED_FIELDS,
    description="Enum representing the types of required fields.",
)

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


ObservablesInput = build_input_class(
    "ObservablesInput",
    _SUPPORTED_FIELDS,
    description="Data observables dictionary.",
)

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


@strawberry.input(description="Input object for generating observables from threat intel feeds.")
class GenerateObservablesInput:
    count: int
    observable_type: ObservableTypeEnum
    known: Optional[ObservableKnownEnum] = ObservableKnownEnum.BAD


@strawberry.type(description="Output object containing generated observables.")
class GenerateObservablesOutput:
    observables: List[str]
    observable_type: str
    known: str
    count: int
