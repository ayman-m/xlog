import strawberry
from typing import List, Optional

@strawberry.type
class TacticInput:
    name: str
    description: Optional[str] = None
    type: str  # e.g., 'CEF', 'JSON', etc.
    count: int
    interval: int
    required_fields: Optional[str] = None
    fields: Optional[str] = None
    observables: Optional[dict] = None

@strawberry.type
class ScenarioInput:
    name: str
    description: Optional[str] = None
    tactics: List[TacticInput]
