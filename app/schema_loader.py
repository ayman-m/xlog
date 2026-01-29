import json
import os
import re
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import List, Optional, Type

import strawberry


SCHEMA_DIR = Path(__file__).resolve().parent / "schem"


@lru_cache
def load_schema_list(name: str) -> List[str]:
    path = SCHEMA_DIR / f"{name}.json"
    if not path.exists():
        raise FileNotFoundError(f"Schema file not found: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list) or not all(isinstance(item, str) for item in data):
        raise ValueError(f"Schema file must contain a list of strings: {path}")
    return data


@lru_cache
def load_supported_fields() -> List[str]:
    from rosetta import Events

    values = Events.get_supported_fields()
    if isinstance(values, list) and all(isinstance(item, str) for item in values) and values:
        return values

    fallback_path = os.getenv("SUPPORTED_FIELDS_PATH", str(SCHEMA_DIR / "supported_fields.json"))
    fallback = Path(fallback_path)
    if fallback.exists():
        data = json.loads(fallback.read_text(encoding="utf-8"))
        if isinstance(data, list) and all(isinstance(item, str) for item in data) and data:
            return data

    raise ValueError("Supported fields list is empty. Check Rosetta or SUPPORTED_FIELDS_PATH.")


@lru_cache
def load_schema_dict(name: str) -> dict:
    path = SCHEMA_DIR / f"{name}.json"
    if not path.exists():
        raise FileNotFoundError(f"Schema file not found: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Schema file must contain an object: {path}")
    return data


def build_enum(name: str, values: List[str], description: str):
    members = {}
    for value in values:
        key = re.sub(r"[^A-Z0-9_]", "_", value.upper())
        if key in members:
            raise ValueError(f"Duplicate enum key {key} for value {value}")
        members[key] = value
    enum_cls = Enum(name, members)
    return strawberry.enum(enum_cls, description=description)


def build_input_class(name: str, fields: List[str], description: str):
    annotations = {field: Optional[List[str]] for field in fields}
    namespace = {"__annotations__": annotations}
    for field in fields:
        namespace[field] = None
    cls = type(name, (), namespace)
    return strawberry.input(cls, description=description)
