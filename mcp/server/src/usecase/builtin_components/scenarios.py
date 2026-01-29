"""MCP tools for managing XLog scenarios."""

import logging
import ast
import json
from typing import Any, Dict, List, Optional

from fastmcp import Context
from pydantic import BaseModel, Field

from pkg.graphql_client import XLogGraphQLClient

logger = logging.getLogger("XLog MCP")


class ScenarioStep(BaseModel):
    """Model for scenario step."""

    tactic: Optional[str] = Field(default=None, description="MITRE ATT&CK tactic name. Example: 'discovery'")
    tactic_id: Optional[str] = Field(default=None, description="MITRE ATT&CK tactic ID. Example: 'TA0007'")
    technique: Optional[str] = Field(
        default=None,
        description="MITRE ATT&CK technique name or ID. Example: 'T1046' or 'Network Service Discovery'",
    )
    technique_id: Optional[str] = Field(default=None, description="MITRE ATT&CK technique ID. Example: 'T1046'")
    procedure: Optional[str] = Field(
        default=None,
        description="Procedure description. Example: 'Internal Network Port Scan'",
    )
    type: Optional[str] = Field(default=None, description="Optional step type label. Example: 'network-scan'")
    logs: List[Dict[str, Any]] = Field(
        description=(
            "Log configuration objects for this step. Each log entry supports: "
            "type, vendor, product, version, count, datetimeIso, fields, requiredFields, observablesDict. "
            "Use camelCase for observablesDict keys (e.g., 'remoteIP', 'srcHost')."
        )
    )


class GenerateScenarioRequest(BaseModel):
    """Request model for generating scenario fake data."""

    name: str = Field(description="Scenario name. Example: 'Internal Port Scan and Lateral Movement'")
    tags: Optional[List[str]] = Field(
        default=None,
        description="Tags for categorizing the scenario. Example: ['attack-simulation', 'lateral-movement']",
    )
    steps: List[ScenarioStep] = Field(
        description=(
            "List of scenario steps with log configurations. Each step can contain one or more log entries."
        )
    )


_OBSERVABLE_SNAKE_KEYS = [
    "local_ip",
    "remote_ip",
    "local_ip_v6",
    "remote_ip_v6",
    "source_port",
    "remote_port",
    "protocol",
    "src_host",
    "dst_host",
    "src_domain",
    "dst_domain",
    "sender_email",
    "recipient_email",
    "email_subject",
    "email_body",
    "url",
    "inbound_bytes",
    "outbound_bytes",
    "app",
    "os",
    "user",
    "cve",
    "file_name",
    "file_hash",
    "win_cmd",
    "unix_cmd",
    "win_process",
    "win_child_process",
    "unix_process",
    "unix_child_process",
    "technique",
    "entry_type",
    "severity",
    "sensor",
    "action",
    "event_id",
    "error_code",
    "terms",
    "incident_types",
    "analysts",
    "alert_types",
    "alert_name",
    "action_status",
    "query_type",
    "database_name",
    "query",
]


def _snake_to_camel(value: str, upper_ip: bool) -> str:
    parts = value.split("_")
    if not parts:
        return value
    converted = [parts[0]]
    for token in parts[1:]:
        if token == "ip":
            converted.append("IP" if upper_ip else "Ip")
        elif token in {"v6", "v4"}:
            converted.append(token.upper())
        else:
            converted.append(token.capitalize())
    return "".join(converted)


_OBSERVABLE_KEY_MAP = {key: _snake_to_camel(key, upper_ip=True) for key in _OBSERVABLE_SNAKE_KEYS}
_OBSERVABLE_KEY_MAP.update(
    {key: _snake_to_camel(key, upper_ip=False) for key in _OBSERVABLE_SNAKE_KEYS}
)
_OBSERVABLE_KEY_MAP["remorePort"] = "remotePort"


def _normalize_observable_keys(values: Dict[str, Any]) -> Dict[str, Any]:
    normalized: Dict[str, Any] = {}
    for key, value in values.items():
        mapped_key = _OBSERVABLE_KEY_MAP.get(key, key)
        normalized[mapped_key] = value
    return normalized


def _load_string_value(raw: str) -> Any:
    value = raw.strip()
    if not value:
        return None
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        try:
            return ast.literal_eval(value)
        except (ValueError, SyntaxError):
            return value


def _parse_required_fields(value: Any) -> Optional[List[str]]:
    if value is None:
        return None
    if isinstance(value, list):
        return [str(item).strip().upper() for item in value if str(item).strip()]
    if isinstance(value, str):
        loaded = _load_string_value(value)
        if loaded is None:
            return None
        if isinstance(loaded, list):
            return [str(item).strip().upper() for item in loaded if str(item).strip()]
        if isinstance(loaded, str):
            parts = [item.strip().upper() for item in loaded.split(",") if item.strip()]
            return parts or None
    return None


def _parse_fields(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, list):
        parts = [str(item).strip() for item in value if str(item).strip()]
        return ",".join(parts) if parts else None
    if isinstance(value, str):
        loaded = _load_string_value(value)
        if loaded is None:
            return None
        if isinstance(loaded, list):
            parts = [str(item).strip() for item in loaded if str(item).strip()]
            return ",".join(parts) if parts else None
        if isinstance(loaded, str):
            return loaded.strip() or None
    return None


def _parse_observables_dict(value: Any) -> Optional[Dict[str, Any]]:
    if value is None:
        return None
    if isinstance(value, dict):
        return _normalize_observable_keys(value)
    if isinstance(value, str):
        loaded = _load_string_value(value)
        if loaded is None:
            return None
        if isinstance(loaded, dict):
            return _normalize_observable_keys(loaded)
    return None


def _normalize_log_entry(log_entry: Dict[str, Any]) -> Dict[str, Any]:
    normalized = dict(log_entry)

    if "type" in normalized and isinstance(normalized["type"], str):
        normalized["type"] = normalized["type"].upper()

    if "datetime_iso" in normalized and "datetimeIso" not in normalized:
        normalized["datetimeIso"] = normalized.pop("datetime_iso")

    if "required_fields" in normalized and "requiredFields" not in normalized:
        normalized["requiredFields"] = normalized.pop("required_fields")
    if "requiredFields" in normalized:
        parsed_required = _parse_required_fields(normalized["requiredFields"])
        if parsed_required:
            normalized["requiredFields"] = parsed_required
        else:
            normalized.pop("requiredFields", None)

    if "observables_dict" in normalized and "observablesDict" not in normalized:
        normalized["observablesDict"] = normalized.pop("observables_dict")
    if "observablesDict" in normalized:
        parsed_observables = _parse_observables_dict(normalized["observablesDict"])
        if parsed_observables:
            normalized["observablesDict"] = parsed_observables
        else:
            normalized.pop("observablesDict", None)

    if "fields" in normalized:
        parsed_fields = _parse_fields(normalized["fields"])
        if parsed_fields:
            normalized["fields"] = parsed_fields
        else:
            normalized.pop("fields", None)

    return normalized


class CreateScenarioWorkerRequest(BaseModel):
    """Request model for creating scenario workers from a query."""

    name: str = Field(description="Scenario name. Example: 'Internal Port Scan and Lateral Movement'")
    destination: str = Field(
        description=(
            "Destination for logs (e.g., udp:host:port, tcp:host:port, or 'XSIAM_WEBHOOK'). "
            "Use 'XSIAM_WEBHOOK' to send each log as a separate webhook event using WEBHOOK_ENDPOINT/WEBHOOK_KEY "
            "configured on the XLog service. Example: 'tcp:192.168.20.235:5115'"
        )
    )
    tags: Optional[List[str]] = Field(
        default=None,
        description="Scenario tags. Example: ['attack-simulation', 'lateral-movement']",
    )
    steps: List[ScenarioStep] = Field(
        description=(
            "Scenario steps with logs (same structure as xlog_generate_scenario_fake_data). "
            "Observables should use camelCase keys (e.g., 'srcHost', 'remotePort')."
        ),
    )


async def xlog_generate_scenario_fake_data(request: GenerateScenarioRequest, ctx: Context) -> Dict[str, Any]:
    """
    Generate fake data for a complete attack scenario with multiple steps.

    This tool generates synthetic log data for a multi-step attack scenario, typically
    following the MITRE ATT&CK framework with tactics, techniques, and procedures.

    Observables:
    - Use camelCase keys in observablesDict (e.g., 'remoteIP', 'srcHost', 'winProcess').
    - Use xlog_get_field_info for the full observable catalog and field support by log type.

    Usage Example:
    {
      "name": "Internal Port Scan and Lateral Movement",
      "tags": ["attack-simulation", "internal-discovery", "lateral-movement"],
      "steps": [
        {
          "tactic": "discovery",
          "technique": "T1046",
          "procedure": "Internal Network Port Scan",
          "logs": [
            {
              "type": "CEF",
              "vendor": "Xlog",
              "product": "EDR",
              "version": "1.0",
              "count": 35,
              "datetimeIso": "2024-01-02 08:00:00",
              "observablesDict": {
                "srcHost": ["192.168.10.15"],
                "dstHost": ["192.168.10.1", "192.168.10.2"],
                "winProcess": ["portscan.exe"],
                "protocol": ["TCP"],
                "remotePort": ["80", "445", "22"]
              },
              "requiredFields": ["SRC_HOST", "DST_HOST", "WIN_PROCESS", "PROTOCOL", "REMOTE_PORT", "USER"]
            }
          ]
        }
      ]
    }

    Example MCP tool call:
    {
      "method": "tools/call",
      "params": {
        "name": "xlog_generate_scenario_fake_data",
        "arguments": {
          "request": {
            "name": "Internal Port Scan and Lateral Movement",
            "tags": ["attack-simulation", "internal-discovery", "lateral-movement"],
            "steps": [
              {
                "tactic": "discovery",
                "technique": "T1046",
                "procedure": "Internal Network Port Scan",
                "logs": [
                  {
                    "type": "CEF",
                    "vendor": "Xlog",
                    "product": "EDR",
                    "version": "1.0",
                    "count": 10,
                    "datetimeIso": "2024-01-02 08:00:00",
                    "observablesDict": {
                      "srcHost": ["192.168.10.15"],
                      "dstHost": ["192.168.10.1"],
                      "remotePort": ["80", "445"],
                      "protocol": ["TCP"]
                    },
                    "requiredFields": ["SRC_HOST", "DST_HOST", "REMOTE_PORT", "PROTOCOL"]
                  }
                ]
              }
            ]
          }
        }
      }
    }

    Args:
        request: Scenario generation parameters
        ctx: MCP context containing XLog URL

    Returns:
        Dictionary containing scenario name, tags, and generated steps with logs
    """
    lifespan_context = ctx.request_context.lifespan_context
    client = XLogGraphQLClient(lifespan_context["xlog_url"])

    query = """
    query GenerateScenarioFakeData($name: String!, $tags: [String!], $steps: [DetailedScenarioStep!]!) {
      generateScenarioFakeData(requestInput: {
        name: $name
        tags: $tags
        steps: $steps
      }) {
        name
        tags
        steps
      }
    }
    """

    steps_payload = []
    for step in request.steps:
        step_payload = step.model_dump(exclude_none=True)
        logs = step_payload.get("logs", [])
        normalized_logs = [
            _normalize_log_entry(log) if isinstance(log, dict) else log for log in logs
        ]
        step_payload["logs"] = normalized_logs
        steps_payload.append(step_payload)

    variables = {
        "name": request.name,
        "tags": request.tags,
        "steps": steps_payload,
    }

    result = await client.execute_query(query, variables)
    return result.get("generateScenarioFakeData", {})


async def xlog_create_scenario_worker(request: CreateScenarioWorkerRequest, ctx: Context) -> List[Dict[str, Any]]:
    """
    Create workers from a scenario query definition.

    This tool creates multiple workers based on an inline scenario definition.
    Observables should use camelCase keys (e.g., 'srcHost', 'remotePort').
    When destination is 'XSIAM_WEBHOOK', each log is sent as a separate webhook event and
    uses WEBHOOK_ENDPOINT/WEBHOOK_KEY configured on the XLog service.

    Example MCP tool call:
    {
      "method": "tools/call",
      "params": {
        "name": "xlog_create_scenario_worker",
        "arguments": {
          "request": {
            "name": "Internal Port Scan and Lateral Movement",
            "destination": "XSIAM_WEBHOOK",
            "tags": ["attack-simulation", "internal-discovery", "lateral-movement"],
            "steps": [
              {
                "tactic": "discovery",
                "technique": "T1046",
                "procedure": "Internal Network Port Scan",
                "logs": [
                  {
                    "type": "CEF",
                    "vendor": "XLOG",
                    "product": "EDR",
                    "version": "1.0",
                    "count": 10,
                    "datetimeIso": "2024-01-02 08:00:00",
                    "observablesDict": {
                      "srcHost": ["192.168.10.15"],
                      "dstHost": ["192.168.10.1", "192.168.10.2", "192.168.10.3"],
                      "winProcess": ["portscan.exe"],
                      "protocol": ["TCP"],
                      "remotePort": ["80", "445", "22"]
                    },
                    "requiredFields": ["SRC_HOST", "DST_HOST", "WIN_PROCESS", "PROTOCOL", "REMOTE_PORT", "USER"]
                  }
                ]
              }
            ]
          }
        }
      }
    }


    Returns:
        List of created worker information dictionaries
    """
    lifespan_context = ctx.request_context.lifespan_context
    client = XLogGraphQLClient(lifespan_context["xlog_url"])

    query = """
    query CreateScenarioWorkerFromQuery($name: String!, $tags: [String!], $destination: String!,
                                        $steps: [DetailedQueryScenarioStep!]!) {
      createScenarioWorkerFromQuery(requestInput: {
        name: $name
        tags: $tags
        destination: $destination
        steps: $steps
      }) {
        count
        createdAt
        destination
        type
        worker
        status
      }
    }
    """

    steps_payload = []
    for step in request.steps:
        step_payload = step.model_dump(exclude_none=True)
        logs = step_payload.get("logs", [])
        normalized_logs = [
            _normalize_log_entry(log) if isinstance(log, dict) else log for log in logs
        ]
        step_payload["logs"] = normalized_logs
        steps_payload.append(step_payload)

    variables = {
        "name": request.name,
        "tags": request.tags,
        "destination": request.destination,
        "steps": steps_payload,
    }

    # Remove None values
    variables = {k: v for k, v in variables.items() if v is not None}

    result = await client.execute_query(query, variables)
    return result.get("createScenarioWorkerFromQuery", [])
