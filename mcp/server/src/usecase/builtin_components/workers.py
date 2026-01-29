"""MCP tools for managing XLog workers."""

import ast
import json
import logging
from typing import Any, Dict, List, Optional, Union

from fastmcp import Context
from pydantic import BaseModel, Field

from pkg.graphql_client import XLogGraphQLClient

logger = logging.getLogger("XLog MCP")


class CreateDataWorkerRequest(BaseModel):
    """Request model for creating a data worker."""

    type: str = Field(
        description=(
            "Worker log type (SYSLOG, CEF, LEEF and JSON ). "
            "Example: 'CEF'"
        )
    )
    destination: str = Field(
        description=(
            "Destination (e.g., udp:127.0.0.1:514, tcp:127.0.0.1:514, or 'XSIAM_WEBHOOK'). "
            "Use 'XSIAM' for PAPI ingestion and 'XSIAM_WEBHOOK' for the HTTP collector (uses WEBHOOK_ENDPOINT/WEBHOOK_KEY "
            "configured on the XLog service). Example: 'udp:127.0.0.1:514'"
        )
    )
    count: int = Field(default=1, description="Number of logs per batch. Example: 100")
    interval: int = Field(default=2, description="Interval in seconds between batches. Example: 1")
    vendor: Optional[str] = Field(default=None, description="Vendor name. Example: 'Xlog'")
    product: Optional[str] = Field(default=None, description="Product name. Example: 'EDR'")
    version: Optional[str] = Field(default=None, description="Version. Example: '1.0'")
    fields: Optional[Union[str, List[str]]] = Field(
        default=None,
        description=(
            "Custom fields to include. Accepts a comma-separated string or JSON list. "
            "Example: 'custom1,custom2' or [\"custom1\", \"custom2\"]"
        ),
    )
    datetime_iso: Optional[str] = Field(
        default=None,
        description="Timestamp in ISO format. Example: '2024-01-02 08:00:00'",
    )
    observables_dict: Optional[Union[Dict[str, List[str]], str]] = Field(
        default=None,
        description=(
            "Observables dictionary (camelCase keys) , you can use xlog_get_field_info to retrieve the full observable catalog. "
            "Example: {'srcHost': ['192.168.10.15'], 'remotePort': ['443']}"
        ),
    )
    required_fields: Optional[Union[List[str], str]] = Field(
        default=None,
        description=(
            "Required field enums as list , you can use xlog_get_field_info to retrieve the required fields for each log type. "
            "Example: ['SRC_HOST', 'DST_HOST', 'REMOTE_PORT']"
        ),
    )
    verify_ssl: bool = Field(
        default=False,
        description="Verify SSL certificates for HTTPS destinations (ignored in scenario worker mode).",
    )
    name: Optional[str] = Field(
        default=None,
        description="Scenario name (used to create the worker). Example: 'Single Worker Scenario'",
    )
    tags: Optional[List[str]] = Field(
        default=None,
        description="Scenario tags. Example: ['worker', 'single-step']",
    )
    tactic: Optional[str] = Field(default=None, description="MITRE ATT&CK tactic. Example: 'discovery'")
    technique: Optional[str] = Field(default=None, description="MITRE ATT&CK technique. Example: 'T1046'")
    procedure: Optional[str] = Field(default=None, description="Procedure description. Example: 'Port Scan'")


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


async def xlog_create_data_worker(request: CreateDataWorkerRequest, ctx: Context) -> List[Dict[str, Any]]:
    """
    Create a data worker to continuously send fake logs to a destination.

    This tool creates a worker that generates and sends fake log data at regular intervals
    to a specified destination. Supports UDP Syslog, TCP Syslog  and XSIAM Webhook.

    This tool uses the XLog API to start a data worker. You can get the supported log types,
    required fields, and observable catalog using the xlog_get_field_info tool.
    Observables must use camelCase keys (e.g., 'srcHost', 'remotePort').
    When destination is 'XSIAM_WEBHOOK', each log is sent as a separate webhook event and
    uses WEBHOOK_ENDPOINT/WEBHOOK_KEY configured on the XLog service.

    Example MCP tool call:
    {
      "method": "tools/call",
      "params": {
        "name": "xlog_create_data_worker",
        "arguments": {
          "request": {
            "type": "CEF",
            "destination": "XSIAM_WEBHOOK",
            "count": 100,
            "interval": 1,
            "vendor": "Xlog",
            "product": "EDR",
            "datetime_iso": "2024-01-02 08:00:00",
            "observables_dict": {
              "srcHost": ["192.168.10.15"],
              "dstHost": ["192.168.10.1"],
              "remotePort": ["80", "445"],
              "protocol": ["TCP"]
            },
            "required_fields": ["SRC_HOST", "DST_HOST", "REMOTE_PORT", "PROTOCOL"],
            "name": "Single Worker Scenario",
            "tags": ["worker", "single-step"],
            "tactic": "discovery",
            "technique": "T1046",
            "procedure": "Internal Network Port Scan"
          }
        }
      }
    }

    Returns:
        List of worker information dictionaries (worker ID, type, status, count, interval, etc.)
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
        worker
        type
        status
        count
        interval
        destination
        createdAt
      }
    }
    """

    required_fields = _parse_required_fields(request.required_fields)
    observables_dict = _parse_observables_dict(request.observables_dict)
    fields = _parse_fields(request.fields)

    # DEBUG LOGGING: Track observable mapping
    logger.info(f"[MCP-DEBUG] Raw request.observables_dict: {request.observables_dict}")
    logger.info(f"[MCP-DEBUG] Normalized observables_dict: {observables_dict}")
    logger.info(f"[MCP-DEBUG] Required fields: {required_fields}")

    log_entry: Dict[str, Any] = {
        "type": request.type.upper(),
        "vendor": request.vendor,
        "product": request.product,
        "version": request.version,
        "count": request.count,
        "interval": request.interval,
        "datetimeIso": request.datetime_iso,
        "fields": fields,
        "observablesDict": observables_dict,
        "requiredFields": required_fields,
    }
    log_entry = {k: v for k, v in log_entry.items() if v is not None}

    step_payload = {
        "tactic": request.tactic,
        "technique": request.technique,
        "procedure": request.procedure,
        "logs": [log_entry],
    }
    step_payload = {k: v for k, v in step_payload.items() if v is not None}

    variables = {
        "name": request.name or "Single Worker Scenario",
        "tags": request.tags,
        "destination": request.destination,
        "steps": [step_payload],
    }

    # Remove None values
    variables = {k: v for k, v in variables.items() if v is not None}

    result = await client.execute_query(query, variables)
    return result.get("createScenarioWorkerFromQuery", [])


async def xlog_list_workers(ctx: Context) -> List[Dict[str, Any]]:
    """
    List all active workers.

    This tool retrieves information about all currently running workers.

    Example MCP tool call:
    {
      "method": "tools/call",
      "params": {
        "name": "xlog_list_workers",
        "arguments": {}
      }
    }

    Args:
        ctx: MCP context containing XLog URL

    Returns:
        List of worker information dictionaries
    """
    lifespan_context = ctx.request_context.lifespan_context
    client = XLogGraphQLClient(lifespan_context["xlog_url"])

    query = """
    query ListWorkers {
      listWorkers {
        destination
        status
        type
        count
        interval
        worker
        createdAt
      }
    }
    """

    result = await client.execute_query(query)
    return result.get("listWorkers", [])
