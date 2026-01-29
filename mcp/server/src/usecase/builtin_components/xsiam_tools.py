"""XSIAM tools ported from advanced-mcp for enrichment, lookups, and XQL references."""

import asyncio
import json
import time
import socket
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx
from fastmcp import Context
from pydantic import BaseModel, Field

from config.config import get_config
from pkg.papi_client import Fetcher
from pkg.xql_rag_service import XqlRagService


def _create_response(data: dict, is_error: bool = False) -> dict:
    if "success" not in data:
        data["success"] = not is_error
    return data


def _get_fetcher() -> Fetcher:
    config = get_config()
    if not config.papi_url_env_key:
        raise ValueError("CORTEX_MCP_PAPI_URL is required")
    if not config.papi_auth_header_key or not config.papi_auth_id_key:
        raise ValueError("CORTEX_MCP_PAPI_AUTH_HEADER and CORTEX_MCP_PAPI_AUTH_ID are required")

    base_url = config.papi_url_env_key.rstrip("/")
    if "/public_api" in base_url:
        if not base_url.endswith("/public_api/v1"):
            base_url = base_url.split("/public_api")[0].rstrip("/") + "/public_api/v1"
    else:
        base_url = f"{base_url}/public_api/v1"

    return Fetcher(base_url, config.papi_auth_header_key, config.papi_auth_id_key)


def _get_resources_dir() -> Path:
    module_dir = Path(__file__).resolve().parents[3]
    resources_dir = module_dir / "resources"
    if resources_dir.exists():
        return resources_dir
    return Path("/app/resources")


class RunXqlQueryRequest(BaseModel):
    """Request model for running XQL queries."""

    query: str = Field(description="XQL query to execute. Use get_xql_doc and get_dataset_fields for syntax help.")


class GetCasesRequest(BaseModel):
    """Request model for searching cases."""

    query: str = Field(description="Search query for cases (e.g., 'severity:high AND status:new').")


class WebhookLogRequest(BaseModel):
    """Request model for sending webhook logs to XSIAM."""

    message: str = Field(description="Log message/body to send to the XSIAM HTTP custom collector.")
    event_type: Optional[str] = Field(
        default="mcp_event",
        description="Logical event type/name. Example: 'mcp_event'",
    )
    severity: Optional[str] = Field(
        default="info",
        description="Severity label (info|warning|error). Example: 'info'",
    )
    metadata_json: Optional[str] = Field(
        default=None,
        description="Optional JSON metadata payload to include.",
    )


class LookupDataRequest(BaseModel):
    """Request model for adding lookup data."""

    dataset_name: str = Field(description="Name of the lookup dataset to add data to.")
    data: List[Dict[str, Any]] = Field(description="List of records to add (each record is a dict).")
    key_fields: Optional[List[str]] = Field(default=None, description="Optional unique key fields.")


class GetLookupDataRequest(BaseModel):
    """Request model for retrieving lookup data."""

    dataset_name: str = Field(description="Name of the lookup dataset to query.")
    filters: Optional[List[Dict[str, Any]]] = Field(
        default=None,
        description="Filter conditions (field, operator, value).",
    )
    limit: int = Field(default=20, ge=1, le=1000, description="Max records (1-1000).")


class RemoveLookupDataRequest(BaseModel):
    """Request model for removing lookup data."""

    dataset_name: str = Field(description="Name of the lookup dataset.")
    filters: List[Dict[str, Any]] = Field(description="Filter conditions to identify records to delete.")


class CreateDatasetRequest(BaseModel):
    """Request model for creating a dataset."""

    dataset_name: str = Field(description="Name for new dataset (lowercase with underscores).")
    dataset_schema: Dict[str, Any] = Field(description="Schema definition with field types.")
    dataset_type: str = Field(default="lookup", description="Dataset type (default: lookup).")


class FindXqlExamplesRequest(BaseModel):
    """Request model for XQL RAG search."""

    intent: str = Field(description="Analyst intent to match against the curated XQL library.")
    top_k: int = Field(default=5, ge=1, le=10, description="Number of top examples to return (max 10).")


class GetAssessmentResultsRequest(BaseModel):
    """Request model for vulnerability assessment results."""

    filters: Optional[List[Dict[str, Any]]] = Field(
        default=None,
        description="Filter conditions for vulnerability assessments.",
    )


class GetAssetByIdRequest(BaseModel):
    """Request model for fetching asset by ID."""

    asset_id: str = Field(description="Unique asset identifier in XSIAM.")


class GetAssetsRequest(BaseModel):
    """Request model for asset search."""

    filters: Optional[Dict[str, Any]] = Field(
        default=None,
        description=(
            "Filter object with AND/OR arrays. Each item uses SEARCH_FIELD, SEARCH_TYPE, SEARCH_VALUE. "
            "SEARCH_TYPE values: EQ, IN, NIN, NEQ, IS, IS_NOT, LIKE_ANY, NOT_LIKE_ANY, WILDCARD, "
            "WILDCARD_NOT, REGEX, REGEX_NOT, GT, LT, GTE, LTE, RELATIVE_TIMESTAMP, RANGE, CONTAINS, "
            "JSON_SEARCH, JSON_OVERLAPS, JSON_OVERLAPS_NOT, NCONTAINS, CONTAINS_IN_LIST, "
            "NOT_CONTAINS_IN_LIST, ARRAY_LEN_EQ, ARRAY_LEN_NEQ, ARRAY_CONTAINS, ARRAY_CONTAINS_NUMBERS, "
            "ARRAY_NOT_CONTAINS, JSON_EQ, JSON_NEQ, JSON_WILDCARD_NOT, JSON_WILDCARD, JSON_GTE, "
            "JSON_LTE, JSON_GT, JSON_LT, JSON_CONTAINS_NOT, JSON_CONTAINS, JSON_ARRAY_CONTAINED_IN, "
            "JSON_ARRAY_NOT_CONTAINED_IN, JSON_ARRAY_CONTAINS, JSON_ARRAY_CONTAINS_NOT, "
            "JSON_IS_EMPTY, JSON_IS_NOT_EMPTY."
        ),
    )
    sort: Optional[List[Dict[str, Any]]] = Field(
        default=None,
        description="Sort criteria (field and order).",
    )
    search_from: int = Field(default=0, description="Pagination offset.")
    search_to: int = Field(default=100, description="Pagination limit (max 1000).")


class GetIssuesRequest(BaseModel):
    """Request model for issues search."""

    filters: Optional[List[Dict[str, Any]]] = Field(
        default=None,
        description=(
            "Filters array of objects with keys: field, operator, value. "
            "field allowed values: issue_id, external_id, detection_method, domain, "
            "severity, _insert_time, status. "
            "operator allowed values: in, gte, lte. "
            "value is the value or list of values to compare against."
        ),
    )
    search_from: int = Field(default=0, description="Pagination offset.")


async def xsiam_run_xql_query(request: RunXqlQueryRequest, ctx: Context) -> dict:
    """
    Execute custom XQL query against XSIAM datasets.

    Queries last 30 minutes by default. Returns JSON results.

    Example MCP tool call:
    {
      "method": "tools/call",
      "params": {
        "name": "xsiam_run_xql_query",
        "arguments": {
          "request": {
            "query": "datamodel dataset = corelight_http_raw | limit 10"
          }
        }
      }
    }
    """
    if not request.query or not request.query.strip():
        return _create_response({"error": "XQL query is required"}, is_error=True)

    try:
        fetcher = _get_fetcher()
        to_ts = int(time.time() * 1000)
        from_ts = to_ts - (30 * 60 * 1000)

        start_payload = {"request_data": {"query": request.query.strip(), "timeframe": {"from": from_ts, "to": to_ts}}}
        start_resp = await fetcher.send_request("xql/start_xql_query", data=start_payload)
        query_id = start_resp.get("reply")
        if not query_id:
            return _create_response({"error": "Error starting XQL", "details": start_resp}, is_error=True)

        await asyncio.sleep(2)
        results_payload = {
            "request_data": {"query_id": query_id, "pending_flag": False, "limit": 1000, "format": "json"}
        }
        results_resp = await fetcher.send_request("xql/get_query_results", data=results_payload)
        return _create_response(results_resp)
    except Exception as e:
        return _create_response({"error": f"Error running XQL: {str(e)}"}, is_error=True)


async def xsiam_get_cases(request: GetCasesRequest, ctx: Context) -> dict:
    """
    Search security cases/issues in XSIAM.

    Example MCP tool call:
    {
      "method": "tools/call",
      "params": {
        "name": "xsiam_get_cases",
        "arguments": {
          "request": {
            "query": "severity:high AND status:new"
          }
        }
      }
    }
    """
    if not request.query:
        return _create_response({"error": "Query required"}, is_error=True)

    try:
        config = get_config()
        if not config.playground_id:
            return _create_response(
                {"error": "PLAYGROUND_ID is required to execute XSOAR commands"}, is_error=True
            )
        fetcher = _get_fetcher()
        command = f"!getIssues query=`{request.query}`"
        payload = {"investigationId": config.playground_id, "data": command}
        response = await fetcher.send_request("/xsoar/entry/execute/sync", data=payload)
        return _create_response({"result": response})
    except Exception as e:
        return _create_response({"error": str(e)}, is_error=True)


async def xsiam_send_webhook_log(request: WebhookLogRequest, ctx: Context) -> dict:
    """
    Send a structured log to the XSIAM HTTP Custom Collector using WEBHOOK_ENDPOINT/WEBHOOK_KEY env vars.

    Example MCP tool call:
    {
      "method": "tools/call",
      "params": {
        "name": "xsiam_send_webhook_log",
        "arguments": {
          "request": {
            "message": "Test log from XLog MCP",
            "event_type": "mcp_event",
            "severity": "info"
          }
        }
      }
    }
    """
    config = get_config()
    if not config.webhook_endpoint or not config.webhook_key:
        return _create_response(
            {"error": "WEBHOOK_ENDPOINT and WEBHOOK_KEY must be configured on the MCP server"},
            is_error=True,
        )

    try:
        ip_address = socket.gethostbyname(socket.gethostname())
    except Exception:
        ip_address = "unknown"

    metadata: Optional[dict] = None
    if request.metadata_json:
        try:
            loaded = json.loads(request.metadata_json)
            metadata = loaded if isinstance(loaded, dict) else {"data": loaded}
        except json.JSONDecodeError:
            metadata = {"raw": request.metadata_json}

    payload = {
        "timestamp": int(time.time() * 1000),
        "hostname": socket.gethostname(),
        "ip": ip_address,
        "event_type": request.event_type or "mcp_event",
        "severity": (request.severity or "info").lower(),
        "message": request.message,
    }
    if metadata is not None:
        payload["metadata"] = metadata

    headers = {"Authorization": config.webhook_key, "Content-Type": "application/json"}

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(config.webhook_endpoint, json=payload, headers=headers)

        if 200 <= response.status_code < 300:
            return _create_response({"message": f"Sent log to webhook (HTTP {response.status_code})"})
        return _create_response(
            {"error": f"HTTP {response.status_code}", "details": response.text[:500]},
            is_error=True,
        )
    except httpx.TimeoutException:
        return _create_response({"error": "Request timeout while sending webhook log"}, is_error=True)
    except httpx.RequestError as e:
        return _create_response({"error": f"Request failed - {str(e)}"}, is_error=True)
    except Exception as e:
        return _create_response({"error": str(e)}, is_error=True)


async def xsiam_add_lookup_data(request: LookupDataRequest, ctx: Context) -> dict:
    """
    Add or update data in an XSIAM lookup dataset.

    Example MCP tool call:
    {
      "method": "tools/call",
      "params": {
        "name": "xsiam_add_lookup_data",
        "arguments": {
          "request": {
            "dataset_name": "ioc_lookup",
            "data": [{"ip": "1.2.3.4", "label": "suspicious"}]
          }
        }
      }
    }
    """
    try:
        fetcher = _get_fetcher()
        payload = {"request_data": {"dataset_name": request.dataset_name, "data": request.data}}
        if request.key_fields:
            payload["request_data"]["key_fields"] = request.key_fields
        response = await fetcher.send_request("xql/lookups/add_data", data=payload)
        return _create_response(response)
    except Exception as e:
        return _create_response({"error": str(e)}, is_error=True)


async def xsiam_get_lookup_data(request: GetLookupDataRequest, ctx: Context) -> dict:
    """
    Retrieve data from an XSIAM lookup dataset.

    Example MCP tool call:
    {
      "method": "tools/call",
      "params": {
        "name": "xsiam_get_lookup_data",
        "arguments": {
          "request": {
            "dataset_name": "ioc_lookup",
            "limit": 10
          }
        }
      }
    }
    """
    try:
        fetcher = _get_fetcher()
        payload = {"request_data": {"dataset_name": request.dataset_name, "limit": request.limit}}
        if request.filters:
            payload["request_data"]["filters"] = request.filters
        response = await fetcher.send_request("xql/lookups/get_data", data=payload)
        return _create_response(response)
    except Exception as e:
        return _create_response({"error": str(e)}, is_error=True)


async def xsiam_remove_lookup_data(request: RemoveLookupDataRequest, ctx: Context) -> dict:
    """
    Remove data from an XSIAM lookup dataset.

    Example MCP tool call:
    {
      "method": "tools/call",
      "params": {
        "name": "xsiam_remove_lookup_data",
        "arguments": {
          "request": {
            "dataset_name": "ioc_lookup",
            "filters": [{"field": "ip", "operator": "equals", "value": "1.2.3.4"}]
          }
        }
      }
    }
    """
    try:
        fetcher = _get_fetcher()
        payload = {"request_data": {"dataset_name": request.dataset_name, "filters": request.filters}}
        response = await fetcher.send_request("xql/lookups/remove_data", data=payload)
        return _create_response(response)
    except Exception as e:
        return _create_response({"error": str(e)}, is_error=True)


async def xsiam_get_datasets(ctx: Context) -> dict:
    """
    List all available datasets in XSIAM.

    Example MCP tool call:
    {
      "method": "tools/call",
      "params": {
        "name": "xsiam_get_datasets",
        "arguments": {}
      }
    }
    """
    try:
        fetcher = _get_fetcher()
        response = await fetcher.send_request("xql/get_datasets", data={})
        return _create_response(response)
    except Exception as e:
        return _create_response({"error": str(e)}, is_error=True)


async def xsiam_create_dataset(request: CreateDatasetRequest, ctx: Context) -> dict:
    """
    Create a new lookup dataset in XSIAM.

    Example MCP tool call:
    {
      "method": "tools/call",
      "params": {
        "name": "xsiam_create_dataset",
        "arguments": {
          "request": {
            "dataset_name": "ioc_lookup",
            "dataset_schema": {"ip": "string", "label": "string"}
          }
        }
      }
    }
    """
    try:
        fetcher = _get_fetcher()
        payload = {
            "request_data": {
                "dataset_name": request.dataset_name,
                "dataset_schema": request.dataset_schema,
                "dataset_type": request.dataset_type,
            }
        }
        response = await fetcher.send_request("xql/add_dataset", data=payload)
        return _create_response(response)
    except Exception as e:
        return _create_response({"error": str(e)}, is_error=True)


async def xsiam_find_xql_examples_rag(request: FindXqlExamplesRequest, ctx: Context) -> dict:
    """
    Retrieve top XQL examples using embeddings.

    Example MCP tool call:
    {
      "method": "tools/call",
      "params": {
        "name": "xsiam_find_xql_examples_rag",
        "arguments": {
          "request": {
            "intent": "Find C2 beaconing examples",
            "top_k": 5
          }
        }
      }
    }
    """
    resources_dir = _get_resources_dir()
    service = XqlRagService(resources_dir)
    return service.search(request.intent, top_k=request.top_k)


async def xsiam_get_dataset_fields(ctx: Context) -> dict:
    """
    Get reference mapping of XSIAM dataset names to their available XDM fields.

    Example MCP tool call:
    {
      "method": "tools/call",
      "params": {
        "name": "xsiam_get_dataset_fields",
        "arguments": {}
      }
    }
    """
    path = _get_resources_dir() / "dataset_fields.md"
    if not path.exists():
        return _create_response({"error": "dataset_fields.md not found"}, is_error=True)
    return {"content": path.read_text(encoding="utf-8")}


async def xsiam_get_xql_examples(ctx: Context) -> dict:
    """
    Get collection of real-world XQL query examples from correlation rules and dashboards.

    Example MCP tool call:
    {
      "method": "tools/call",
      "params": {
        "name": "xsiam_get_xql_examples",
        "arguments": {}
      }
    }
    """
    path = _get_resources_dir() / "xql_examples.md"
    if not path.exists():
        return _create_response({"error": "xql_examples.md not found"}, is_error=True)
    return {"content": path.read_text(encoding="utf-8")}


async def xsiam_get_xql_doc(ctx: Context) -> dict:
    """
    Get comprehensive XQL reference documentation for Cortex XSIAM.

    Example MCP tool call:
    {
      "method": "tools/call",
      "params": {
        "name": "xsiam_get_xql_doc",
        "arguments": {}
      }
    }
    """
    path = _get_resources_dir() / "xql_doc.md"
    if not path.exists():
        return _create_response({"error": "xql_doc.md not found"}, is_error=True)
    return {"content": path.read_text(encoding="utf-8")}


async def xsiam_get_asset_by_id(request: GetAssetByIdRequest, ctx: Context) -> dict:
    """
    Retrieve full details for a specific asset by ID.

    Example MCP tool call:
    {
      "method": "tools/call",
      "params": {
        "name": "xsiam_get_asset_by_id",
        "arguments": {
          "request": {
            "asset_id": "ff75e045ecc6b1f47fd6104752b2f15ec3f0cedf9346dba6a1453d26c34001e6"
          }
        }
      }
    }
    """
    try:
        fetcher = _get_fetcher()
        response = await fetcher.send_request(f"/assets/{request.asset_id}/", method="GET")
        return _create_response(response)
    except Exception as e:
        return _create_response({"error": str(e)}, is_error=True)


async def xsiam_get_assets(request: GetAssetsRequest, ctx: Context) -> dict:
    """
    Search and retrieve monitored assets from XSIAM.

    Filters format: object with AND/OR arrays of {SEARCH_FIELD, SEARCH_TYPE, SEARCH_VALUE}.
    Example:
    {
      "filters": {
        "AND": [
          {
            "SEARCH_FIELD": "xdm.asset.type.class",
            "SEARCH_TYPE": "NEQ",
            "SEARCH_VALUE": "Other"
          }
        ]
      }
    }

    Example MCP tool call:
    {
      "method": "tools/call",
      "params": {
        "name": "xsiam_get_assets",
        "arguments": {
          "request": {
            "search_from": 0,
            "search_to": 25,
            "filters": {
              "AND": [
                {
                  "SEARCH_FIELD": "xdm.asset.type.class",
                  "SEARCH_TYPE": "NEQ",
                  "SEARCH_VALUE": "Other"
                }
              ]
            }
          }
        }
      }
    }
    """
    try:
        fetcher = _get_fetcher()
        request_data: Dict[str, Any] = {"search_from": request.search_from, "search_to": request.search_to}
        if request.filters:
            request_data["filters"] = request.filters
        if request.sort:
            request_data["sort"] = request.sort
        response = await fetcher.send_request("/assets/", method="POST", data={"request_data": request_data})
        return _create_response(response)
    except Exception as e:
        return _create_response({"error": str(e)}, is_error=True)


async def xsiam_get_issues(request: GetIssuesRequest, ctx: Context) -> dict:
    """
    Search and retrieve security issues from XSIAM.

    Filters format: an array of objects with {field, operator, value}.
    Allowed fields: issue_id, external_id, detection_method, domain, severity, _insert_time, status.
    Allowed operators: in, gte, lte.
    Value can be a scalar or list depending on the operator.

    Example MCP tool call:
    {
      "method": "tools/call",
      "params": {
        "name": "xsiam_get_issues",
        "arguments": {
          "request": {
            "search_from": 0,
            "filters": [
              {
                "field": "severity",
                "operator": "in",
                "value": ["HIGH", "CRITICAL"]
              }
            ]
          }
        }
      }
    }
    """
    try:
        fetcher = _get_fetcher()
        payload: Dict[str, Any] = {"request_data": {"search_from": request.search_from}}
        if request.filters:
            payload["request_data"]["filters"] = request.filters
        response = await fetcher.send_request("/issue/search/", data=payload)
        return _create_response(response)
    except Exception as e:
        return _create_response({"error": str(e)}, is_error=True)
