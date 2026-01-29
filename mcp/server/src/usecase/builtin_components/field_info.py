"""MCP tools for querying supported fields and observables by log type."""

import logging
from typing import Any, Dict, Optional

from fastmcp import Context
from pydantic import BaseModel, Field

from pkg.graphql_client import XLogGraphQLClient

logger = logging.getLogger("XLog MCP")


class FieldInfoRequest(BaseModel):
    """Request model for querying field support details."""

    log_type: Optional[str] = Field(
        default=None,
        description=(
            "Optional log type to query. Must be one of: SYSLOG, CEF, LEEF, WINEVENT, JSON, Incident, "
            "XSIAM_Parsed, XSIAM_CEF (case-insensitive). When omitted, only supported types are returned."
        ),
    )
    include_observables: bool = Field(
        default=True,
        description=(
            "Deprecated. Observable catalog is no longer returned."
        ),
    )


async def _get_supported_fields(ctx: Context) -> list[str]:
    lifespan_context = ctx.request_context.lifespan_context
    client = XLogGraphQLClient(lifespan_context["xlog_url"])
    query = """
    query GetSupportedFields {
      getSupportedFields
    }
    """
    try:
        data = await client.execute_query(query)
        fields = data.get("getSupportedFields", [])
        if not isinstance(fields, list) or not all(isinstance(item, str) for item in fields):
            logger.warning("XLog getSupportedFields returned unexpected payload.")
            return []
        return fields
    except Exception as exc:
        logger.warning(f"Failed to fetch supported fields from XLog: {exc}")
        return []


async def xlog_get_field_info(request: FieldInfoRequest, ctx: Context) -> Dict[str, Any]:
    """
    Get field support by log type.

    Use this tool to discover supported log types and check parameter support for a specific format.

    IMPORTANT DIFFERENCES BY LOG TYPE:

    1. WINEVENT:
       - Does NOT support 'required_fields' parameter
       - ONLY supports: observables_dict, datetime_iso, count
       - Cannot specify vendor, product, version, or fields

    2. SYSLOG:
       - Supports: required_fields, observables_dict, datetime_iso, count
       - Does NOT support: vendor, product, version

    3. CEF, LEEF, JSON:
       - Supports ALL parameters: required_fields, observables_dict, vendor, product, version,
         datetime_iso, count, fields

    4. Incident:
       - Supports ALL parameters including 'fields' for custom incident fields

    5. XSIAM_Parsed:
       - Has predefined mandatory fields (automatically included)
       - Supports: observables_dict, vendor, product, datetime_iso, count

    Args:
        request: Request containing the log type (optional)
        ctx: MCP context (not used, but required by MCP)

    Returns:
        Dictionary containing:
        - supported_types: List of supported log types (always present when log_type is omitted)
        - log_type: The queried log type (when provided)
        - supports_required_fields: Boolean indicating if required_fields is supported
        - supports_observables: Boolean indicating if observables_dict is supported
        - supports_vendor: Boolean indicating if vendor is supported
        - supports_product: Boolean indicating if product is supported
        - supports_version: Boolean indicating if version is supported
        - supports_fields: Boolean indicating if custom fields parameter is supported
        - supports_datetime: Boolean indicating if datetime_iso parameter is supported
        - available_fields: Comma-separated list of field names that can be used (if supported)
        - description: Detailed description of parameter support
        - usage_notes: Important notes about using this log type
        - naming_convention: How to format fields for required_fields vs observables_dict

    Example Request:
        {
          "log_type": "WINEVENT",
          "include_observables": false
        }

    Example Response:
        {
          "log_type": "WINEVENT",
          "supports_required_fields": false,
          "supports_observables": true,
          "supports_vendor": false,
          "supports_product": false,
          "supports_version": false,
          "supports_fields": false,
          "supports_datetime": true,
          "description": "Windows Event logs in XML format. Only supports observables injection.",
          "usage_notes": "WINEVENT format does NOT accept required_fields. Use observables_dict to inject specific values like eventId, user, remoteIp, etc."
        }

    Example MCP tool call:
        {
          "method": "tools/call",
          "params": {
            "name": "xlog_get_field_info",
            "arguments": {
              "request": {
                "log_type": "CEF",
                "include_observables": true
              }
            }
          }
        }
    """
    log_type = request.log_type.upper() if request.log_type else None

    supported_fields = await _get_supported_fields(ctx)
    required_fields_str = ", ".join(field.upper() for field in supported_fields)
    response: Dict[str, Any] = {
        "naming_convention": {
            "required_fields": "UPPER_SNAKE_CASE",
            "observables_dict": "camelCase",
            "available_fields": "Use these fields for both required_fields (UPPER_SNAKE_CASE) and observables_dict (camelCase).",
        }
    }

    # Field support matrix based on XLog schema.py implementation
    field_info = {
        "SYSLOG": {
            "supports_required_fields": True,
            "supports_observables": True,
            "supports_vendor": False,
            "supports_product": False,
            "supports_version": False,
            "supports_fields": False,
            "supports_datetime": True,
            "available_fields": required_fields_str,
            "description": "Standard syslog format (RFC 3164/5424) for Unix/Linux system logs.",
            "usage_notes": (
                "Supports both required_fields and observables_dict. "
                "Does not support vendor/product/version parameters. "
                "Use required_fields to ensure specific fields are present, and observables_dict to inject specific values."
            ),
        },
        "CEF": {
            "supports_required_fields": True,
            "supports_observables": True,
            "supports_vendor": True,
            "supports_product": True,
            "supports_version": True,
            "supports_fields": False,
            "supports_datetime": True,
            "available_fields": required_fields_str,
            "description": "Common Event Format - structured log format for security events.",
            "usage_notes": (
                "Fully supports all parameters. "
                "Vendor and product can be customized (defaults to 'XLog' if not specified). "
                "Use required_fields for mandatory fields and observables_dict for specific values."
            ),
        },
        "LEEF": {
            "supports_required_fields": True,
            "supports_observables": True,
            "supports_vendor": True,
            "supports_product": True,
            "supports_version": True,
            "supports_fields": False,
            "supports_datetime": True,
            "available_fields": required_fields_str,
            "description": "Log Event Extended Format - structured log format for security events.",
            "usage_notes": (
                "Fully supports all parameters. "
                "Vendor and product can be customized (defaults to 'XLog' if not specified). "
                "Use required_fields for mandatory fields and observables_dict for specific values."
            ),
        },
        "WINEVENT": {
            "supports_required_fields": False,
            "supports_observables": True,
            "supports_vendor": False,
            "supports_product": False,
            "supports_version": False,
            "supports_fields": False,
            "supports_datetime": True,
            "available_fields": None,
            "description": "Windows Event logs in XML format with security and system events.",
            "usage_notes": (
                "CRITICAL: WINEVENT does NOT support required_fields parameter. "
                "ONLY supports observables_dict and datetime_iso. "
                "Use observables_dict to inject specific values like eventId, user, remoteIp, winProcess, etc. "
                "Cannot customize vendor, product, or version."
            ),
        },
        "JSON": {
            "supports_required_fields": True,
            "supports_observables": True,
            "supports_vendor": True,
            "supports_product": True,
            "supports_version": True,
            "supports_fields": False,
            "supports_datetime": True,
            "available_fields": required_fields_str,
            "description": "Generic JSON-formatted security logs with flexible structure.",
            "usage_notes": (
                "Fully supports all parameters. "
                "Vendor and product can be customized. "
                "Use required_fields for mandatory fields and observables_dict for specific values."
            ),
        },
        "INCIDENT": {
            "supports_required_fields": True,
            "supports_observables": True,
            "supports_vendor": True,
            "supports_product": True,
            "supports_version": True,
            "supports_fields": True,
            "supports_datetime": True,
            "available_fields": required_fields_str,
            "description": "Security incident records with full context including multiple event types.",
            "usage_notes": (
                "Fully supports all parameters including 'fields' for custom incident fields. "
                "Incidents contain multiple event types (syslog, CEF, LEEF, etc.). "
                "Use fields parameter for comma-separated custom incident fields."
            ),
        },
        "XSIAM_PARSED": {
            "supports_required_fields": False,
            "supports_observables": True,
            "supports_vendor": True,
            "supports_product": True,
            "supports_version": False,
            "supports_fields": False,
            "supports_datetime": True,
            "available_fields": None,
            "description": "Pre-parsed logs optimized for ingestion with predefined mandatory fields.",
            "usage_notes": (
                "Has predefined mandatory fields that are automatically included. "
                "Does NOT support required_fields parameter (uses predefined ones). "
                "Supports vendor, product, observables_dict, and datetime_iso. "
                "Automatically adds event_timestamp field for compatibility."
            ),
        },
        "XSIAM_CEF": {
            "supports_required_fields": True,
            "supports_observables": True,
            "supports_vendor": True,
            "supports_product": True,
            "supports_version": True,
            "supports_fields": False,
            "supports_datetime": True,
            "available_fields": required_fields_str,
            "description": "CEF format optimized for security platform alert ingestion.",
            "usage_notes": (
                "CEF format specifically designed for security platforms. "
                "Supports all standard CEF parameters. "
                "Use for sending alerts via CEF-based ingestion APIs."
            ),
        },
    }

    if log_type:
        if log_type not in field_info:
            response.update({
                "log_type": log_type,
                "error": f"Unknown log type '{log_type}'. Supported types: {', '.join(field_info.keys())}",
                "supported_types": list(field_info.keys()),
            })
            return response
        info = field_info[log_type].copy()
        info["log_type"] = log_type
        response.update(info)
    else:
        response["supported_types"] = list(field_info.keys())
        response["description"] = "Provide log_type to get parameter support for that format."

    return response
