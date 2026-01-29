"""MCP tools for generating observables and technology stack configuration."""

import json
import logging
from typing import Any, Dict

from fastmcp import Context
from pydantic import BaseModel, Field

from config.config import get_config
from pkg.graphql_client import XLogGraphQLClient

logger = logging.getLogger("XLog MCP")


class GenerateObservablesRequest(BaseModel):
    """Request model for generating observables from threat intel feeds."""

    count: int = Field(
        default=10,
        description="Number of observables to generate. Example: 10",
        ge=1,
        le=1000,
    )
    observable_type: str = Field(
        description=(
            "Type of observable to generate. Must be one of: IP, URL, SHA256, CVE, TERMS. "
            "- IP: Malicious/benign IP addresses from threat intel feeds\n"
            "- URL: Malicious/benign URLs\n"
            "- SHA256: File hashes (malware samples or known-good files)\n"
            "- CVE: CVE identifiers\n"
            "- TERMS: Security-related search terms (MITRE techniques, threat names)"
        )
    )
    known: str = Field(
        default="BAD",
        description=(
            "Whether to generate known-malicious or known-benign observables. "
            "Must be one of: BAD, GOOD. "
            "- BAD: Known malicious indicators (default)\n"
            "- GOOD: Known benign/safe indicators"
        )
    )


async def xlog_generate_observables(
    request: GenerateObservablesRequest, ctx: Context
) -> Dict[str, Any]:
    """
    Generate observables (IPs, URLs, hashes, CVEs, terms) from threat intelligence feeds.

    This tool leverages rosetta-ce's Observables.generator() to fetch real indicators
    from curated threat intel sources. If sources are unavailable, it falls back to
    generating realistic fake values.

    Use cases:
    - Generate malicious IPs for testing detection rules
    - Create realistic threat scenarios with known-bad URLs
    - Populate test environments with sample IOCs
    - Generate benign indicators for allowlist testing

    Args:
        request: Request containing count, observable_type, and known status
        ctx: MCP context

    Returns:
        Dictionary containing:
        - observables: List of generated observable values
        - observable_type: The type of observables generated
        - known: Whether they are BAD (malicious) or GOOD (benign)
        - count: Number of observables returned

    Example Request:
        {
          "count": 10,
          "observable_type": "IP",
          "known": "BAD"
        }

    Example Response:
        {
          "observables": ["192.168.1.100", "10.0.0.50", ...],
          "observable_type": "ip",
          "known": "bad",
          "count": 10
        }
    """
    # Validate observable_type
    valid_types = ["IP", "URL", "SHA256", "CVE", "TERMS"]
    observable_type = request.observable_type.upper()
    if observable_type not in valid_types:
        return {
            "error": f"Invalid observable_type '{request.observable_type}'. Must be one of: {', '.join(valid_types)}",
            "valid_types": valid_types,
        }

    # Validate known
    valid_known = ["BAD", "GOOD"]
    known = request.known.upper()
    if known not in valid_known:
        return {
            "error": f"Invalid known value '{request.known}'. Must be one of: {', '.join(valid_known)}",
            "valid_known": valid_known,
        }

    # Build GraphQL query
    query = """
    query GenerateObservables($input: GenerateObservablesInput!) {
        generateObservables(requestInput: $input) {
            observables
            observableType
            known
            count
        }
    }
    """

    variables = {
        "input": {
            "count": request.count,
            "observableType": observable_type,
            "known": known,
        }
    }

    try:
        lifespan_context = ctx.request_context.lifespan_context
        client = XLogGraphQLClient(lifespan_context["xlog_url"])
        result = await client.execute_query(query, variables)

        logger.info(
            f"Generated {result.get('generateObservables', {}).get('count', 0)} {observable_type} observables (known={known})"
        )
        return result.get("generateObservables", {})

    except Exception as e:
        logger.error(f"Error generating observables: {e}")
        return {"error": str(e), "query": query, "variables": variables}


async def xlog_get_technology_stack(ctx: Context) -> Dict[str, Any]:
    """
    Get the organization's custom technology stack configuration.

    This tool returns a list of vendor/product combinations configured for the
    organization via the TECHNOLOGY_STACK environment variable. Use this to
    discover which security products are deployed in the environment and generate
    realistic logs for those specific products.

    The technology stack is configured as a JSON object with the following structure:
    {
        "stack_name": "Enterprise SOC Stack",
        "log_destination": {
            "type": "syslog",
            "protocol": "udp",
            "host": "10.10.0.8",
            "port": 514,
            "full_address": "udp:10.10.0.8:514"
        },
        "vendors": [
            {
                "vendor": "F5",
                "product": "ASM",
                "category": "WAF",
                "formats": ["CEF", "JSON"],
                "description": "Web Application Firewall"
            },
            ...
        ]
    }

    Returns:
        Dictionary containing:
        - stack_name: Name of the technology stack (if configured)
        - log_destination: Default log destination configuration (if configured)
        - vendors: List of vendor entries with vendor, product, category, formats, description
        - total_vendors: Count of vendors in the stack
        - configured: Boolean indicating if a custom stack is configured

    Example Response (configured):
        {
            "stack_name": "Enterprise SOC Stack",
            "log_destination": {
                "type": "syslog",
                "protocol": "udp",
                "host": "10.10.0.8",
                "port": 514,
                "full_address": "udp:10.10.0.8:514"
            },
            "vendors": [
                {
                    "vendor": "F5",
                    "product": "ASM",
                    "category": "WAF",
                    "formats": ["CEF", "JSON"],
                    "description": "Web Application Firewall"
                },
                {
                    "vendor": "CrowdStrike",
                    "product": "Falcon",
                    "category": "EDR",
                    "formats": ["JSON"],
                    "description": "Endpoint Detection and Response"
                }
            ],
            "total_vendors": 2,
            "configured": true
        }

    Example Response (not configured):
        {
            "stack_name": null,
            "log_destination": null,
            "vendors": [],
            "total_vendors": 0,
            "configured": false,
            "message": "No technology stack configured. Set TECHNOLOGY_STACK environment variable."
        }
    """
    config = get_config()

    if not config.technology_stack:
        logger.info("Technology stack not configured")
        return {
            "stack_name": None,
            "log_destination": None,
            "vendors": [],
            "total_vendors": 0,
            "configured": False,
            "message": "No technology stack configured. Set TECHNOLOGY_STACK environment variable.",
        }

    try:
        stack_data = json.loads(config.technology_stack)

        # Validate structure
        if not isinstance(stack_data, dict):
            raise ValueError("Technology stack must be a JSON object")

        stack_name = stack_data.get("stack_name")
        log_destination = stack_data.get("log_destination")
        vendors = stack_data.get("vendors", [])

        if not isinstance(vendors, list):
            raise ValueError("'vendors' must be a list")

        logger.info(
            f"Returning technology stack '{stack_name}' with {len(vendors)} vendors"
        )

        if log_destination:
            logger.info(
                f"Default log destination configured: {log_destination.get('full_address', 'N/A')}"
            )

        return {
            "stack_name": stack_name,
            "log_destination": log_destination,
            "vendors": vendors,
            "total_vendors": len(vendors),
            "configured": True,
        }

    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in TECHNOLOGY_STACK: {e}")
        return {
            "error": f"Invalid JSON in TECHNOLOGY_STACK: {e}",
            "configured": False,
        }
    except ValueError as e:
        logger.error(f"Invalid technology stack structure: {e}")
        return {
            "error": str(e),
            "configured": False,
        }
    except Exception as e:
        logger.error(f"Error getting technology stack: {e}")
        return {
            "error": str(e),
            "configured": False,
        }
