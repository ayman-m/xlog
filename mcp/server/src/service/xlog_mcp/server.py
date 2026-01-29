"""MCP Server creation and lifecycle management."""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse

logger = logging.getLogger("XLog MCP")


def create_mcp_lifespan(xlog_url: str):
    """
    Factory function to create mcp_lifespan with injected dependencies.

    Args:
        xlog_url: XLog server URL
    """

    @asynccontextmanager
    async def mcp_lifespan(mcp_server: FastMCP) -> AsyncIterator[dict]:
        """
        Manage application lifecycle.

        Args:
            mcp_server: FastMCP server

        Yields:
            dict: MCP context with xlog_url
        """
        try:
            logger.info("Initializing XLog MCP Server...")
            context = {"xlog_url": xlog_url}

            logger.info("XLog MCP Server initialized successfully")
            yield context
        except Exception as e:
            logger.exception(f"Error during MCP server initialization: {e}")
            raise

    return mcp_lifespan


def create_mcp_server(xlog_url: str) -> FastMCP:
    """
    Create FastMCP server with injected dependencies.

    Args:
        xlog_url: XLog server URL

    Returns:
        FastMCP: Configured server instance
    """
    lifespan = create_mcp_lifespan(xlog_url)

    mcp = FastMCP(
        name="XLog MCP Server",
        instructions="""
# XLog MCP Server - Security Testing & Simulation Platform

You are connected to the XLog MCP Server, a comprehensive security testing and simulation platform that enables:

## Core Capabilities

### 1. Synthetic Log Generation (ARB CISD Standard - 46 Data Sources)
- Generate realistic security logs for **46 different data sources** across **6 domains**:
  - Operating System (7): Windows Server, Active Directory, Workstations, Exchange, Sysmon, Linux/Unix, AIX
  - Network & Infrastructure (14): Load Balancer, Middleware, File Share, DNS, DHCP, Switches, Routers, etc.
  - Security Controls (11): EDR, CSPM, Email Gateway, FIM, DLP, PAM, MDM, XSOAR, Threat Intel, Vuln Mgmt, EPP
  - Network Security (9): NDR, TLS Inspection, DDoS Protection, NGFW, IPS/IDS, VPN, WLC, Proxy, NAC
  - Database (2): Database Engine (RDBMS), Database Security Control (DAM)
  - Applications (3): API Gateway, WAF, Custom Applications

- Support multiple formats (SYSLOG, CEF, LEEF, WINEVENT, JSON)
- Create continuous log streams with customizable intervals and observables
- Send logs to various destinations (UDP, TCP, HTTPS, XSIAM, Webhooks)
- Simulate attack scenarios following MITRE ATT&CK framework

### 2. CALDERA Attack Simulation Integration
- Full CALDERA C2 framework control for adversary emulation
- Manage abilities (atomic attack techniques) mapped to MITRE ATT&CK
- Create and execute operations with adversary profiles
- Track execution with links, facts, and relationship graphs
- Generate comprehensive attack reports and telemetry

### 3. XSIAM (Cortex) Security Platform Integration
- Execute XQL queries for threat hunting and investigation
- Manage security cases, assets, and issues
- Interact with lookup tables for enrichment data
- Send logs via HTTP collectors (webhooks)
- Access datasets and field information
- AI-powered XQL query assistance with RAG

## Vendor & Product Standards

**CRITICAL**: Always use realistic vendor/product names from the Device Vendor Catalog:
- ✅ Use specific vendors: Palo Alto, CrowdStrike, Microsoft, Cisco, F5, Proofpoint, etc.
- ❌ NEVER use: "XLog", "Generic", "Unknown", or made-up names
- ✅ Create variety: Use different vendors for different logs (e.g., Palo Alto for perimeter firewall, Fortinet for branch firewall)
- ✅ Match vendors to context: Azure for cloud, Cisco for data center, CrowdStrike for EDR, Proofpoint for email

**Format-Specific Requirements:**
- **JSON** (XSIAM): Azure, Corelight, Zscaler, Symantec, Akamai, CrowdStrike, Kong, AWS, Okta, HashiCorp
- **CEF**: Palo Alto, Cisco, F5, Imperva, Fortinet, Check Point, Suricata
- **LEEF**: Proofpoint, Mimecast, Zscaler
- **SYSLOG**: Cisco, Infoblox, Pulse Secure, Red Hat, IBM, Juniper, Arista, Apache, Nginx
- **WINEVENT**: Microsoft (no vendor/product field needed - use srcHost in observables)

## Common Use Cases

**Security Testing**: Test SIEM ingestion, parsing rules, and correlation logic with realistic synthetic data from all 46 data sources

**Red Team Exercises**: Execute end-to-end attack simulations using CALDERA and capture telemetry from multiple security controls

**Detection Engineering**: Generate attack scenarios to validate detection rules across different vendor products

**Training & Education**: Create realistic security incidents for SOC analyst training with industry-standard vendor logs

**Performance Testing**: Test log processing pipelines with high-volume synthetic data streams from diverse sources

## Best Practices

1. **Start with CALDERA health check** before running operations
2. **Create workers for continuous log generation**, use scenarios for attack sequences
3. **Use Device Vendor Catalog** (skills/foundation/DEVICE_VENDOR_CATALOG.md) for vendor selection
4. **Use XSIAM queries** to validate that generated logs are being ingested correctly
5. **Track CALDERA operations** through their full lifecycle: create → start → monitor → report
6. **Build knowledge graphs** using facts and relationships from CALDERA operations
7. **Generate variety**: Use different vendors for different devices in the same exercise

## Important Notes

- CALDERA operations start in "paused" state - update state to "running" to execute
- Workers stream logs continuously until stopped - monitor and stop when done
- XSIAM webhooks require proper authentication (WEBHOOK_ENDPOINT and WEBHOOK_KEY)
- Use observables_dict to control specific field values in generated logs
- Link execution status: 0=success, -1=running, -2=discarded
- Network devices REQUIRE network fields: localIp, remoteIp, sourcePort, remotePort, protocol

Always verify connectivity to backend services (XLog, CALDERA, XSIAM) before starting operations.
""",
        lifespan=lifespan,
    )

    @mcp.custom_route("/ping/", methods=["GET"], include_in_schema=False)
    async def _health_check_route(request: Request) -> JSONResponse:
        """Health check endpoint."""
        return JSONResponse({"status": "ok"})

    return mcp
