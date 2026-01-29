"""
XLog MCP Server Main Module

This module serves as the entry point for the XLog MCP (Model Context Protocol) Server.
It handles server initialization, signal handling for graceful shutdown, and manages
the async event loop for the MCP server operations.
"""

import asyncio
import logging
import os
import signal
import tempfile
from functools import partial

import atexit
import uvicorn
from fastmcp import FastMCP

from config.config import get_config
from pkg.setup_logging import setup_logging
from service.xlog_mcp.server import create_mcp_server

# Import MCP tools
from usecase.builtin_components import (
    data_faker, field_info, scenarios, workers, xsiam_tools,
    caldera_tools, simulation_skills, observables_catalog, skills_crud
)

logger = logging.getLogger("XLog MCP")


async def shutdown(sig: signal.Signals, loop: asyncio.AbstractEventLoop):
    """
    Handle graceful shutdown of the XLog MCP Server.

    Args:
        sig: The signal that triggered the shutdown (SIGINT or SIGTERM)
        loop: The current asyncio event loop to be stopped
    """
    logger.info(f"Received exit signal {sig.name}...")

    # Get all running tasks except the current shutdown task
    tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
    [task.cancel() for task in tasks]

    logger.info("Cancelling outstanding tasks")
    await asyncio.gather(*tasks, return_exceptions=True)

    logger.info("Stopping the event loop")
    loop.stop()


async def async_main(transport: str):
    """
    Main async function that initializes and runs the XLog MCP Server.

    Args:
        transport: The transport mechanism for the MCP server ('stdio' or 'streamable-http')
    """
    config = get_config()
    setup_logging(config)
    logger.info("Starting XLog MCP Server")

    loop = asyncio.get_running_loop()

    # Add signal handlers for SIGINT and SIGTERM for graceful shutdown
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, partial(lambda s: asyncio.create_task(shutdown(s, loop)), sig))

    # Create MCP server
    mcp = create_mcp_server(config.xlog_url)

    # Register tools from builtin components
    logger.info("Registering MCP tools...")

    # Data faker tools

    # Field information tool (helper tool for understanding field support and observables)
    mcp.tool()(field_info.xlog_get_field_info)

    # Worker tools
    mcp.tool()(workers.xlog_create_data_worker)
    mcp.tool()(workers.xlog_list_workers)

    # Scenario tools
    mcp.tool()(scenarios.xlog_create_scenario_worker)

    # Simulation skills tool
    mcp.tool()(simulation_skills.load_simulation_skills)

    # Skills CRUD tools (management)
    mcp.tool()(skills_crud.skills_list_all)
    mcp.tool()(skills_crud.skills_read)
    mcp.tool()(skills_crud.skills_create)
    mcp.tool()(skills_crud.skills_update)
    mcp.tool()(skills_crud.skills_delete)

    # Observable generator and technology stack tools
    mcp.tool()(observables_catalog.xlog_generate_observables)
    mcp.tool()(observables_catalog.xlog_get_technology_stack)

    # XSIAM integration tools
    mcp.tool()(xsiam_tools.xsiam_run_xql_query)
    mcp.tool()(xsiam_tools.xsiam_get_cases)
    mcp.tool()(xsiam_tools.xsiam_send_webhook_log)
    mcp.tool()(xsiam_tools.xsiam_add_lookup_data)
    mcp.tool()(xsiam_tools.xsiam_get_lookup_data)
    mcp.tool()(xsiam_tools.xsiam_remove_lookup_data)
    mcp.tool()(xsiam_tools.xsiam_get_datasets)
    mcp.tool()(xsiam_tools.xsiam_create_dataset)
    mcp.tool()(xsiam_tools.xsiam_find_xql_examples_rag)
    mcp.tool()(xsiam_tools.xsiam_get_dataset_fields)
    mcp.tool()(xsiam_tools.xsiam_get_xql_examples)
    mcp.tool()(xsiam_tools.xsiam_get_xql_doc)
    mcp.tool()(xsiam_tools.xsiam_get_asset_by_id)
    mcp.tool()(xsiam_tools.xsiam_get_assets)
    mcp.tool()(xsiam_tools.xsiam_get_issues)

    # Caldera tools
    mcp.tool()(caldera_tools.caldera_get_abilities_by_tactic)
    mcp.tool()(caldera_tools.caldera_get_all_abilities)
    mcp.tool()(caldera_tools.caldera_get_adversaries)
    mcp.tool()(caldera_tools.caldera_get_adversary_by_name)
    mcp.tool()(caldera_tools.caldera_get_all_agents)
    mcp.tool()(caldera_tools.caldera_get_all_operations)
    mcp.tool()(caldera_tools.caldera_get_operation_by_id)
    mcp.tool()(caldera_tools.caldera_get_operation_links)
    mcp.tool()(caldera_tools.caldera_get_operation_link)
    mcp.tool()(caldera_tools.caldera_get_operation_link_result)
    mcp.tool()(caldera_tools.caldera_add_link_to_operation)
    mcp.tool()(caldera_tools.caldera_create_adversary)
    mcp.tool()(caldera_tools.caldera_create_operation)
    mcp.tool()(caldera_tools.caldera_update_operation)
    mcp.tool()(caldera_tools.caldera_replace_operation)
    mcp.tool()(caldera_tools.caldera_create_windows_ability)
    mcp.tool()(caldera_tools.caldera_create_linux_ability)
    mcp.tool()(caldera_tools.caldera_get_payloads)
    mcp.tool()(caldera_tools.caldera_get_payload_by_name)
    mcp.tool()(caldera_tools.caldera_get_planners)
    mcp.tool()(caldera_tools.caldera_get_objectives)
    mcp.tool()(caldera_tools.caldera_get_objective_by_id)
    mcp.tool()(caldera_tools.caldera_get_obfuscators)
    mcp.tool()(caldera_tools.caldera_get_obfuscator_by_name)
    mcp.tool()(caldera_tools.caldera_get_plugins)
    mcp.tool()(caldera_tools.caldera_get_contacts)
    mcp.tool()(caldera_tools.caldera_get_contact_by_name)
    mcp.tool()(caldera_tools.caldera_get_operations_summary)
    mcp.tool()(caldera_tools.caldera_get_operation_report)
    mcp.tool()(caldera_tools.caldera_get_operation_event_logs)
    mcp.tool()(caldera_tools.caldera_get_operation_potential_links)
    mcp.tool()(caldera_tools.caldera_get_operation_potential_links_by_paw)
    mcp.tool()(caldera_tools.caldera_get_operation_facts)
    mcp.tool()(caldera_tools.caldera_get_facts)
    mcp.tool()(caldera_tools.caldera_create_fact)
    mcp.tool()(caldera_tools.caldera_update_facts)
    mcp.tool()(caldera_tools.caldera_delete_facts)
    mcp.tool()(caldera_tools.caldera_get_relationships)
    mcp.tool()(caldera_tools.caldera_create_relationships)
    mcp.tool()(caldera_tools.caldera_update_relationships)
    mcp.tool()(caldera_tools.caldera_delete_relationships)
    mcp.tool()(caldera_tools.caldera_get_operation_relationships)
    mcp.tool()(caldera_tools.caldera_get_deploy_commands)
    mcp.tool()(caldera_tools.caldera_get_deploy_command_by_ability_id)
    mcp.tool()(caldera_tools.caldera_get_schedules)
    mcp.tool()(caldera_tools.caldera_get_schedule_by_id)
    mcp.tool()(caldera_tools.caldera_create_schedule)
    mcp.tool()(caldera_tools.caldera_update_schedule)
    mcp.tool()(caldera_tools.caldera_get_config)
    mcp.tool()(caldera_tools.caldera_update_main_config)
    mcp.tool()(caldera_tools.caldera_update_agent_config)

    logger.info("MCP tools registered successfully")

    # Start server with appropriate transport configuration
    if transport == "stdio":
        await mcp.run_async(transport=transport)
    else:
        # Use uvicorn for HTTP transport
        app = mcp.http_app(path=config.mcp_path, transport=transport)

        ssl_keyfile = config.ssl_key_file
        ssl_certfile = config.ssl_cert_file

        # Handle SSL via PEM content if files are not provided
        def normalize_pem(pem_str: str) -> str:
            """Normalize PEM content for proper formatting."""
            content = pem_str.replace("\\n", "\n").replace("\\r", "")
            content = content.replace("-----BEGIN CERTIFICATE-----", "-----BEGIN CERTIFICATE-----\n")
            content = content.replace("-----END CERTIFICATE-----", "\n-----END CERTIFICATE-----")
            content = content.replace("-----BEGIN PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----\n")
            content = content.replace("-----END PRIVATE KEY-----", "\n-----END PRIVATE KEY-----")
            content = content.replace("-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----\n")
            content = content.replace("-----END RSA PRIVATE KEY-----", "\n-----END RSA PRIVATE KEY-----")
            while "\n\n" in content:
                content = content.replace("\n\n", "\n")
            return content.strip() + "\n"

        temp_files = []
        if not ssl_keyfile and config.ssl_key_pem:
            key_temp = tempfile.NamedTemporaryFile(delete=False, mode="w")
            key_temp.write(normalize_pem(config.ssl_key_pem))
            key_temp.close()
            ssl_keyfile = key_temp.name
            temp_files.append(key_temp.name)

        if not ssl_certfile and config.ssl_cert_pem:
            cert_temp = tempfile.NamedTemporaryFile(delete=False, mode="w")
            cert_temp.write(normalize_pem(config.ssl_cert_pem))
            cert_temp.close()
            ssl_certfile = cert_temp.name
            temp_files.append(cert_temp.name)

        # Register cleanup on exit
        def cleanup_temp_files():
            for f in temp_files:
                if os.path.exists(f):
                    os.unlink(f)

        atexit.register(cleanup_temp_files)

        server_config = uvicorn.Config(
            app=app,
            host=config.mcp_host,
            port=config.mcp_port,
            ssl_keyfile=ssl_keyfile,
            ssl_certfile=ssl_certfile,
            log_level=config.log_level.lower(),
        )
        server = uvicorn.Server(server_config)
        try:
            logger.info(f"Starting HTTP server on {config.mcp_host}:{config.mcp_port}")
            await server.serve()
        finally:
            cleanup_temp_files()


def main():
    """
    Entry point for the XLog MCP Server application.
    """
    try:
        asyncio.run(async_main(get_config().mcp_transport))
    except Exception as e:
        logger.exception(f"Main loop stopped: {e}")
    finally:
        logger.info("XLog MCP Server has shut down.")


if __name__ == "__main__":
    main()
