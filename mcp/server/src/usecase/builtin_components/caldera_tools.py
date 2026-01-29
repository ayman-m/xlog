"""Caldera tools for MCP operations."""

import uuid
from typing import Any, Dict, List, Optional

import httpx
from fastmcp import Context

from config.config import get_config
from pkg.caldera_factory import create_command_from_description


def _normalize_caldera_base_url(raw_url: str) -> str:
    base_url = raw_url.rstrip("/")
    if not base_url.endswith("/api/v2"):
        base_url = f"{base_url}/api/v2"
    return f"{base_url}/"


def _get_caldera_config() -> tuple[str, str]:
    config = get_config()
    if not config.caldera_url or not config.caldera_api_key:
        raise ValueError("CALDERA_URL and CALDERA_API_KEY are required")
    base_url = _normalize_caldera_base_url(config.caldera_url)
    return base_url, config.caldera_api_key


async def _caldera_request(
    method: str,
    endpoint: str,
    body: Optional[Dict[str, Any]] = None,
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    base_url, api_key = _get_caldera_config()
    url = base_url + endpoint.lstrip("/")
    headers = {"KEY": api_key, "Content-Type": "application/json"}
    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.request(method, url, headers=headers, json=body, params=params)
    if response.status_code != 200:
        return {"error": f"Request did not return 200. Error: {response.text}"}
    try:
        data = response.json()
    except ValueError:
        return {"error": "Invalid JSON response", "status_code": response.status_code, "text": response.text}
    if isinstance(data, list):
        return {"result": data}
    return data


async def _caldera_get(endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return await _caldera_request("GET", endpoint, params=params)


async def _caldera_post(endpoint: str, body: Dict[str, Any]) -> Dict[str, Any]:
    return await _caldera_request("POST", endpoint, body=body)


def _build_query_params(
    sort: Optional[str] = None,
    include: Optional[List[str]] = None,
    exclude: Optional[List[str]] = None,
) -> Dict[str, Any]:
    params: Dict[str, Any] = {}
    if sort:
        params["sort"] = sort
    if include:
        params["include"] = include
    if exclude:
        params["exclude"] = exclude
    return params


def _filter_abilities(req: List[Dict[str, Any]], tactic: str, atomic: bool) -> List[Dict[str, Any]]:
    stockpile_abilities: List[Dict[str, Any]] = []
    if atomic:
        atomic_abilities = [item for item in req if item.get("plugin") == "atomic"]
        tactic_abilities = [item for item in atomic_abilities if item.get("tactic") == tactic]
    else:
        stockpile_only = [item for item in req if item.get("plugin") == "stockpile"]
        tactic_abilities = [item for item in stockpile_only if item.get("tactic") == tactic]

    for ability in tactic_abilities:
        ability_stripped = {
            "ability_id": ability.get("ability_id"),
            "name": ability.get("name"),
            "tactic": ability.get("tactic"),
            "technique": ability.get("technique_name"),
        }
        stockpile_abilities.append(ability_stripped)
    return stockpile_abilities


async def caldera_health_check(ctx: Context) -> Dict[str, Any]:
    """
    Check the health status of the CALDERA API server.

    Returns the status of CALDERA and additional details including versions of system components
    and all loaded plugins. This is useful for verifying that the CALDERA server is running
    and accessible.

    Returns:
        dict: A dictionary containing:
            - status: Health status message
            - details: Contains application name, version, and list of plugins with their status

    Example response:
        {
            "status": "Caldera API is UP!",
            "details": {
                "application": "caldera",
                "version": "4.2.0",
                "plugins": [
                    {
                        "name": "stockpile",
                        "description": "A collection of abilities",
                        "enabled": true,
                        "address": "/plugins/stockpile"
                    }
                ]
            }
        }
    """
    result = await _caldera_get("health")
    if "error" in result:
        return result
    return {"status": "Caldera API is UP!", "details": result}


async def caldera_get_abilities_by_tactic(tactic: str, ctx: Context) -> Dict[str, Any]:
    """
    Retrieve CALDERA abilities filtered by MITRE ATT&CK tactic.

    Abilities are atomic adversary actions mapped to MITRE ATT&CK techniques. This function
    retrieves abilities from the stockpile plugin first, then falls back to atomic plugin
    if no stockpile abilities are found. Returns up to 5 atomic abilities if the list is large.

    Args:
        tactic (str): The MITRE ATT&CK tactic to filter by. Possible values:
            - persistence: Maintain access to systems
            - privilege-escalation: Gain higher-level permissions
            - lateral-movement: Move through the environment
            - collection: Gather information of interest
            - execution: Run malicious code
            - command-and-control: Communicate with compromised systems
            - credential-access: Steal account names and passwords
            - discovery: Figure out the environment
            - defense-evasion: Avoid being detected

    Returns:
        dict: Dictionary containing:
            - result: List of abilities, each with:
                - ability_id: UUID of the ability
                - name: Human-readable name
                - tactic: MITRE ATT&CK tactic
                - technique: MITRE ATT&CK technique name

    Example usage:
        abilities = await caldera_get_abilities_by_tactic("discovery", ctx)

    Example response:
        {
            "result": [
                {
                    "ability_id": "c0da588f-79f0-4263-8998-7496b1a40596",
                    "name": "Find System Network Connections",
                    "tactic": "discovery",
                    "technique": "System Network Connections Discovery"
                }
            ]
        }
    """
    req = await _caldera_get("abilities")
    if "error" in req:
        return req
    abilities = req.get("result", [])
    stockpile_abilities = _filter_abilities(abilities, tactic, atomic=False)
    if stockpile_abilities:
        return {"result": stockpile_abilities}
    stockpile_abilities = _filter_abilities(abilities, tactic, atomic=True)
    if len(stockpile_abilities) > 5:
        return {"result": stockpile_abilities[:5]}
    return {"result": stockpile_abilities}


async def caldera_get_all_abilities(ctx: Context) -> Dict[str, Any]:
    """
    Retrieve all available abilities from CALDERA.

    Abilities are atomic adversary actions that map to MITRE ATT&CK techniques. Each ability
    contains executors (commands) for different platforms (Windows, Linux, macOS) and can be
    combined into adversary profiles.

    Returns:
        dict: Dictionary containing:
            - result: List of all abilities with full AbilitySchema including:
                - ability_id: Unique UUID identifier
                - name: Human-readable name
                - description: Detailed description of what the ability does
                - tactic: MITRE ATT&CK tactic
                - technique_id: MITRE ATT&CK technique ID (e.g., T1082)
                - technique_name: MITRE ATT&CK technique name
                - executors: List of platform-specific command implementations
                - plugin: Source plugin (stockpile, atomic, etc.)
                - privilege: Required privilege level
                - repeatable: Whether ability can be executed multiple times

    Example usage:
        abilities = await caldera_get_all_abilities(ctx)

    Example response:
        {
            "result": [
                {
                    "ability_id": "c0da588f-79f0-4263-8998-7496b1a40596",
                    "name": "Find System Network Connections",
                    "description": "Identify network connections",
                    "tactic": "discovery",
                    "technique_id": "T1049",
                    "technique_name": "System Network Connections Discovery",
                    "executors": [
                        {
                            "name": "windows",
                            "platform": "windows",
                            "command": "netstat -ano",
                            "payloads": []
                        }
                    ],
                    "plugin": "stockpile",
                    "repeatable": false
                }
            ]
        }
    """
    return await _caldera_get("abilities")


async def caldera_get_ability_by_id(id: str, ctx: Context) -> Dict[str, Any]:
    """
    Retrieve a specific ability by its UUID.

    Provides detailed information about a single ability including all executors,
    requirements, and metadata.

    Args:
        id (str): UUID of the ability to retrieve (e.g., "c0da588f-79f0-4263-8998-7496b1a40596")

    Returns:
        dict: Complete ability object in AbilitySchema format with all fields including:
            - ability_id: UUID identifier
            - name: Human-readable name
            - description: Detailed description
            - tactic: MITRE ATT&CK tactic
            - technique_id: MITRE ATT&CK technique ID
            - technique_name: MITRE ATT&CK technique name
            - executors: Full executor details with commands, payloads, parsers
            - requirements: Prerequisites for execution
            - plugin: Source plugin name

    Example usage:
        ability = await caldera_get_ability_by_id("c0da588f-79f0-4263-8998-7496b1a40596", ctx)
    """
    return await _caldera_get(f"abilities/{id}")


async def caldera_get_adversaries(ctx: Context) -> Dict[str, Any]:
    """
    Retrieve all adversary profiles available in CALDERA.

    Adversaries are ordered collections of abilities that represent attack sequences.
    They define the tactics, techniques, and procedures (TTPs) that can be executed
    during an operation. Each adversary has an atomic_ordering that specifies which
    abilities to execute and in what order.

    Returns:
        dict: Dictionary containing:
            - result: List of adversaries with:
                - adversary_id: UUID identifier
                - name: Human-readable name
                - description: Description of the adversary profile

    Example usage:
        adversaries = await caldera_get_adversaries(ctx)

    Example response:
        {
            "result": [
                {
                    "adversary_id": "de07f52d-9928-4071-9142-cb1d3bd851e8",
                    "name": "Hunter",
                    "description": "Discover host details and steal sensitive files"
                },
                {
                    "adversary_id": "5d3e170e-f1b8-49f9-9ee1-c51605552a08",
                    "name": "Collection",
                    "description": "A collection adversary pack"
                }
            ]
        }
    """
    req = await _caldera_get("adversaries")
    if "error" in req:
        return req
    adversaries = req.get("result", [])
    adversary_list = []
    for adversary in adversaries:
        adversary_stripped = {
            "adversary_id": adversary.get("adversary_id"),
            "name": adversary.get("name"),
            "description": adversary.get("description"),
        }
        adversary_list.append(adversary_stripped)
    return {"result": adversary_list}


async def caldera_get_adversary_by_ability_id(
    ability_id: Optional[str],
    ctx: Context,
    ability_name: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Find adversaries that contain a specific ability.

    This function searches through all adversaries to find which ones include a specific
    ability in their atomic_ordering. You can search by ability_id or ability_name.

    Args:
        ability_id (str, optional): UUID of the ability to search for
        ability_name (str, optional): Name of the ability to search for (if ability_id not provided)

    Returns:
        dict: Dictionary containing:
            - result: List of adversaries that contain the specified ability, each with:
                - adversary_id: UUID identifier
                - name: Adversary name
                - description: Adversary description

    Example usage:
        # Search by ability ID
        adversaries = await caldera_get_adversary_by_ability_id("c0da588f-79f0-4263-8998-7496b1a40596", ctx)

        # Search by ability name
        adversaries = await caldera_get_adversary_by_ability_id(None, ctx, ability_name="Find System Network Connections")
    """
    req = await _caldera_get("adversaries")
    if "error" in req:
        return req

    abilities = await _caldera_get("abilities")
    if "error" in abilities:
        return abilities

    if ability_name:
        named_abilities = [item for item in abilities.get("result", []) if item.get("name") == ability_name]
        if named_abilities:
            ability_id = named_abilities[0].get("ability_id")

    if not ability_id:
        return {"result": []}

    adversary_list = []
    for adversary in req.get("result", []):
        atomic_ordering = adversary.get("atomic_ordering") or []
        if ability_id in atomic_ordering:
            adversary_stripped = {
                "adversary_id": adversary.get("adversary_id"),
                "name": adversary.get("name"),
                "description": adversary.get("description"),
            }
            adversary_list.append(adversary_stripped)
    return {"result": adversary_list}


async def caldera_get_adversary_by_name(name: str, ctx: Context) -> Dict[str, Any]:
    """
    Retrieve an adversary by its name.

    Search for and retrieve adversary profiles by exact name match. This is useful when
    you know the adversary name and want to get its full details including atomic_ordering.

    Args:
        name (str): Exact name of the adversary to retrieve (e.g., "Hunter", "Collection")

    Returns:
        dict: Dictionary containing:
            - result: List of matching adversaries (usually 0 or 1) with full AdversarySchema

    Example usage:
        adversary = await caldera_get_adversary_by_name("Hunter", ctx)

    Example response:
        {
            "result": [
                {
                    "adversary_id": "de07f52d-9928-4071-9142-cb1d3bd851e8",
                    "name": "Hunter",
                    "description": "Discover host details and steal sensitive files",
                    "atomic_ordering": ["ability-uuid-1", "ability-uuid-2"],
                    "plugin": "stockpile"
                }
            ]
        }
    """
    req = await _caldera_get("adversaries")
    if "error" in req:
        return req
    matches = [adversary for adversary in req.get("result", []) if adversary.get("name") == name]
    return {"result": matches}


async def caldera_get_adversary_by_id(id: str, ctx: Context) -> Dict[str, Any]:
    """
    Retrieve a specific adversary by its UUID.

    Get detailed information about a single adversary including its atomic_ordering
    which defines the sequence of abilities to execute.

    Args:
        id (str): UUID of the adversary to retrieve (e.g., "de07f52d-9928-4071-9142-cb1d3bd851e8")

    Returns:
        dict: Adversary object with:
            - adversary_id: UUID identifier
            - name: Adversary name
            - description: Description of attack sequence

    Example usage:
        adversary = await caldera_get_adversary_by_id("de07f52d-9928-4071-9142-cb1d3bd851e8", ctx)

    Example response:
        {
            "adversary_id": "de07f52d-9928-4071-9142-cb1d3bd851e8",
            "name": "Hunter",
            "description": "Discover host details and steal sensitive files"
        }
    """
    req = await _caldera_get(f"adversaries/{id}")
    if "error" in req:
        return req
    adversary_stripped = {
        "adversary_id": req.get("adversary_id"),
        "name": req.get("name"),
        "description": req.get("description"),
    }
    return adversary_stripped


async def caldera_get_all_agents(ctx: Context) -> Dict[str, Any]:
    """
    Retrieve all agents (both active and inactive) connected to CALDERA.

    Agents are deployed endpoints running the CALDERA agent software. They beacon back to
    the server and can execute abilities. This function returns both active agents that are
    currently connected and dead/inactive agents.

    Returns:
        dict: Dictionary containing:
            - result: List of all agents with details including:
                - paw: Unique identifier for the agent
                - platform: Operating system (windows, linux, darwin)
                - hostname: Computer name
                - username: User running the agent
                - architecture: System architecture (x86_64, etc.)
                - pid: Process ID of the agent
                - server: C2 server address
                - group: Agent group assignment
                - location: File path where agent is running
                - executors: Available command executors (psh, cmd, sh, etc.)
                - privilege: Current privilege level
                - last_seen: Last beacon timestamp
                - sleep_min: Minimum sleep time
                - sleep_max: Maximum sleep time

    Example usage:
        agents = await caldera_get_all_agents(ctx)

    Example response:
        {
            "result": [
                {
                    "paw": "abc123",
                    "hostname": "WIN-SERVER01",
                    "platform": "windows",
                    "username": "Administrator",
                    "group": "red",
                    "last_seen": "2024-01-09T10:30:00Z",
                    "executors": ["psh", "cmd"]
                }
            ]
        }
    """
    return await _caldera_get("agents")


async def caldera_get_agent_by_paw(paw: str, ctx: Context) -> Dict[str, Any]:
    """
    Retrieve a specific agent by its PAW (unique identifier).

    The PAW (Platform, Architecture, Workstation) is the unique identifier assigned to
    each agent when it first connects to CALDERA.

    Args:
        paw (str): Unique PAW identifier of the agent (e.g., "abc123", "agent-001")

    Returns:
        dict: Complete agent object with all details including executors, privilege,
              last_seen time, and system information

    Example usage:
        agent = await caldera_get_agent_by_paw("abc123", ctx)

    Example response:
        {
            "paw": "abc123",
            "hostname": "WIN-SERVER01",
            "platform": "windows",
            "username": "Administrator",
            "architecture": "x86_64",
            "group": "red",
            "executors": ["psh", "cmd"],
            "privilege": "Elevated",
            "last_seen": "2024-01-09T10:30:00Z"
        }
    """
    return await _caldera_get(f"agents/{paw}")


async def caldera_get_all_operations(ctx: Context) -> Dict[str, Any]:
    """
    Retrieve all operations (both active and completed) from CALDERA.

    Operations are execution instances that run adversary profiles against agents.
    They contain the configuration, state, and results of attack simulations.

    Returns:
        dict: Dictionary containing:
            - result: List of all operations with details including:
                - id: UUID of the operation
                - name: Operation name
                - state: Current state (running, paused, finished, etc.)
                - adversary: Adversary profile being executed
                - start: Start timestamp
                - finish: Completion timestamp (if finished)
                - group: Target agent group
                - planner: Planner controlling execution logic
                - autonomous: Whether operation runs autonomously
                - chain: List of executed links (abilities)

    Example usage:
        operations = await caldera_get_all_operations(ctx)

    Example response:
        {
            "result": [
                {
                    "id": "op-uuid-123",
                    "name": "My Operation",
                    "state": "running",
                    "adversary": {"name": "Hunter", "adversary_id": "adv-uuid"},
                    "start": "2024-01-09T10:00:00Z",
                    "group": "red"
                }
            ]
        }
    """
    return await _caldera_get("operations")


async def caldera_get_operation_by_id(id: str, ctx: Context) -> Dict[str, Any]:
    """
    Retrieve a specific operation by its UUID.

    Get detailed information about a single operation including all executed links,
    facts discovered, and current state.

    Args:
        id (str): UUID of the operation to retrieve (e.g., "op-uuid-123")

    Returns:
        dict: Complete operation object with full details including adversary configuration,
              executed chain of links, discovered facts, and operation metrics

    Example usage:
        operation = await caldera_get_operation_by_id("op-uuid-123", ctx)

    Example response:
        {
            "id": "op-uuid-123",
            "name": "My Operation",
            "state": "running",
            "adversary": {"name": "Hunter"},
            "start": "2024-01-09T10:00:00Z",
            "chain": [{"id": "link-1", "ability": {"name": "whoami"}}]
        }
    """
    return await _caldera_get(f"operations/{id}")


async def caldera_get_operation_links(operation_id: str, ctx: Context) -> Dict[str, Any]:
    """
    Retrieve all links (executed abilities) for a specific operation.

    Links represent individual ability executions within an operation. Each link contains
    the command that was run, the agent that executed it, the status, and any collected facts.

    Args:
        operation_id (str): UUID of the operation

    Returns:
        dict: Dictionary containing:
            - result: List of all links with details including:
                - id: UUID of the link
                - paw: Agent that executed the link
                - ability: Ability that was executed
                - command: Actual command that was run
                - status: Execution status (0=success, -1=running, -2=discarded, etc.)
                - collect: Timestamp when output was collected
                - finish: Completion timestamp
                - facts: Facts discovered during execution
                - output: Command output (may be encoded)

    Example usage:
        links = await caldera_get_operation_links("op-uuid-123", ctx)
    """
    return await _caldera_get(f"operations/{operation_id}/links")


async def caldera_get_operation_link(operation_id: str, link_id: str, ctx: Context) -> Dict[str, Any]:
    """
    Retrieve a specific link from an operation.

    Get detailed information about a single ability execution including the exact command,
    status, output, and any facts or relationships discovered.

    Args:
        operation_id (str): UUID of the operation
        link_id (str): UUID of the link to retrieve

    Returns:
        dict: Complete link object with full execution details

    Example usage:
        link = await caldera_get_operation_link("op-uuid-123", "link-uuid-456", ctx)
    """
    return await _caldera_get(f"operations/{operation_id}/links/{link_id}")


async def caldera_get_operation_link_result(operation_id: str, link_id: str, ctx: Context) -> Dict[str, Any]:
    """
    Retrieve the execution result/output of a specific link.

    Returns both the link object and its decoded output result. This is useful for
    getting the actual command output from an executed ability.

    Args:
        operation_id (str): UUID of the operation
        link_id (str): UUID of the link

    Returns:
        dict: Dictionary containing:
            - link: Complete link object with execution details
            - result: Decoded command output as string

    Example usage:
        result = await caldera_get_operation_link_result("op-uuid-123", "link-uuid-456", ctx)

    Example response:
        {
            "link": {
                "id": "link-uuid-456",
                "command": "whoami",
                "status": 0,
                "paw": "agent-123"
            },
            "result": "DOMAIN\\username"
        }
    """
    return await _caldera_get(f"operations/{operation_id}/links/{link_id}/result")


async def caldera_add_link_to_operation(
    operation_id: str,
    ability_id: str,
    ability_executor: str,
    paw: str,
    ctx: Context,
) -> Dict[str, Any]:
    """
    Manually add an ability execution to a running operation.

    This allows you to inject additional abilities into an operation beyond what the
    adversary profile specifies. The ability will be queued for execution on the
    specified agent.

    Args:
        operation_id (str): UUID of the operation to add the link to
        ability_id (str): UUID of the ability to execute
        ability_executor (str): Executor to use (e.g., "psh", "cmd", "sh")
        paw (str): PAW of the agent that should execute the ability

    Returns:
        dict: Created link object with execution details

    Example usage:
        link = await caldera_add_link_to_operation(
            "op-uuid-123",
            "ability-uuid-456",
            "psh",
            "agent-abc123",
            ctx
        )

    Example response:
        {
            "id": "new-link-uuid",
            "operation": "op-uuid-123",
            "ability": {"ability_id": "ability-uuid-456"},
            "paw": "agent-abc123",
            "status": -1
        }
    """
    return await _caldera_post(
        f"operations/{operation_id}/links",
        {"ability_id": ability_id, "ability_executor": ability_executor, "paw": paw},
    )


async def caldera_create_adversary(
    name: str,
    description: str,
    atomic_ordering: list,
    ctx: Context,
) -> Dict[str, Any]:
    """
    Create a new adversary profile with a custom sequence of abilities.

    Adversaries define attack sequences by specifying abilities in order. The atomic_ordering
    list determines which abilities are executed and in what sequence during an operation.

    Args:
        name (str): Name for the new adversary (e.g., "Custom Red Team")
        description (str): Description of the adversary's purpose and tactics
        atomic_ordering (list): Ordered list of ability UUIDs to execute
            Example: ["ability-uuid-1", "ability-uuid-2", "ability-uuid-3"]

    Returns:
        dict: Created adversary object with generated UUID and provided details

    Example usage:
        adversary = await caldera_create_adversary(
            "Reconnaissance Pack",
            "Discover system and network information",
            ["c0da588f-79f0-4263-8998-7496b1a40596", "other-ability-uuid"],
            ctx
        )

    Example response:
        {
            "adversary_id": "generated-uuid",
            "name": "Reconnaissance Pack",
            "description": "Discover system and network information",
            "atomic_ordering": ["c0da588f-79f0-4263-8998-7496b1a40596"],
            "plugin": "stockpile"
        }
    """
    adversary_id = str(uuid.uuid4())
    return await _caldera_post(
        "adversaries",
        {
            "adversary_id": adversary_id,
            "name": name,
            "description": description,
            "atomic_ordering": atomic_ordering,
        },
    )


async def caldera_create_operation(operation_name: str, adversary_name: str, ctx: Context) -> Dict[str, Any]:
    """
    Create a new operation to execute an adversary profile.

    Operations are execution instances that run adversary profiles against agents.
    The operation starts in a "paused" state and must be manually started through
    the CALDERA UI or by updating the operation state.

    Args:
        operation_name (str): Name for the new operation (e.g., "Test Run 1")
        adversary_name (str): Name of an existing adversary profile to execute

    Returns:
        dict: Created operation object with generated UUID and configuration

    Example usage:
        operation = await caldera_create_operation("Security Assessment", "Hunter", ctx)

    Example response:
        {
            "id": "op-uuid-123",
            "name": "Security Assessment",
            "state": "paused",
            "adversary": {
                "name": "Hunter",
                "adversary_id": "adv-uuid"
            },
            "autonomous": 1,
            "planner_id": "aaa7c857-37a0-4c4a-85f7-4e9f7f30e31a"
        }

    Note:
        Returns an error if the adversary name is not found.
        The operation is created in "paused" state - use caldera_update_operation
        to change state to "running".
    """
    req = await _caldera_get("adversaries")
    if "error" in req:
        return req
    adversary_details = next((adv for adv in req.get("result", []) if adv.get("name") == adversary_name), None)
    if not adversary_details:
        return {"error": f"Adversary not found: {adversary_name}"}

    operation_body = {
        "name": operation_name,
        "adversary": {
            **{
                k: adversary_details.get(k, "")
                for k in [
                    "adversary_id",
                    "name",
                    "description",
                    "atomic_ordering",
                    "tags",
                    "plugin",
                ]
            },
            "objective": "495a9828-cab1-44dd-a0ca-66e58177d8cc",
        },
        "planner_id": "aaa7c857-37a0-4c4a-85f7-4e9f7f30e31a",
        "source_id": "ed32b9c3-9593-4c33-b0db-e2007315096b",
        "objective_id": "495a9828-cab1-44dd-a0ca-66e58177d8cc",
        "state": "paused",
        "autonomous": 1,
        "auto_close": False,
        "obfuscator": "plain-text",
        "jitter": "2/4",
        "visibility": 51,
        "use_learning_parsers": True,
        "group": "",
    }

    return await _caldera_post("operations", operation_body)


def _create_executor(platform_name: str, shell_platform: str, command: str, payloads: Optional[list]) -> Dict[str, Any]:
    return {
        "name": platform_name,
        "platform": shell_platform,
        "command": command,
        "code": None,
        "language": None,
        "build_target": None,
        "payloads": payloads or [],
        "uploads": [],
        "timeout": 60,
        "parsers": [],
        "cleanup": [],
        "variations": [],
        "additional_info": {},
    }


async def caldera_create_windows_ability(
    name: str,
    description: str,
    command_description: str,
    tactic: str,
    technique_name: str,
    ctx: Context,
    technique_id: Optional[str] = None,
    payloads: Optional[list] = None,
) -> Dict[str, Any]:
    """
    Create a new Windows-specific ability using AI-generated PowerShell commands.

    This function uses an AI service to generate PowerShell commands from natural language
    descriptions, then creates a complete ability that can be used in adversary profiles.

    Args:
        name (str): Short name for the ability (e.g., "Get User Info")
        description (str): Detailed description of what the ability does
        command_description (str): Natural language description of the command to generate
            Example: "list all running processes with their PIDs"
        tactic (str): MITRE ATT&CK tactic (discovery, execution, persistence, etc.)
        technique_name (str): MITRE ATT&CK technique name
        technique_id (str, optional): MITRE ATT&CK technique ID (e.g., "T1082")
        payloads (list, optional): List of payload files required by the ability

    Returns:
        dict: Created ability object with generated UUID and PowerShell executor

    Example usage:
        ability = await caldera_create_windows_ability(
            "List Processes",
            "Enumerate all running processes",
            "get all running processes",
            "discovery",
            "Process Discovery",
            ctx,
            technique_id="T1057"
        )

    Example response:
        {
            "ability_id": "generated-uuid",
            "name": "List Processes",
            "tactic": "discovery",
            "executors": [{
                "name": "windows",
                "platform": "psh",
                "command": "Get-Process"
            }]
        }
    """
    ability_id = str(uuid.uuid4())
    created_command = create_command_from_description(command_description, "windows")
    executor = _create_executor("windows", "psh", created_command, payloads)

    ability_body = {
        "ability_id": ability_id,
        "tactic": tactic,
        "technique_name": technique_name,
        "technique_id": technique_id,
        "name": name,
        "description": description,
        "executors": [executor],
        "requirements": [],
        "privilege": "",
        "repeatable": False,
        "buckets": [tactic],
        "additional_info": {},
        "access": {},
        "singleton": False,
        "plugin": "stockpile",
        "delete_payload": True,
    }

    return await _caldera_post("abilities", ability_body)


async def caldera_create_linux_ability(
    name: str,
    description: str,
    command_description: str,
    tactic: str,
    technique_name: str,
    ctx: Context,
    technique_id: Optional[str] = None,
    payloads: Optional[list] = None,
) -> Dict[str, Any]:
    """
    Create a new Linux-specific ability using AI-generated shell commands.

    This function uses an AI service to generate bash/shell commands from natural language
    descriptions, then creates a complete ability that can be used in adversary profiles.

    Args:
        name (str): Short name for the ability (e.g., "Enum Network")
        description (str): Detailed description of what the ability does
        command_description (str): Natural language description of the command to generate
            Example: "list all network connections and listening ports"
        tactic (str): MITRE ATT&CK tactic (discovery, execution, persistence, etc.)
        technique_name (str): MITRE ATT&CK technique name
        technique_id (str, optional): MITRE ATT&CK technique ID (e.g., "T1049")
        payloads (list, optional): List of payload files required by the ability

    Returns:
        dict: Created ability object with generated UUID and shell executor

    Example usage:
        ability = await caldera_create_linux_ability(
            "Network Enum",
            "List all network connections",
            "show all network connections",
            "discovery",
            "System Network Connections Discovery",
            ctx,
            technique_id="T1049"
        )

    Example response:
        {
            "ability_id": "generated-uuid",
            "name": "Network Enum",
            "tactic": "discovery",
            "executors": [{
                "name": "linux",
                "platform": "sh",
                "command": "netstat -an"
            }]
        }
    """
    ability_id = str(uuid.uuid4())
    created_command = create_command_from_description(command_description, "linux")
    executor = _create_executor("linux", "sh", created_command, payloads)

    ability_body = {
        "ability_id": ability_id,
        "tactic": tactic,
        "technique_name": technique_name,
        "technique_id": technique_id,
        "name": name,
        "description": description,
        "executors": [executor],
        "requirements": [],
        "privilege": "",
        "repeatable": False,
        "buckets": [tactic],
        "additional_info": {},
        "access": {},
        "singleton": False,
        "plugin": "stockpile",
        "delete_payload": True,
    }

    return await _caldera_post("abilities", ability_body)


async def caldera_get_payloads(ctx: Context) -> Dict[str, Any]:
    """
    Returns all payloads.
    """
    return await _caldera_get("payloads")


async def caldera_get_payload_by_name(name: str, ctx: Context) -> Dict[str, Any]:
    """
    Returns a payload by name.
    """
    return await _caldera_get(f"payloads/{name}")


async def caldera_get_planners(ctx: Context) -> Dict[str, Any]:
    """
    Returns all planners.
    """
    return await _caldera_get("planners")


async def caldera_get_planner_by_id(planner_id: str, ctx: Context) -> Dict[str, Any]:
    """
    Returns a planner by id.
    """
    return await _caldera_get(f"planners/{planner_id}")


async def caldera_get_objectives(ctx: Context) -> Dict[str, Any]:
    """
    Returns all objectives.
    """
    return await _caldera_get("objectives")


async def caldera_get_objective_by_id(objective_id: str, ctx: Context) -> Dict[str, Any]:
    """
    Returns an objective by id.
    """
    return await _caldera_get(f"objectives/{objective_id}")


async def caldera_get_obfuscators(ctx: Context) -> Dict[str, Any]:
    """
    Returns all obfuscators.
    """
    return await _caldera_get("obfuscators")


async def caldera_get_obfuscator_by_name(name: str, ctx: Context) -> Dict[str, Any]:
    """
    Returns an obfuscator by name.
    """
    return await _caldera_get(f"obfuscators/{name}")


async def caldera_get_plugins(ctx: Context) -> Dict[str, Any]:
    """
    Returns all plugins.
    """
    return await _caldera_get("plugins")


async def caldera_get_plugin_by_name(name: str, ctx: Context) -> Dict[str, Any]:
    """
    Returns a plugin by name.
    """
    return await _caldera_get(f"plugins/{name}")


async def caldera_get_contacts(ctx: Context) -> Dict[str, Any]:
    """
    Returns all contacts.
    """
    return await _caldera_get("contacts")


async def caldera_get_contact_by_name(name: str, ctx: Context) -> Dict[str, Any]:
    """
    Returns a contact by name.
    """
    return await _caldera_get(f"contacts/{name}")


async def caldera_get_operations_summary(ctx: Context) -> Dict[str, Any]:
    """
    Returns a summary of operations.
    """
    return await _caldera_get("operations/summary")


async def caldera_get_operation_report(operation_id: str, ctx: Context) -> Dict[str, Any]:
    """
    Generate a comprehensive report for a completed operation.

    Returns detailed information about all links executed, their results, facts discovered,
    and overall operation statistics. This is useful for post-operation analysis.

    Args:
        operation_id (str): UUID of the operation to generate a report for

    Returns:
        dict: Comprehensive operation report including execution timeline, results, and statistics

    Example usage:
        report = await caldera_get_operation_report("op-uuid-123", ctx)
    """
    return await _caldera_get(f"operations/{operation_id}/report")


async def caldera_get_operation_event_logs(operation_id: str, ctx: Context) -> Dict[str, Any]:
    """
    Retrieve event logs for a specific operation.

    Event logs contain detailed timing and state change information for the operation,
    including when abilities were executed, completed, or failed.

    Args:
        operation_id (str): UUID of the operation

    Returns:
        dict: List of timestamped events that occurred during the operation

    Example usage:
        logs = await caldera_get_operation_event_logs("op-uuid-123", ctx)
    """
    return await _caldera_get(f"operations/{operation_id}/event-logs")


async def caldera_get_operation_potential_links(operation_id: str, ctx: Context) -> Dict[str, Any]:
    """
    Get potential abilities that could be executed next in an operation.

    Returns abilities that are eligible for execution based on the current operation state,
    available agents, and planner logic. Useful for understanding what the operation might
    execute next.

    Args:
        operation_id (str): UUID of the operation

    Returns:
        dict: List of potential links that could be executed next

    Example usage:
        potential = await caldera_get_operation_potential_links("op-uuid-123", ctx)
    """
    return await _caldera_get(f"operations/{operation_id}/potential-links")


async def caldera_get_operation_potential_links_by_paw(
    operation_id: str,
    paw: str,
    ctx: Context,
) -> Dict[str, Any]:
    """
    Get potential abilities for a specific agent in an operation.

    Returns abilities that could be executed on a specific agent, filtered by the
    agent's capabilities, privilege level, and platform.

    Args:
        operation_id (str): UUID of the operation
        paw (str): PAW identifier of the agent

    Returns:
        dict: List of potential links for the specified agent

    Example usage:
        potential = await caldera_get_operation_potential_links_by_paw("op-uuid-123", "agent-abc", ctx)
    """
    return await _caldera_get(f"operations/{operation_id}/potential-links/{paw}")


async def caldera_get_operation_facts(operation_id: str, ctx: Context) -> Dict[str, Any]:
    """
    Retrieve all facts discovered during an operation.

    Facts are pieces of information learned during ability execution, such as usernames,
    file paths, IP addresses, etc. They can be used by subsequent abilities.

    Args:
        operation_id (str): UUID of the operation

    Returns:
        dict: List of facts in FactSchema format discovered during the operation

    Example usage:
        facts = await caldera_get_operation_facts("op-uuid-123", ctx)
    """
    return await _caldera_get(f"facts/{operation_id}")


async def caldera_get_facts(
    sort: Optional[str] = None,
    include: Optional[List[str]] = None,
    exclude: Optional[List[str]] = None,
    ctx: Context = None,
) -> Dict[str, Any]:
    """
    Query facts with optional filtering, sorting, and field selection.

    Facts are key-value pairs of information discovered during operations, such as
    hostnames, usernames, file paths, IP addresses, etc. They can be referenced by
    abilities using the #{fact_name} syntax.

    Args:
        sort (str, optional): Field to sort results by
        include (list, optional): List of fields to include in response
        exclude (list, optional): List of fields to exclude from response

    Returns:
        dict: List of facts matching the criteria in FactSchema format with fields:
            - unique: Unique identifier combining trait and value
            - trait: Fact type/category (e.g., "host.user.name", "file.path")
            - name: Display name for the fact
            - value: The actual value discovered
            - source: Operation ID where fact was discovered
            - score: Confidence score
            - collected_by: List of link IDs that discovered this fact

    Example usage:
        # Get all facts
        facts = await caldera_get_facts(ctx=ctx)

        # Get facts sorted by score
        facts = await caldera_get_facts(sort="score", ctx=ctx)

        # Get facts with only specific fields
        facts = await caldera_get_facts(include=["trait", "value"], ctx=ctx)
    """
    params = _build_query_params(sort=sort, include=include, exclude=exclude)
    return await _caldera_get("facts", params=params or None)


async def caldera_create_fact(payload: Dict[str, Any], ctx: Context) -> Dict[str, Any]:
    """
    Create a new fact manually.

    Facts are typically discovered automatically by abilities, but you can also create
    them manually for testing or to seed operations with known information.

    Args:
        payload (dict): FactSchema object containing:
            - trait (required): Fact type (e.g., "host.user.name")
            - value (required): Fact value
            - source: Operation ID (optional)
            - score: Confidence score 0-100 (optional)
            - name: Display name (optional)

    Returns:
        dict: Created fact in FactSchema format

    Example usage:
        fact = await caldera_create_fact({
            "trait": "host.user.name",
            "value": "administrator",
            "score": 100,
            "source": "manual"
        }, ctx)
    """
    return await _caldera_post("facts", payload)


async def caldera_update_facts(payload: Dict[str, Any], ctx: Context) -> Dict[str, Any]:
    """
    Update existing facts matching specific criteria.

    Updates all facts that match the criteria in the payload. Use with caution as
    this can update multiple facts at once.

    Args:
        payload (dict): Object containing:
            - criteria: FactSchema fields to match facts
            - updates: FactSchema fields to update

    Returns:
        dict: Updated fact(s) in FactSchema format

    Example usage:
        result = await caldera_update_facts({
            "criteria": {"trait": "host.user.name", "value": "admin"},
            "updates": {"score": 90}
        }, ctx)
    """
    return await _caldera_request("PATCH", "facts", body=payload)


async def caldera_delete_facts(payload: Dict[str, Any], ctx: Context) -> Dict[str, Any]:
    """
    Delete facts matching specific criteria.

    Deletes all facts that match the criteria in the payload. Use with caution as
    this can delete multiple facts at once.

    Args:
        payload (dict): FactSchema fields to match facts for deletion
            - trait: Fact type to match (optional)
            - value: Fact value to match (optional)
            - source: Operation ID to match (optional)

    Returns:
        dict: Deleted fact(s) in FactSchema format

    Example usage:
        # Delete specific fact
        result = await caldera_delete_facts({
            "trait": "host.user.name",
            "value": "testuser"
        }, ctx)

        # Delete all facts from an operation
        result = await caldera_delete_facts({
            "source": "op-uuid-123"
        }, ctx)
    """
    return await _caldera_request("DELETE", "facts", body=payload)


async def caldera_get_relationships(
    sort: Optional[str] = None,
    include: Optional[List[str]] = None,
    exclude: Optional[List[str]] = None,
    ctx: Context = None,
) -> Dict[str, Any]:
    """
    Query relationships with optional filtering, sorting, and field selection.

    Relationships connect two facts with a directional edge, forming a knowledge graph.
    For example: "user X has access to file Y" or "process A spawned process B".

    Args:
        sort (str, optional): Field to sort results by
        include (list, optional): List of fields to include in response
        exclude (list, optional): List of fields to exclude from response

    Returns:
        dict: List of relationships in RelationshipSchema format with fields:
            - unique: Unique identifier for the relationship
            - source: Source fact object
            - edge: Relationship type (e.g., "has_access", "spawned")
            - target: Target fact object
            - score: Confidence score
            - origin: Link ID where relationship was discovered

    Example usage:
        # Get all relationships
        relationships = await caldera_get_relationships(ctx=ctx)

        # Get relationships with specific fields
        relationships = await caldera_get_relationships(include=["source", "edge", "target"], ctx=ctx)
    """
    params = _build_query_params(sort=sort, include=include, exclude=exclude)
    return await _caldera_get("relationships", params=params or None)


async def caldera_create_relationships(payload: Dict[str, Any], ctx: Context) -> Dict[str, Any]:
    """
    Create a new relationship between two facts.

    Relationships build a knowledge graph connecting discovered facts. They are typically
    discovered automatically by abilities but can be created manually.

    Args:
        payload (dict): RelationshipSchema object containing:
            - source (required): Source fact object with trait/value
            - edge (required): Relationship type string
            - target (required): Target fact object with trait/value
            - score: Confidence score (optional)
            - origin: Link ID that discovered this (optional)

    Returns:
        dict: Created relationship in RelationshipSchema format

    Example usage:
        relationship = await caldera_create_relationships({
            "source": {"trait": "host.user.name", "value": "admin"},
            "edge": "has_access_to",
            "target": {"trait": "file.path", "value": "/etc/passwd"},
            "score": 100
        }, ctx)
    """
    return await _caldera_post("relationships", payload)


async def caldera_update_relationships(payload: Dict[str, Any], ctx: Context) -> Dict[str, Any]:
    """
    Update existing relationships matching specific criteria.

    Updates all relationships that match the criteria. Use with caution as this can
    update multiple relationships at once.

    Args:
        payload (dict): Object containing:
            - criteria: RelationshipSchema fields to match relationships
            - updates: RelationshipSchema fields to update

    Returns:
        dict: Updated relationship(s) in RelationshipSchema format

    Example usage:
        result = await caldera_update_relationships({
            "criteria": {"edge": "has_access_to"},
            "updates": {"score": 90}
        }, ctx)
    """
    return await _caldera_request("PATCH", "relationships", body=payload)


async def caldera_delete_relationships(payload: Dict[str, Any], ctx: Context) -> Dict[str, Any]:
    """
    Delete relationships matching specific criteria.

    Deletes all relationships that match the criteria. Use with caution as this can
    delete multiple relationships at once.

    Args:
        payload (dict): RelationshipSchema fields to match relationships for deletion
            - edge: Relationship type to match (optional)
            - origin: Link ID to match (optional)

    Returns:
        dict: Deleted relationship(s) in RelationshipSchema format

    Example usage:
        # Delete relationships by edge type
        result = await caldera_delete_relationships({
            "edge": "has_access_to"
        }, ctx)

        # Delete relationships from a specific link
        result = await caldera_delete_relationships({
            "origin": "link-uuid-123"
        }, ctx)
    """
    return await _caldera_request("DELETE", "relationships", body=payload)


async def caldera_get_operation_relationships(operation_id: str, ctx: Context) -> Dict[str, Any]:
    """
    Retrieve all relationships discovered during an operation.

    Returns the knowledge graph of relationships built during the operation's execution.
    This shows how discovered facts are connected.

    Args:
        operation_id (str): UUID of the operation

    Returns:
        dict: List of relationships in RelationshipSchema format

    Example usage:
        relationships = await caldera_get_operation_relationships("op-uuid-123", ctx)
    """
    return await _caldera_get(f"relationships/{operation_id}")


async def caldera_get_deploy_commands(ctx: Context) -> Dict[str, Any]:
    """
    Returns deploy commands for all abilities.
    """
    return await _caldera_get("deploy_commands")


async def caldera_get_deploy_command_by_ability_id(ability_id: str, ctx: Context) -> Dict[str, Any]:
    """
    Returns deploy commands for a specific ability id.
    """
    return await _caldera_get(f"deploy_commands/{ability_id}")


async def caldera_get_schedules(ctx: Context) -> Dict[str, Any]:
    """
    Returns all schedules.
    """
    return await _caldera_get("schedules")


async def caldera_get_schedule_by_id(schedule_id: str, ctx: Context) -> Dict[str, Any]:
    """
    Returns a schedule by id.
    """
    return await _caldera_get(f"schedules/{schedule_id}")


async def caldera_create_schedule(payload: Dict[str, Any], ctx: Context) -> Dict[str, Any]:
    """
    Create a schedule using the ScheduleSchema payload.
    """
    return await _caldera_post("schedules", payload)


async def caldera_update_schedule(schedule_id: str, payload: Dict[str, Any], ctx: Context) -> Dict[str, Any]:
    """
    Update an existing schedule by id.
    """
    return await _caldera_request("PATCH", f"schedules/{schedule_id}", body=payload)


async def caldera_get_config(name: str, ctx: Context) -> Dict[str, Any]:
    """
    Retrieve configuration by name.
    """
    return await _caldera_get(f"config/{name}")


async def caldera_update_main_config(payload: Dict[str, Any], ctx: Context) -> Dict[str, Any]:
    """
    Update the main configuration file.
    """
    return await _caldera_request("PATCH", "config/main", body=payload)


async def caldera_update_agent_config(payload: Dict[str, Any], ctx: Context) -> Dict[str, Any]:
    """
    Update the agent configuration file.
    """
    return await _caldera_request("PATCH", "config/agents", body=payload)


async def caldera_update_operation(operation_id: str, payload: Dict[str, Any], ctx: Context) -> Dict[str, Any]:
    """
    Update specific fields of an existing operation.

    This is commonly used to change the operation state (e.g., from "paused" to "running")
    or modify operation parameters like autonomous mode or obfuscation settings.

    Args:
        operation_id (str): UUID of the operation to update
        payload (dict): Partial operation schema with fields to update:
            - state: "running", "paused", "finished", or "cleanup"
            - autonomous: 0 (manual) or 1 (autonomous)
            - obfuscator: Obfuscator name (e.g., "plain-text", "base64")
            - visibility: Visibility level (0-100)
            - jitter: Jitter format (e.g., "2/4" = 2-4 seconds)

    Returns:
        dict: Updated operation object

    Example usage:
        # Start a paused operation
        op = await caldera_update_operation("op-uuid-123", {"state": "running"}, ctx)

        # Change autonomous mode
        op = await caldera_update_operation("op-uuid-123", {"autonomous": 0}, ctx)

        # Update multiple fields
        op = await caldera_update_operation("op-uuid-123", {
            "state": "running",
            "visibility": 51,
            "jitter": "4/8"
        }, ctx)
    """
    return await _caldera_request("PATCH", f"operations/{operation_id}", body=payload)


async def caldera_replace_operation(operation_id: str, payload: Dict[str, Any], ctx: Context) -> Dict[str, Any]:
    """
    Replace an entire operation with new configuration.

    This completely replaces the operation object. Use caldera_update_operation for
    partial updates instead.

    Args:
        operation_id (str): UUID of the operation to replace
        payload (dict): Complete operation schema

    Returns:
        dict: Replaced operation object

    Example usage:
        op = await caldera_replace_operation("op-uuid-123", full_operation_object, ctx)
    """
    return await _caldera_request("PUT", f"operations/{operation_id}", body=payload)
