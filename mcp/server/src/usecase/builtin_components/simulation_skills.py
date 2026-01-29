"""
Simulation Skills MCP Tool

Provides access to purple team simulation skill prompts for LLM agents.
Skills are structured guides for orchestrating attack scenarios using XLog, CALDERA, and XSIAM.
"""

import os
from pathlib import Path
from typing import Dict, List, Optional, Any
from mcp import types as mcp_types


# Path to skills directory
# This file is at: mcp/server/src/usecase/builtin_components/simulation_skills.py
# Skills are at: mcp/server/skills/
#
# Local path: /Users/.../xlog/xlog/mcp/server/src/usecase/builtin_components/simulation_skills.py
# Docker path: /app/src/usecase/builtin_components/simulation_skills.py
#
# Skills are now co-located with the MCP server for single source of truth

_current_file = Path(__file__).resolve()

# Search upward for a directory that contains "mcp/server/skills"
def find_skills_dir(start_path: Path) -> Path:
    """Search upward from start_path to find mcp/server/skills directory."""
    current = start_path.parent

    # Limit search to prevent infinite loops
    for _ in range(10):
        # Check if mcp/server/skills exists from current directory
        candidate = current / "mcp" / "server" / "skills"
        if candidate.exists() and candidate.is_dir():
            return candidate

        # Also check if we're already inside mcp/server directory structure
        # In that case, navigate to server/skills
        if current.name == "server" and (current / "skills").exists():
            return current / "skills"

        # Check if we're in src/usecase/builtin_components and go up to server/skills
        if current.name == "builtin_components":
            server_dir = current.parent.parent.parent  # up from builtin_components -> usecase -> src -> server
            skills_candidate = server_dir / "skills"
            if skills_candidate.exists() and skills_candidate.is_dir():
                return skills_candidate

        # Move up one level
        if current.parent == current:  # Reached filesystem root
            break
        current = current.parent

    # Fallback: assume Docker structure where skills are at /app/skills (server/skills mounted)
    # or use environment variable if set
    fallback = Path(os.getenv("SKILLS_DIR", "/app/skills")).resolve()
    if fallback.exists():
        return fallback

    # Final fallback: return expected path even if it doesn't exist yet
    # (allows for testing/development scenarios)
    return Path("/app/skills")

SKILLS_DIR = find_skills_dir(_current_file)


def get_skill_metadata() -> Dict[str, Dict[str, Any]]:
    """
    Returns metadata for all available skills.

    This metadata is used to filter and categorize skills based on user requests.
    """
    return {
        # Foundation Skills
        "generate_shared_iocs": {
            "category": "foundation",
            "file_path": "foundation/generate_shared_iocs.md",
            "name": "Generate Shared IoCs",
            "description": "Generate consistent IoCs across synthetic logs and CALDERA execution",
            "complexity": "low",
            "prerequisites": ["scenario_type"],
            "outputs": ["ioc_dictionary", "xlog_observables", "caldera_facts"]
        },
        "create_device_topology": {
            "category": "foundation",
            "file_path": "foundation/create_device_topology.md",
            "name": "Create Device Topology",
            "description": "Design network topology with multiple log-generating devices",
            "complexity": "low",
            "prerequisites": ["shared_iocs"],
            "outputs": ["topology_config", "device_inventory", "worker_configs"]
        },
        "device_vendor_catalog": {
            "category": "foundation",
            "file_path": "foundation/DEVICE_VENDOR_CATALOG.md",
            "name": "Device Vendor & Product Catalog",
            "description": "Reference catalog of official vendor and product names per device type and log format",
            "complexity": "low",
            "prerequisites": [],
            "outputs": ["vendor_product_selection", "device_context_mapping"]
        },

        # Scenario Skills
        "ransomware_attack": {
            "category": "scenarios",
            "file_path": "scenarios/ransomware_attack.md",
            "name": "Ransomware Attack",
            "description": "Complete ransomware attack chain from phishing to encryption",
            "attack_type": "ransomware",
            "complexity": "medium",
            "duration": "1-2 hours",
            "tactics": ["TA0001", "TA0002", "TA0003", "TA0008", "TA0040"],
            "techniques": ["T1566.001", "T1204.002", "T1105", "T1547.001", "T1021.002", "T1486"],
            "caldera_required": False,
            "devices_required": ["email_gateway", "firewall", "workstation", "file_server"],
            "prerequisites": ["generate_shared_iocs", "create_device_topology"]
        },
        "credential_theft_apt": {
            "category": "scenarios",
            "file_path": "scenarios/credential_theft_apt.md",
            "name": "Credential Theft APT",
            "description": "Sophisticated APT attack focused on credential theft and domain compromise",
            "attack_type": "apt",
            "complexity": "high",
            "duration": "2-3 days",
            "tactics": ["TA0001", "TA0002", "TA0003", "TA0005", "TA0006", "TA0007", "TA0008", "TA0009", "TA0010"],
            "techniques": ["T1189", "T1218.005", "T1546.003", "T1087.002", "T1003.001", "T1003.006", "T1550.002", "T1074.001", "T1048.003"],
            "caldera_required": True,
            "devices_required": ["web_proxy", "firewall", "workstation", "file_server", "domain_controller"],
            "prerequisites": ["generate_shared_iocs", "create_device_topology"]
        },
        "port_scan": {
            "category": "scenarios",
            "file_path": "scenarios/port_scan.md",
            "name": "Port Scan Detection",
            "description": "Network reconnaissance via port scanning to identify open services and detection capabilities",
            "attack_type": "reconnaissance",
            "complexity": "low",
            "duration": "5-10 minutes",
            "tactics": ["TA0043", "TA0007"],
            "techniques": ["T1046"],
            "caldera_required": False,
            "devices_required": ["firewall", "ids_ips", "waf"],
            "prerequisites": ["generate_shared_iocs"]
        },

        # Validation Skills
        "validate_ioc_correlation": {
            "category": "validation",
            "file_path": "validation/validate_ioc_correlation.md",
            "name": "Validate IoC Correlation",
            "description": "Verify IoCs appear consistently across synthetic and real telemetry",
            "complexity": "low",
            "prerequisites": ["completed_scenario_execution", "ioc_dictionary"],
            "outputs": ["correlation_matrix", "detection_gaps", "validation_report"]
        },

        # Workflow Skills
        "purple_team_exercise": {
            "category": "workflows",
            "file_path": "workflows/purple_team_exercise.md",
            "name": "Complete Purple Team Exercise",
            "description": "End-to-end purple team exercise with planning, execution, validation, and reporting",
            "complexity": "high",
            "duration": "4-6 hours",
            "prerequisites": ["all_foundation_skills", "scenario_selection"],
            "outputs": ["exercise_report", "action_items", "lessons_learned"]
        },
        "caldera_adversary_selection_guide": {
            "category": "workflows",
            "file_path": "workflows/CALDERA_ADVERSARY_SELECTION_GUIDE.md",
            "name": "CALDERA Adversary Selection Guide",
            "description": "Guide for selecting CALDERA adversaries without external tool dependencies (Atomic Red Team)",
            "complexity": "low",
            "duration": "10 minutes",
            "prerequisites": ["caldera_server_available"],
            "outputs": ["safe_adversary_selection", "alternative_approaches"]
        }
    }


def read_skill_file(file_path: str) -> Optional[str]:
    """
    Read a skill markdown file and return its contents.

    Args:
        file_path: Relative path from skills directory (e.g., "foundation/generate_shared_iocs.md")

    Returns:
        File contents as string, or None if file not found
    """
    full_path = SKILLS_DIR / file_path

    if not full_path.exists():
        return None

    try:
        with open(full_path, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception as e:
        return None


def filter_skills(
    category: Optional[str] = None,
    attack_type: Optional[str] = None,
    complexity: Optional[str] = None,
    caldera_available: Optional[bool] = None
) -> List[Dict[str, Any]]:
    """
    Filter skills based on criteria.

    Args:
        category: Filter by category (foundation, scenarios, validation, workflows)
        attack_type: Filter by attack type (ransomware, apt, credential_theft, etc.)
        complexity: Filter by complexity (low, medium, high)
        caldera_available: Filter by whether CALDERA is available

    Returns:
        List of matching skill metadata
    """
    all_skills = get_skill_metadata()
    filtered = []

    for skill_id, metadata in all_skills.items():
        # Apply filters
        if category and metadata.get("category") != category:
            continue

        if attack_type and metadata.get("attack_type") != attack_type:
            continue

        if complexity and metadata.get("complexity") != complexity:
            continue

        if caldera_available is False and metadata.get("caldera_required") is True:
            continue

        # Add skill_id to metadata
        skill_data = {"skill_id": skill_id, **metadata}
        filtered.append(skill_data)

    return filtered


async def load_simulation_skills(
    category: Optional[str] = None,
    attack_type: Optional[str] = None,
    complexity: Optional[str] = None,
    include_content: bool = True,
    include_field_reference: bool = False,
    caldera_available: Optional[bool] = None
) -> Dict[str, Any]:
    """
    Load simulation skill prompts for purple team exercises.

    This tool provides access to structured skill guides that teach LLM agents how to:
    - Generate consistent IoCs across synthetic and real attack telemetry
    - Create realistic network topologies with multiple log sources
    - Execute complete attack scenarios (ransomware, APT, etc.)
    - Validate detection coverage and IoC correlation
    - Conduct end-to-end purple team exercises

    Skills can be filtered by category, attack type, complexity, and CALDERA availability.

    Args:
        category: Filter by category
            - "foundation": Core building blocks (IoC generation, topology design)
            - "scenarios": Complete attack chains (ransomware, APT)
            - "validation": Verification and testing (IoC correlation)
            - "workflows": End-to-end processes (purple team exercise)
            - None: Return summary of all skills

        attack_type: Filter scenario skills by attack type
            - "ransomware": Ransomware attack chains
            - "apt": Advanced Persistent Threat scenarios
            - "credential_theft": Credential-focused attacks
            - None: Return all attack types

        complexity: Filter by skill complexity
            - "low": Simple, quick to execute
            - "medium": Moderate complexity, standard scenarios
            - "high": Complex, multi-day exercises
            - None: Return all complexity levels

        include_content: Whether to include full skill markdown content
            - True: Return full skill content (for execution)
            - False: Return only metadata (for browsing)

        caldera_available: Filter by CALDERA requirement
            - True: Return all skills (CALDERA optional and required)
            - False: Return only skills that don't require CALDERA
            - None: Return all skills regardless of CALDERA

    Returns:
        Dictionary containing:
        - skills: List of skill objects with metadata and optionally content
        - summary: Overview of returned skills
        - total_count: Number of skills returned

    Examples:
        # Get foundation skills with full content
        load_simulation_skills(category="foundation", include_content=True)

        # Get ransomware scenario
        load_simulation_skills(category="scenarios", attack_type="ransomware")

        # Browse all available skills (metadata only)
        load_simulation_skills(include_content=False)

        # Get skills that don't require CALDERA
        load_simulation_skills(caldera_available=False)

        # Get high complexity scenarios
        load_simulation_skills(category="scenarios", complexity="high")
    """
    # Filter skills based on criteria
    matched_skills = filter_skills(
        category=category,
        attack_type=attack_type,
        complexity=complexity,
        caldera_available=caldera_available
    )

    # Prepare response
    skills = []

    for skill_metadata in matched_skills:
        skill_data = skill_metadata.copy()

        # Load content if requested
        if include_content:
            content = read_skill_file(skill_metadata["file_path"])
            if content:
                skill_data["content"] = content
            else:
                skill_data["content"] = f"Error: Could not read skill file at {skill_metadata['file_path']}"

        skills.append(skill_data)

    # Generate summary
    categories = {}
    for skill in skills:
        cat = skill.get("category", "unknown")
        categories[cat] = categories.get(cat, 0) + 1

    summary = {
        "total_skills": len(skills),
        "by_category": categories,
        "filters_applied": {
            "category": category,
            "attack_type": attack_type,
            "complexity": complexity,
            "caldera_available": caldera_available
        }
    }

    # Build usage guidance based on what was returned
    usage_guidance = []

    if category == "foundation":
        usage_guidance.append("Foundation skills are building blocks. Execute them in order:")
        usage_guidance.append("1. generate_shared_iocs - Create consistent IoCs")
        usage_guidance.append("2. create_device_topology - Design network environment")
        usage_guidance.append("Then proceed to a scenario skill.")

    elif category == "scenarios":
        usage_guidance.append("Scenario skills provide complete attack chains.")
        usage_guidance.append("Prerequisites:")
        usage_guidance.append("1. Run foundation skills first (IoCs and topology)")
        usage_guidance.append("2. Follow step-by-step instructions in the scenario")
        usage_guidance.append("3. Use validation skills after execution")

    elif category == "validation":
        usage_guidance.append("Validation skills verify scenario execution.")
        usage_guidance.append("Run these AFTER completing a scenario to:")
        usage_guidance.append("- Check IoC correlation across data sources")
        usage_guidance.append("- Identify detection gaps")
        usage_guidance.append("- Generate validation reports")

    elif category == "workflows":
        usage_guidance.append("Workflow skills orchestrate complete exercises.")
        usage_guidance.append("These combine multiple skills into end-to-end processes.")
        usage_guidance.append("Follow the phase-by-phase instructions for complete exercises.")

    else:
        # No category filter - provide general guidance
        usage_guidance.append("Typical execution order:")
        usage_guidance.append("1. Foundation skills (generate IoCs, create topology)")
        usage_guidance.append("2. Scenario skills (execute attack chain)")
        usage_guidance.append("3. Validation skills (verify correlation and coverage)")
        usage_guidance.append("4. Workflow skills (for complete exercises with reporting)")

    return {
        "success": True,
        "skills": skills,
        "summary": summary,
        "usage_guidance": usage_guidance,
        "skills_directory": str(SKILLS_DIR)
    }


# MCP tool resource for listing available skills
def get_skills_list_resource() -> mcp_types.Resource:
    """
    Creates an MCP resource listing all available simulation skills.

    This resource provides a quick reference of available skills without loading full content.
    """
    metadata = get_skill_metadata()

    # Build markdown content
    content = "# Available Purple Team Simulation Skills\n\n"

    # Group by category
    categories = {}
    for skill_id, data in metadata.items():
        cat = data.get("category", "unknown")
        if cat not in categories:
            categories[cat] = []
        categories[cat].append((skill_id, data))

    # Foundation skills
    if "foundation" in categories:
        content += "## Foundation Skills\n\n"
        content += "Core building blocks for scenario creation.\n\n"
        for skill_id, data in categories["foundation"]:
            content += f"### {data['name']}\n"
            content += f"**ID:** `{skill_id}`\n\n"
            content += f"{data['description']}\n\n"
            content += f"- **Complexity:** {data.get('complexity', 'N/A')}\n"
            content += f"- **Prerequisites:** {', '.join(data.get('prerequisites', []))}\n"
            content += f"- **Outputs:** {', '.join(data.get('outputs', []))}\n\n"

    # Scenario skills
    if "scenarios" in categories:
        content += "## Scenario Skills\n\n"
        content += "Complete attack chains following MITRE ATT&CK.\n\n"
        for skill_id, data in categories["scenarios"]:
            content += f"### {data['name']}\n"
            content += f"**ID:** `{skill_id}`\n\n"
            content += f"{data['description']}\n\n"
            content += f"- **Attack Type:** {data.get('attack_type', 'N/A')}\n"
            content += f"- **Complexity:** {data.get('complexity', 'N/A')}\n"
            content += f"- **Duration:** {data.get('duration', 'N/A')}\n"
            content += f"- **CALDERA Required:** {'Yes' if data.get('caldera_required') else 'No'}\n"
            content += f"- **Tactics:** {', '.join(data.get('tactics', []))}\n"
            content += f"- **Prerequisites:** {', '.join(data.get('prerequisites', []))}\n\n"

    # Validation skills
    if "validation" in categories:
        content += "## Validation Skills\n\n"
        content += "Verify execution and validate detection coverage.\n\n"
        for skill_id, data in categories["validation"]:
            content += f"### {data['name']}\n"
            content += f"**ID:** `{skill_id}`\n\n"
            content += f"{data['description']}\n\n"
            content += f"- **Complexity:** {data.get('complexity', 'N/A')}\n"
            content += f"- **Prerequisites:** {', '.join(data.get('prerequisites', []))}\n"
            content += f"- **Outputs:** {', '.join(data.get('outputs', []))}\n\n"

    # Workflow skills
    if "workflows" in categories:
        content += "## Workflow Skills\n\n"
        content += "End-to-end processes combining multiple skills.\n\n"
        for skill_id, data in categories["workflows"]:
            content += f"### {data['name']}\n"
            content += f"**ID:** `{skill_id}`\n\n"
            content += f"{data['description']}\n\n"
            content += f"- **Complexity:** {data.get('complexity', 'N/A')}\n"
            content += f"- **Duration:** {data.get('duration', 'N/A')}\n"
            content += f"- **Prerequisites:** {', '.join(data.get('prerequisites', []))}\n"
            content += f"- **Outputs:** {', '.join(data.get('outputs', []))}\n\n"

    content += "\n---\n\n"
    content += "## Usage\n\n"
    content += "Load skills using the `load_simulation_skills` tool:\n\n"
    content += "```json\n"
    content += '{\n'
    content += '  "tool": "load_simulation_skills",\n'
    content += '  "params": {\n'
    content += '    "category": "scenarios",\n'
    content += '    "attack_type": "ransomware"\n'
    content += '  }\n'
    content += '}\n'
    content += "```\n"

    return mcp_types.Resource(
        uri="skills://simulation/list",
        name="Purple Team Simulation Skills",
        description="List of all available simulation skills for purple team exercises",
        mimeType="text/markdown",
        text=content
    )
