"""
Skills CRUD MCP Tools

Provides tools for managing simulation skills: Create, Read, Update, Delete
"""

import os
from pathlib import Path
from typing import Dict, List, Optional, Any
from mcp import types as mcp_types
import json


# Re-use skills directory logic from simulation_skills.py
_current_file = Path(__file__).resolve()

def find_skills_dir(start_path: Path) -> Path:
    """Search upward from start_path to find mcp/server/skills directory."""
    current = start_path.parent

    for _ in range(10):
        candidate = current / "mcp" / "server" / "skills"
        if candidate.exists() and candidate.is_dir():
            return candidate

        if current.name == "server" and (current / "skills").exists():
            return current / "skills"

        if current.name == "builtin_components":
            server_dir = current.parent.parent.parent
            skills_candidate = server_dir / "skills"
            if skills_candidate.exists() and skills_candidate.is_dir():
                return skills_candidate

        if current.parent == current:
            break
        current = current.parent

    fallback = Path(os.getenv("SKILLS_DIR", "/app/skills")).resolve()
    if fallback.exists():
        return fallback

    return Path("/app/skills")

SKILLS_DIR = find_skills_dir(_current_file)


def get_all_skills() -> List[Dict[str, Any]]:
    """
    Get list of all skills with metadata.

    Returns:
        List of skill dictionaries with path, category, name, size
    """
    import logging
    logger = logging.getLogger(__name__)

    skills = []

    logger.info(f"[SKILLS_CRUD] SKILLS_DIR = {SKILLS_DIR}")
    logger.info(f"[SKILLS_CRUD] SKILLS_DIR.exists() = {SKILLS_DIR.exists()}")

    if not SKILLS_DIR.exists():
        logger.warning(f"[SKILLS_CRUD] Skills directory does not exist: {SKILLS_DIR}")
        return skills

    # List all items in SKILLS_DIR
    try:
        items = list(SKILLS_DIR.iterdir())
        logger.info(f"[SKILLS_CRUD] Found {len(items)} items in {SKILLS_DIR}")
        for item in items:
            logger.info(f"[SKILLS_CRUD]   - {item.name} (is_dir={item.is_dir()})")
    except Exception as e:
        logger.error(f"[SKILLS_CRUD] Error listing directory: {e}")
        return skills

    # Scan all subdirectories
    for category_dir in SKILLS_DIR.iterdir():
        if category_dir.is_dir() and category_dir.name not in ["__pycache__", ".git", ".deleted"]:
            category = category_dir.name
            logger.info(f"[SKILLS_CRUD] Scanning category: {category}")

            md_files = list(category_dir.glob("*.md"))
            logger.info(f"[SKILLS_CRUD]   Found {len(md_files)} .md files in {category}")

            for skill_file in md_files:
                try:
                    content = skill_file.read_text(encoding="utf-8")
                    # Extract skill name from first H1 heading
                    skill_name = skill_file.stem
                    for line in content.split("\n"):
                        if line.startswith("# "):
                            skill_name = line[2:].strip()
                            break

                    skills.append({
                        "file_path": str(skill_file.relative_to(SKILLS_DIR)),
                        "absolute_path": str(skill_file),
                        "category": category,
                        "name": skill_name,
                        "filename": skill_file.name,
                        "size_bytes": skill_file.stat().st_size,
                        "modified": skill_file.stat().st_mtime
                    })
                    logger.info(f"[SKILLS_CRUD]     Added skill: {skill_name}")
                except Exception as e:
                    logger.error(f"[SKILLS_CRUD] Error reading {skill_file}: {e}")

    logger.info(f"[SKILLS_CRUD] Total skills found: {len(skills)}")
    return sorted(skills, key=lambda x: (x["category"], x["filename"]))


def create_skill(category: str, filename: str, content: str) -> Dict[str, Any]:
    """
    Create a new skill file.

    Args:
        category: Skill category (foundation, scenarios, validation, workflows)
        filename: Filename (must end with .md)
        content: Markdown content of the skill

    Returns:
        Result dictionary with success status and message
    """
    if not filename.endswith(".md"):
        return {"success": False, "error": "Filename must end with .md"}

    if category not in ["foundation", "scenarios", "validation", "workflows"]:
        return {"success": False, "error": f"Invalid category: {category}. Must be one of: foundation, scenarios, validation, workflows"}

    category_dir = SKILLS_DIR / category
    category_dir.mkdir(parents=True, exist_ok=True)

    skill_path = category_dir / filename

    if skill_path.exists():
        return {"success": False, "error": f"Skill already exists: {skill_path.relative_to(SKILLS_DIR)}"}

    try:
        skill_path.write_text(content, encoding="utf-8")
        return {
            "success": True,
            "message": f"Created skill: {skill_path.relative_to(SKILLS_DIR)}",
            "path": str(skill_path.relative_to(SKILLS_DIR))
        }
    except Exception as e:
        return {"success": False, "error": f"Failed to create skill: {str(e)}"}


def read_skill(file_path: str) -> Dict[str, Any]:
    """
    Read a skill file content.

    Args:
        file_path: Relative path from skills directory (e.g., "scenarios/port_scan.md")

    Returns:
        Result dictionary with skill content
    """
    skill_path = SKILLS_DIR / file_path

    if not skill_path.exists():
        return {"success": False, "error": f"Skill not found: {file_path}"}

    if not skill_path.is_file():
        return {"success": False, "error": f"Not a file: {file_path}"}

    try:
        content = skill_path.read_text(encoding="utf-8")
        return {
            "success": True,
            "content": content,
            "path": file_path,
            "size_bytes": skill_path.stat().st_size
        }
    except Exception as e:
        return {"success": False, "error": f"Failed to read skill: {str(e)}"}


def update_skill(file_path: str, content: str) -> Dict[str, Any]:
    """
    Update an existing skill file.

    Args:
        file_path: Relative path from skills directory (e.g., "scenarios/port_scan.md")
        content: New markdown content

    Returns:
        Result dictionary with success status
    """
    skill_path = SKILLS_DIR / file_path

    if not skill_path.exists():
        return {"success": False, "error": f"Skill not found: {file_path}"}

    try:
        # Backup original content
        original = skill_path.read_text(encoding="utf-8")
        backup_path = skill_path.with_suffix(".md.bak")
        backup_path.write_text(original, encoding="utf-8")

        # Write new content
        skill_path.write_text(content, encoding="utf-8")

        return {
            "success": True,
            "message": f"Updated skill: {file_path}",
            "backup": str(backup_path.relative_to(SKILLS_DIR))
        }
    except Exception as e:
        return {"success": False, "error": f"Failed to update skill: {str(e)}"}


def delete_skill(file_path: str) -> Dict[str, Any]:
    """
    Delete a skill file.

    Args:
        file_path: Relative path from skills directory (e.g., "scenarios/port_scan.md")

    Returns:
        Result dictionary with success status
    """
    skill_path = SKILLS_DIR / file_path

    if not skill_path.exists():
        return {"success": False, "error": f"Skill not found: {file_path}"}

    try:
        # Create backup before deleting
        backup_dir = SKILLS_DIR / ".deleted"
        backup_dir.mkdir(exist_ok=True)

        backup_path = backup_dir / skill_path.name
        counter = 1
        while backup_path.exists():
            backup_path = backup_dir / f"{skill_path.stem}_{counter}.md"
            counter += 1

        skill_path.rename(backup_path)

        return {
            "success": True,
            "message": f"Deleted skill: {file_path}",
            "backup": str(backup_path.relative_to(SKILLS_DIR))
        }
    except Exception as e:
        return {"success": False, "error": f"Failed to delete skill: {str(e)}"}


# MCP Tool Definitions

def get_tools() -> List[mcp_types.Tool]:
    """Return all skills CRUD MCP tools."""
    return [
        mcp_types.Tool(
            name="skills_list_all",
            description="List all available simulation skills with metadata. Returns all skills across foundation, scenarios, validation, and workflows categories.",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        ),
        mcp_types.Tool(
            name="skills_read",
            description="Read the content of a specific skill file. Use this to view or edit an existing skill.",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Relative path to skill file from skills directory (e.g., 'scenarios/port_scan.md')"
                    }
                },
                "required": ["file_path"]
            }
        ),
        mcp_types.Tool(
            name="skills_create",
            description="Create a new skill file. Use this to add new scenarios, foundation skills, validation skills, or workflows.",
            inputSchema={
                "type": "object",
                "properties": {
                    "category": {
                        "type": "string",
                        "enum": ["foundation", "scenarios", "validation", "workflows"],
                        "description": "Skill category"
                    },
                    "filename": {
                        "type": "string",
                        "description": "Filename for the skill (must end with .md)"
                    },
                    "content": {
                        "type": "string",
                        "description": "Markdown content of the skill"
                    }
                },
                "required": ["category", "filename", "content"]
            }
        ),
        mcp_types.Tool(
            name="skills_update",
            description="Update an existing skill file. Creates a backup (.md.bak) before updating.",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Relative path to skill file (e.g., 'scenarios/port_scan.md')"
                    },
                    "content": {
                        "type": "string",
                        "description": "New markdown content"
                    }
                },
                "required": ["file_path", "content"]
            }
        ),
        mcp_types.Tool(
            name="skills_delete",
            description="Delete a skill file. Creates a backup in .deleted directory before deletion.",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Relative path to skill file (e.g., 'scenarios/port_scan.md')"
                    }
                },
                "required": ["file_path"]
            }
        )
    ]


# FastMCP tool functions (for registration in main.py)

def skills_list_all() -> str:
    """
    List all available simulation skills with metadata.

    Returns all skills across foundation, scenarios, validation, and workflows categories
    with information about file path, category, name, size, and last modified time.
    """
    skills = get_all_skills()
    return json.dumps(skills, indent=2)


def skills_read(file_path: str) -> str:
    """
    Read the content of a specific skill file.

    Args:
        file_path: Relative path to skill file from skills directory (e.g., 'scenarios/port_scan.md')

    Returns:
        JSON with skill content and metadata
    """
    result = read_skill(file_path)
    return json.dumps(result, indent=2)


def skills_create(category: str, filename: str, content: str) -> str:
    """
    Create a new skill file.

    Args:
        category: Skill category (foundation, scenarios, validation, workflows)
        filename: Filename for the skill (must end with .md)
        content: Markdown content of the skill

    Returns:
        JSON with success status and created file path
    """
    result = create_skill(category, filename, content)
    return json.dumps(result, indent=2)


def skills_update(file_path: str, content: str) -> str:
    """
    Update an existing skill file.

    Creates a backup (.md.bak) before updating.

    Args:
        file_path: Relative path to skill file (e.g., 'scenarios/port_scan.md')
        content: New markdown content

    Returns:
        JSON with success status and backup file location
    """
    result = update_skill(file_path, content)
    return json.dumps(result, indent=2)


def skills_delete(file_path: str) -> str:
    """
    Delete a skill file.

    Creates a backup in .deleted directory before deletion.

    Args:
        file_path: Relative path to skill file (e.g., 'scenarios/port_scan.md')

    Returns:
        JSON with success status and backup file location
    """
    result = delete_skill(file_path)
    return json.dumps(result, indent=2)
