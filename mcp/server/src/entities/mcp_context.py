"""MCP Context for maintaining session state."""

from dataclasses import dataclass
from typing import Dict, Optional


@dataclass
class MCPContext:
    """Context object for MCP server operations."""

    xlog_url: str
    metadata: Optional[Dict] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}
