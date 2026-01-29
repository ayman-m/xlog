"""Logging configuration for XLog MCP Server."""

import logging
import sys
from typing import Optional


def setup_logging(config) -> None:
    """
    Configure logging for the application.

    Args:
        config: Configuration object with log_level and log_file_path
    """
    log_level = getattr(logging, config.log_level.upper(), logging.INFO)

    # Configure root logger
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler(sys.stderr)],
    )

    # Add file handler if log file path is specified
    if config.log_file_path:
        file_handler = logging.FileHandler(config.log_file_path)
        file_handler.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
        logging.getLogger().addHandler(file_handler)

    # Set specific loggers to appropriate levels
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
