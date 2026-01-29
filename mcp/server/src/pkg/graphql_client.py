"""GraphQL client for XLog API."""

import logging
from typing import Any, Dict, Optional

import httpx

logger = logging.getLogger("XLog MCP")


class XLogGraphQLClient:
    """Client for interacting with XLog GraphQL API."""

    def __init__(self, base_url: str, timeout: int = 30):
        """
        Initialize GraphQL client.

        Args:
            base_url: Base URL of the XLog server
            timeout: Request timeout in seconds
        """
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    async def execute_query(
        self, query: str, variables: Optional[Dict[str, Any]] = None, operation_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Execute a GraphQL query.

        Args:
            query: GraphQL query string
            variables: Query variables
            operation_name: Optional operation name

        Returns:
            GraphQL response data

        Raises:
            httpx.HTTPError: If the request fails
            ValueError: If the response contains errors
        """
        payload: Dict[str, Any] = {"query": query}

        if variables:
            payload["variables"] = variables

        if operation_name:
            payload["operationName"] = operation_name

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                self.base_url, json=payload, headers={"Content-Type": "application/json"}
            )

            response.raise_for_status()
            result = response.json()

            if "errors" in result:
                error_messages = [error.get("message", str(error)) for error in result["errors"]]
                raise ValueError(f"GraphQL errors: {', '.join(error_messages)}")

            return result.get("data", {})
