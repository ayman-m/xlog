"""XSIAM Public API (PAPI) client implementation."""

import os
import json
import logging
from typing import Optional

import httpx

from pkg.papi_exceptions import (
    PAPIConnectionError,
    PAPIResponseError,
    PAPIAuthenticationError,
    PAPIServerError,
    PAPIClientRequestError,
)


class PAPIClient(httpx.AsyncClient):
    """
    Async HTTP client for XSIAM Public API.
    """

    def __init__(self, base_url: str, headers: dict[str, str], timeout: int = 120, **kwargs):
        if "timeout" not in kwargs:
            kwargs["timeout"] = timeout
        if "follow_redirects" not in kwargs:
            kwargs["follow_redirects"] = True

        super().__init__(base_url=base_url, headers=headers, **kwargs)
        self.logger = logging.getLogger(self.__class__.__name__)

    def _get_default_headers(self) -> httpx.Headers:
        headers = self.headers.copy()
        headers.update({"Content-Type": "application/json"})
        return httpx.Headers(headers)

    async def send(
        self,
        request: httpx.Request,
        *,
        auth=httpx.USE_CLIENT_DEFAULT,
        follow_redirects=httpx.USE_CLIENT_DEFAULT,
    ) -> httpx.Response:
        client_auth = self.headers.get("Authorization")
        client_auth_id = self.headers.get("x-xdr-auth-id") or self.headers.get("X-XDR-AUTH-ID")

        if client_auth:
            if "Authorization" in request.headers and request.headers["Authorization"] != client_auth:
                request.headers["Authorization"] = client_auth
            elif "Authorization" not in request.headers:
                request.headers["Authorization"] = client_auth

        if client_auth_id:
            for key in ["x-xdr-auth-id", "X-XDR-AUTH-ID"]:
                if key in request.headers and request.headers[key] != client_auth_id:
                    request.headers[key] = client_auth_id
            if "x-xdr-auth-id" not in request.headers and "X-XDR-AUTH-ID" not in request.headers:
                request.headers["x-xdr-auth-id"] = client_auth_id

        return await super().send(request, auth=auth, follow_redirects=follow_redirects)

    async def request(self, method: str, url: str, **kwargs) -> dict:
        if "headers" not in kwargs:
            kwargs["headers"] = self._get_default_headers()
        else:
            default_headers = dict(self._get_default_headers())
            default_headers.update(kwargs.get("headers", {}))
            kwargs["headers"] = default_headers

        full_url = f"{self.base_url}{url}"
        debug_headers = dict(kwargs["headers"])
        for key in ["Authorization", "authorization", "x-xdr-auth-id", "X-XDR-AUTH-ID"]:
            if key in debug_headers:
                debug_headers[key] = "***REDACTED***"

        self.logger.info(f"Request: {method} {full_url}")
        self.logger.debug(f"Headers: {debug_headers}")

        try:
            response = await super().request(method=method, url=url, **kwargs)
        except httpx.ConnectError as e:
            self.logger.exception(f"Connection failed: {url}")
            raise PAPIConnectionError(f"Failed to connect to {full_url}: {str(e)}")
        except httpx.TimeoutException as e:
            self.logger.exception(f"Request timeout: {url}")
            raise PAPIConnectionError(f"Request timeout: {str(e)}")
        except httpx.RequestError as e:
            self.logger.exception(f"Request failed: {url}")
            raise PAPIConnectionError(f"Request error: {str(e)}")
        except Exception as e:
            self.logger.exception(f"Unexpected error: {url}")
            raise PAPIConnectionError(f"Unexpected error: {str(e)}")

        if response is None:
            raise PAPIResponseError("Received None response")

        if response.status_code == 401:
            raise PAPIAuthenticationError(f"Authentication failed: {response.status_code} {response.text}")
        if response.status_code == 403:
            raise PAPIAuthenticationError(f"Authorization failed (forbidden): {response.status_code} {response.text}")
        if response.status_code >= 500:
            raise PAPIServerError(f"Server error {response.status_code}: {response.text}")
        if response.status_code >= 400:
            raise PAPIClientRequestError(f"Client error {response.status_code}: {response.text}")

        try:
            return response.json()
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON response: {response.text[:500]}")
            raise PAPIResponseError(f"Invalid JSON response: {str(e)}")


class Fetcher:
    """
    High-level XSIAM API request helper.
    """

    def __init__(self, url: str, api_key: str, api_key_id: str):
        self.url = url
        self.api_key = api_key
        self.api_key_id = api_key_id
        self.logger = logging.getLogger(self.__class__.__name__)

    def _build_headers(self) -> dict[str, str]:
        return {
            "x-xdr-auth-id": self.api_key_id,
            "Authorization": self.api_key,
            "Content-Type": "application/json",
        }

    async def send_request(
        self,
        path: str,
        method: str = "POST",
        data: Optional[dict | str] = None,
    ) -> dict:
        if "/public_api/v1" not in path:
            path = os.path.join("/", path.lstrip("/"))

        headers = self._build_headers()

        async with PAPIClient(self.url, headers) as client:
            return await client.request(method, path, json=data, headers=headers)
