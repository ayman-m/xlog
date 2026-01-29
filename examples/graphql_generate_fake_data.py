#!/usr/bin/env python3
"""Run a few generateFakeData GraphQL queries with different parameters."""

import json
import os
import sys
from typing import Any, Dict

import requests

XLOG_URL = os.environ.get("XLOG_URL", "http://localhost:8999")
GRAPHQL_URL = XLOG_URL.rstrip("/")

QUERY = """
query GenerateFakeData($input: DataFakerInput!) {
  generateFakeData(requestInput: $input) {
    count
    type
    data
  }
}
"""


def call_graphql(variables: Dict[str, Any]) -> Dict[str, Any]:
    response = requests.post(
        GRAPHQL_URL,
        json={"query": QUERY, "variables": variables},
        timeout=30,
    )
    response.raise_for_status()
    payload = response.json()
    if "errors" in payload:
        raise RuntimeError(json.dumps(payload["errors"], indent=2))
    return payload


def run_case(title: str, variables: Dict[str, Any]) -> None:
    print(f"\n=== {title} ===")
    payload = call_graphql(variables)
    if os.environ.get("VERBOSE") == "1":
        print(json.dumps(payload, indent=2))
        return
    data = payload.get("data", {}).get("generateFakeData", {})
    sample = ""
    if data.get("data"):
        sample = str(data["data"][0])
        if len(sample) > 200:
            sample = sample[:200] + "..."
    print(json.dumps({
        "count": data.get("count"),
        "type": data.get("type"),
        "sample": sample,
    }, indent=2))

def ensure_service() -> None:
    probe = {"query": "query ServiceProbe { __typename }"}
    response = requests.post(GRAPHQL_URL, json=probe, timeout=10)
    response.raise_for_status()
    payload = response.json()
    if "errors" in payload:
        raise RuntimeError(json.dumps(payload["errors"], indent=2))

def main() -> None:
    ensure_service()
    run_case(
        "SYSLOG (basic)",
        {
            "input": {
                "type": "SYSLOG",
                "count": 2,
            }
        },
    )

    run_case(
        "CEF (vendor/product/version)",
        {
            "input": {
                "type": "CEF",
                "count": 1,
                "vendor": "XLog",
                "product": "Firewall",
                "version": "1.0",
            }
        },
    )

    run_case(
        "JSON (observables + datetime)",
        {
            "input": {
                "type": "JSON",
                "count": 2,
                "datetimeIso": "2025-01-05 18:29:25",
                "observablesDict": {
                    "remoteIp": "203.0.113.10",
                    "localIp": "10.0.0.5",
                    "user": "svc-backup",
                    "url": "https://example.com/login"
                },
            }
        },
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
