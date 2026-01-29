#!/usr/bin/env python3
"""Exercise worker management and scenario fake data queries."""

import json
import os
import sys
from typing import Any, Dict

import requests

XLOG_URL = os.environ.get("XLOG_URL", "http://localhost:8999")
GRAPHQL_URL = XLOG_URL.rstrip("/")


CREATE_WORKER = """
query CreateWorker($input: DataWorkerCreateInput!) {
  createDataWorker(requestInput: $input) {
    worker
    status
    type
    interval
    destination
  }
}
"""

LIST_WORKERS = """
query ListWorkers {
  listWorkers {
    worker
    status
    type
    interval
    destination
  }
}
"""

ACTION_WORKER = """
query ActionWorker($input: DataWorkerActionInput!) {
  actionWorker(requestInput: $input) {
    worker
    status
  }
}
"""

SCENARIO_FAKE = """
query ScenarioFake($input: DetailedScenarioInput!) {
  generateScenarioFakeData(requestInput: $input) {
    name
    tags
    steps
  }
}
"""


def call_graphql(query: str, variables: Dict[str, Any]) -> Dict[str, Any]:
    response = requests.post(
        GRAPHQL_URL,
        json={"query": query, "variables": variables},
        timeout=30,
    )
    response.raise_for_status()
    payload = response.json()
    if "errors" in payload:
        raise RuntimeError(json.dumps(payload["errors"], indent=2))
    return payload


def ensure_service() -> None:
    probe = {"query": "query ServiceProbe { __typename }"}
    response = requests.post(GRAPHQL_URL, json=probe, timeout=10)
    response.raise_for_status()
    payload = response.json()
    if "errors" in payload:
        raise RuntimeError(json.dumps(payload["errors"], indent=2))


def print_payload(title: str, payload: Dict[str, Any]) -> None:
    print(f"\n=== {title} ===")
    if os.environ.get("VERBOSE") == "1":
        print(json.dumps(payload, indent=2))
        return
    print(json.dumps(payload.get("data", {}), indent=2))


def main() -> None:
    ensure_service()
    create_payload = call_graphql(
        CREATE_WORKER,
        {
            "input": {
                "type": "CEF",
                "count": 1,
                "interval": 1,
                "destination": "udp:127.0.0.1:514",
                "vendor": "XLog",
                "product": "Demo",
            }
        },
    )
    print_payload("Create worker", create_payload)

    worker_id = (
        create_payload.get("data", {})
        .get("createDataWorker", {})
        .get("worker")
    )

    list_payload = call_graphql(LIST_WORKERS, {})
    print_payload("List workers", list_payload)

    if worker_id:
        stop_payload = call_graphql(
            ACTION_WORKER,
            {"input": {"worker": worker_id, "action": "STOP"}},
        )
        print_payload("Stop worker", stop_payload)

    scenario_payload = call_graphql(
        SCENARIO_FAKE,
        {
            "input": {
                "name": "Crossroads",
                "tags": ["demo", "mitre"],
                "steps": [
                    {
                        "tactic": "Initial Access",
                        "tacticId": "TA0001",
                        "technique": "Valid Accounts",
                        "techniqueId": "T1078",
                        "procedure": "Suspicious VPN login",
                        "type": "CEF",
                        "logs": [
                            {
                                "type": "CEF",
                                "count": 2,
                                "vendor": "XLog",
                                "product": "VPN",
                                "observablesDict": {
                                    "remoteIp": "198.51.100.10",
                                    "user": "alex"
                                }
                            }
                        ]
                    }
                ]
            }
        },
    )
    print_payload("Scenario fake data", scenario_payload)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
