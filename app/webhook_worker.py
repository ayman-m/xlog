import datetime
import threading
import time
from typing import List, Dict, Any

import httpx


class WebhookSender:
    def __init__(
        self,
        worker_name: str,
        destination: str,
        payloads: List[Dict[str, Any]],
        interval: int,
        verify_ssl: bool,
        headers: Dict[str, str],
    ):
        self.worker_name = worker_name
        self.destination = destination
        self.payloads = payloads
        self.interval = int(interval)
        self.verify_ssl = verify_ssl
        self.headers = headers
        self.created_at = datetime.datetime.now()
        self.count = str(len(payloads))
        self.data_type = "JSON"
        self.status = "Stopped"
        self._stop_event = threading.Event()
        self._thread = None

    def start(self):
        if self.status == "Running":
            return
        self.status = "Running"
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        self.status = "Stopped"

    def _run(self):
        with httpx.Client(timeout=10.0, verify=self.verify_ssl) as client:
            for payload in self.payloads:
                if self._stop_event.is_set():
                    break
                try:
                    client.post(self.destination, json=payload, headers=self.headers)
                except Exception:
                    pass
                if self.interval > 0:
                    time.sleep(self.interval)
        if not self._stop_event.is_set():
            self.status = "Completed"
