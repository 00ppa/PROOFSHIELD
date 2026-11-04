"""Small offline Splunk export endpoint used by Phase 21 integration tests."""

from contextlib import contextmanager
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs

from proofshield.connectors.splunk import SplunkClient, SplunkConnectorSettings


class MockSplunkHandler(BaseHTTPRequestHandler):
    server: "MockSplunkHTTPServer"

    def log_message(self, *_args: Any) -> None:
        pass

    def do_POST(self) -> None:
        if self.path != "/services/search/jobs/export":
            self.send_response(404)
            self.end_headers()
            return
        length = int(self.headers.get("Content-Length", 0))
        body = parse_qs(self.rfile.read(length).decode("utf-8"))
        with self.server.lock:
            self.server.requests.append({"headers": dict(self.headers), "body": body})
            if self.headers.get("Authorization", "") != f"Bearer {self.server.expected_token}":
                self._send(401, "{\"messages\":[]}")
                return
            if self.server.fail_status is not None:
                self._send(self.server.fail_status, "{\"messages\":[]}")
                return
            search = body.get("search", [""])[0]
            dataset = self.server.alerts if "index=alerts" in search else self.server.telemetry
            count = int(body.get("count", ["1000"])[0])
            results = dataset[:count]
        payload = "".join(json.dumps({"preview": False, "offset": index,
            "lastrow": index == len(results) - 1, "result": item}) + "\n" for index, item in enumerate(results))
        self._send(200, payload)

    def _send(self, status: int, payload: str) -> None:
        encoded = payload.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded) + self.server.extra_content_length))
        self.end_headers()
        self.wfile.write(encoded)


class MockSplunkHTTPServer(HTTPServer):
    def __init__(self, address, expected_token: str):
        super().__init__(address, MockSplunkHandler)
        self.expected_token = expected_token
        self.lock = threading.Lock()
        self.telemetry: List[Dict[str, Any]] = []
        self.alerts: List[Dict[str, Any]] = []
        self.requests: List[Dict[str, Any]] = []
        self.fail_status: Optional[int] = None
        self.extra_content_length: int = 0


class MockSplunkServer:
    def __init__(self, token: str = "splunk-test-token"):
        self.token = token
        self.server = MockSplunkHTTPServer(("127.0.0.1", 0), token)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_port}"

    def get_client(self, max_results: int = 1000) -> SplunkClient:
        return SplunkClient(
            SplunkConnectorSettings(
                base_url=self.base_url,
                token=self.token,
                telemetry_index="telemetry",
                alert_index="alerts",
                max_results=max_results,
                verify_tls=False,
                enabled=True,
            )
        )

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2.0)


@contextmanager
def run_mock_splunk_server(token: str = "splunk-test-token"):
    server = MockSplunkServer(token)
    try:
        yield server
    finally:
        server.close()
