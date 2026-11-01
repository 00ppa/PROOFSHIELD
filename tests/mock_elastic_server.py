"""Offline Mock Elasticsearch Server for PROOFSHIELD Integration Testing.

Uses Python standard-library http.server to provide deterministic, offline
simulation of Elasticsearch 8.x search endpoints, including:
- ApiKey authentication verification
- Query DSL handling and parameter parsing
- search_after pagination simulation
- Hits total relation ('eq' vs 'gte') and truncation simulation
- Transient error simulation (HTTP 429, 502, 503, 504) with recovery
- Delayed alert generation (settling time simulation)
- Non-retryable error simulation (HTTP 401, 403, 400)
"""

from contextlib import contextmanager
import json
import socket
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
from http.server import HTTPServer, BaseHTTPRequestHandler

from proofshield.connectors.elastic import ElasticAlertClient, ElasticConnectorSettings


class MockElasticRequestHandler(BaseHTTPRequestHandler):
    """Handles HTTP requests matching Elasticsearch 8.x search API conventions."""

    server: "ThreadedMockServer"  # Type hint for custom server

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress default stderr HTTP request logging in test runs."""
        pass

    def do_POST(self) -> None:
        """Handle POST search requests against Elasticsearch indices."""
        content_length = int(self.headers.get("Content-Length", 0))
        body_bytes = self.rfile.read(content_length) if content_length > 0 else b"{}"

        try:
            req_json = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
        except Exception:
            req_json = {}

        auth_header = self.headers.get("Authorization", "")
        path = self.path

        # Record request for test assertions
        with self.server.lock:
            self.server.received_requests.append(
                {
                    "path": path,
                    "method": "POST",
                    "headers": dict(self.headers),
                    "body": req_json,
                }
            )

        # Check injected error hooks first
        with self.server.lock:
            if self.server.error_hook is not None:
                err_code, err_body = self.server.error_hook(path, req_json, self.headers)
                if err_code is not None:
                    self._send_json_response(err_code, err_body or {"error": {"type": "injected", "reason": "injected error"}})
                    return

            # Check transient failure queues (e.g. 429 on first try, then 200)
            if self.server.transient_errors:
                code, reason = self.server.transient_errors.pop(0)
                self._send_json_response(
                    code,
                    {
                        "error": {
                            "root_cause": [{"type": "transient_error", "reason": reason}],
                            "type": "transient_error",
                            "reason": reason,
                        },
                        "status": code,
                    },
                )
                return

        # Check authentication
        if self.server.expected_api_key:
            expected_auth = f"ApiKey {self.server.expected_api_key}"
            if auth_header != expected_auth:
                self._send_json_response(
                    401,
                    {
                        "error": {
                            "root_cause": [{"type": "security_exception", "reason": "missing or invalid api key"}],
                            "type": "security_exception",
                            "reason": "missing or invalid api key",
                        },
                        "status": 401,
                    },
                )
                return

        # Handle Elasticsearch _search endpoints
        if "/_search" in path:
            self._handle_search(path, req_json)
        else:
            self._send_json_response(404, {"error": "Not found", "status": 404})

    def _handle_search(self, path: str, query_dsl: Dict[str, Any]) -> None:
        """Generate response based on mock server state and query DSL."""
        with self.server.lock:
            # Determine whether query targets telemetry or alerts based on index path
            is_alert_query = "alert" in path or "signal" in path
            dataset = self.server.alert_hits if is_alert_query else self.server.telemetry_hits

            # If delayed alerts simulation is active, return 0 hits on first poll
            if is_alert_query and self.server.delayed_alert_polls_remaining > 0:
                self.server.delayed_alert_polls_remaining -= 1
                dataset = []

            # Check custom total override
            override_total = self.server.custom_total
            relation = self.server.custom_relation or "eq"

            size = query_dsl.get("size", 100)
            search_after = query_dsl.get("search_after")

            # Simple search_after paging simulation
            start_index = 0
            if search_after and isinstance(search_after, list):
                # Locate hit by sort key / timestamp
                after_id = str(search_after[-1])
                for idx, hit in enumerate(dataset):
                    if str(hit.get("_id", "")) == after_id:
                        start_index = idx + 1
                        break

            page_hits = dataset[start_index : start_index + size]

            # Ensure each page hit contains a sort array for search_after continuity
            enriched_page_hits: List[Dict[str, Any]] = []
            for hit in page_hits:
                hit_copy = dict(hit)
                if "sort" not in hit_copy:
                    ts = hit_copy.get("_source", {}).get("@timestamp", "2026-11-01T00:00:00Z")
                    hit_id = hit_copy.get("_id", "unknown-id")
                    hit_copy["sort"] = [ts, hit_id]
                enriched_page_hits.append(hit_copy)

            total_val = override_total if override_total is not None else len(dataset)

            response_payload = {
                "took": 2,
                "timed_out": False,
                "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0},
                "hits": {
                    "total": {
                        "value": total_val,
                        "relation": relation,
                    },
                    "max_score": None,
                    "hits": enriched_page_hits,
                },
            }

            self._send_json_response(200, response_payload)

    def _send_json_response(self, status_code: int, body: Dict[str, Any]) -> None:
        """Send formatted JSON HTTP response."""
        data = json.dumps(body).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class ThreadedMockServer(HTTPServer):
    """Threaded HTTPServer carrying mutable test mock state."""

    def __init__(
        self,
        server_address: Tuple[str, int],
        expected_api_key: Optional[str] = None,
    ) -> None:
        super().__init__(server_address, MockElasticRequestHandler)
        self.lock = threading.Lock()
        self.expected_api_key = expected_api_key
        self.received_requests: List[Dict[str, Any]] = []
        self.telemetry_hits: List[Dict[str, Any]] = []
        self.alert_hits: List[Dict[str, Any]] = []
        self.transient_errors: List[Tuple[int, str]] = []
        self.error_hook: Optional[Callable[[str, Dict[str, Any], Any], Tuple[Optional[int], Optional[Dict[str, Any]]]]] = None
        self.custom_total: Optional[int] = None
        self.custom_relation: Optional[str] = None
        self.delayed_alert_polls_remaining: int = 0


class MockElasticServer:
    """Manager for the background Mock Elasticsearch server."""

    def __init__(self, expected_api_key: str = "mock-secret-key-xyz-123") -> None:
        self.expected_api_key = expected_api_key
        self._server: Optional[ThreadedMockServer] = None
        self._thread: Optional[threading.Thread] = None
        self.port: int = 0

    def start(self) -> None:
        """Bind ephemeral port and start background server thread."""
        self._server = ThreadedMockServer(("127.0.0.1", 0), expected_api_key=self.expected_api_key)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Shutdown and terminate background server thread."""
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread:
            self._thread.join(timeout=2.0)
            self._thread = None

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def set_telemetry_hits(self, hits: List[Dict[str, Any]]) -> None:
        if self._server:
            with self._server.lock:
                self._server.telemetry_hits = list(hits)

    def set_alert_hits(self, hits: List[Dict[str, Any]]) -> None:
        if self._server:
            with self._server.lock:
                self._server.alert_hits = list(hits)

    def queue_transient_error(self, code: int = 429, reason: str = "Too Many Requests") -> None:
        """Queue a transient error that fires on the next HTTP request, then returns to normal."""
        if self._server:
            with self._server.lock:
                self._server.transient_errors.append((code, reason))

    def set_truncation(self, total: int, relation: str = "gte") -> None:
        """Configure mock to return relation='gte' and total > page hits."""
        if self._server:
            with self._server.lock:
                self._server.custom_total = total
                self._server.custom_relation = relation

    def set_delayed_alerts(self, empty_polls: int = 1) -> None:
        """Configure alert queries to return empty hits for N polls before returning alert hits."""
        if self._server:
            with self._server.lock:
                self._server.delayed_alert_polls_remaining = empty_polls

    def set_error_hook(
        self,
        hook: Callable[[str, Dict[str, Any], Any], Tuple[Optional[int], Optional[Dict[str, Any]]]],
    ) -> None:
        if self._server:
            with self._server.lock:
                self._server.error_hook = hook

    def get_received_requests(self) -> List[Dict[str, Any]]:
        if self._server:
            with self._server.lock:
                return list(self._server.received_requests)
        return []

    def get_settings(
        self,
        index_pattern: str = ".alerts-security.alerts-*",
        telemetry_index_pattern: str = "logs-*",
        timeout: float = 5.0,
        max_results: int = 1000,
    ) -> ElasticConnectorSettings:
        return ElasticConnectorSettings(
            base_url=self.base_url,
            api_key=self.expected_api_key,
            index_pattern=index_pattern,
            telemetry_index_pattern=telemetry_index_pattern,
            request_timeout=timeout,
            max_results=max_results,
            enabled=True,
        )

    def get_client(
        self,
        index_pattern: str = ".alerts-security.alerts-*",
        telemetry_index_pattern: str = "logs-*",
        timeout: float = 5.0,
        max_results: int = 1000,
    ) -> ElasticAlertClient:
        settings = self.get_settings(
            index_pattern=index_pattern,
            telemetry_index_pattern=telemetry_index_pattern,
            timeout=timeout,
            max_results=max_results,
        )
        return ElasticAlertClient(settings=settings)


@contextmanager
def run_mock_elastic_server(api_key: str = "mock-secret-key-xyz-123"):
    """Context manager for running a mock Elastic server during test execution."""
    server = MockElasticServer(expected_api_key=api_key)
    server.start()
    try:
        yield server
    finally:
        server.stop()

