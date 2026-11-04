"""Controlled, benign network connection validation actions."""

import socket
import threading
import time
from typing import Any, Dict

from proofshield.execution.actions.base import ActionContext, ActionResult, BaseAction
from proofshield.schemas.common import EventCategory


class NetworkLoopbackAction(BaseAction):
    """Establishes a strictly loopback-only TCP connection to produce observable network telemetry."""

    action_id = "network.loopback_check"
    version = "1.0.0"
    name = "Loopback Network Connection Check"
    description = (
        "Opens an ephemeral TCP listener on 127.0.0.1 and initiates a loopback client connection, "
        "transmitting the execution token. Strictly rejects non-loopback destinations."
    )
    supported_platforms = ["windows", "linux", "darwin"]
    expected_observable_category = EventCategory.NETWORK_CONNECTION
    max_timeout_seconds = 5.0

    def get_parameter_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target_host": {
                    "type": "string",
                    "description": "Must be loopback (127.0.0.1 or localhost)",
                    "default": "127.0.0.1",
                },
            },
        }

    def validate_parameters(self, params: Dict[str, Any]) -> Dict[str, Any]:
        host = str(params.get("target_host", "127.0.0.1")).strip().lower()
        # Mandatory security restriction: ONLY loopback allowed
        if host not in ("127.0.0.1", "::1", "localhost"):
            raise ValueError(
                f"Security violation: Non-loopback network connection rejected: '{host}'. "
                f"ProofShield endpoint runner only permits loopback (127.0.0.1, ::1, localhost)."
            )
        return {"target_host": "127.0.0.1"}

    def execute(self, ctx: ActionContext) -> ActionResult:
        self.validate_parameters(ctx.parameters)

        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(("127.0.0.1", 0))
        server_sock.listen(1)
        port = server_sock.getsockname()[1]

        received_token = None
        server_error = None

        def _server_worker():
            nonlocal received_token, server_error
            try:
                server_sock.settimeout(3.0)
                conn, _ = server_sock.accept()
                with conn:
                    data = conn.recv(1024).decode("utf-8", errors="replace")
                    received_token = data.strip()
            except Exception as e:
                server_error = str(e)
            finally:
                server_sock.close()

        th = threading.Thread(target=_server_worker, daemon=True)
        th.start()

        time.sleep(0.05)  # Allow server socket to listen

        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_sock.settimeout(ctx.timeout_seconds)

        try:
            client_sock.connect(("127.0.0.1", port))
            client_sock.sendall(f"TOKEN:{ctx.execution_token}\n".encode("utf-8"))
            client_sock.close()
            th.join(timeout=2.0)

            return ActionResult(
                exit_code=0,
                output_data={
                    "source_host": "127.0.0.1",
                    "destination_host": "127.0.0.1",
                    "destination_port": port,
                    "protocol": "TCP",
                    "execution_token": ctx.execution_token,
                    "token_received": (received_token is not None and ctx.execution_token in received_token),
                },
                error_message=server_error,
            )
        except Exception as exc:
            return ActionResult(
                exit_code=-1,
                output_data={"destination_port": port},
                error_message=f"Loopback connection failed: {exc}",
            )
        finally:
            try:
                client_sock.close()
            except Exception:
                pass
            try:
                server_sock.close()
            except Exception:
                pass
