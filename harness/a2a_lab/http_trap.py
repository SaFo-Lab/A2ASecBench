from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
from typing import Any
from urllib.parse import urlparse

from harness.a2a_lab.events import EventRecorder


class LocalHTTPTrapServer:
    def __init__(self, recorder: EventRecorder, host: str = "127.0.0.1") -> None:
        self.recorder = recorder
        self.host = host
        self._routes: dict[str, dict[str, Any]] = {}
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def origin(self) -> str:
        if self._server is None:
            raise RuntimeError("Trap server has not been started.")
        return f"http://{self.host}:{self._server.server_port}"

    def add_route(self, path: str, metadata: dict[str, Any]) -> str:
        if not path.startswith("/"):
            raise ValueError(f"Route path must start with '/': {path!r}")
        self._routes[path] = dict(metadata)
        return path

    def start(self) -> None:
        if self._server is not None:
            return
        trap = self

        class TrapHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 - stdlib callback name
                trap._handle_get(self)

            def log_message(self, format: str, *args: object) -> None:
                return

        self._server = ThreadingHTTPServer((self.host, 0), TrapHandler)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            kwargs={"poll_interval": 0.01},
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        if self._server is None:
            return
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        self._server = None
        self._thread = None

    def _handle_get(self, handler: BaseHTTPRequestHandler) -> None:
        parsed = urlparse(handler.path)
        metadata = self._routes.get(parsed.path)
        request_uri = f"{self.origin}{handler.path}"
        if metadata is None:
            self.recorder.record(
                "unknown_uri_dereference",
                "local_http_trap",
                actor_id="sut",
                evidence={"method": "GET", "uri": request_uri, "path": parsed.path},
            )
            handler.send_response(404)
            handler.end_headers()
            handler.wfile.write(b"not found")
            return

        event_type = str(metadata.get("event_type", "uri_dereference"))
        evidence = {
            "method": "GET",
            "uri": request_uri,
            "path": parsed.path,
            "route_id": metadata.get("route_id"),
        }
        if event_type == "artifact_executed":
            evidence.update(
                {
                    "artifact_id": metadata.get("artifact_id"),
                    "marker_id": metadata.get("marker_id"),
                    "execution_sink": metadata.get("execution_sink"),
                    "artifact_type": metadata.get("artifact_type"),
                }
            )
        self.recorder.record(
            event_type,
            "local_http_trap",
            actor_id="sut",
            public_surface=metadata.get("request_surface"),
            evidence=evidence,
            private_tags={
                "uri_class": metadata.get("uri_class"),
                "nonce": metadata.get("nonce"),
                "case_role": metadata.get("case_role"),
                "request_surface": metadata.get("request_surface"),
                "artifact_id": metadata.get("artifact_id"),
                "marker_id": metadata.get("marker_id"),
                "execution_sink": metadata.get("execution_sink"),
            },
        )
        handler.send_response(200)
        handler.send_header("Content-Type", "application/json")
        handler.end_headers()
        body = (
            '{"status":"ok","message":"local benchmark resource",'
            f'"route_id":"{metadata.get("route_id", "")}"}}'
        )
        handler.wfile.write(body.encode("utf-8"))
