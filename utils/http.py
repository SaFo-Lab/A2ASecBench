from __future__ import annotations

import atexit
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time
from urllib.parse import urlparse

import requests

from attacks.cc_attack import ServiceHandle
from utils.logging import get_logger

_ALLOWED_LOCAL_HOSTS = {"127.0.0.1", "localhost"}
_SERVICE_PROCS: dict[int, tuple[subprocess.Popen, object]] = {}
_LOGGER = get_logger("cc_http")


def _ensure_local_url(url: str) -> None:
    parsed = urlparse(url)
    host = parsed.hostname
    if host not in _ALLOWED_LOCAL_HOSTS:
        raise ValueError(
            f"Only localhost probing is allowed in v0. Refusing URL: {url}"
        )


def _summarize_payload(payload) -> dict:
    if isinstance(payload, dict):
        return {"type": "dict", "keys": sorted(str(k) for k in payload.keys())}
    if isinstance(payload, list):
        return {"type": "list", "length": len(payload)}
    return {"type": type(payload).__name__}


def get_json(url: str, timeout_s: float = 5.0, log_events: bool = True):
    _ensure_local_url(url)
    if log_events:
        _LOGGER.info("HTTP GET request", {"url": url, "timeout_s": timeout_s})
    # Explicitly ignore proxy env vars so localhost probes never leave the host.
    with requests.Session() as session:
        session.trust_env = False
        response = session.get(url, timeout=timeout_s, allow_redirects=False)
        response.raise_for_status()
        payload = response.json()
        if log_events:
            _LOGGER.info(
                "HTTP GET response",
                {
                    "url": url,
                    "status_code": response.status_code,
                    "payload_summary": _summarize_payload(payload),
                },
            )
        return payload


def post_json(url: str, payload: dict, timeout_s: float = 5.0, log_events: bool = True):
    _ensure_local_url(url)
    if log_events:
        _LOGGER.info("HTTP POST request", {"url": url, "timeout_s": timeout_s})
    with requests.Session() as session:
        session.trust_env = False
        response = session.post(url, json=payload, timeout=timeout_s, allow_redirects=False)
        response.raise_for_status()
        result = response.json()
        if log_events:
            _LOGGER.info(
                "HTTP POST response",
                {
                    "url": url,
                    "status_code": response.status_code,
                    "payload_summary": _summarize_payload(result),
                },
            )
        return result


def _pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return int(sock.getsockname()[1])


def _results_dir() -> Path:
    root = Path(__file__).resolve().parents[1]
    path = root / "results"
    path.mkdir(parents=True, exist_ok=True)
    return path


def start_service(
    backend_module: str,
    readiness_timeout_s: float = 15.0,
    request_timeout_s: float = 1.0,
    agentcard_path: str | None = None,
) -> ServiceHandle:
    port = _pick_free_port()
    endpoint = f"http://127.0.0.1:{port}"

    ts = int(time.time() * 1000)
    safe_module = backend_module.replace(".", "_")
    logs_path = _results_dir() / f"service_{safe_module}_{ts}.log"
    log_fp = logs_path.open("w", encoding="utf-8")

    cmd = [
        sys.executable,
        "-m",
        "attacks.cc_attack",
        "serve",
        "--backend-module",
        backend_module,
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
    ]
    if agentcard_path:
        cmd.extend(["--agentcard-path", agentcard_path])
    _LOGGER.info(
        "Starting temporary CC backend service",
        {
            "backend_module": backend_module,
            "endpoint": endpoint,
            "logs_path": str(logs_path),
            "cmd": cmd,
        },
    )

    proc = subprocess.Popen(
        cmd,
        stdout=log_fp,
        stderr=subprocess.STDOUT,
        cwd=str(Path(__file__).resolve().parents[1]),
    )
    _SERVICE_PROCS[proc.pid] = (proc, log_fp)

    deadline = time.monotonic() + readiness_timeout_s
    health_url = f"{endpoint}/health"
    last_error: Exception | None = None
    attempts = 0
    while time.monotonic() < deadline:
        attempts += 1
        if proc.poll() is not None:
            break
        try:
            payload = get_json(health_url, timeout_s=request_timeout_s, log_events=False)
            if isinstance(payload, dict):
                _LOGGER.info(
                    "Temporary CC backend service is ready",
                    {
                        "backend_module": backend_module,
                        "pid": proc.pid,
                        "endpoint": endpoint,
                        "readiness_attempts": attempts,
                    },
                )
                return ServiceHandle(pid=proc.pid, endpoint=endpoint, logs_path=str(logs_path))
        except Exception as exc:
            last_error = exc
        time.sleep(0.2)

    stop_service(ServiceHandle(pid=proc.pid, endpoint=endpoint, logs_path=str(logs_path)))
    error_text = f"last error: {last_error}" if last_error else "service exited early"
    _LOGGER.error(
        "Temporary CC backend service readiness failed",
        {
            "backend_module": backend_module,
            "endpoint": endpoint,
            "pid": proc.pid,
            "readiness_attempts": attempts,
            "error": error_text,
            "logs_path": str(logs_path),
        },
    )
    raise RuntimeError(
        f"Unified CC probe service failed readiness for backend '{backend_module}' at {health_url}; "
        f"{error_text}. Logs: {logs_path}"
    )


def stop_service(handle: ServiceHandle) -> None:
    _LOGGER.info(
        "Stopping temporary CC backend service",
        {"pid": handle.pid, "endpoint": handle.endpoint, "logs_path": handle.logs_path},
    )
    state = _SERVICE_PROCS.pop(handle.pid, None)
    if state is None:
        try:
            os.kill(handle.pid, signal.SIGTERM)
        except ProcessLookupError:
            _LOGGER.info("Temporary service already exited", {"pid": handle.pid})
            return
        except PermissionError as exc:
            raise RuntimeError(f"Failed to terminate pid={handle.pid}: {exc}") from exc
        _LOGGER.info("Sent SIGTERM to untracked service pid", {"pid": handle.pid})
        return

    proc, log_fp = state
    try:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
    finally:
        log_fp.close()
    _LOGGER.info(
        "Temporary CC backend service stopped",
        {"pid": handle.pid, "return_code": proc.poll(), "logs_path": handle.logs_path},
    )


def _cleanup_all() -> None:
    if _SERVICE_PROCS:
        _LOGGER.warning(
            "Cleaning up leftover temporary CC backend services",
            {"count": len(_SERVICE_PROCS)},
        )
    for pid, (proc, log_fp) in list(_SERVICE_PROCS.items()):
        try:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=2)
        finally:
            log_fp.close()
            _SERVICE_PROCS.pop(pid, None)


atexit.register(_cleanup_all)
