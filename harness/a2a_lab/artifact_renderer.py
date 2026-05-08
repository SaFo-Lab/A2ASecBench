from __future__ import annotations

from typing import Any
from urllib.request import urlopen

from harness.a2a_lab.events import EventRecorder


class ArtifactRenderer:
    def __init__(self, recorder: EventRecorder, timeout_s: float = 2.0) -> None:
        self.recorder = recorder
        self.timeout_s = timeout_s
        self._render_count = 0
        self._safe_render_count = 0
        self._execution_error_count = 0

    def render(
        self,
        *,
        artifact: dict[str, Any],
        execution_sink: str,
        render_mode: str,
        case_role: str | None,
        request_surface: str | None,
    ) -> dict[str, Any]:
        artifact_id = str(artifact.get("artifact_id", ""))
        artifact_type = str(artifact.get("artifact_type", ""))
        marker_id = str(artifact.get("marker_id", ""))
        callback_url = str(artifact.get("callback_url", ""))
        body = str(artifact.get("body", ""))
        self._render_count += 1
        self.recorder.record(
            "artifact_rendered",
            "artifact_renderer",
            actor_id="sut",
            public_surface=request_surface,
            evidence={
                "artifact_id": artifact_id,
                "artifact_type": artifact_type,
                "execution_sink": execution_sink,
                "render_mode": render_mode,
            },
            private_tags={
                "case_role": case_role,
                "artifact_id": artifact_id,
                "marker_id": marker_id,
                "execution_sink": execution_sink,
                "request_surface": request_surface,
            },
        )

        if render_mode != "active" or not callback_url or callback_url not in body:
            self._safe_render_count += 1
            return {"status": "rendered", "executed": False}

        try:
            with urlopen(callback_url, timeout=self.timeout_s) as response:  # noqa: S310 - local callback URL only
                response.read()
            return {"status": "rendered", "executed": True}
        except Exception as exc:
            self._execution_error_count += 1
            self.recorder.record(
                "artifact_execution_error",
                "artifact_renderer",
                actor_id="sut",
                public_surface=request_surface,
                evidence={
                    "artifact_id": artifact_id,
                    "execution_sink": execution_sink,
                    "callback_url": callback_url,
                    "error": str(exc),
                },
                private_tags={
                    "case_role": case_role,
                    "artifact_id": artifact_id,
                    "marker_id": marker_id,
                    "execution_sink": execution_sink,
                    "request_surface": request_surface,
                },
            )
            return {"status": "error", "executed": False, "error": str(exc)}

    @property
    def metrics(self) -> dict[str, int]:
        return {
            "artifact_render_count": self._render_count,
            "safe_artifact_render_count": self._safe_render_count,
            "artifact_execution_error_count": self._execution_error_count,
        }
