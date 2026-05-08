from __future__ import annotations

from typing import Any

from sut.base import A2AProbeResult, A2ASecuritySUT


class A2ASUT(A2ASecuritySUT):
    """Deterministic reference fixture calibrated against structured oracles."""

    def run_probe(self, case: dict[str, Any], env: Any | None = None) -> A2AProbeResult:
        attack_id = case["attack_id"]
        if attack_id == "ASRF":
            return self._run_asrf(case)
        if attack_id == "ATSI":
            return self._run_atsi(case)
        if attack_id == "CO":
            return self._run_co(case)
        if attack_id == "HOTF":
            return self._run_hotf(case)
        return A2AProbeResult(error_message=f"unsupported attack_id {attack_id!r}")

    def _run_asrf(self, case: dict[str, Any]) -> A2AProbeResult:
        resource = case["resource"]
        event = {
            "type": "uri_dereference",
            "uri": resource["uri"],
            "marker_id": resource["marker_id"],
            "request_surface": case["request_surface"],
            "source_agent": case["source_agent"],
            "target_agent": case["target_agent"],
        }
        return A2AProbeResult(
            response_text=f"Fetched delegated resource for {case['target_agent']}.",
            events=[event],
            metrics={"uri_dereference_count": 1},
        )

    def _run_atsi(self, case: dict[str, Any]) -> A2AProbeResult:
        artifact = case["artifact"]
        event = {
            "type": "artifact_executed",
            "artifact_id": artifact["artifact_id"],
            "marker_id": artifact["marker_id"],
            "execution_sink": artifact["execution_sink"],
            "artifact_type": artifact["artifact_type"],
            "renderer": case["renderer"],
        }
        return A2AProbeResult(
            response_text=f"Preview rendered for artifact {artifact['artifact_id']}.",
            events=[event],
            metrics={"rendered_artifacts": 1},
        )

    def _run_co(self, case: dict[str, Any]) -> A2AProbeResult:
        path = list(case["delegation_graph"]["cycle_path"])
        depth = int(case["delegation_graph"]["min_depth"])
        events = [
            {"type": "delegation_step", "path": path[:2], "depth": 1},
            {"type": "cycle_detected", "path": path, "depth": depth},
            {"type": "max_depth_exceeded", "path": path, "depth": depth},
        ]
        return A2AProbeResult(
            response_text="Delegation loop exhausted coordinator depth budget.",
            events=events,
            metrics={"delegation_depth": depth, "cycle_count": 1},
        )

    def _run_hotf(self, case: dict[str, Any]) -> A2AProbeResult:
        pressure = case["task_pressure"]
        count = int(pressure["input_required_count"])
        event = {
            "type": "task_store_pressure",
            "input_required_count": count,
            "task_type": pressure["task_type"],
            "queue": pressure["queue"],
        }
        return A2AProbeResult(
            response_text=f"Task queue retained {count} input-required tasks.",
            events=[event],
            metrics={"input_required_count": count, "open_task_count": count},
        )

