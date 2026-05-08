from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from harness.a2a_lab.events import EventRecorder


@dataclass
class DelegationEdge:
    source_agent_id: str
    target_agent_id: str
    task_signature: str
    depth: int


class DelegationTracker:
    def __init__(self, recorder: EventRecorder) -> None:
        self.recorder = recorder
        self._edges: list[DelegationEdge] = []
        self._target_path: list[str] = []
        self._cycle_event_count = 0
        self._max_depth_event_count = 0
        self._completed = False
        self._rejected = False

    def record_delegation(
        self,
        *,
        source_agent_id: str,
        target_agent_id: str,
        task_signature: str,
        depth_budget: int | None,
        expected_cycle_path: list[str] | None,
        request_surface: str | None,
        case_role: str | None,
    ) -> DelegationEdge:
        depth = len(self._edges) + 1
        edge = DelegationEdge(
            source_agent_id=source_agent_id,
            target_agent_id=target_agent_id,
            task_signature=task_signature,
            depth=depth,
        )
        self._edges.append(edge)
        self._target_path.append(target_agent_id)
        private_tags = {
            "case_role": case_role,
            "request_surface": request_surface,
            "task_signature": task_signature,
        }
        self.recorder.record(
            "delegation_edge",
            "delegation_graph",
            actor_id=source_agent_id,
            public_surface=request_surface,
            evidence={
                "source_agent_id": source_agent_id,
                "target_agent_id": target_agent_id,
                "task_signature": task_signature,
                "depth": depth,
            },
            private_tags=private_tags,
        )
        self._record_cycle_if_present(
            depth=depth,
            expected_cycle_path=expected_cycle_path,
            private_tags=private_tags,
        )
        self._record_limit_if_present(
            depth=depth,
            depth_budget=depth_budget,
            private_tags=private_tags,
        )
        return edge

    def record_completed(
        self,
        *,
        task_signature: str,
        request_surface: str | None,
        case_role: str | None,
    ) -> None:
        self._completed = True
        self.recorder.record(
            "delegation_completed",
            "delegation_graph",
            evidence={
                "task_signature": task_signature,
                "depth": len(self._edges),
                "target_path": list(self._target_path),
            },
            private_tags={
                "case_role": case_role,
                "request_surface": request_surface,
                "task_signature": task_signature,
            },
        )

    def record_rejected(
        self,
        *,
        source_agent_id: str,
        target_agent_id: str,
        task_signature: str,
        reason: str,
        request_surface: str | None,
        case_role: str | None,
    ) -> None:
        self._rejected = True
        self.recorder.record(
            "delegation_rejected",
            "delegation_graph",
            actor_id=source_agent_id,
            public_surface=request_surface,
            evidence={
                "source_agent_id": source_agent_id,
                "target_agent_id": target_agent_id,
                "task_signature": task_signature,
                "reason": reason,
                "depth": len(self._edges),
            },
            private_tags={
                "case_role": case_role,
                "request_surface": request_surface,
                "task_signature": task_signature,
            },
        )

    @property
    def metrics(self) -> dict[str, Any]:
        return {
            "delegation_edge_count": len(self._edges),
            "max_delegation_depth": len(self._edges),
            "observed_delegation_path": list(self._target_path),
            "cycle_detected_count": self._cycle_event_count,
            "max_depth_exceeded_count": self._max_depth_event_count,
            "delegation_completed": self._completed,
            "delegation_rejected": self._rejected,
        }

    def _record_cycle_if_present(
        self,
        *,
        depth: int,
        expected_cycle_path: list[str] | None,
        private_tags: dict[str, Any],
    ) -> None:
        if not expected_cycle_path:
            return
        cycle_len = len(expected_cycle_path)
        if cycle_len < 3 or len(self._target_path) < cycle_len:
            return
        if self._target_path[-cycle_len:] != expected_cycle_path:
            return
        self._cycle_event_count += 1
        self.recorder.record(
            "cycle_detected",
            "delegation_graph",
            evidence={
                "path": list(expected_cycle_path),
                "depth": depth,
                "cycle_length": cycle_len,
            },
            private_tags=private_tags,
        )

    def _record_limit_if_present(
        self,
        *,
        depth: int,
        depth_budget: int | None,
        private_tags: dict[str, Any],
    ) -> None:
        if depth_budget is None or depth < depth_budget:
            return
        self._max_depth_event_count += 1
        self.recorder.record(
            "max_depth_exceeded",
            "delegation_graph",
            evidence={
                "depth": depth,
                "depth_budget": depth_budget,
                "target_path": list(self._target_path),
            },
            private_tags=private_tags,
        )
