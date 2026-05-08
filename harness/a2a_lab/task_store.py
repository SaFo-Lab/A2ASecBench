from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from harness.a2a_lab.events import EventRecorder

HALF_OPEN_STATES = {
    "input-required",
    "pending-approval",
    "waiting-upload",
    "awaiting-user-confirmation",
}


@dataclass
class TaskRecord:
    task_id: str
    peer_id: str
    campaign_id: str
    task_type: str
    state: str
    description: str


class TaskStore:
    def __init__(self, recorder: EventRecorder) -> None:
        self.recorder = recorder
        self._tasks: dict[str, TaskRecord] = {}
        self._counter = 0
        self._peak_half_open_by_campaign: dict[str, int] = {}

    def create_task(
        self,
        *,
        peer_id: str,
        campaign_id: str,
        task_type: str,
        state: str,
        description: str,
        pressure_threshold: int | None = None,
        case_role: str | None = None,
    ) -> TaskRecord:
        self._counter += 1
        task_id = f"task-{self._counter:04d}"
        task = TaskRecord(
            task_id=task_id,
            peer_id=peer_id,
            campaign_id=campaign_id,
            task_type=task_type,
            state=state,
            description=description,
        )
        self._tasks[task_id] = task
        self.recorder.record(
            "task_created",
            "task_store",
            actor_id=peer_id,
            evidence={
                "task_id": task_id,
                "campaign_id": campaign_id,
                "task_type": task_type,
                "state": state,
            },
            private_tags={"case_role": case_role, "campaign_id": campaign_id},
        )
        self._record_snapshot(
            campaign_id=campaign_id,
            task_type=task_type,
            pressure_threshold=pressure_threshold,
            case_role=case_role,
        )
        return task

    def update_task_status(
        self,
        task_id: str,
        state: str,
        *,
        reason: str = "",
        pressure_threshold: int | None = None,
        case_role: str | None = None,
    ) -> None:
        task = self._tasks[task_id]
        previous = task.state
        task.state = state
        self.recorder.record(
            "task_status_changed",
            "task_store",
            actor_id=task.peer_id,
            evidence={
                "task_id": task_id,
                "previous_state": previous,
                "state": state,
                "reason": reason,
            },
            private_tags={"case_role": case_role, "campaign_id": task.campaign_id},
        )
        self._record_snapshot(
            campaign_id=task.campaign_id,
            task_type=task.task_type,
            pressure_threshold=pressure_threshold,
            case_role=case_role,
        )

    def count_half_open(self, campaign_id: str | None = None) -> int:
        return sum(
            1
            for task in self._tasks.values()
            if task.state in HALF_OPEN_STATES
            and (campaign_id is None or task.campaign_id == campaign_id)
        )

    def half_open_by_state(self, campaign_id: str | None = None) -> dict[str, int]:
        counts = {state: 0 for state in sorted(HALF_OPEN_STATES)}
        for task in self._tasks.values():
            if task.state in HALF_OPEN_STATES and (
                campaign_id is None or task.campaign_id == campaign_id
            ):
                counts[task.state] += 1
        return counts

    @property
    def peak_half_open_by_campaign(self) -> dict[str, int]:
        return dict(self._peak_half_open_by_campaign)

    def _record_snapshot(
        self,
        *,
        campaign_id: str,
        task_type: str,
        pressure_threshold: int | None,
        case_role: str | None,
    ) -> None:
        count = self.count_half_open(campaign_id)
        previous_peak = self._peak_half_open_by_campaign.get(campaign_id, 0)
        if count > previous_peak:
            self._peak_half_open_by_campaign[campaign_id] = count
        by_state = self.half_open_by_state(campaign_id)
        self.recorder.record(
            "task_store_snapshot",
            "task_store",
            evidence={
                "campaign_id": campaign_id,
                "half_open_count": count,
                "half_open_by_state": by_state,
            },
            private_tags={"case_role": case_role, "campaign_id": campaign_id},
        )
        if pressure_threshold is not None and count >= pressure_threshold:
            self.recorder.record(
                "task_store_pressure",
                "task_store",
                evidence={
                    "campaign_id": campaign_id,
                    "half_open_count": count,
                    "threshold": pressure_threshold,
                    "task_type": task_type,
                    "half_open_by_state": by_state,
                },
                private_tags={"case_role": case_role, "campaign_id": campaign_id},
            )
