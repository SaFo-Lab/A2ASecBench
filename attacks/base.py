from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class TrialOutcome:
    attack_id: str
    case_id: str
    trial_index: int
    success: bool
    details: dict
    errors: list[str]


class AttackCase(ABC):
    attack_id: str
    scenario: str = "generic"

    @abstractmethod
    def get_ground_truth(self) -> object:
        raise NotImplementedError

    @abstractmethod
    def run(self, sut, **kwargs) -> TrialOutcome:
        raise NotImplementedError
