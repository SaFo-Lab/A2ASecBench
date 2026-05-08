from __future__ import annotations

import re

from sut.base import SelectionResult, SelectorSUT


_TOKEN_RE = re.compile(r"[a-z0-9_]+")


def _tokenize(text: str) -> set[str]:
    return set(_TOKEN_RE.findall(text.lower()))


def _card_text(card: dict) -> str:
    parts: list[str] = [str(card.get("name", "")), str(card.get("description", ""))]
    for skill in card.get("skills", []):
        if isinstance(skill, dict):
            parts.append(str(skill.get("name", "")))
            parts.append(str(skill.get("description", "")))
            parts.append(str(skill.get("id", "")))
        else:
            parts.append(str(skill))
    return " ".join(parts)


class HeuristicSelector(SelectorSUT):
    def select(self, task_prompt: str, cards: list[dict]) -> SelectionResult:
        if not cards:
            raise ValueError("HeuristicSelector received an empty card list.")

        prompt_tokens = _tokenize(task_prompt)
        scored: list[tuple[int, int, int]] = []
        for idx, card in enumerate(cards, start=1):
            tokens = _tokenize(_card_text(card))
            overlap = len(prompt_tokens & tokens)
            skill_count = len(card.get("skills", [])) if isinstance(card.get("skills"), list) else 0
            scored.append((idx, overlap, skill_count))

        # Deterministic tie-break: higher overlap, then higher skill_count, then lower index.
        choice = min(
            scored,
            key=lambda item: (-item[1], -item[2], item[0]),
        )[0]

        return SelectionResult(
            choice=choice,
            raw=str(choice),
            meta={
                "method": "keyword_overlap",
                "scores": [
                    {"choice": idx, "overlap": overlap, "skill_count": skill_count}
                    for idx, overlap, skill_count in scored
                ],
                "parse_meta": {"valid": True, "reason": ""},
                "retry_count": 0,
            },
        )
