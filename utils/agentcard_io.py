from __future__ import annotations

import json
from pathlib import Path

_REQUIRED_KEYS = {
    "protocolVersion",
    "name",
    "description",
    "url",
    "preferredTransport",
    "version",
    "capabilities",
    "skills",
    "supportsAuthenticatedExtendedCard",
}


def _agentcard_roots() -> tuple[Path, ...]:
    repo_root = Path(__file__).resolve().parents[1]
    return (
        repo_root / "attacks" / "fixtures",
        repo_root / "attacks" / "legacy" / "cc_explicit" / "fixtures",
    )


def _ensure_under_agentcard_roots(path: Path) -> None:
    resolved = path.resolve()
    for root in _agentcard_roots():
        try:
            resolved.relative_to(root.resolve())
            return
        except ValueError:
            continue
    roots = ", ".join(str(root) for root in _agentcard_roots())
    raise ValueError(f"AgentCard must be stored under one of: {roots}. Got: {path}")


def load_agentcard(path: str) -> dict:
    path_obj = Path(path)
    _ensure_under_agentcard_roots(path_obj)
    try:
        content = path_obj.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"AgentCard file not found: {path_obj}") from exc

    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in AgentCard '{path_obj}': {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError(f"AgentCard '{path_obj}' must be a JSON object.")

    missing = sorted(_REQUIRED_KEYS - set(data.keys()))
    if missing:
        raise ValueError(f"AgentCard '{path_obj}' missing required keys: {missing}")
    return data
