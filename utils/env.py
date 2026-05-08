from __future__ import annotations

import os
from pathlib import Path


def _strip_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def _load_dotenv_fallback(path: Path, override: bool = False) -> None:
    if not path.exists():
        return

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].strip()
        if "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = _strip_quotes(value.strip())
        if not key or (not override and key in os.environ):
            continue
        os.environ[key] = value


def load_repo_env(path: Path | None = None, override: bool = False) -> None:
    env_path = path or Path(__file__).resolve().parents[1] / ".env"
    try:
        from dotenv import load_dotenv
    except ImportError:
        _load_dotenv_fallback(env_path, override=override)
        return

    load_dotenv(env_path, override=override)
