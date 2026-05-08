from pathlib import Path

import pytest

import utils.agentcard_io as agentcard_io


def test_agentcard_missing_required_keys_lists_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "_tmp_missing_keys.json"
    path.write_text('{"name": "broken"}', encoding="utf-8")
    monkeypatch.setattr(agentcard_io, "_agentcard_roots", lambda: (tmp_path,))

    with pytest.raises(ValueError) as exc:
        agentcard_io.load_agentcard(str(path))

    message = str(exc.value)
    assert "missing required keys" in message
    assert "protocolVersion" in message
    assert "skills" in message
