from __future__ import annotations

import json
import importlib.util
from pathlib import Path
import subprocess
import sys
import time

import pytest

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"


def _write_config(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def _run_command(command: list[str]) -> None:
    subprocess.run(
        command,
        cwd=ROOT,
        check=True,
        text=True,
        capture_output=True,
    )


def _latest_jsonl_after(start_ts: float) -> Path:
    candidates = [
        path
        for path in RESULTS.glob("run_*.jsonl")
        if path.stat().st_mtime >= start_ts - 1e-3
    ]
    assert candidates, "No run_*.jsonl output created"
    return max(candidates, key=lambda path: path.stat().st_mtime)


def _assert_summary_has_asr() -> None:
    summary_path = RESULTS / "summary.json"
    assert summary_path.exists(), "summary.json was not created"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert "asr" in summary


def test_orchestration_smoke_as(tmp_path: Path) -> None:
    config = tmp_path / "as_smoke.json"
    _write_config(
        config,
        {
            "trials": 1,
            "cases": ["attacks.instances.as.as_001:AS_001"],
            "sut": {
                "selector": "sut.as.heuristic_selector:HeuristicSelector",
                "kwargs": {},
            },
        },
    )
    start = time.time()
    _run_command(
        [
            sys.executable,
            "orchestration.py",
            "--config",
            str(config),
            "--trials",
            "1",
        ]
    )
    jsonl = _latest_jsonl_after(start)
    assert jsonl.exists()
    _assert_summary_has_asr()


def test_orchestration_smoke_cc_whitebox(tmp_path: Path) -> None:
    config = tmp_path / "cc_smoke.json"
    _write_config(
        config,
        {
            "trials": 1,
            "cases": ["attacks.instances.cc_whitebox:CCWhitebox001"],
            "sut": {
                "comparator": "sut.cc.whitebox_static_comparator:WhiteboxStaticComparator",
                "kwargs": {},
            },
        },
    )
    start = time.time()
    _run_command(
        [
            sys.executable,
            "orchestration.py",
            "--config",
            str(config),
            "--mode",
            "whitebox",
            "--trials",
            "1",
        ]
    )
    jsonl = _latest_jsonl_after(start)
    assert jsonl.exists()
    _assert_summary_has_asr()


def test_orchestration_smoke_cc_blackbox(tmp_path: Path) -> None:
    if importlib.util.find_spec("uvicorn") is None or importlib.util.find_spec("fastapi") is None:
        pytest.skip("blackbox CC smoke requires fastapi and uvicorn")

    config = tmp_path / "cc_blackbox_smoke.json"
    _write_config(
        config,
        {
            "trials": 1,
            "cases": ["attacks.instances.cc_blackbox:CCBlackbox002"],
            "sut": {
                "comparator": "sut.cc.a2a_smoke_comparator:A2ASmokeComparator",
                "kwargs": {},
            },
        },
    )
    start = time.time()
    _run_command(
        [
            sys.executable,
            "orchestration.py",
            "--config",
            str(config),
            "--mode",
            "blackbox",
            "--trials",
            "1",
        ]
    )
    jsonl = _latest_jsonl_after(start)
    assert jsonl.exists()
    _assert_summary_has_asr()


def test_orchestration_smoke_a2a_security(tmp_path: Path) -> None:
    config = tmp_path / "asrf_smoke.json"
    _write_config(
        config,
        {
            "trials": 1,
            "cases": ["attacks.instances.asrf.calibration:ASRF001"],
            "sut": {
                "a2a_security": "sut.a2a.reference:A2ASUT",
                "kwargs": {},
            },
        },
    )
    start = time.time()
    _run_command(
        [
            sys.executable,
            "orchestration.py",
            "--config",
            str(config),
            "--trials",
            "1",
        ]
    )
    jsonl = _latest_jsonl_after(start)
    assert jsonl.exists()
    _assert_summary_has_asr()


def test_orchestration_smoke_hotf_executable(tmp_path: Path) -> None:
    config = tmp_path / "hotf_smoke.json"
    _write_config(
        config,
        {
            "trials": 1,
            "cases": ["attacks.instances.hotf.executable:HOTFEval001"],
            "sut": {
                "a2a_security": "sut.a2a.reference_env:A2AExecutableSUT",
                "kwargs": {},
            },
        },
    )
    start = time.time()
    _run_command(
        [
            sys.executable,
            "orchestration.py",
            "--config",
            str(config),
            "--trials",
            "1",
        ]
    )
    jsonl = _latest_jsonl_after(start)
    assert jsonl.exists()
    _assert_summary_has_asr()


def test_orchestration_smoke_co_executable(tmp_path: Path) -> None:
    config = tmp_path / "co_smoke.json"
    _write_config(
        config,
        {
            "trials": 1,
            "cases": ["attacks.instances.co.executable:COEval001"],
            "sut": {
                "a2a_security": "sut.a2a.reference_env:A2AExecutableSUT",
                "kwargs": {},
            },
        },
    )
    start = time.time()
    _run_command(
        [
            sys.executable,
            "orchestration.py",
            "--config",
            str(config),
            "--trials",
            "1",
        ]
    )
    jsonl = _latest_jsonl_after(start)
    assert jsonl.exists()
    _assert_summary_has_asr()


def test_orchestration_smoke_atsi_executable(tmp_path: Path) -> None:
    config = tmp_path / "atsi_smoke.json"
    _write_config(
        config,
        {
            "trials": 1,
            "cases": ["attacks.instances.atsi.executable:ATSIEval001"],
            "sut": {
                "a2a_security": "sut.a2a.reference_env:A2AExecutableSUT",
                "kwargs": {},
            },
        },
    )
    start = time.time()
    _run_command(
        [
            sys.executable,
            "orchestration.py",
            "--config",
            str(config),
            "--trials",
            "1",
        ]
    )
    jsonl = _latest_jsonl_after(start)
    assert jsonl.exists()
    _assert_summary_has_asr()
