from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import importlib
import json
import os
from pathlib import Path
from typing import Any

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover - exercised in environments without pyyaml.
    yaml = None

from attacks.base import AttackCase
from attacks.a2a_attack import A2A_ATTACK_IDS
from sut.registry import load_a2a_security, load_comparator, load_selector
from utils.env import load_repo_env
from utils.logging import get_logger

load_repo_env(Path(__file__).resolve().parent / ".env", override=False)


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _config_hash(config: dict) -> str:
    canonical = json.dumps(config, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _load_case(path: str) -> AttackCase:
    if ":" not in path:
        raise ValueError(f"Invalid case path '{path}'. Expected format module:ClassName")
    module_name, class_name = path.split(":", 1)
    try:
        module = importlib.import_module(module_name)
    except Exception as exc:
        raise ImportError(f"Failed to import case module '{module_name}' from '{path}': {exc}") from exc

    if not hasattr(module, class_name):
        available = sorted(name for name in dir(module) if not name.startswith("__"))
        raise AttributeError(
            f"Case class '{class_name}' not found in '{module_name}' for '{path}'. "
            f"Available attributes: {available}"
        )

    cls = getattr(module, class_name)
    try:
        instance = cls()
    except Exception as exc:
        raise TypeError(f"Failed to instantiate case '{path}': {exc}") from exc

    if not isinstance(instance, AttackCase):
        raise TypeError(
            f"Loaded case '{path}' is not an AttackCase. Got {type(instance).__name__}."
        )
    return instance


def _load_config(path: Path) -> dict:
    try:
        text = path.read_text(encoding="utf-8")
        if yaml is not None:
            payload = yaml.safe_load(text)
        else:
            payload = json.loads(text)
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"Config file not found: {path}") from exc
    except Exception as exc:
        if yaml is None:
            raise ValueError(
                f"Invalid config '{path}': pyyaml is unavailable, so config must be JSON-compatible YAML. {exc}"
            ) from exc
        raise ValueError(f"Invalid YAML in config '{path}': {exc}") from exc

    if not isinstance(payload, dict):
        raise ValueError(f"Config '{path}' must be a YAML mapping.")
    return payload


def _default_out_path() -> Path:
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    return Path("results") / f"run_{ts}.jsonl"


def _build_summary(
    records: list[dict[str, Any]],
    config_path: str,
    config_hash: str,
    run_started_at: str,
    run_finished_at: str,
    mode: str | None,
) -> dict:
    case_counts: dict[str, dict[str, float | int]] = {}
    total_trials = len(records)
    total_successes = sum(1 for r in records if r["success"])

    for record in records:
        case_id = record["case_id"]
        bucket = case_counts.setdefault(case_id, {"trials": 0, "successes": 0, "asr": 0.0})
        bucket["trials"] += 1
        if record["success"]:
            bucket["successes"] += 1

    for stats in case_counts.values():
        trials = int(stats["trials"])
        successes = int(stats["successes"])
        stats["asr"] = successes / trials if trials else 0.0

    summary = {
        "config_path": config_path,
        "config_hash": config_hash,
        "run_started_at": run_started_at,
        "run_finished_at": run_finished_at,
        "total_trials": total_trials,
        "total_successes": total_successes,
        "asr": (total_successes / total_trials) if total_trials else 0.0,
        "counts_per_case": case_counts,
    }

    if records and records[0]["attack_id"] == "CC":
        cc_mode = mode or "unknown"
        summary["cc_mode_asr"] = {cc_mode: summary["asr"]}
        label_records = [
            r for r in records
            if isinstance(r.get("details"), dict) and "label_correct" in r["details"]
        ]
        if label_records:
            label_correct = sum(1 for r in label_records if r["details"].get("label_correct"))
            summary["label_accuracy"] = label_correct / len(label_records)
            summary["evidence_metric"] = "not_judged"
    elif records and records[0]["attack_id"] in A2A_ATTACK_IDS:
        attack_records = [
            r for r in records
            if not (isinstance(r.get("details"), dict) and r["details"].get("is_control"))
        ]
        control_records = [
            r for r in records
            if isinstance(r.get("details"), dict) and r["details"].get("is_control")
        ]
        if attack_records:
            summary["a2a_attack_asr"] = sum(1 for r in attack_records if r["success"]) / len(attack_records)
            summary["a2a_attack_trials"] = len(attack_records)
        if control_records:
            passed = sum(1 for r in control_records if r["details"].get("control_pass"))
            summary["control_pass_rate"] = passed / len(control_records)
            summary["overblock_rate"] = 1.0 - summary["control_pass_rate"]
            summary["control_trials"] = len(control_records)

    return summary


def run(config_path: Path, mode: str | None, trials_override: int | None, out: Path | None) -> tuple[Path, Path, dict]:
    # 1) Initialize run-level bookkeeping and load immutable config inputs.
    logger = get_logger("orchestration")
    run_started_at = _iso_now()

    config = _load_config(config_path)
    config_hash = _config_hash(config)

    case_paths = config.get("cases")
    if not isinstance(case_paths, list) or not case_paths:
        raise ValueError(f"Config '{config_path}' must contain non-empty list 'cases'.")

    trials_cfg = config.get("trials", 1)
    try:
        trials = int(trials_override if trials_override is not None else trials_cfg)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid trials value: {trials_override if trials_override is not None else trials_cfg}") from exc
    if trials <= 0:
        raise ValueError("Trials must be >= 1.")

    # 2) Materialize attack cases from import paths and ensure this run is attack-homogeneous.
    cases = [_load_case(path) for path in case_paths]
    attack_ids = {case.attack_id for case in cases}
    if len(attack_ids) != 1:
        raise ValueError(f"All cases in a run must share one attack_id. Got: {sorted(attack_ids)}")
    attack_id = next(iter(attack_ids))

    sut_cfg = config.get("sut")
    if not isinstance(sut_cfg, dict):
        raise ValueError(f"Config '{config_path}' must contain mapping 'sut'.")
    sut_kwargs = sut_cfg.get("kwargs") or {}
    if not isinstance(sut_kwargs, dict):
        raise ValueError(f"Config '{config_path}' field 'sut.kwargs' must be a mapping if provided.")

    # 3) Resolve and instantiate exactly one SUT for the whole run.
    #    AS uses selector interface, CC uses comparator interface, and
    #    coordinator-level A2A attacks use the structured probe interface.
    if attack_id == "AS":
        selector_path = sut_cfg.get("selector")
        if not isinstance(selector_path, str):
            raise ValueError("AS config must set sut.selector as 'module:Class'.")
        if mode is not None:
            raise ValueError("--mode is not valid for AS runs.")
        sut = load_selector(selector_path, **sut_kwargs)
    elif attack_id == "CC":
        comparator_path = sut_cfg.get("comparator")
        if not isinstance(comparator_path, str):
            raise ValueError("CC config must set sut.comparator as 'module:Class'.")
        if mode not in {"whitebox", "blackbox"}:
            raise ValueError("CC runs require --mode whitebox|blackbox.")
        sut = load_comparator(comparator_path, **sut_kwargs)
    elif attack_id in A2A_ATTACK_IDS:
        a2a_security_path = sut_cfg.get("a2a_security")
        if not isinstance(a2a_security_path, str):
            raise ValueError(
                f"{attack_id} config must set sut.a2a_security as 'module:Class'."
            )
        if mode is not None:
            raise ValueError(f"--mode is not valid for {attack_id} runs.")
        sut = load_a2a_security(a2a_security_path, **sut_kwargs)
    else:
        raise ValueError(f"Unsupported attack_id '{attack_id}'.")

    out_path = out or _default_out_path()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # 4) Execute trials case-by-case and append one JSONL record per trial.
    records: list[dict[str, Any]] = []
    logger.info(
        "Run started",
        {
            "config_path": str(config_path),
            "config_hash": config_hash,
            "attack_id": attack_id,
            "trials": trials,
            "out": str(out_path),
            "mode": mode,
        },
    )

    with out_path.open("w", encoding="utf-8") as fp:
        for case in cases:
            for trial_index in range(trials):
                # Delegate attack-specific execution to the case implementation.
                if attack_id == "AS":
                    outcome = case.run(sut=sut, trial_index=trial_index)
                elif attack_id == "CC":
                    outcome = case.run(sut=sut, mode=mode, trial_index=trial_index)
                else:
                    outcome = case.run(sut=sut, trial_index=trial_index)

                # Persist trial output immediately for deterministic, crash-tolerant logging.
                record = {
                    "timestamp": _iso_now(),
                    "config_path": str(config_path),
                    "config_hash": config_hash,
                    **asdict(outcome),
                }
                fp.write(json.dumps(record, sort_keys=True) + "\n")
                fp.flush()
                records.append(record)

    # 5) Compute aggregate metrics, emit summary.json, and print user-facing ASR.
    run_finished_at = _iso_now()
    summary = _build_summary(
        records=records,
        config_path=str(config_path),
        config_hash=config_hash,
        run_started_at=run_started_at,
        run_finished_at=run_finished_at,
        mode=mode,
    )

    summary_path = out_path.with_name("summary.json")
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")

    if attack_id == "AS":
        print(f"ASR (AS): {summary['asr']:.4f}")
    elif attack_id == "CC":
        print(f"ASR (CC/{mode}): {summary['asr']:.4f}")
    else:
        display_asr = summary.get("a2a_attack_asr", summary["asr"])
        print(f"ASR ({attack_id}): {display_asr:.4f}")
        if "control_pass_rate" in summary:
            print(f"Control pass rate ({attack_id}): {summary['control_pass_rate']:.4f}")

    logger.info(
        "Run finished",
        {
            "records": len(records),
            "summary_path": str(summary_path),
            "asr": summary["asr"],
        },
    )
    return out_path, summary_path, summary


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="A2ASecBench orchestration runner")
    parser.add_argument("--config", required=True, help="Path to YAML config.")
    parser.add_argument(
        "--mode",
        choices=["whitebox", "blackbox"],
        default=None,
        help="CC mode: `whitebox` inspects source; `blackbox` probes A2A behavior.",
    )
    parser.add_argument("--trials", type=int, default=None, help="Override number of trials.")
    parser.add_argument("--out", default=None, help="Output JSONL path.")
    return parser


def main(argv: list[str] | None = None) -> None:
    parser = _build_parser()
    args = parser.parse_args(argv)
    out = Path(args.out) if args.out else None
    run(config_path=Path(args.config), mode=args.mode, trials_override=args.trials, out=out)


if __name__ == "__main__":
    main()
