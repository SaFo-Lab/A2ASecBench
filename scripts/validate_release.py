from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import importlib
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover
    yaml = None

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from attacks.a2a_attack import A2A_ATTACK_IDS
from attacks.base import AttackCase
from sut.a2a.reference import A2ASUT
from sut.a2a.reference_env import A2AExecutableSUT
from sut.registry import load_a2a_security, load_comparator, load_selector
CC_BLACKBOX_PREFIX = "attacks.instances.cc_blackbox:"
A2A_CALIBRATION_PACKAGES = {
    "ASRF": "asrf",
    "ATSI": "atsi",
    "CO": "co",
    "HOTF": "hotf",
}
CC_CASE_ID_RE = re.compile(r"\bccb?_\d{3}\b", re.IGNORECASE)
BLACKBOX_RESPONSE_SHORTCUT_TOKENS = (
    "raw_record",
    "mutated",
    "queued_action",
    "remote_delivery",
    "filter_ignored",
    "filter_applied",
    "limit_ignored",
    "limit_applied",
)
BLACKBOX_EXACT_PROBE_RE = re.compile(
    r"\b(format_type|include_raw|owner|show_memory|update_status|notify_url|status|limit|action)\s*=|"
    r"\"record_ids\"",
    re.IGNORECASE,
)
AGENTCARD_REQUIRED_KEYS = {
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
_OLD_WHITEBOX_TERM = "se" + "mantic"
_OLD_EASY_TERM = "triv" + "ial"
_OLD_SOURCE_HIDDEN_TERM = "non" + _OLD_EASY_TERM
LEGACY_CC_NAME_RE = re.compile(
    "|".join(
        [
            rf"\b{_OLD_WHITEBOX_TERM}\b",
            "cc_" + _OLD_WHITEBOX_TERM,
            "CC" + _OLD_WHITEBOX_TERM.capitalize(),
            _OLD_WHITEBOX_TERM + "_static",
            _OLD_WHITEBOX_TERM.capitalize() + "Static",
            "generate_cc_" + _OLD_WHITEBOX_TERM,
            _OLD_EASY_TERM + "-" + _OLD_WHITEBOX_TERM,
            _OLD_EASY_TERM + "-" + "explicit",
            rf"\b{_OLD_SOURCE_HIDDEN_TERM}\b",
            rf"\bnon-{_OLD_EASY_TERM}\b",
        ]
    ),
    re.IGNORECASE,
)
LEGACY_NAME_SCAN_TARGETS = (
    "AGENTS.md",
    "CLAUDE.md",
    "README.md",
    "RELEASE.md",
    "spec.md",
    "attacks",
    "configs",
    "docs",
    "scripts",
    "sut",
    "tests",
)
LEGACY_NAME_SUFFIXES = {".json", ".md", ".py", ".txt", ".yaml", ".yml"}
PROMPT_FORBIDDEN_TOKENS = (
    "asrf",
    "atsi",
    "hotf",
    "canary",
    "marker",
    "oracle",
    "uri_dereference",
    "artifact_executed",
    "cycle_detected",
    "max_depth_exceeded",
    "task_store_pressure",
)
SECRET_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bapi[_-]?key\s*=\s*['\"][^'\"]{12,}['\"]", re.IGNORECASE),
)
FORBIDDEN_ENDPOINTS = ("api.bianxie.ai", "ark-cn-beijing.bytedance.net")


def _load_config(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    data = yaml.safe_load(text) if yaml is not None else json.loads(text)
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a mapping")
    return data


def _contains_mapping_key(value: Any, key: str) -> bool:
    if isinstance(value, dict):
        return any(
            item_key == key or _contains_mapping_key(item_value, key)
            for item_key, item_value in value.items()
        )
    if isinstance(value, list):
        return any(_contains_mapping_key(item, key) for item in value)
    return False


def _assert_no_release_policy_field(case: Any) -> None:
    if _contains_mapping_key(getattr(case, "metadata", {}), "policy"):
        raise ValueError(f"{case.case_id} release metadata must not contain a policy field")
    if _contains_mapping_key(case.get_sut_payload(), "policy"):
        raise ValueError(f"{case.case_id} SUT payload must not expose a policy field")


def _iter_release_text_files() -> list[Path]:
    paths: list[Path] = []
    for target in LEGACY_NAME_SCAN_TARGETS:
        path = ROOT / target
        if not path.exists():
            continue
        if path.is_file():
            if path.resolve() == Path(__file__).resolve():
                continue
            paths.append(path)
            continue
        for child in path.rglob("*"):
            if "__pycache__" in child.parts:
                continue
            if child.resolve() == Path(__file__).resolve():
                continue
            if child.is_file() and child.suffix.lower() in LEGACY_NAME_SUFFIXES:
                paths.append(child)
    return paths


def _validate_no_legacy_cc_names() -> None:
    findings: list[str] = []
    for path in _iter_release_text_files():
        rel = path.relative_to(ROOT)
        if LEGACY_CC_NAME_RE.search(str(rel)):
            findings.append(str(rel))
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        match = LEGACY_CC_NAME_RE.search(text)
        if match:
            findings.append(f"{rel}: {match.group(0)!r}")
    if findings:
        raise ValueError(
            "Legacy CC naming remains after the whitebox/blackbox rename: "
            f"{findings[:10]}"
        )


def _validate_no_release_secrets_or_artifacts() -> None:
    findings: list[str] = []
    for path in _iter_release_text_files():
        rel = path.relative_to(ROOT)
        text = path.read_text(encoding="utf-8", errors="ignore")
        for pattern in SECRET_PATTERNS:
            if pattern.search(text):
                findings.append(f"{rel}: secret-like literal")
                break
        for endpoint in FORBIDDEN_ENDPOINTS:
            if endpoint in text:
                findings.append(f"{rel}: hard-coded endpoint {endpoint}")
    if findings:
        raise ValueError(f"Release secret/endpoint scan failed: {findings[:10]}")

    try:
        proc = subprocess.run(
            ["git", "ls-files"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
    except Exception:
        return
    generated_patterns = ("/__pycache__/", ".pyc", "/target/", ".class", ".jar", "results/run_")
    tracked = [
        path for path in proc.stdout.splitlines()
        if any(pattern in f"/{path}" for pattern in generated_patterns)
    ]
    if tracked:
        raise ValueError(f"Generated artifacts are tracked: {tracked[:10]}")


def _load_case(path: str) -> AttackCase:
    module_name, class_name = path.split(":", 1)
    cls = getattr(importlib.import_module(module_name), class_name)
    case = cls()
    if not isinstance(case, AttackCase):
        raise TypeError(f"{path} did not instantiate an AttackCase")
    return case


def _validate_case_assets(case: AttackCase) -> None:
    if case.attack_id == "AS":
        cards = case.get_agent_card_list()
        if not cards:
            raise ValueError(f"{case.case_id} has no AgentCards")
        if not (1 <= case.get_ground_truth() <= len(cards)):
            raise ValueError(f"{case.case_id} benign choice is out of range")
    elif case.attack_id == "CC":
        card = case.get_agent_card()
        if not card:
            raise ValueError(f"{case.case_id} has an empty AgentCard")
        case.get_backend_code()
    elif case.attack_id in A2A_ATTACK_IDS:
        payload = case.get_sut_payload()
        oracle = case.get_ground_truth()
        if not payload or not isinstance(payload, dict):
            raise ValueError(f"{case.case_id} has an empty SUT payload")
        if not oracle or not isinstance(oracle, dict):
            raise ValueError(f"{case.case_id} has an empty oracle")
    else:
        raise ValueError(f"Unsupported attack_id {case.attack_id!r} in {case.case_id}")


def _validate_config(path: Path) -> tuple[str, int]:
    config = _load_config(path)
    case_paths = config.get("cases")
    if not isinstance(case_paths, list) or not case_paths:
        raise ValueError(f"{path} must define a non-empty cases list")

    cases = [_load_case(case_path) for case_path in case_paths]
    attack_ids = {case.attack_id for case in cases}
    if len(attack_ids) != 1:
        raise ValueError(f"{path} mixes attack IDs: {sorted(attack_ids)}")

    attack_id = next(iter(attack_ids))
    if attack_id == "CC":
        release_cc_cases = [
            case_path
            for case_path in case_paths
            if not case_path.startswith("attacks.instances.cc_whitebox:")
            and not case_path.startswith("attacks.instances.cc_blackbox:")
        ]
        if release_cc_cases:
            raise ValueError(
                f"{path} references non-release CC cases; release configs must use "
                f"cc_whitebox or cc_blackbox cases: {release_cc_cases[:3]}"
            )
    for case in cases:
        _validate_case_assets(case)

    sut = config.get("sut")
    if not isinstance(sut, dict):
        raise ValueError(f"{path} must define sut")
    kwargs = sut.get("kwargs") or {}
    if attack_id == "AS":
        load_selector(sut["selector"], **kwargs)
        if "full" in path.name and len(cases) != 100:
            raise ValueError(f"{path} must contain 100 AS cases, got {len(cases)}")
    elif attack_id == "CC":
        load_comparator(sut["comparator"], **kwargs)
        if "blackbox" in path.name:
            _validate_blackbox_config(path, case_paths, cases, str(sut["comparator"]))
    else:
        if attack_id not in A2A_ATTACK_IDS:
            raise ValueError(f"Unsupported attack_id {attack_id!r} in {path}")
        _validate_a2a_track_imports(path, case_paths)
        load_a2a_security(sut["a2a_security"], **kwargs)
        if path.name in {"asrf_eval.yaml", "atsi_eval.yaml", "co_eval.yaml", "hotf_eval.yaml"}:
            if len(cases) != 200:
                raise ValueError(f"{path} must contain 200 eval/control cases, got {len(cases)}")
        elif path.parent.name == "offline" and len(cases) != 100:
            raise ValueError(f"{path} must contain 100 {attack_id} cases, got {len(cases)}")
    return attack_id, len(cases)


def _validate_a2a_track_imports(path: Path, case_paths: list[str]) -> None:
    expected_prefix = None
    if path.name.endswith("_eval.yaml"):
        package = path.name.split("_eval", 1)[0]
        expected_prefix = f"attacks.instances.{package}.executable:"
    elif path.parent.name == "calibration":
        package = path.stem
        expected_prefix = f"attacks.instances.{package}.calibration:"

    if expected_prefix is None:
        return

    mismatches = [case_path for case_path in case_paths if not case_path.startswith(expected_prefix)]
    if mismatches:
        raise ValueError(
            f"{path} must use {expected_prefix!r} case imports after A2A package consolidation; "
            f"got {mismatches[:3]}"
        )


def _diff_paths(left: Any, right: Any, prefix: str = "") -> list[str]:
    if type(left) is not type(right):
        return [prefix or "<root>"]
    if isinstance(left, dict):
        paths: list[str] = []
        for key in sorted(set(left) | set(right)):
            child_prefix = f"{prefix}.{key}" if prefix else str(key)
            if key not in left or key not in right:
                paths.append(child_prefix)
            else:
                paths.extend(_diff_paths(left[key], right[key], child_prefix))
        return paths
    if isinstance(left, list):
        paths = []
        for idx in range(max(len(left), len(right))):
            child_prefix = f"{prefix}.{idx}" if prefix else str(idx)
            if idx >= len(left) or idx >= len(right):
                paths.append(child_prefix)
            else:
                paths.extend(_diff_paths(left[idx], right[idx], child_prefix))
        return paths
    return [] if left == right else [prefix or "<root>"]


def _validate_as_perturbations(case: AttackCase, cards: list[dict]) -> None:
    benign = cards[0]
    expected_paths = {
        1: "name",
        2: "url",
        3: "preferredTransport",
        4: "skills.0.id",
        5: "version",
        6: "protocolVersion",
        8: "description",
        9: "skills.0.name",
    }
    for idx, expected in expected_paths.items():
        diff = _diff_paths(benign, cards[idx])
        if diff != [expected]:
            raise ValueError(
                f"{case.case_id} spoofed_{idx:02d} must modify only {expected}, got {diff}"
            )

    capability_diff = _diff_paths(benign, cards[7])
    if len(capability_diff) != 1 or not capability_diff[0].startswith("capabilities."):
        raise ValueError(
            f"{case.case_id} spoofed_07 must flip exactly one capability, got {capability_diff}"
        )
    _, cap_name = capability_diff[0].split(".", 1)
    if not (
        isinstance(benign["capabilities"].get(cap_name), bool)
        and isinstance(cards[7]["capabilities"].get(cap_name), bool)
        and benign["capabilities"][cap_name] is not cards[7]["capabilities"][cap_name]
    ):
        raise ValueError(f"{case.case_id} spoofed_07 capability {cap_name!r} is not a boolean flip")


def _validate_as_dataset() -> None:
    config = _load_config(ROOT / "configs/offline/as.yaml")
    cases = [_load_case(case_path) for case_path in config["cases"]]
    if len(cases) != 100:
        raise ValueError(f"configs/offline/as.yaml must contain 100 AS cases, got {len(cases)}")
    case_ids = [case.case_id for case in cases]
    if len(case_ids) != len(set(case_ids)):
        raise ValueError("AS case IDs must be unique")

    prompts = set()
    for case in cases:
        cards = case.get_agent_card_list()
        if len(cards) != 10:
            raise ValueError(f"{case.case_id} must contain 10 AgentCards, got {len(cards)}")
        if case.get_ground_truth() != 1:
            raise ValueError(f"{case.case_id} benign card must be original choice 1")
        prompts.add(case.task_prompt)
        for idx, card in enumerate(cards, start=1):
            missing = AGENTCARD_REQUIRED_KEYS - set(card)
            if missing:
                raise ValueError(f"{case.case_id} card {idx} missing keys: {sorted(missing)}")
            if not isinstance(card.get("skills"), list) or not card["skills"]:
                raise ValueError(f"{case.case_id} card {idx} must contain non-empty skills")
            if not isinstance(card.get("capabilities"), dict):
                raise ValueError(f"{case.case_id} card {idx} capabilities must be a mapping")
        _validate_as_perturbations(case, cards)

    if len(prompts) < 90:
        raise ValueError(f"AS prompt diversity too low: {len(prompts)} unique prompts for 100 cases")


def _validate_blackbox_config(
    path: Path,
    case_paths: list[str],
    cases: list[AttackCase],
    comparator_path: str,
) -> None:
    wrong_split = [case_path for case_path in case_paths if not case_path.startswith(CC_BLACKBOX_PREFIX)]
    if wrong_split:
        raise ValueError(
            f"{path} must use the dedicated CC blackbox split, got: {wrong_split[:5]}"
        )
    if "full" in path.name and len(cases) != 100:
        raise ValueError(f"{path} must contain 100 CC blackbox cases, got {len(cases)}")
    if "llm_interactive_comparator" in comparator_path and len(cases) > 1:
        labels = Counter(case.ground_truth_consistent for case in cases)
        if labels[True] != labels[False]:
            raise ValueError(f"{path} blackbox LLM cases must be label-balanced, got {dict(labels)}")
    missing_probes = [case.case_id for case in cases if not getattr(case, "validation_probes", [])]
    if missing_probes:
        raise ValueError(f"{path} contains blackbox cases without validation probes: {missing_probes[:5]}")


def _validate_cc_agentcard_release_surface(cases: list[AttackCase], split_name: str) -> None:
    domain_labels: dict[str, Counter] = defaultdict(Counter)
    for case in cases:
        card = case.get_agent_card()
        card_text = json.dumps(card, ensure_ascii=True).lower()
        if case.case_id.lower() in card_text or CC_CASE_ID_RE.search(card_text):
            raise ValueError(f"{case.case_id} {split_name} AgentCard exposes a case identifier")
        url = str(card.get("url", "")).lower()
        if case.case_id.lower() in url or CC_CASE_ID_RE.search(url):
            raise ValueError(f"{case.case_id} {split_name} AgentCard URL exposes a case identifier")
        domain_labels[case.domain][case.ground_truth_consistent] += 1

    single_label_domains = [
        domain for domain, labels in domain_labels.items()
        if labels[True] == 0 or labels[False] == 0
    ]
    if single_label_domains:
        raise ValueError(
            f"{split_name} domains must contain both labels; single-label domains: {single_label_domains[:5]}"
        )


def _validate_whitebox_cc_dataset() -> None:
    config = _load_config(ROOT / "configs/offline/cc_whitebox.yaml")
    cases = [_load_case(case_path) for case_path in config["cases"]]
    if len(cases) != 100:
        raise ValueError(f"configs/offline/cc_whitebox.yaml must contain 100 CC whitebox cases, got {len(cases)}")

    labels = Counter(case.ground_truth_consistent for case in cases)
    if labels[True] != labels[False]:
        raise ValueError(f"CC whitebox labels must be balanced, got {dict(labels)}")
    _validate_cc_agentcard_release_surface(cases, "CC whitebox")

    domains = Counter(case.domain for case in cases)
    capability_types = Counter(case.capability_type for case in cases)
    side_effect_types = Counter(case.side_effect_type for case in cases if not case.ground_truth_consistent)
    difficulties = Counter(case.difficulty for case in cases)
    if len(domains) < 10:
        raise ValueError(f"CC whitebox domain coverage is too narrow: {dict(domains)}")
    if len(capability_types) < 6:
        raise ValueError(f"CC whitebox capability coverage is too narrow: {dict(capability_types)}")
    if len(side_effect_types) < 8:
        raise ValueError(f"CC whitebox side-effect coverage is too narrow: {dict(side_effect_types)}")
    if set(difficulties) != {"easy", "medium", "hard"}:
        raise ValueError(f"CC whitebox must cover easy/medium/hard difficulties: {dict(difficulties)}")

    forbidden = ("hidden_", "capabilities_manifest_json", "exfil", "malicious")
    for case in cases:
        backend_code = case.get_backend_code().lower()
        card_text = json.dumps(case.get_agent_card(), ensure_ascii=True).lower()
        for token in forbidden:
            if token in backend_code:
                raise ValueError(f"{case.case_id} whitebox backend exposes forbidden token {token!r}")
            if token in card_text:
                raise ValueError(f"{case.case_id} whitebox AgentCard exposes forbidden token {token!r}")
        if not case.gt_reason:
            raise ValueError(f"{case.case_id} whitebox case is missing gt_reason")
        if not case.expected_evidence:
            raise ValueError(f"{case.case_id} whitebox case is missing expected_evidence")


def _validate_blackbox_cc_dataset() -> None:
    config = _load_config(ROOT / "configs/llm/cc_blackbox_full.yaml")
    case_paths = config["cases"]
    if not all(str(case_path).startswith(CC_BLACKBOX_PREFIX) for case_path in case_paths):
        raise ValueError("configs/llm/cc_blackbox_full.yaml must use attacks.instances.cc_blackbox")
    cases = [_load_case(case_path) for case_path in case_paths]
    if len(cases) != 100:
        raise ValueError(f"configs/llm/cc_blackbox_full.yaml must contain 100 cases, got {len(cases)}")

    labels = Counter(case.ground_truth_consistent for case in cases)
    if labels[True] != labels[False]:
        raise ValueError(f"CC blackbox labels must be balanced, got {dict(labels)}")
    _validate_cc_agentcard_release_surface(cases, "CC blackbox")

    domains = Counter(case.domain for case in cases)
    capability_types = Counter(case.capability_type for case in cases)
    side_effect_types = Counter(case.side_effect_type for case in cases if not case.ground_truth_consistent)
    difficulties = Counter(case.difficulty for case in cases)
    if len(domains) < 10:
        raise ValueError(f"CC blackbox domain coverage is too narrow: {dict(domains)}")
    if len(capability_types) < 8:
        raise ValueError(f"CC blackbox capability coverage is too narrow: {dict(capability_types)}")
    if len(side_effect_types) < 8:
        raise ValueError(f"CC blackbox side-effect coverage is too narrow: {dict(side_effect_types)}")
    if set(difficulties) != {"easy", "medium", "hard"}:
        raise ValueError(f"CC blackbox must cover easy/medium/hard difficulties: {dict(difficulties)}")

    structural_keys = Counter(
        (case.domain, case.get_agent_card()["skills"][0]["id"])
        for case in cases
    )
    repeated_structures = [key for key, count in structural_keys.items() if count > 1]
    if repeated_structures:
        raise ValueError(
            f"CC blackbox contains repeated domain/primary-skill structures: {repeated_structures[:5]}"
        )

    forbidden = ("hidden_", "capabilities_manifest_json", "exfil", "malicious")
    for case in cases:
        backend_code = case.get_backend_code().lower()
        card_text = json.dumps(case.get_agent_card(), ensure_ascii=True).lower()
        for token in forbidden:
            if token in backend_code:
                raise ValueError(f"{case.case_id} blackbox backend exposes forbidden token {token!r}")
            if token in card_text:
                raise ValueError(f"{case.case_id} blackbox AgentCard exposes forbidden token {token!r}")
        for token in BLACKBOX_RESPONSE_SHORTCUT_TOKENS:
            if token in backend_code:
                raise ValueError(f"{case.case_id} blackbox backend exposes response shortcut token {token!r}")
        if not case.validation_probes:
            raise ValueError(f"{case.case_id} blackbox case is missing validation_probes")
        for probe in case.validation_probes:
            text = str(probe.get("text", ""))
            if BLACKBOX_EXACT_PROBE_RE.search(text):
                raise ValueError(
                    f"{case.case_id} blackbox validation probe uses exact argument syntax: {text!r}"
                )
        if not case.gt_reason:
            raise ValueError(f"{case.case_id} blackbox case is missing gt_reason")
        if not case.expected_evidence:
            raise ValueError(f"{case.case_id} blackbox case is missing expected_evidence")


def _validate_a2a_case_schema(case: AttackCase) -> None:
    payload = case.get_sut_payload()
    oracle = case.get_ground_truth()
    prompt = str(payload.get("prompt", "")).lower()
    forbidden = [token for token in PROMPT_FORBIDDEN_TOKENS if token in prompt]
    if forbidden:
        raise ValueError(f"{case.case_id} prompt leaks benchmark/oracle tokens: {forbidden}")
    if payload.get("attack_id") != case.attack_id:
        raise ValueError(f"{case.case_id} payload attack_id mismatch")
    if payload.get("case_id") != case.case_id:
        raise ValueError(f"{case.case_id} payload case_id mismatch")
    if not getattr(case, "gt_reason", None) and not getattr(case, "metadata", {}).get("gt_reason"):
        raise ValueError(f"{case.case_id} is missing gt_reason")

    if case.attack_id == "ASRF":
        resource = payload.get("resource")
        if not isinstance(resource, dict):
            raise ValueError(f"{case.case_id} ASRF payload missing resource")
        expected = {"target_uri", "marker_id", "request_surface"}
        if set(oracle) != expected:
            raise ValueError(f"{case.case_id} ASRF oracle keys must be {sorted(expected)}, got {sorted(oracle)}")
        if oracle["target_uri"] != resource.get("uri"):
            raise ValueError(f"{case.case_id} ASRF target URI oracle mismatch")
        if oracle["marker_id"] != resource.get("marker_id"):
            raise ValueError(f"{case.case_id} ASRF marker oracle mismatch")
    elif case.attack_id == "ATSI":
        artifact = payload.get("artifact")
        if not isinstance(artifact, dict):
            raise ValueError(f"{case.case_id} ATSI payload missing artifact")
        expected = {"artifact_id", "marker_id", "execution_sink"}
        if set(oracle) != expected:
            raise ValueError(f"{case.case_id} ATSI oracle keys must be {sorted(expected)}, got {sorted(oracle)}")
        for key in expected:
            if oracle[key] != artifact.get(key):
                raise ValueError(f"{case.case_id} ATSI oracle mismatch for {key}")
    elif case.attack_id == "CO":
        graph = payload.get("delegation_graph")
        if not isinstance(graph, dict):
            raise ValueError(f"{case.case_id} CO payload missing delegation_graph")
        expected = {"cycle_path", "min_depth", "pattern"}
        if set(oracle) != expected:
            raise ValueError(f"{case.case_id} CO oracle keys must be {sorted(expected)}, got {sorted(oracle)}")
        cycle_path = oracle["cycle_path"]
        if not isinstance(cycle_path, list) or len(cycle_path) < 3 or cycle_path[0] != cycle_path[-1]:
            raise ValueError(f"{case.case_id} CO cycle_path must be a closed path with at least two agents")
        if int(oracle["min_depth"]) < len(cycle_path):
            raise ValueError(f"{case.case_id} CO min_depth must cover the full cycle path")
    elif case.attack_id == "HOTF":
        pressure = payload.get("task_pressure")
        if not isinstance(pressure, dict):
            raise ValueError(f"{case.case_id} HOTF payload missing task_pressure")
        expected = {"input_required_threshold", "task_type", "queue"}
        if set(oracle) != expected:
            raise ValueError(f"{case.case_id} HOTF oracle keys must be {sorted(expected)}, got {sorted(oracle)}")
        if int(pressure.get("input_required_count", 0)) < int(oracle["input_required_threshold"]):
            raise ValueError(f"{case.case_id} HOTF count must meet or exceed oracle threshold")


def _validate_a2a_dataset(attack_id: str, package: str) -> None:
    config = _load_config(ROOT / "configs" / "calibration" / f"{package}.yaml")
    cases = [_load_case(case_path) for case_path in config["cases"]]
    if len(cases) != 100:
        raise ValueError(f"configs/calibration/{package}.yaml must contain 100 cases, got {len(cases)}")
    if {case.attack_id for case in cases} != {attack_id}:
        raise ValueError(f"configs/offline/{package}.yaml must contain only {attack_id} cases")

    case_ids = [case.case_id for case in cases]
    if len(case_ids) != len(set(case_ids)):
        raise ValueError(f"{attack_id} case IDs must be unique")

    prompts = Counter(case.get_sut_payload()["prompt"] for case in cases)
    repeated_prompts = [prompt for prompt, count in prompts.items() if count > 1]
    if repeated_prompts:
        raise ValueError(f"{attack_id} prompts must be unique; repeated: {repeated_prompts[:3]}")

    domains = Counter(case.domain for case in cases)
    vectors = Counter(case.vector for case in cases)
    difficulties = Counter(case.difficulty for case in cases)
    if len(domains) != 10 or any(count != 10 for count in domains.values()):
        raise ValueError(f"{attack_id} must be balanced across 10 domains, got {dict(domains)}")
    if len(vectors) != 10 or any(count != 10 for count in vectors.values()):
        raise ValueError(f"{attack_id} must be balanced across 10 vectors, got {dict(vectors)}")
    if set(difficulties) != {"easy", "medium", "hard"}:
        raise ValueError(f"{attack_id} must cover easy/medium/hard difficulties, got {dict(difficulties)}")

    markers: list[str] = []
    reference = A2ASUT()
    for case in cases:
        _validate_a2a_case_schema(case)
        oracle = case.get_ground_truth()
        marker = oracle.get("marker_id")
        if marker is not None:
            markers.append(str(marker))
        reference_outcome = case.run(reference, trial_index=0)
        if not reference_outcome.success:
            raise ValueError(f"{case.case_id} reference SUT did not trigger success")
    if markers and len(markers) != len(set(markers)):
        raise ValueError(f"{attack_id} marker IDs must be unique")


def _validate_asrf_executable_dataset() -> None:
    config = _load_config(ROOT / "configs" / "offline" / "asrf_eval.yaml")
    cases = [_load_case(case_path) for case_path in config["cases"]]
    if len(cases) != 200:
        raise ValueError(f"configs/offline/asrf_eval.yaml must contain 200 cases, got {len(cases)}")
    if {case.attack_id for case in cases} != {"ASRF"}:
        raise ValueError("configs/offline/asrf_eval.yaml must contain only ASRF cases")

    controls = [case for case in cases if getattr(case, "is_control", False)]
    attacks = [case for case in cases if not getattr(case, "is_control", False)]
    if len(attacks) != 100 or len(controls) != 100:
        raise ValueError(
            "ASRF executable split must contain 100 attack cases and 100 controls, "
            f"got attack={len(attacks)} controls={len(controls)}"
        )

    case_ids = [case.case_id for case in cases]
    if len(case_ids) != len(set(case_ids)):
        raise ValueError("ASRF executable case IDs must be unique")

    forbidden_public_tokens = (
        "oracle",
        "marker",
        "forbidden",
        "unsafe",
        "uri_dereference",
        "expected",
        "threshold",
        "attack",
    )
    domains = Counter(case.domain for case in attacks)
    vectors = Counter(case.vector for case in attacks)
    control_domains = Counter(case.domain for case in controls)
    control_vectors = Counter(case.vector for case in controls)
    for label, counter in {
        "attack domains": domains,
        "attack vectors": vectors,
        "control domains": control_domains,
        "control vectors": control_vectors,
    }.items():
        if len(counter) != 10 or any(count != 10 for count in counter.values()):
            raise ValueError(f"ASRF executable {label} must be balanced, got {dict(counter)}")

    reference = A2AExecutableSUT()
    for case in cases:
        _assert_no_release_policy_field(case)
        sut_payload = case.get_sut_payload()
        public = json.dumps(sut_payload, ensure_ascii=True).lower()
        leaks = [token for token in forbidden_public_tokens if token in public]
        if leaks:
            raise ValueError(f"{case.case_id} public view leaks private/scoring tokens: {leaks}")
        metadata = getattr(case, "metadata", {})
        if metadata.get("schema_version") != "a2a-env-v1":
            raise ValueError(f"{case.case_id} missing a2a-env-v1 schema")
        environment = metadata.get("environment", {})
        oracle = case.get_ground_truth()
        if "{{nonce}}" not in str(environment.get("resource_route_template", "")):
            raise ValueError(f"{case.case_id} must use runtime nonce route templates")
        if oracle.get("required_event") != "uri_dereference":
            raise ValueError(f"{case.case_id} ASRF executable oracle must require uri_dereference")
        if oracle.get("uri_class") != environment.get("uri_class"):
            raise ValueError(f"{case.case_id} ASRF executable uri_class mismatch")
        if oracle.get("request_surface") != environment.get("request_surface"):
            raise ValueError(f"{case.case_id} ASRF executable request_surface mismatch")

        reference_outcome = case.run(reference, trial_index=0)
        _validate_protocol_backed_executable_outcome(case.case_id, reference_outcome)
        if getattr(case, "is_control", False):
            if reference_outcome.success:
                raise ValueError(f"{case.case_id} control case should not count as attack success")
            if not reference_outcome.details.get("control_pass"):
                raise ValueError(f"{case.case_id} reference executable SUT failed control")
        else:
            if not reference_outcome.success:
                raise ValueError(f"{case.case_id} reference executable SUT did not trigger ASRF")


def _validate_atsi_executable_dataset() -> None:
    config = _load_config(ROOT / "configs" / "offline" / "atsi_eval.yaml")
    cases = [_load_case(case_path) for case_path in config["cases"]]
    if len(cases) != 200:
        raise ValueError(f"configs/offline/atsi_eval.yaml must contain 200 cases, got {len(cases)}")
    if {case.attack_id for case in cases} != {"ATSI"}:
        raise ValueError("configs/offline/atsi_eval.yaml must contain only ATSI cases")

    controls = [case for case in cases if getattr(case, "is_control", False)]
    attacks = [case for case in cases if not getattr(case, "is_control", False)]
    if len(attacks) != 100 or len(controls) != 100:
        raise ValueError(
            "ATSI executable split must contain 100 attack cases and 100 controls, "
            f"got attack={len(attacks)} controls={len(controls)}"
        )

    case_ids = [case.case_id for case in cases]
    if len(case_ids) != len(set(case_ids)):
        raise ValueError("ATSI executable case IDs must be unique")

    forbidden_public_tokens = (
        "oracle",
        "marker",
        "artifact_executed",
        "callback",
        "expected",
        "threshold",
        "attack",
    )
    for label, sample in {"attack": attacks, "control": controls}.items():
        domains = Counter(case.domain for case in sample)
        vectors = Counter(case.vector for case in sample)
        if len(domains) != 10 or any(count != 10 for count in domains.values()):
            raise ValueError(f"ATSI executable {label} domains must be balanced, got {dict(domains)}")
        if len(vectors) != 10 or any(count != 10 for count in vectors.values()):
            raise ValueError(f"ATSI executable {label} vectors must be balanced, got {dict(vectors)}")

    reference = A2AExecutableSUT()
    for case in cases:
        _assert_no_release_policy_field(case)
        sut_payload = case.get_sut_payload()
        public = json.dumps(sut_payload, ensure_ascii=True).lower()
        leaks = [token for token in forbidden_public_tokens if token in public]
        if leaks:
            raise ValueError(f"{case.case_id} public view leaks private/scoring tokens: {leaks}")
        metadata = getattr(case, "metadata", {})
        if metadata.get("schema_version") != "a2a-env-v1":
            raise ValueError(f"{case.case_id} missing a2a-env-v1 schema")
        environment = metadata.get("environment", {})
        oracle = case.get_ground_truth()
        if "{{nonce}}" not in str(environment.get("callback_route_template", "")):
            raise ValueError(f"{case.case_id} must use runtime nonce callback route templates")
        if oracle.get("required_event") != "artifact_executed":
            raise ValueError(f"{case.case_id} ATSI executable oracle must require artifact_executed")
        for key in ("artifact_id", "marker_id", "execution_sink", "artifact_type"):
            if oracle.get(key) != environment.get(key):
                raise ValueError(f"{case.case_id} ATSI executable {key} mismatch")
        if getattr(case, "is_control", False):
            if "{{callback_url}}" in str(environment.get("body_template", "")):
                raise ValueError(f"{case.case_id} ATSI control body must not contain callback template")
        else:
            if "{{callback_url}}" not in str(environment.get("body_template", "")):
                raise ValueError(f"{case.case_id} ATSI attack body must contain callback template")

        reference_outcome = case.run(reference, trial_index=0)
        _validate_protocol_backed_executable_outcome(case.case_id, reference_outcome)
        if getattr(case, "is_control", False):
            if reference_outcome.success:
                raise ValueError(f"{case.case_id} control case should not count as attack success")
            if not reference_outcome.details.get("control_pass"):
                raise ValueError(f"{case.case_id} reference executable SUT failed control")
        else:
            if not reference_outcome.success:
                raise ValueError(f"{case.case_id} reference executable SUT did not trigger ATSI")


def _validate_hotf_executable_dataset() -> None:
    config = _load_config(ROOT / "configs" / "offline" / "hotf_eval.yaml")
    cases = [_load_case(case_path) for case_path in config["cases"]]
    if len(cases) != 200:
        raise ValueError(f"configs/offline/hotf_eval.yaml must contain 200 cases, got {len(cases)}")
    if {case.attack_id for case in cases} != {"HOTF"}:
        raise ValueError("configs/offline/hotf_eval.yaml must contain only HOTF cases")

    controls = [case for case in cases if getattr(case, "is_control", False)]
    attacks = [case for case in cases if not getattr(case, "is_control", False)]
    if len(attacks) != 100 or len(controls) != 100:
        raise ValueError(
            "HOTF executable split must contain 100 attack cases and 100 controls, "
            f"got attack={len(attacks)} controls={len(controls)}"
        )

    case_ids = [case.case_id for case in cases]
    if len(case_ids) != len(set(case_ids)):
        raise ValueError("HOTF executable case IDs must be unique")

    forbidden_public_tokens = (
        "oracle",
        "marker",
        "forbidden",
        "unsafe",
        "task_store_pressure",
        "expected",
        "threshold",
        "attack",
        "half_open",
    )
    for label, sample in {"attack": attacks, "control": controls}.items():
        domains = Counter(case.domain for case in sample)
        vectors = Counter(case.vector for case in sample)
        if len(domains) != 10 or any(count != 10 for count in domains.values()):
            raise ValueError(f"HOTF executable {label} domains must be balanced, got {dict(domains)}")
        if len(vectors) != 10 or any(count != 10 for count in vectors.values()):
            raise ValueError(f"HOTF executable {label} vectors must be balanced, got {dict(vectors)}")

    reference = A2AExecutableSUT()
    for case in cases:
        _assert_no_release_policy_field(case)
        sut_payload = case.get_sut_payload()
        public = json.dumps(sut_payload, ensure_ascii=True).lower()
        leaks = [token for token in forbidden_public_tokens if token in public]
        if leaks:
            raise ValueError(f"{case.case_id} public view leaks private/scoring tokens: {leaks}")
        metadata = getattr(case, "metadata", {})
        if metadata.get("schema_version") != "a2a-env-v1":
            raise ValueError(f"{case.case_id} missing a2a-env-v1 schema")
        environment = metadata.get("environment", {})
        oracle = case.get_ground_truth()
        if oracle.get("required_event") != "task_store_pressure":
            raise ValueError(f"{case.case_id} HOTF executable oracle must require task_store_pressure")
        if int(environment.get("request_count", 0)) <= 0:
            raise ValueError(f"{case.case_id} HOTF executable request_count must be positive")
        if oracle.get("half_open_state") != environment.get("half_open_state"):
            raise ValueError(f"{case.case_id} HOTF executable half_open_state mismatch")
        if oracle.get("task_type") != environment.get("task_type"):
            raise ValueError(f"{case.case_id} HOTF executable task_type mismatch")
        if int(oracle.get("half_open_threshold", 0)) != int(environment.get("pressure_threshold", -1)):
            raise ValueError(f"{case.case_id} HOTF executable threshold mismatch")

        reference_outcome = case.run(reference, trial_index=0)
        _validate_protocol_backed_executable_outcome(case.case_id, reference_outcome)
        if getattr(case, "is_control", False):
            if reference_outcome.success:
                raise ValueError(f"{case.case_id} control case should not count as attack success")
            if not reference_outcome.details.get("control_pass"):
                raise ValueError(f"{case.case_id} reference executable SUT failed control")
        else:
            if not reference_outcome.success:
                raise ValueError(f"{case.case_id} reference executable SUT did not trigger HOTF")


def _validate_co_executable_dataset() -> None:
    config = _load_config(ROOT / "configs" / "offline" / "co_eval.yaml")
    cases = [_load_case(case_path) for case_path in config["cases"]]
    if len(cases) != 200:
        raise ValueError(f"configs/offline/co_eval.yaml must contain 200 cases, got {len(cases)}")
    if {case.attack_id for case in cases} != {"CO"}:
        raise ValueError("configs/offline/co_eval.yaml must contain only CO cases")

    controls = [case for case in cases if getattr(case, "is_control", False)]
    attacks = [case for case in cases if not getattr(case, "is_control", False)]
    if len(attacks) != 100 or len(controls) != 100:
        raise ValueError(
            "CO executable split must contain 100 attack cases and 100 controls, "
            f"got attack={len(attacks)} controls={len(controls)}"
        )

    case_ids = [case.case_id for case in cases]
    if len(case_ids) != len(set(case_ids)):
        raise ValueError("CO executable case IDs must be unique")

    forbidden_public_tokens = (
        "oracle",
        "marker",
        "forbidden",
        "unsafe",
        "cycle_detected",
        "max_depth_exceeded",
        "depth_budget",
        "attack",
        "threshold",
    )
    for label, sample in {"attack": attacks, "control": controls}.items():
        domains = Counter(case.domain for case in sample)
        vectors = Counter(case.vector for case in sample)
        if len(domains) != 10 or any(count != 10 for count in domains.values()):
            raise ValueError(f"CO executable {label} domains must be balanced, got {dict(domains)}")
        if len(vectors) != 10 or any(count != 10 for count in vectors.values()):
            raise ValueError(f"CO executable {label} vectors must be balanced, got {dict(vectors)}")

    reference = A2AExecutableSUT()
    for case in cases:
        _assert_no_release_policy_field(case)
        public_payload = case.get_sut_payload()
        public = json.dumps(public_payload, ensure_ascii=True).lower()
        leaks = [token for token in forbidden_public_tokens if token in public]
        if leaks:
            raise ValueError(f"{case.case_id} public view leaks private/scoring tokens: {leaks}")
        metadata = getattr(case, "metadata", {})
        if metadata.get("schema_version") != "a2a-env-v1":
            raise ValueError(f"{case.case_id} missing a2a-env-v1 schema")
        environment = metadata.get("environment", {})
        oracle = case.get_ground_truth()
        if set(oracle.get("required_events", [])) != {"cycle_detected", "max_depth_exceeded"}:
            raise ValueError(f"{case.case_id} CO executable oracle must require cycle and depth evidence")
        if int(environment.get("depth_budget", 0)) <= 0:
            raise ValueError(f"{case.case_id} CO executable depth_budget must be positive")
        if int(environment.get("public_step_budget", 0)) <= 0:
            raise ValueError(f"{case.case_id} CO executable public_step_budget must be positive")
        if environment.get("request_surface") != oracle.get("pattern"):
            raise ValueError(f"{case.case_id} CO executable request_surface mismatch")
        if getattr(case, "is_control", False):
            if oracle.get("cycle_path") != []:
                raise ValueError(f"{case.case_id} CO control oracle cycle_path must be empty")
            if environment.get("cycle_path") != []:
                raise ValueError(f"{case.case_id} CO control environment cycle_path must be empty")
            if len(environment.get("delegation_path", [])) != int(oracle.get("control_min_depth", -1)):
                raise ValueError(f"{case.case_id} CO control delegation_path depth mismatch")
        else:
            cycle_path = oracle.get("cycle_path")
            if (
                not isinstance(cycle_path, list)
                or len(cycle_path) < 3
                or cycle_path[0] != cycle_path[-1]
            ):
                raise ValueError(f"{case.case_id} CO attack oracle must contain a closed path")
            if environment.get("cycle_path") != cycle_path:
                raise ValueError(f"{case.case_id} CO executable cycle_path mismatch")
            if int(oracle.get("min_depth", 0)) != int(environment.get("depth_budget", -1)):
                raise ValueError(f"{case.case_id} CO executable min_depth/depth_budget mismatch")

        reference_outcome = case.run(reference, trial_index=0)
        _validate_protocol_backed_executable_outcome(case.case_id, reference_outcome)
        if getattr(case, "is_control", False):
            if reference_outcome.success:
                raise ValueError(f"{case.case_id} control case should not count as attack success")
            if not reference_outcome.details.get("control_pass"):
                raise ValueError(f"{case.case_id} reference executable SUT failed control")
        else:
            if not reference_outcome.success:
                raise ValueError(f"{case.case_id} reference executable SUT did not trigger CO")


def _validate_protocol_backed_executable_outcome(case_id: str, outcome: Any) -> None:
    metrics = outcome.details.get("metrics", {})
    if metrics.get("a2a_protocol_backend") != "a2a-sdk":
        raise ValueError(f"{case_id} executable case did not use a2a-sdk protocol backend")
    if int(metrics.get("a2a_protocol_messages", 0)) < 1:
        raise ValueError(f"{case_id} executable case did not send an A2A message")
    if int(metrics.get("a2a_protocol_card_fetches", 0)) < 1:
        raise ValueError(f"{case_id} executable case did not fetch an A2A AgentCard")
    events = outcome.details.get("events", [])
    if not any(event.get("event_type") == "a2a_message_sent" for event in events):
        raise ValueError(f"{case_id} executable case missing a2a_message_sent event")
    if not any(event.get("event_type") == "a2a_agent_card_fetched" for event in events):
        raise ValueError(f"{case_id} executable case missing a2a_agent_card_fetched event")


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate A2ASecBench release assets")
    parser.add_argument(
        "--configs",
        nargs="*",
        default=None,
        help="Config files to validate.",
    )
    args = parser.parse_args()

    checked = []
    config_paths = args.configs or [
        str(path.relative_to(ROOT)) for path in sorted((ROOT / "configs").rglob("*.yaml"))
    ]
    for raw_path in config_paths:
        path = ROOT / raw_path
        attack_id, case_count = _validate_config(path)
        checked.append(f"{raw_path}: {attack_id} cases={case_count}")

    _validate_no_legacy_cc_names()
    _validate_no_release_secrets_or_artifacts()

    as_config = _load_config(ROOT / "configs/offline/as.yaml")
    cc_config = _load_config(ROOT / "configs/offline/cc_whitebox.yaml")
    if "llm_" in as_config["sut"]["selector"].lower():
        raise ValueError("configs/offline/as.yaml must remain offline by default")
    if "llm_" in cc_config["sut"]["comparator"].lower():
        raise ValueError("configs/offline/cc_whitebox.yaml must remain offline by default")
    if cc_config["sut"]["comparator"] != "sut.cc.whitebox_static_comparator:WhiteboxStaticComparator":
        raise ValueError("configs/offline/cc_whitebox.yaml must use the whitebox static offline baseline")

    _validate_whitebox_cc_dataset()
    _validate_blackbox_cc_dataset()
    _validate_as_dataset()
    for attack_id, package in A2A_CALIBRATION_PACKAGES.items():
        _validate_a2a_dataset(attack_id, package)
    _validate_asrf_executable_dataset()
    _validate_atsi_executable_dataset()
    _validate_co_executable_dataset()
    _validate_hotf_executable_dataset()

    print("Release validation passed")
    for item in checked:
        print(f"- {item}")


if __name__ == "__main__":
    main()
