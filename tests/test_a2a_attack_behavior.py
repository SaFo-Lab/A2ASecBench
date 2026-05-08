from __future__ import annotations

from collections import Counter
import importlib

import pytest

from sut.a2a.reference import A2ASUT

ATTACK_PACKAGES = {
    "ASRF": ("attacks.instances.asrf.calibration", "ASRF001"),
    "ATSI": ("attacks.instances.atsi.calibration", "ATSI001"),
    "CO": ("attacks.instances.co.calibration", "CO001"),
    "HOTF": ("attacks.instances.hotf.calibration", "HOTF001"),
}


@pytest.mark.parametrize(("attack_id", "module_name", "class_name"), [
    (attack_id, module_name, class_name)
    for attack_id, (module_name, class_name) in ATTACK_PACKAGES.items()
])
def test_a2a_reference_suts_calibrate_oracles(
    attack_id: str,
    module_name: str,
    class_name: str,
) -> None:
    module = importlib.import_module(module_name)
    case = getattr(module, class_name)()

    reference = case.run(A2ASUT(), trial_index=0)

    assert reference.attack_id == attack_id
    assert reference.success is True
    assert reference.details["success_evidence"]


@pytest.mark.parametrize("module_name", [package[0] for package in ATTACK_PACKAGES.values()])
def test_a2a_release_split_shape(module_name: str) -> None:
    module = importlib.import_module(module_name)
    metadata = module.CASE_METADATA
    assert len(metadata) == 100

    case_ids = [row["case_id"] for row in metadata]
    prompts = [row["sut_payload"]["prompt"] for row in metadata]
    assert len(case_ids) == len(set(case_ids))
    assert len(prompts) == len(set(prompts))

    domains = Counter(row["domain"] for row in metadata)
    vectors = Counter(row["vector"] for row in metadata)
    difficulties = Counter(row["difficulty"] for row in metadata)
    assert len(domains) == 10
    assert set(domains.values()) == {10}
    assert len(vectors) == 10
    assert set(vectors.values()) == {10}
    assert set(difficulties) == {"easy", "medium", "hard"}
