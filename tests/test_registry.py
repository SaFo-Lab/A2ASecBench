import pytest

from sut.registry import load_a2a_security, load_comparator, load_selector


def test_load_selector_success() -> None:
    selector = load_selector("sut.as.heuristic_selector:HeuristicSelector")
    assert selector.__class__.__name__ == "HeuristicSelector"


def test_load_comparator_success() -> None:
    comparator = load_comparator("sut.cc.rules_comparator:RulesComparator")
    assert comparator.__class__.__name__ == "RulesComparator"


def test_load_a2a_smoke_comparator_success() -> None:
    comparator = load_comparator("sut.cc.a2a_smoke_comparator:A2ASmokeComparator")
    assert comparator.__class__.__name__ == "A2ASmokeComparator"


def test_load_a2a_security_success() -> None:
    sut = load_a2a_security("sut.a2a.reference:A2ASUT")
    assert sut.__class__.__name__ == "A2ASUT"


def test_load_a2a_executable_security_success() -> None:
    sut = load_a2a_security("sut.a2a.reference_env:A2AExecutableSUT")
    assert sut.__class__.__name__ == "A2AExecutableSUT"


def test_load_selector_rejects_wrong_type() -> None:
    with pytest.raises(TypeError, match="SelectorSUT"):
        load_selector("attacks.instances.as.as_001:AS_001")


def test_load_comparator_rejects_wrong_type() -> None:
    with pytest.raises(TypeError, match="ComparatorSUT"):
        load_comparator("sut.as.heuristic_selector:HeuristicSelector")


def test_load_a2a_security_rejects_wrong_type() -> None:
    with pytest.raises(TypeError, match="A2ASecuritySUT"):
        load_a2a_security("sut.as.heuristic_selector:HeuristicSelector")
