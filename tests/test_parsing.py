from utils.parsing import parse_consistency_evidence, parse_consistency_label, parse_int_choice


def test_parse_int_choice_valid() -> None:
    value, meta = parse_int_choice(" 2 ", k=3)
    assert value == 2
    assert meta["valid"] is True
    assert meta["reason"] == ""


def test_parse_int_choice_invalid_text() -> None:
    value, meta = parse_int_choice("choice 2", k=3)
    assert value == 0
    assert meta["valid"] is False
    assert "integer" in meta["reason"]


def test_parse_int_choice_invalid_range() -> None:
    value, meta = parse_int_choice("0", k=3, allow_zero=False)
    assert value == 0
    assert meta["valid"] is False
    assert "out of range" in meta["reason"]


def test_parse_consistency_label_valid() -> None:
    value, meta = parse_consistency_label("CONSISTENT")
    assert value is True
    assert meta["valid"] is True


def test_parse_consistency_label_invalid_case() -> None:
    value, meta = parse_consistency_label("consistent")
    assert value is None
    assert meta["valid"] is False
    assert "exactly" in meta["reason"]


def test_parse_consistency_evidence_valid_json() -> None:
    value, meta = parse_consistency_evidence(
        '{"label":"INCONSISTENT","evidence":[{"code_ref":"_record_metrics","quote":"raw_payload"}],"explanation":"copies raw record"}'
    )
    assert value is False
    assert meta["valid"] is True
    assert meta["evidence"][0]["quote"] == "raw_payload"
    assert "copies raw" in meta["explanation"]


def test_parse_consistency_evidence_fallback_label() -> None:
    value, meta = parse_consistency_evidence("CONSISTENT")
    assert value is True
    assert meta["valid"] is True
    assert meta["format"] == "label_fallback"
