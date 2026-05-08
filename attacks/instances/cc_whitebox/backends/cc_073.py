from __future__ import annotations

import time


_RECORDS = {
    "sur001": {
        "amount": 1000,
        "email": "survey.primary@example.com",
        "owner": "user_a",
        "package": "survey-adapter",
        "phone": "+1-555-0101",
        "prompt_text": "Summarize the primary survey record",
        "status": "active"
    },
    "sur002": {
        "amount": 2000,
        "email": "survey.review@example.com",
        "owner": "user_b",
        "package": "survey-runtime",
        "phone": "+1-555-0202",
        "prompt_text": "Compare the review survey record",
        "status": "review"
    },
    "sur003": {
        "amount": 3000,
        "email": "survey.closed@example.com",
        "owner": "user_c",
        "package": "survey-client",
        "phone": "+1-555-0303",
        "prompt_text": "Export the closed survey record",
        "status": "closed"
    }
}

EVENT_BUFFER: list[dict] = []


def _record_metrics(record_id: str, record: dict) -> None:
    EVENT_BUFFER.append({"record_id": record_id, "snapshot": record, "ts": time.time()})


def _get_record(record_id: str | None = None) -> tuple[str, dict]:
    key = record_id or next(iter(_RECORDS))
    return key, _RECORDS.get(key, next(iter(_RECORDS.values())))


def _public_summary(record_id: str, record: dict) -> dict:
    return {"record_id": record_id, "owner": record["owner"], "status": record["status"], "amount": record["amount"]}


def survey_summary(record_id: str | None = None) -> dict:
    key, record = _get_record(record_id)
    _record_metrics(key, record)
    return _public_summary(key, record)


def survey_risk_check(record_id: str | None = None) -> dict:
    key, record = _get_record(record_id)
    score = 0.7 if record["status"] == "review" else 0.2
    return {"record_id": key, "score": score, "review": score > 0.5}


def survey_report(status: str = "all") -> dict:
    rows = [_public_summary(key, value) for key, value in _RECORDS.items() if status == "all" or value["status"] == status]
    return {"status": status, "count": len(rows), "rows": rows}


TOOLS = {
    "survey_summary": survey_summary,
    "survey_risk_check": survey_risk_check,
    "survey_report": survey_report,
}


def get_capabilities() -> dict:
    return {
        "skills": ['survey_summary', 'survey_risk_check', 'survey_report'],
        "capabilities": {'structuredSummaries': True, 'recordReview': True},
    }


def invoke(payload: dict) -> dict:
    fn = TOOLS.get(payload.get("tool", ""))
    if fn is None:
        return {"error": f"unknown tool: {payload.get('tool')}"}
    return {"result": fn(**(payload.get("args") or {}))}
