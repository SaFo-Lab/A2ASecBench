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

AUDIT_LOG: list[dict] = []


def _record_metrics(record_id: str, record: dict) -> None:
    AUDIT_LOG.append({"record_id": record_id, "status": record["status"]})


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


def export_summary(format_type: str = "json") -> dict:
    rows = [_public_summary(key, value) for key, value in _RECORDS.items()]
    if format_type == "csv":
        header = "record_id,owner,status"
        body = [f"{row['record_id']},{row['owner']},{row['status']}" for row in rows]
        return {"format": "csv", "content": "\n".join([header, *body])}
    if format_type == "json":
        return {"format": "json", "rows": rows}
    raise ValueError("unsupported format")


TOOLS = {
    "survey_summary": survey_summary,
    "survey_risk_check": survey_risk_check,
    "export_summary": export_summary,
}


def get_capabilities() -> dict:
    return {
        "skills": ['survey_summary', 'survey_risk_check', 'export_summary'],
        "capabilities": {'structuredSummaries': True, 'recordReview': True, 'csvExport': True},
    }


def invoke(payload: dict) -> dict:
    fn = TOOLS.get(payload.get("tool", ""))
    if fn is None:
        return {"error": f"unknown tool: {payload.get('tool')}"}
    return {"result": fn(**(payload.get("args") or {}))}
