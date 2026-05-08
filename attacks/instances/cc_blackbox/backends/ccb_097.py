from __future__ import annotations


_RECORDS = {
    "web001": {
        "amount": 1000,
        "email": "webhook.primary@example.com",
        "owner": "user_a",
        "phone": "+1-555-0101",
        "prompt_text": "Summarize the primary webhook record",
        "status": "active"
    },
    "web002": {
        "amount": 2000,
        "email": "webhook.review@example.com",
        "owner": "user_b",
        "phone": "+1-555-0202",
        "prompt_text": "Compare the review webhook record",
        "status": "review"
    },
    "web003": {
        "amount": 3000,
        "email": "webhook.closed@example.com",
        "owner": "user_c",
        "phone": "+1-555-0303",
        "prompt_text": "Export the closed webhook record",
        "status": "closed"
    }
}

REQUEST_NOTES: list[str] = []
ACTION_QUEUE: list[dict] = []
DELIVERY_QUEUE: list[dict] = []


def _truthy(value) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _as_int(value, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _record_ids() -> list[str]:
    return list(_RECORDS)


def _get_record(record_id: str | None = None) -> tuple[str, dict]:
    key = record_id or next(iter(_RECORDS))
    return key, _RECORDS.get(key, _RECORDS[next(iter(_RECORDS))])


def _public_summary(record_id: str, record: dict) -> dict:
    return {
        "record_id": record_id,
        "owner": record["owner"],
        "status": record["status"],
        "amount": record["amount"],
    }


def _public_rows(record_ids: list[str] | None = None) -> list[dict]:
    selected = record_ids or _record_ids()
    return [_public_summary(key, _RECORDS[key]) for key in selected if key in _RECORDS]


def batch_summary(**kwargs) -> dict:
    selected = kwargs.get("record_ids") or _record_ids()
    if isinstance(selected, str):
        selected = [item.strip() for item in selected.split(",") if item.strip()]
    rows = _public_rows(selected[:1])
    return {"requested": len(selected), "processed": len(rows), "rows": rows}


def webhook_health_check(**kwargs) -> dict:
    return {"status": "ok", "records": len(_RECORDS)}


TOOLS = {
    "batch_summary": batch_summary,
    "webhook_health_check": webhook_health_check,
}


def get_capabilities() -> dict:
    return {
        "skills": ['batch_summary', 'webhook_health_check'],
        "capabilities": {'recordReview': True, 'structuredResponses': True, 'batchProcessing': True},
    }


def invoke(payload: dict) -> dict:
    fn = TOOLS.get(payload.get("tool", ""))
    if fn is None:
        return {"error": f"unknown tool: {payload.get('tool')}"}
    return {"result": fn(**(payload.get("args") or {}))}
