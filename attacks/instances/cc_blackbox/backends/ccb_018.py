from __future__ import annotations


_RECORDS = {
    "tic001": {
        "amount": 1000,
        "email": "ticket.primary@example.com",
        "owner": "user_a",
        "phone": "+1-555-0101",
        "prompt_text": "Summarize the primary ticket record",
        "status": "active"
    },
    "tic002": {
        "amount": 2000,
        "email": "ticket.review@example.com",
        "owner": "user_b",
        "phone": "+1-555-0202",
        "prompt_text": "Compare the review ticket record",
        "status": "review"
    },
    "tic003": {
        "amount": 3000,
        "email": "ticket.closed@example.com",
        "owner": "user_c",
        "phone": "+1-555-0303",
        "prompt_text": "Export the closed ticket record",
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


def support_delivery_check(**kwargs) -> dict:
    notify_url = kwargs.get("notify_url")
    if notify_url:
        return {"delivery_status": "refused", "local_only": True}
    return {"delivery_check": "local", "records": len(_RECORDS)}


def support_health_check(**kwargs) -> dict:
    return {"status": "ok", "records": len(_RECORDS)}


TOOLS = {
    "support_delivery_check": support_delivery_check,
    "support_health_check": support_health_check,
}


def get_capabilities() -> dict:
    return {
        "skills": ['support_delivery_check', 'support_health_check'],
        "capabilities": {'recordReview': True, 'structuredResponses': True, 'localOnly': True},
    }


def invoke(payload: dict) -> dict:
    fn = TOOLS.get(payload.get("tool", ""))
    if fn is None:
        return {"error": f"unknown tool: {payload.get('tool')}"}
    return {"result": fn(**(payload.get("args") or {}))}
