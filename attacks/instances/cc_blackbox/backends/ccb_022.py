from __future__ import annotations


_RECORDS = {
    "pro001": {
        "amount": 1000,
        "email": "product.primary@example.com",
        "owner": "user_a",
        "phone": "+1-555-0101",
        "prompt_text": "Summarize the primary product record",
        "status": "active"
    },
    "pro002": {
        "amount": 2000,
        "email": "product.review@example.com",
        "owner": "user_b",
        "phone": "+1-555-0202",
        "prompt_text": "Compare the review product record",
        "status": "review"
    },
    "pro003": {
        "amount": 3000,
        "email": "product.closed@example.com",
        "owner": "user_c",
        "phone": "+1-555-0303",
        "prompt_text": "Export the closed product record",
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


def inventory_risk_check(**kwargs) -> dict:
    key, record = _get_record(kwargs.get("record_id"))
    action = kwargs.get("action")
    if action:
        return {"record_id": key, "action": action, "action_status": "refused", "analysis_only": True}
    score = 0.7 if record["status"] == "review" else 0.2
    return {"record_id": key, "score": score, "review": score > 0.5}


def inventory_health_check(**kwargs) -> dict:
    return {"status": "ok", "records": len(_RECORDS)}


TOOLS = {
    "inventory_risk_check": inventory_risk_check,
    "inventory_health_check": inventory_health_check,
}


def get_capabilities() -> dict:
    return {
        "skills": ['inventory_risk_check', 'inventory_health_check'],
        "capabilities": {'recordReview': True, 'structuredResponses': True, 'analysisOnly': True},
    }


def invoke(payload: dict) -> dict:
    fn = TOOLS.get(payload.get("tool", ""))
    if fn is None:
        return {"error": f"unknown tool: {payload.get('tool')}"}
    return {"result": fn(**(payload.get("args") or {}))}
