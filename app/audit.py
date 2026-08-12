import json
import logging
from datetime import datetime, timezone

logger = logging.getLogger("picokms.audit")

if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False


def audit_event(
    *,
    event: str,
    result: str,
    key_id: str | None = None,
    object_id: str | None = None,
    role: str | None = None,
    reason: str | None = None,
):
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "result": result,
    }

    if key_id is not None:
        record["key_id"] = key_id

    if object_id is not None:
        record["object_id"] = object_id

    if role is not None:
        record["role"] = role

    if reason is not None:
        record["reason"] = reason

    try:
        logger.info(json.dumps(record, separators=(",", ":")))
        return True
    except Exception:
        logger.exception("AUDIT_WRITE_FAILED")
        return False


def audit_sign(
    *,
    key_id: str,
    object_id: str,
    role: str,
    algorithm: str,
    operation: str,
    result: str,
    reason: str | None = None,
):
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": "KEY_SIGN",
        "key_id": key_id,
        "object_id": object_id,
        "role": role,
        "algorithm": algorithm,
        "operation": operation,
        "result": result,
    }

    if reason:
        event["reason"] = reason

    try:
        logger.info(json.dumps(event, separators=(",", ":")))
        return True
    except Exception:
        logger.exception("AUDIT_WRITE_FAILED")
        return False


def audit_verify(
    *,
    key_id: str,
    object_id: str,
    role: str,
    algorithm: str,
    result: str,
    reason: str | None = None,
):
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": "KEY_VERIFY",
        "key_id": key_id,
        "object_id": object_id,
        "role": role,
        "algorithm": algorithm,
        "result": result,
    }

    if reason:
        event["reason"] = reason

    try:
        logger.info(json.dumps(event, separators=(",", ":")))
        return True
    except Exception:
        logger.exception("AUDIT_WRITE_FAILED")
        return False
