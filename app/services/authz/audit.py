import json
import logging
import sqlite3
import time
from typing import Any

from app.core.config import get_settings

logger = logging.getLogger("coe.audit")

_SENSITIVE_KEYS = {"token", "cookie", "secret", "password", "authorization", "csrf", "content", "body"}


def _sanitize(data: dict[str, Any] | None) -> dict[str, Any]:
    if not data:
        return {}
    cleaned = {}
    for k, v in data.items():
        if any(s in k.lower() for s in _SENSITIVE_KEYS):
            continue
        if isinstance(v, dict):
            cleaned[k] = _sanitize(v)
        elif isinstance(v, (str, int, float, bool)) or v is None:
            cleaned[k] = v
        else:
            cleaned[k] = str(v)
    return cleaned


def init_audit_table() -> None:
    s = get_settings()
    try:
        conn = sqlite3.connect(s.identity_db_path, check_same_thread=False)
        with conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS coe_audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT DEFAULT (datetime('now')),
                    event TEXT NOT NULL,
                    actor_oid TEXT,
                    permission TEXT,
                    resource_type TEXT,
                    resource_id TEXT,
                    decision TEXT,
                    reason TEXT,
                    rule_id INTEGER,
                    ip TEXT,
                    request_id TEXT,
                    details TEXT
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_event ON coe_audit_log(event);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_actor ON coe_audit_log(actor_oid);")
        conn.close()
    except Exception as e:
        logger.warning("Could not initialize audit table in db: %s", e)


def audit(
    event: str,
    actor_oid: str | None = None,
    permission: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    decision: str = "allow",
    reason: str | None = None,
    rule_id: int | None = None,
    ip: str | None = None,
    request_id: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    """Writes an immutable audit entry to the audit log, stripped of sensitive data."""
    sanitized_details = _sanitize(details)
    details_json = json.dumps(sanitized_details) if sanitized_details else "{}"

    logger.info(
        "AUDIT: event=%s actor=%s perm=%s decision=%s reason=%s rule=%s res_type=%s res_id=%s",
        event,
        actor_oid,
        permission,
        decision,
        reason,
        rule_id,
        resource_type,
        resource_id,
    )

    s = get_settings()
    try:
        conn = sqlite3.connect(s.identity_db_path, check_same_thread=False)
        with conn:
            conn.execute(
                """
                INSERT INTO coe_audit_log
                (event, actor_oid, permission, resource_type, resource_id, decision, reason, rule_id, ip, request_id, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event,
                    actor_oid,
                    permission,
                    resource_type,
                    resource_id,
                    decision,
                    reason,
                    rule_id,
                    ip,
                    request_id,
                    details_json,
                ),
            )
        conn.close()
    except Exception as e:
        logger.error("Failed to persist audit log entry: %s", e)
