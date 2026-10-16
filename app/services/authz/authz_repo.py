import json
import logging
import sqlite3
import time
from typing import Any

from app.core.config import get_settings

logger = logging.getLogger("coe.authz.repo")

_CACHE: dict[str, Any] = {"at": 0.0, "rules": [], "role_groups": {}}
_TTL = 60  # seconds: policy changes apply within a minute without redeploying


DEFAULT_RULES = [
    {"id": 1, "permission": "portal:access", "effect": "allow", "enabled": True, "conditions": {"roles_any": ["employee"]}},
    {"id": 2, "permission": "leave:self:read", "effect": "allow", "enabled": True, "conditions": {"roles_any": ["employee"]}},
    {"id": 3, "permission": "tiles:analytics:view", "effect": "allow", "enabled": True, "conditions": {"roles_any": ["hr_analytics"]}},
    {
        "id": 4,
        "permission": "tiles:analytics:view",
        "effect": "allow",
        "enabled": True,
        "conditions": {"roles_any": ["department_lead"], "resource_matches_subject": {"division": "division"}},
    },
    {
        "id": 5,
        "permission": "team:leave:read",
        "effect": "allow",
        "enabled": True,
        "conditions": {
            "roles_any": ["line_manager"],
            "relationship": "manager_of",
            "resource_eq": {"manager_access_agreed": True},
        },
    },
    {
        "id": 6,
        "permission": "erp:budget:read",
        "effect": "allow",
        "enabled": True,
        "conditions": {"roles_any": ["finance"], "resource_matches_subject": {"cost_center": "costCenter"}},
    },
    {
        "id": 7,
        "permission": "content:publish",
        "effect": "allow",
        "enabled": True,
        "conditions": {"roles_any": ["content_editor"], "resource_matches_subject": {"division": "division"}},
    },
    {"id": 8, "permission": "documents:search", "effect": "allow", "enabled": True, "conditions": {"roles_any": ["employee"]}},
    {"id": 9, "permission": "documents:open", "effect": "allow", "enabled": True, "conditions": {"roles_any": ["employee"]}},
    {"id": 10, "permission": "documents:chat", "effect": "allow", "enabled": True, "conditions": {"roles_any": ["employee"]}},
    {"id": 11, "permission": "m365:mail:read", "effect": "allow", "enabled": True, "conditions": {"roles_any": ["employee"]}},
    {"id": 12, "permission": "m365:teams:read", "effect": "allow", "enabled": True, "conditions": {"roles_any": ["employee"]}},
    {"id": 13, "permission": "m365:calendar:read", "effect": "allow", "enabled": True, "conditions": {"roles_any": ["employee"]}},
    {"id": 14, "permission": "approvals:inbox", "effect": "allow", "enabled": True, "conditions": {"roles_any": ["employee"]}},
    {"id": 15, "permission": "approvals:act", "effect": "allow", "enabled": True, "conditions": {"roles_any": ["employee"]}},
    {"id": 16, "permission": "people:directory:read", "effect": "allow", "enabled": True, "conditions": {"roles_any": ["employee"]}},
    {"id": 18, "permission": "audit:read", "effect": "allow", "enabled": True, "conditions": {"roles_any": ["auditor"]}},
    {"id": 19, "permission": "admin:policy:manage", "effect": "allow", "enabled": True, "conditions": {"roles_any": ["coe_admin"]}},
]


def init_authz_tables() -> None:
    s = get_settings()
    try:
        conn = sqlite3.connect(s.identity_db_path, check_same_thread=False)
        with conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS coe_roles (
                    name TEXT PRIMARY KEY,
                    description TEXT
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS coe_role_groups (
                    role TEXT REFERENCES coe_roles(name),
                    group_id TEXT NOT NULL,
                    PRIMARY KEY (role, group_id)
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS coe_permissions (
                    name TEXT PRIMARY KEY,
                    description TEXT,
                    sensitivity TEXT CHECK (sensitivity IN ('normal','personal','financial','admin'))
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS coe_policy_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    permission TEXT REFERENCES coe_permissions(name),
                    effect TEXT CHECK (effect IN ('allow','deny')),
                    conditions TEXT NOT NULL DEFAULT '{}',
                    enabled INTEGER NOT NULL DEFAULT 1,
                    note TEXT,
                    updated_by TEXT,
                    updated_at TEXT DEFAULT (datetime('now'))
                );
                """
            )

            # Check if rules table is empty; if so, populate with default seed
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM coe_policy_rules")
            if cur.fetchone()[0] == 0:
                for r in DEFAULT_RULES:
                    conn.execute(
                        """
                        INSERT INTO coe_policy_rules (id, permission, effect, conditions, enabled)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (r["id"], r["permission"], r["effect"], json.dumps(r["conditions"]), 1 if r["enabled"] else 0),
                    )
        conn.close()
    except Exception as e:
        logger.warning("Could not initialize authz tables: %s", e)


def _load() -> None:
    if time.time() - _CACHE["at"] < _TTL and _CACHE["rules"]:
        return

    s = get_settings()
    rules: list[dict[str, Any]] = []
    role_groups: dict[str, set[str]] = {}

    try:
        conn = sqlite3.connect(s.identity_db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT id, permission, effect, conditions, enabled FROM coe_policy_rules WHERE enabled = 1")
            for row in cur.fetchall():
                cond = json.loads(row["conditions"]) if row["conditions"] else {}
                rules.append({
                    "id": row["id"],
                    "permission": row["permission"],
                    "effect": row["effect"],
                    "conditions": cond,
                    "enabled": bool(row["enabled"]),
                })

            cur.execute("SELECT role, group_id FROM coe_role_groups")
            for row in cur.fetchall():
                role_groups.setdefault(row["group_id"].lower(), set()).add(row["role"].lower())
        conn.close()
    except Exception as e:
        logger.warning("Failed to load rules from db (%s); using default seed", e)
        rules = DEFAULT_RULES

    if not rules:
        rules = DEFAULT_RULES

    _CACHE.update(at=time.time(), rules=rules, role_groups=role_groups)


def get_rules() -> list[dict[str, Any]]:
    _load()
    return _CACHE["rules"]


def resolve_roles(groups: set[str], oid: str) -> set[str]:
    """Resolves Entra group IDs to application roles."""
    _load()
    roles = {"employee"}  # everyone who passed the gate is at least an employee
    for gid in groups:
        clean_gid = gid.lower()
        if clean_gid in _CACHE["role_groups"]:
            roles |= _CACHE["role_groups"][clean_gid]

    # Check if this user is a line manager (has direct reports) from identity repo
    try:
        s = get_settings()
        conn = sqlite3.connect(s.identity_db_path, check_same_thread=False)
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM identity_mappings WHERE lower(manager_oid) = ?", (oid.lower(),))
            count = cur.fetchone()[0]
            if count > 0:
                roles.add("line_manager")
        conn.close()
    except Exception:
        pass

    return roles


def invalidate_cache() -> None:
    _CACHE["at"] = 0.0
