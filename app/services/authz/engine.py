from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Subject:
    oid: str
    tid: str
    roles: frozenset[str]
    groups: frozenset[str]
    attrs: dict[str, Any]
    report_oids: frozenset[str] = frozenset()  # direct reports, from the synced people directory


@dataclass(frozen=True)
class Decision:
    allow: bool
    reason: str
    rule_id: int | None = None


def _match(cond: dict[str, Any], subj: Subject, res: dict[str, Any]) -> bool:
    if "roles_any" in cond and not (set(cond["roles_any"]) & subj.roles):
        return False
    if "groups_any" in cond and not (set(cond["groups_any"]) & subj.groups):
        return False
    for key, wanted in cond.get("subject_attr", {}).items():
        allowed = wanted if isinstance(wanted, list) else [wanted]
        if subj.attrs.get(key) not in allowed:
            return False
    for res_key, subj_key in cond.get("resource_matches_subject", {}).items():
        have = res.get(res_key)
        if have is None or have != subj.attrs.get(subj_key):
            return False
    for res_key, literal in cond.get("resource_eq", {}).items():
        if res.get(res_key) != literal:
            return False
    rel = cond.get("relationship")
    owner = res.get("owner_oid")
    if rel == "self" and (owner is None or owner.lower() != subj.oid.lower()):
        return False
    if rel == "manager_of" and (owner is None or owner.lower() not in {r.lower() for r in subj.report_oids}):
        return False
    if "any_of" in cond and not any(_match(c, subj, res) for c in cond["any_of"]):
        return False
    return True


def evaluate(
    rules: list[dict[str, Any]],
    subj: Subject,
    permission: str,
    resource: dict[str, Any] | None = None,
) -> Decision:
    """Default deny. An explicit deny beats any allow."""
    res = resource or {}
    allow_rule: int | None = None
    for r in rules:
        if r.get("permission") != permission or not r.get("enabled", True):
            continue
        if _match(r.get("conditions", {}), subj, res):
            if r.get("effect") == "deny":
                return Decision(False, "explicit deny", r.get("id"))
            allow_rule = allow_rule or r.get("id")
    if allow_rule is not None:
        return Decision(True, "allowed", allow_rule)
    return Decision(False, "no matching allow rule")
