import pytest
from app.services.authz.engine import Subject, evaluate

RULES = [
    {
        "id": 1,
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
        "id": 2,
        "permission": "tiles:analytics:view",
        "effect": "allow",
        "enabled": True,
        "conditions": {"roles_any": ["hr_analytics"]},
    },
    {
        "id": 3,
        "permission": "tiles:analytics:view",
        "effect": "allow",
        "enabled": True,
        "conditions": {
            "roles_any": ["department_lead"],
            "resource_matches_subject": {"division": "division"},
        },
    },
    {
        "id": 4,
        "permission": "erp:budget:read",
        "effect": "allow",
        "enabled": True,
        "conditions": {
            "roles_any": ["finance"],
            "resource_matches_subject": {"cost_center": "costCenter"},
        },
    },
    {
        "id": 99,
        "permission": "confidential:read",
        "effect": "deny",
        "enabled": True,
        "conditions": {"roles_any": ["guest"]},
    },
    {
        "id": 100,
        "permission": "confidential:read",
        "effect": "allow",
        "enabled": True,
        "conditions": {"roles_any": ["employee"]},
    },
]


def subj(oid="omar", roles=("employee", "line_manager"), reports=(), attrs=None):
    return Subject(
        oid=oid,
        tid="t",
        roles=frozenset(roles),
        groups=frozenset(),
        attrs=attrs or {},
        report_oids=frozenset(reports),
    )


def test_manager_with_agreement_allowed():
    d = evaluate(
        RULES,
        subj(reports={"aisha"}),
        "team:leave:read",
        {"owner_oid": "aisha", "manager_access_agreed": True},
    )
    assert d.allow
    assert d.rule_id == 1


def test_not_agreed_denied():
    d = evaluate(
        RULES,
        subj(reports={"aisha"}),
        "team:leave:read",
        {"owner_oid": "aisha", "manager_access_agreed": False},
    )
    assert not d.allow


def test_not_a_report_denied():
    d = evaluate(
        RULES,
        subj(reports=set()),
        "team:leave:read",
        {"owner_oid": "aisha", "manager_access_agreed": True},
    )
    assert not d.allow


def test_unknown_permission_denied():
    assert not evaluate(RULES, subj(), "non_existent_perm").allow


def test_department_lead_division_match():
    s = subj(roles=("department_lead",), attrs={"division": "Media"})
    assert evaluate(RULES, s, "tiles:analytics:view", {"division": "Media"}).allow
    assert not evaluate(RULES, s, "tiles:analytics:view", {"division": "Urban"}).allow


def test_finance_cost_center_match():
    s = subj(roles=("finance",), attrs={"costCenter": "CC-100"})
    assert evaluate(RULES, s, "erp:budget:read", {"cost_center": "CC-100"}).allow
    assert not evaluate(RULES, s, "erp:budget:read", {"cost_center": "CC-200"}).allow


def test_explicit_deny_beats_allow():
    # User has both employee (allow) and guest (deny)
    s = subj(roles=("employee", "guest"))
    d = evaluate(RULES, s, "confidential:read")
    assert not d.allow
    assert d.reason == "explicit deny"
