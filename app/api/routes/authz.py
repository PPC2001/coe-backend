from fastapi import APIRouter, Depends

from app.services.auth.deps import AuthContext, get_auth_context
from app.services.authz.engine import evaluate
from app.services.authz.authz_repo import get_rules

router = APIRouter()


from app.schemas.authz import EntitlementsResponse


@router.get("/entitlements", response_model=EntitlementsResponse)
def entitlements(ctx: AuthContext = Depends(get_auth_context)) -> dict:
    """Returns the effective permissions and roles for the signed-in user."""
    rules = get_rules()
    names = sorted({r["permission"] for r in rules})
    allowed = [p for p in names if evaluate(rules, ctx.subject, p).allow]
    return {
        "permissions": allowed,
        "roles": sorted(ctx.subject.roles),
        "oid": ctx.oid,
    }
