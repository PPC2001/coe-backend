"""Phase 1: User Profile & Admin Role Verification.

Scope:
- /api/me: Returns the authenticated user's Entra ID profile (oid, tid, roles, name, username).
- /api/admin/ping: Verifies that the caller has the Entra ID "Admin" role.
"""

import logging
from typing import Annotated

from fastapi import APIRouter, Depends

from app.core.security import CurrentUser, get_current_user, require_roles
from app.schemas.users import (
    AdminPingResponse,
    UserProfileResponse,
)

logger = logging.getLogger("coe.api.users")

router = APIRouter()


@router.get("/me", response_model=UserProfileResponse)
def me(user: Annotated[CurrentUser, Depends(get_current_user)]) -> dict:
    """[Phase 1 Active] Current authenticated user identity derived from the validated access token."""
    return user.model_dump(exclude={"token"})


@router.get("/admin/ping", response_model=AdminPingResponse)
def admin_ping(user: Annotated[CurrentUser, Depends(require_roles("Admin"))]) -> AdminPingResponse:
    """[Phase 1 Active] Verifies caller has the Entra ID 'Admin' app role."""
    return AdminPingResponse(ok=True, oid=user.oid)
