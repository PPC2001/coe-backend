from fastapi import APIRouter

from app.api.routes import (
    auth,
    authz,
    documents,
    m365,
    sharepoint,
    suggestions,
    users,
)

api_router = APIRouter()

# Authentication & Session Lifecycle -> /api/auth/*
api_router.include_router(auth.router, prefix="/api/auth", tags=["auth"])

# User Profile & Admin Role Verification -> /api/me and /api/admin/ping
api_router.include_router(users.router, prefix="/api", tags=["users"])

# User Entitlements & Permissions -> /api/me/entitlements
api_router.include_router(authz.router, prefix="/api/me", tags=["authz"])

# SharePoint & OneDrive OBO Delegation -> /api/graph/* and /api/sharepoint/*
api_router.include_router(sharepoint.router, prefix="/api", tags=["sharepoint"])

# Microsoft 365 Delegated Graph Integration (Mail, Calendar, Teams) -> /api/m365/*
api_router.include_router(m365.router, prefix="/api/m365", tags=["m365"])

# Documents ACL-Trimmed Search & Delegated Stream -> /api/documents/*
api_router.include_router(documents.router, prefix="/api/documents", tags=["documents"])

# Anonymous Suggestion Box -> /api/suggestions
api_router.include_router(suggestions.router, prefix="/api/suggestions", tags=["anonymous"])
