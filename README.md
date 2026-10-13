# coe-backend

Center of Excellence (CoE) API: FastAPI (managed by `uv`). A protected API that validates
Microsoft Entra ID v2.0 access tokens on every request (signature, issuer, audience, expiry,
version, tenant, client, scope, optional app roles). Used by [coe-frontend](https://github.com/PPC2001/coe-frontend).

## Local development

```bash
cp .env.example .env   # fill in the values
uv run uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
uv run pytest -q
```

| Variable | Meaning |
|---|---|
| `TENANT_ID` | Entra tenant ID |
| `API_CLIENT_ID` | Client ID of the `COE-API` app registration (token audience) |
| `SPA_CLIENT_ID` | Client ID of `COE-UI`; only tokens issued to it (`azp`) are accepted |
| `API_CLIENT_SECRET` | Optional. Only for On-Behalf-Of calls to Microsoft Graph. Secret. |
| `REQUIRED_SCOPE` | Default `access_as_user` |
| `CORS_ORIGINS` | Comma-separated exact origins, never `*` |
| `ALLOWED_TENANT_IDS` | Optional tenant allow-list (single-tenant defaults to `TENANT_ID`) |
| `ENVIRONMENT` | `development` enables `/docs`; `production` (default) disables it |
| `TRUSTED_PROXY_COUNT` | Reverse proxies whose `X-Forwarded-For` is trusted (default 0) |
| `RATE_LIMIT_PER_MINUTE` | Per-IP limit (default 120) |

## Endpoints

- `GET /health` public
- `GET /api/me` validated identity from the access token
- `GET /api/admin/ping` requires the `Admin` app role
- `GET /api/graph/me` Microsoft Graph profile via OBO (needs `API_CLIENT_SECRET`)

## Deploy on Vercel

1. Import this repo as a Vercel project. FastAPI is detected from `app/main.py`, dependencies from `uv.lock`.
2. Add the variables above under Settings → Environment Variables (mark `API_CLIENT_SECRET` as Sensitive).
   Set `ENVIRONMENT=production` and `CORS_ORIGINS` to the deployed frontend URL.
3. The in-app rate limiter is per process and is not effective on serverless. Configure
   Vercel Firewall rate limiting for production.
