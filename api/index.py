import os
import sys
from pathlib import Path

# Add project root directory to sys.path so 'app' imports work smoothly
root_dir = Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

# Ensure writable sqlite path in Vercel serverless environment
if os.getenv("VERCEL") or os.getenv("AWS_LAMBDA_FUNCTION_NAME"):
    os.environ.setdefault("IDENTITY_DB_PATH", "/tmp/identity_store.db")

from app.main import app as fastapi_app
from fastapi import Request

async def app(scope, receive, send):
    """Vercel Serverless ASGI entrypoint with path resolution."""
    if scope.get("type") == "http":
        headers = dict(scope.get("headers", []))
        matched_path = (
            headers.get(b"x-matched-path", b"")
            or headers.get(b"x-forwarded-uri", b"")
            or headers.get(b"x-real-path", b"")
        ).decode("latin1")

        current_path = scope.get("path", "")
        if matched_path and (current_path in ("/api/index.py", "/api/index", "/api") or current_path.endswith("/api/index.py")):
            clean_path = matched_path.split("?")[0]
            scope["path"] = clean_path
            scope["raw_path"] = clean_path.encode("latin1")

    await fastapi_app(scope, receive, send)

