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

from app.main import app

# Vercel's Python runtime exposes 'app' as the ASGI application entrypoint
