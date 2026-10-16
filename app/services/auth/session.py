from __future__ import annotations

import json
import logging
import secrets
import time
from typing import Any, Set

import redis
from cryptography.fernet import Fernet

from app.core.config import get_settings

logger = logging.getLogger("coe.session")

_s = get_settings()

try:
    _r = redis.Redis.from_url(
        _s.redis_url,
        decode_responses=True,
        socket_timeout=5.0,
        socket_connect_timeout=5.0,
        retry_on_timeout=True,
    )
    # Quick connectivity verification
    _r.ping()
except Exception as exc:
    logger.warning("Redis connection failed (%s); fallback to in-memory dictionary for isolated testing", exc)

    class InMemoryRedis:
        def __init__(self):
            self.store: dict[str, str] = {}
            self.sets: dict[str, set[str]] = {}
            self.ttls: dict[str, float] = {}

        def _is_expired(self, key: str) -> bool:
            if key in self.ttls and time.time() > self.ttls[key]:
                self.store.pop(key, None)
                self.sets.pop(key, None)
                self.ttls.pop(key, None)
                return True
            return False

        def get(self, key: str):
            if self._is_expired(key):
                return None
            return self.store.get(key)

        def set(self, key: str, value: str, ex: int | None = None):
            self.store[key] = value
            if ex:
                self.ttls[key] = time.time() + ex
            else:
                self.ttls.pop(key, None)

        def setex(self, key: str, time_sec: int, value: str):
            self.set(key, value, ex=time_sec)

        def getdel(self, key: str):
            if self._is_expired(key):
                return None
            val = self.store.pop(key, None)
            self.ttls.pop(key, None)
            return val

        def delete(self, key: str):
            self.store.pop(key, None)
            self.sets.pop(key, None)
            self.ttls.pop(key, None)

        def exists(self, key: str) -> int:
            if self._is_expired(key):
                return 0
            return 1 if (key in self.store or key in self.sets) else 0

        def ttl(self, key: str) -> int:
            if self._is_expired(key) or key not in self.ttls:
                return -2
            rem = int(self.ttls[key] - time.time())
            return max(rem, 0)

        def sadd(self, key: str, *members: str):
            self._is_expired(key)
            if key not in self.sets:
                self.sets[key] = set()
            self.sets[key].update(members)

        def srem(self, key: str, *members: str):
            self._is_expired(key)
            if key in self.sets:
                self.sets[key].difference_update(members)

        def smembers(self, key: str) -> set[str]:
            if self._is_expired(key):
                return set()
            return set(self.sets.get(key, set()))

        def expire(self, key: str, time_sec: int):
            self.ttls[key] = time.time() + time_sec

        def ping(self):
            return True

        def pipeline(self):
            return InMemoryPipeline(self)

    class InMemoryPipeline:
        def __init__(self, backend: InMemoryRedis):
            self.backend = backend
            self.ops = []

        def set(self, key: str, value: str, ex: int | None = None):
            self.ops.append(lambda: self.backend.set(key, value, ex=ex))
            return self

        def setex(self, key: str, time_sec: int, value: str):
            self.ops.append(lambda: self.backend.set(key, value, ex=time_sec))
            return self

        def sadd(self, key: str, *members: str):
            self.ops.append(lambda: self.backend.sadd(key, *members))
            return self

        def srem(self, key: str, *members: str):
            self.ops.append(lambda: self.backend.srem(key, *members))
            return self

        def expire(self, key: str, time_sec: int):
            self.ops.append(lambda: self.backend.expire(key, time_sec))
            return self

        def delete(self, key: str):
            self.ops.append(lambda: self.backend.delete(key))
            return self

        def execute(self):
            results = [op() for op in self.ops]
            self.ops.clear()
            return results

    _r = InMemoryRedis()  # type: ignore

_f = Fernet(_s.fernet_key.encode())

SESS: str = "sess:"
FLOW: str = "flow:"
BY_USER: str = "user_sessions:"
BY_SID: str = "entra_sid:"
SESSION_COOKIE: str = "__Host-coe_session" if _s.cookie_secure else "coe_session"
FLOW_COOKIE: str = "coe_flow"


def seal(text: str) -> str:
    """Encrypts plaintext using server-side Fernet key."""
    return _f.encrypt(text.encode()).decode()


def unseal(token: str) -> str:
    """Decrypts Fernet ciphertext."""
    return _f.decrypt(token.encode()).decode()


def new_id() -> str:
    """Generates 256-bit cryptographically secure identifier."""
    return secrets.token_urlsafe(32)


# ---- short-lived sign-in flow (state, nonce, PKCE verifier stay server-side) ----
def save_flow(flow: dict[str, Any]) -> str:
    fid = new_id()
    _r.set(FLOW + fid, json.dumps(flow), ex=600)
    return fid


def pop_flow(fid: str | None) -> dict[str, Any] | None:
    if not fid:
        return None
    raw = _r.getdel(FLOW + fid)  # one-time use
    return json.loads(raw) if raw else None


# ---- sessions ----
def create_session(data: dict[str, Any]) -> str:
    """Creates a new session ID at login (session fixation prevention)."""
    sid = new_id()
    now = time.time()
    created_time = data.get("created", now)
    data.update(
        created=created_time,
        last_seen=now,
        authenticated_at=data.get("authenticated_at", now),
        csrf=secrets.token_urlsafe(24),
    )
    ttl = int(_s.session_absolute_hours * 3600)
    pipe = _r.pipeline()
    pipe.set(SESS + sid, json.dumps(data), ex=ttl)
    pipe.sadd(BY_USER + data["oid"], sid)
    pipe.expire(BY_USER + data["oid"], ttl)
    if data.get("entra_sid"):
        pipe.set(BY_SID + data["entra_sid"], sid, ex=ttl)
    pipe.execute()
    _enforce_cap(data["oid"])
    return sid


def load_session(sid: str | None) -> dict[str, Any] | None:
    if not sid:
        return None
    raw = _r.get(SESS + sid)
    return json.loads(raw) if raw else None


def save_session(sid: str, data: dict[str, Any]) -> None:
    """Saves session while strictly preserving the absolute expiry."""
    ttl = _r.ttl(SESS + sid)
    if ttl and ttl > 0:
        _r.set(SESS + sid, json.dumps(data), ex=ttl)


def delete_session(sid: str) -> None:
    data = load_session(sid)
    pipe = _r.pipeline()
    pipe.delete(SESS + sid)
    if data:
        pipe.srem(BY_USER + data["oid"], sid)
        if data.get("entra_sid"):
            pipe.delete(BY_SID + data["entra_sid"])
    pipe.execute()


def delete_by_entra_sid(entra_sid: str) -> None:
    sid = _r.get(BY_SID + entra_sid)
    if sid:
        delete_session(sid)


def delete_all_for_user(oid: str) -> None:
    """Admin kill-switch / leaver cleanup: terminates all active sessions for a user."""
    for sid in list(_r.smembers(BY_USER + oid)):
        delete_session(sid)


def _enforce_cap(oid: str) -> None:
    """Limits concurrent active sessions per user, evicting the oldest."""
    sids = list(_r.smembers(BY_USER + oid))
    if len(sids) <= _s.max_sessions_per_user:
        return
    pairs = []
    for x in sids:
        d = load_session(x)
        if d:
            pairs.append((d.get("created", 0), x))
        else:
            _r.srem(BY_USER + oid, x)
    pairs.sort()
    for _, x in pairs[: max(0, len(pairs) - _s.max_sessions_per_user)]:
        delete_session(x)


# Convenience alias for load_session
get_session = load_session
