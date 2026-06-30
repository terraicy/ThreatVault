"""Result cache — Redis with in-memory fallback."""

from __future__ import annotations

import json
import time
from typing import Any

from app.core.config import get_settings

_memory_cache: dict[str, tuple[float, Any]] = {}
_redis_client = None


def _get_redis():
    global _redis_client
    if _redis_client is not None:
        return _redis_client
    settings = get_settings()
    if not settings.enable_cache:
        return None
    try:
        import redis

        client = redis.from_url(settings.redis_url, decode_responses=True)
        client.ping()
        _redis_client = client
        return _redis_client
    except Exception:
        return None


def cache_get(key: str) -> Any | None:
    redis = _get_redis()
    if redis:
        raw = redis.get(f"tv:{key}")
        return json.loads(raw) if raw else None

    entry = _memory_cache.get(key)
    if not entry:
        return None
    expires_at, value = entry
    if time.time() > expires_at:
        del _memory_cache[key]
        return None
    return value


def cache_set(key: str, value: Any, ttl: int | None = None) -> None:
    settings = get_settings()
    ttl = ttl or settings.cache_ttl_seconds
    redis = _get_redis()
    if redis:
        redis.setex(f"tv:{key}", ttl, json.dumps(value, default=str))
        return

    _memory_cache[key] = (time.time() + ttl, value)


def cache_delete(key: str) -> None:
    redis = _get_redis()
    if redis:
        redis.delete(f"tv:{key}")
    _memory_cache.pop(key, None)
# Project version: ThreatVault V1.2
