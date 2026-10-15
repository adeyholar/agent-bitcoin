"""Local record of Lightning payment hashes.

This is not the daily spend cap. A hash marked succeeded or in flight is not
paid again, including after the UTC day rolls over. A failed attempt stays
in flight: failure inside the fee limit or invoice expiry is not proof the
payment will never settle.
"""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_lock = threading.Lock()
_BLOCKED = frozenset({"succeeded", "in_flight"})


def default_attempts_path() -> Path:
    override = (os.getenv("AGENT_BITCOIN_PAYMENT_ATTEMPTS") or "").strip()
    if override:
        return Path(override).expanduser()
    return Path.home() / ".config" / "agent-bitcoin" / "payment-attempts.json"


def _normalize(payment_hash: str) -> str:
    text = (payment_hash or "").strip().lower()
    if len(text) != 64 or any(c not in "0123456789abcdef" for c in text):
        raise ValueError("payment_hash_unknown")
    return text


def _load(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {"payments": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("payment attempt record unreadable") from exc
    if not isinstance(data, dict):
        raise ValueError("payment attempt record unreadable")
    payments = data.get("payments")
    if payments is None:
        data["payments"] = {}
    elif not isinstance(payments, dict):
        raise ValueError("payment attempt record unreadable")
    return data


def _save(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)


def _stamp(status: str) -> dict[str, str]:
    return {
        "status": status,
        "updated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def begin_attempt(payment_hash: str, path: Path | None = None) -> None:
    """Record ``in_flight``. Raise if this hash already succeeded or is in flight."""
    digest = _normalize(payment_hash)
    dest = path or default_attempts_path()
    with _lock:
        data = _load(dest)
        payments = data["payments"]
        current = payments.get(digest)
        if isinstance(current, dict) and current.get("status") in _BLOCKED:
            raise ValueError(f"payment already recorded: {current.get('status')}")
        payments[digest] = _stamp("in_flight")
        _save(dest, data)


def mark_succeeded(payment_hash: str, path: Path | None = None) -> None:
    """Record ``succeeded`` for a payment LND reported as paid."""
    digest = _normalize(payment_hash)
    dest = path or default_attempts_path()
    with _lock:
        data = _load(dest)
        data["payments"][digest] = _stamp("succeeded")
        _save(dest, data)
