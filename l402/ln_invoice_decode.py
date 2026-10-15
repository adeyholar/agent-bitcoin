"""In-process BOLT11 inspect for POST /paid/finance/ln-invoice-decode.

No LND. No QueryRoutes / SendPayment / DecodePayReq.
"""

from __future__ import annotations

import json
import math
from datetime import datetime, timezone
from typing import Any

SERVICE = "ln-invoice-decode"
VERSION = "v1"
SOURCE = "local_bolt11"
MAX_BODY_BYTES = 65_536
MAX_DESCRIPTION_CHARS = 200
DEFAULT_EXPIRY_S = 3600

# Longest currency first so bcrt is not classified as bc.
_CURRENCY_NETWORK = (
    ("bcrt", "regtest"),
    ("tbs", "signet"),
    ("bc", "bitcoin"),
    ("tb", "testnet"),
)


class BadInvoice(Exception):
    """Missing, empty, or unparseable bolt11."""


class DuplicatePaymentHash(BadInvoice):
    """More than one p (payment hash) tag. Do not keep the first."""


# Same walk as agent_bitcoin.bolt11_invoice.inspect_payment_hashes.
# Origin image copies this file alone, so the walk lives here too.
_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_GEN = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
_BECH32_CONST = 1
_TIMESTAMP_WORDS = 7
_SIGNATURE_WORDS = 104  # 65-byte recoverable signature
_PAYMENT_HASH_TYPE = 1  # bech32 tag character "p"
_PAYMENT_HASH_WORDS = 52


def _polymod(values: list[int]) -> int:
    chk = 1
    for value in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ value
        for i in range(5):
            if (top >> i) & 1:
                chk ^= _GEN[i]
    return chk


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _bech32_decode(invoice: str) -> tuple[str, list[int]] | None:
    text = invoice.strip().lower()
    if any(ord(c) < 33 or ord(c) > 126 for c in text):
        return None
    pos = text.rfind("1")
    if pos < 1 or pos + 7 > len(text):
        return None
    hrp = text[:pos]
    data: list[int] = []
    for char in text[pos + 1 :]:
        idx = _CHARSET.find(char)
        if idx < 0:
            return None
        data.append(idx)
    if _polymod(_hrp_expand(hrp) + data) != _BECH32_CONST:
        return None
    return hrp, data[:-6]


def _hash32(words: list[int]) -> str | None:
    acc = 0
    bits = 0
    out = bytearray()
    for word in words:
        acc = (acc << 5) | word
        bits += 5
        while bits >= 8 and len(out) < 32:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    if len(out) != 32:
        return None
    return out.hex()


def inspect_payment_hashes(invoice: str) -> tuple[int, tuple[str, ...]] | None:
    """Return ``(p_tag_count, 32-byte hashes)`` or None if tags cannot be walked.

    Every type-``p`` field counts. A 52-word field also contributes its hash.
    """
    decoded = _bech32_decode(invoice)
    if decoded is None:
        return None
    _hrp, data = decoded
    if len(data) < _TIMESTAMP_WORDS + _SIGNATURE_WORDS:
        return None
    words = data[_TIMESTAMP_WORDS:-_SIGNATURE_WORDS]
    index = 0
    count = 0
    hashes: list[str] = []
    while index < len(words):
        if index + 3 > len(words):
            return None
        tag_type = words[index]
        length = words[index + 1] * 32 + words[index + 2]
        index += 3
        if index + length > len(words):
            return None
        field = words[index : index + length]
        index += length
        if tag_type == _PAYMENT_HASH_TYPE:
            count += 1
            if length == _PAYMENT_HASH_WORDS:
                digest = _hash32(field)
                if digest is not None:
                    hashes.append(digest)
    return count, tuple(hashes)


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _iso_z(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _truncate_prefix(value: str) -> str:
    text = value.strip()
    if len(text) <= 12:
        return text
    return text[:8] + "…"


def _network(currency: str) -> str:
    cur = (currency or "").strip().lower()
    for prefix, network in _CURRENCY_NETWORK:
        if cur == prefix:
            return network
    raise BadInvoice("unknown invoice network")


def _amount_sats(amount_msat: Any) -> int | None:
    if amount_msat is None:
        return None
    try:
        msat = int(amount_msat)
    except (TypeError, ValueError) as exc:
        raise BadInvoice("invalid amount") from exc
    if msat <= 0:
        return None
    return int(math.floor(msat / 1000))


def parse_body(raw: bytes) -> str:
    if not raw or not raw.strip():
        raise BadInvoice("empty body")
    if len(raw) > MAX_BODY_BYTES:
        raise BadInvoice("body too large")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BadInvoice("invalid json") from exc
    if not isinstance(data, dict):
        raise BadInvoice("json object required")
    bolt11 = data.get("bolt11")
    if not isinstance(bolt11, str) or not bolt11.strip():
        raise BadInvoice("bolt11 required")
    invoice = bolt11.strip()
    if not invoice.lower().startswith("ln"):
        raise BadInvoice("bolt11 must be a Lightning invoice")
    return invoice


def digest_invoice(
    invoice: Any,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    when = now or _now_utc()
    currency = str(getattr(invoice, "currency", "") or "")
    network = _network(currency)
    dest = str(getattr(invoice, "payee", "") or "").strip().lower()
    payment_hash = str(getattr(invoice, "payment_hash", "") or "").strip().lower()
    if len(dest) != 66 or any(c not in "0123456789abcdef" for c in dest):
        raise BadInvoice("dest_pubkey missing")
    if len(payment_hash) != 64 or any(
        c not in "0123456789abcdef" for c in payment_hash
    ):
        raise BadInvoice("payment_hash missing")
    date = getattr(invoice, "date", None)
    try:
        created = int(date)
    except (TypeError, ValueError) as exc:
        raise BadInvoice("timestamp missing") from exc
    expiry_s = getattr(invoice, "expiry", None)
    try:
        expiry_s_int = int(expiry_s) if expiry_s is not None else DEFAULT_EXPIRY_S
    except (TypeError, ValueError):
        expiry_s_int = DEFAULT_EXPIRY_S
    if expiry_s_int < 0:
        expiry_s_int = DEFAULT_EXPIRY_S
    expiry_unix = created + expiry_s_int
    now_unix = int(when.timestamp())
    out: dict[str, Any] = {
        "ok": True,
        "service": SERVICE,
        "version": VERSION,
        "as_of": _iso_z(when),
        "ttl_s": 0,
        "source": SOURCE,
        "stale": False,
        "network": network,
        "amount_sats": _amount_sats(getattr(invoice, "amount_msat", None)),
        "dest_pubkey": dest,
        "payment_hash": payment_hash,
        "expiry_unix": expiry_unix,
        "expired": now_unix >= expiry_unix,
    }
    description = getattr(invoice, "description", None)
    if (
        isinstance(description, str)
        and description
        and len(description) <= MAX_DESCRIPTION_CHARS
    ):
        out["description"] = description
    return out


def handle_request(
    body: bytes,
    *,
    now: datetime | None = None,
    decode=None,
) -> dict[str, Any]:
    """Parse POST body. Raises BadInvoice. Never logs full bolt11."""
    invoice_s = parse_body(body)
    seen = inspect_payment_hashes(invoice_s)
    if seen is not None and seen[0] > 1:
        raise DuplicatePaymentHash("duplicate_payment_hash")
    do_decode = decode
    if do_decode is None:
        from bolt11 import decode as bolt11_decode

        do_decode = bolt11_decode
    try:
        parsed = do_decode(invoice_s)
    except BadInvoice:
        raise
    except Exception as exc:
        raise BadInvoice(_truncate_prefix(invoice_s)) from exc
    return digest_invoice(parsed, now=now)
