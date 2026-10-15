"""BOLT11 payment-hash tag walk.

The optional ``bolt11`` package keeps the first ``p`` tag and skips the rest.
This walk counts every ``p`` tag so a pay decision cannot follow one hash
while LND follows another.
"""

from __future__ import annotations

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


def payment_hash_from_decode(decoded: dict) -> str:
    """Lower-case 32-byte hash from an LND decodepayreq dict, or an empty string."""
    for key in ("payment_hash", "payment_hash_str", "r_hash"):
        raw = decoded.get(key)
        if not isinstance(raw, str):
            continue
        text = raw.strip().lower()
        if len(text) == 64 and all(c in "0123456789abcdef" for c in text):
            return text
    return ""


def resolve_lnd_pay_hash(invoice: str, decoded: dict | None) -> str:
    """Hash LND will pay. Refuse a second ``p`` tag or a hash the walks disagree on.

    ``decoded`` is the LND ``decodepayreq`` object. When it has no payment hash,
    pay is refused. The in-process walk is not stored in place of LND's hash.
    """
    seen = inspect_payment_hashes(invoice)
    if seen is not None and seen[0] > 1:
        raise ValueError("duplicate_payment_hash")
    local_hash = ""
    if seen is not None and seen[0] == 1:
        if len(seen[1]) != 1:
            raise ValueError("payment_hash_unknown")
        local_hash = seen[1][0]
    if seen is not None and seen[0] == 0:
        raise ValueError("payment_hash_unknown")
    lnd_hash = ""
    if isinstance(decoded, dict):
        lnd_hash = payment_hash_from_decode(decoded)
    if not lnd_hash:
        raise ValueError("payment_hash_unknown")
    if local_hash and local_hash != lnd_hash:
        raise ValueError("payment_hash_mismatch")
    return lnd_hash
