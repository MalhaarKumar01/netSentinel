from __future__ import annotations

import hashlib
import json
from typing import Any


def anonymize_ip(value: str) -> str:
    if ":" in value:
        parts = value.split(":")
        return ":".join(parts[:4] + ["xxxx"] * max(0, 8 - len(parts[:4])))

    octets = value.split(".")
    if len(octets) != 4:
        return value
    return ".".join(octets[:3] + ["x"])


def stable_sha256(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()
