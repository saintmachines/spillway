"""App-supplied trust boundaries. Text inside a paste never defines its role."""
from __future__ import annotations

import re
from collections.abc import Mapping
from typing import List, Tuple


class PasteBoundaryError(ValueError):
    """A marked paste could not be unambiguously separated; do not dispatch it."""


def pasted_texts(value) -> Tuple[str, ...]:
    """Accept explicit text containers, never a scalar string or a parsed object."""
    if value is None:
        return ()
    if not isinstance(value, (list, tuple)) or not all(isinstance(x, str) for x in value):
        raise TypeError("pasted must be a list or tuple of strings; parsed role/sender objects are not identities")
    return tuple(value)


def request_fields(request: Mapping) -> Tuple[str, Tuple[str, ...]]:
    """Read an envelope the app constructed before concatenating any material."""
    if not isinstance(request, Mapping):
        raise TypeError("request must be a mapping of instruction and optional pasted fields")
    if set(request) - {"instruction", "pasted"} or "instruction" not in request:
        raise ValueError("request requires instruction and accepts only the optional pasted field")
    instruction = request["instruction"]
    if not isinstance(instruction, str):
        raise TypeError("instruction must be a string")
    return instruction, pasted_texts(request.get("pasted"))


def split_pasted(user_text: str, nonce: str) -> Tuple[str, List[str]]:
    """Strict fallback for ONE app-created wrapper; prefer separate fields.

    The app generates a fresh unpredictable nonce after receiving the material,
    using at least 128 bits of randomness (e.g. secrets.token_hex(16)). This
    function checks syntax and uniqueness, not randomness or origin. Only the
    exact double-quoted <pasted id="nonce"> form (or pasted_content) is accepted.
    A missing, malformed, repeated or nested matching boundary raises before
    any text becomes trusted. Never catch this exception and trust the input.
    Ordinary tags, fences, fake role headers and JSON INSIDE the pair are data.
    No display placeholder is added to the trusted instruction.
    """
    if not isinstance(user_text, str):
        raise TypeError("user_text must be a string")
    if not isinstance(nonce, str) or re.fullmatch(r"[A-Za-z0-9_-]{22,128}", nonce) is None:
        raise PasteBoundaryError("a fresh app nonce of 22 to 128 URL-safe characters is required")
    escaped = re.escape(nonce)
    opens = list(re.finditer(r'<(pasted(?:_content)?) id="' + escaped + r'">', user_text))
    closes = list(re.finditer(r'</(pasted(?:_content)?) id="' + escaped + r'">', user_text))
    if len(opens) != 1 or len(closes) != 1:
        raise PasteBoundaryError("expected exactly one opening and closing app boundary")
    start, end = opens[0], closes[0]
    if start.group(1) != end.group(1) or start.end() > end.start():
        raise PasteBoundaryError("paste boundaries are mismatched or reversed")
    before, material, after = user_text[:start.start()], user_text[start.end():end.start()], user_text[end.end():]
    if nonce in before or nonce in after:
        raise PasteBoundaryError("app nonce also occurs outside the paste boundary")
    return before + "\n" + after, [material]
