"""
Embedded Strings: scan raw file bytes for URLs, emails, phones, IPs,
device/software names, social platform names and GPS hints that survive
full metadata stripping (also catches Windows UTF-16 strings).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List

_ASCII_RUN = re.compile(rb"[\x20-\x7e]{4,}")
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_PHONE_RE = re.compile(r"^\+[\d\s\-().]{7,15}$")

_DEVICE_TOKENS = (
    "canon", "nikon", "sony", "fujifilm", "panasonic", "huawei", "xiaomi",
    "oppo", "vivo", "oneplus", "samsung", "google", "pixel", "iphone",
    "apple", "motorola",
)
_SOFTWARE_TOKENS = (
    "adobe", "photoshop", "lightroom", "gimp", "snapseed", "android", "ios",
    "windows", "macos", "miui", "one ui", "coloros", "capture one",
    "irfanview", "xnview",
)
_SOCIAL_TOKENS = (
    "whatsapp", "instagram", "facebook", "twitter", "tiktok", "telegram",
    "snapchat", "signal", "discord", "wechat", "weibo", "pinterest",
    "linkedin",
)
_GPS_TOKENS = ("latitude", "longitude", "geohash", "lat=", "lon=", "gpano",
               "exif:gps")
_OTHER_CAP = 120  # longer "other" strings are usually compressed junk


class StringMiner:
    """Extract meaningful embedded strings from raw file bytes."""

    def analyze(self, file_path: str | Path, max_bytes: int = 2_000_000) -> Dict[str, Any]:
        """Scan for embedded strings; returns categorized, offset-sorted hits."""
        result: Dict[str, Any] = {
            "available": False,
            "scanned_bytes": 0,
            "strings": [],
            "counts": {},
            "cap_hit": False,
            "truncated": False,
            "errors": [],
        }

        path = Path(file_path)
        try:
            data = path.read_bytes()[:max_bytes]
            result["scanned_bytes"] = len(data)
            if path.stat().st_size > len(data):
                result["cap_hit"] = True
        except OSError as e:
            result["errors"].append(f"read error: {e}")
            return result

        hits: List[Dict[str, Any]] = []
        seen: set[str] = set()

        # ASCII pass
        for match in _ASCII_RUN.finditer(data):
            raw = match.group()
            stripped = raw.strip(b" \t\r\n")
            if len(stripped) < 4:
                continue
            value = stripped.decode("ascii", errors="ignore")
            leading = len(raw) - len(raw.lstrip(b" \t\r\n"))
            self._add_hit(hits, seen, value, match.start() + leading, "ascii")

        # UTF-16LE pass (precise byte offsets, 2 bytes per code unit)
        n = len(data)
        i = 0
        while i + 1 < n:
            code = (data[i + 1] << 8) | data[i]
            if not (0x20 <= code <= 0x7E):
                i += 2
                continue
            start = i
            chars: list[str] = []
            while i + 1 < n:
                code = (data[i + 1] << 8) | data[i]
                if not (0x20 <= code <= 0x7E):
                    break
                chars.append(chr(code))
                i += 2
            value = "".join(chars).strip()
            if len(value) >= 4:
                self._add_hit(hits, seen, value, start, "utf-16le")

        hits.sort(key=lambda s: s["offset"])
        if len(hits) > 500:
            result["truncated"] = True
            hits = hits[:500]

        counts: Dict[str, int] = {}
        for hit in hits:
            counts[hit["category"]] = counts.get(hit["category"], 0) + 1

        result["strings"] = hits
        result["counts"] = counts
        result["available"] = bool(hits)
        return result

    def _add_hit(self, hits: List[Dict[str, Any]], seen: set[str], value: str,
                 offset: int, encoding: str) -> None:
        """Append a categorized string hit, honoring dedupe + noise rules."""
        if not value or value in seen:
            return
        category = self._classify(value)
        if category == "other" and len(value) > _OTHER_CAP:
            return
        seen.add(value)
        hits.append({
            "value": value,
            "offset": offset,
            "encoding": encoding,
            "category": category,
            "length": len(value) * 2 if encoding == "utf-16le" else len(value),
        })

    @staticmethod
    def _classify(value: str) -> str:
        """Classify a string into a forensics category (first match wins)."""
        v = value.strip()
        low = v.lower()
        if "://" in low or low.startswith("www."):
            return "url"
        if _EMAIL_RE.match(v):
            return "email"
        if _IPV4_RE.match(v) and all(0 <= int(o) <= 255 for o in v.split(".")):
            return "ip_address"
        if _PHONE_RE.match(v):
            return "phone"
        if any(t in low for t in _DEVICE_TOKENS):
            return "device"
        if any(t in low for t in _SOFTWARE_TOKENS):
            return "software"
        if any(t in low for t in _SOCIAL_TOKENS):
            return "social_platform"
        if any(t in low for t in _GPS_TOKENS):
            return "gps_hint"
        if len(v) >= 6 and ("/" in v or "\\" in v) and _looks_like_path(v):
            return "path"
        return "other"


def _looks_like_path(text: str) -> bool:
    """Heuristic: a plausible filesystem path, not random printable bytes
    from compressed data that happen to contain a slash."""
    # These characters never appear in real filesystem paths.
    if any(ch in text for ch in "|;=^`\"'&"):
        return False
    separators = text.count("/") + text.count("\\")
    if separators >= 2:
        return True
    if separators == 0:
        return False
    # Single separator: needs a file-extension lookalike, a drive letter,
    # or a leading slash (absolute-style) to qualify.
    if "." in text and len(text) >= 7:
        return True
    if text.startswith(("/", "\\")):
        return True
    if len(text) >= 3 and text[1] == ":":
        return True
    return False