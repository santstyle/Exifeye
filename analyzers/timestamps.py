"""
Timestamp consistency: parse every recorded timestamp (EXIF local time,
GPS UTC, document / video container fields), then check for zero or
epoch placeholders, future dates, impossible field ordering, and infer
the capture timezone from the camera-clock-vs-GPS-UTC offset.

Division of labor with gps_spoof: that check compares DATES only (day
level, flags >1 day drift); this one works with the full clock. The
local-minus-UTC offset comes from full datetimes, so any legitimate
timezone reading lands inside UTC-12..UTC+14 - a larger offset means
the camera clock is skewed or the timestamps were edited.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

# Real timezone bounds with a little grace for a fast/slow clock:
# UTC-12 (Baker Island) .. UTC+14 (Kiribati, easternmost inhabited).
_MIN_OFFSET_H = -12.5
_MAX_OFFSET_H = 14.5

# Accept a timestamp as "future" only past this slack - small camera
# clock errors are normal, fabrication is not.
_FUTURE_SLACK = timedelta(days=1)

# Tolerance when comparing timestamps written by the same capture/save.
_ORDER_TOL = timedelta(seconds=5)

# QuickTime's 1904 epoch: ANY 1904 date means the movie clock was
# never set (real videos are years past it).
_QT_EPOCH_YEAR = 1904

# Jan 1 of these years as a timestamp = classic unset-clock epochs
# (Unix epoch, FAT day zero). Restricted to Jan 1 because genuine
# legacy files from those years do exist.
_UNIX_FAT_EPOCHS = (1970, 1980)

# Capture anchors, most specific first (EXIF image, then documents,
# then video mvhd). 'created'/'creation' are UTC in MP4 - harmless for
# the ordering check, and never used for the GPS offset below.
_CAPTURE_KEYS = ("original", "digitized", "created", "creation")
# Edit timestamps across all three families.
_EDIT_KEYS = ("modified", "modification")

# Trailing timezone markers stripped before parsing the wall-clock part
# ('... UTC', '... +07:00', '...Z').
_TZ_SUFFIX = re.compile(r"\s*(?:UTC|Z|[+-]\d{2}:?\d{2})\s*$", re.IGNORECASE)


class TimestampAnalyzer:
    """Cross-check timestamps for skew, placeholders and ordering."""

    def analyze(self, timestamps: Dict[str, Any],
                gps: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Return {available, issues, inferred_tz, verdict}.

        `timestamps` is result.timestamps; `gps` is an optional fallback
        for the GPS date/time when they only live in the GPS dict.
        """
        if not timestamps:
            return {"available": False, "issues": [], "inferred_tz": None,
                    "verdict": "no timestamps recorded"}

        issues: List[str] = []
        parsed: Dict[str, datetime] = {}
        for key, raw in timestamps.items():
            text = str(raw or "").strip()
            if not text:
                continue
            if text.startswith("0000"):
                issues.append(
                    f"{key}: zero placeholder (0000:00:00) - clock was unset"
                )
                continue
            dt = _parse(text)
            if dt is not None:
                parsed[key] = dt

        if not parsed and not issues:
            return {"available": False, "issues": [], "inferred_tz": None,
                    "verdict": "no parseable timestamps"}

        # 1. Future dates (fabrication or a badly wrong clock).
        now = datetime.now()
        for key, dt in parsed.items():
            if dt > now + _FUTURE_SLACK:
                ahead = (dt - now).days
                issues.append(
                    f"{key}: {ahead} day(s) in the future - "
                    "clock wrong or fabricated"
                )

        # 2. Classic unset-clock epochs (QuickTime 1904, Unix/FAT day 0).
        for key, dt in parsed.items():
            if dt.year == _QT_EPOCH_YEAR:
                issues.append(
                    f"{key}: 1904 QuickTime-epoch date - "
                    "movie clock was never set"
                )
            elif dt.year in _UNIX_FAT_EPOCHS and dt.month == 1 \
                    and dt.day == 1:
                issues.append(
                    f"{key}: {dt.year}-01-01 placeholder epoch - "
                    "clock was never set"
                )

        # 3. Field ordering, anchored on capture vs edit. A separate
        #    digitized-vs-original check because both are capture-side.
        capture = _first_of(parsed, _CAPTURE_KEYS)
        edit = _first_of(parsed, _EDIT_KEYS)
        orig = parsed.get("original")
        digi = parsed.get("digitized")
        if orig is not None and digi is not None \
                and digi < orig - _ORDER_TOL:
            issues.append("digitized timestamp predates capture")
        if capture is not None and edit is not None \
                and edit < capture - _ORDER_TOL:
            anchor = ("capture" if "original" in parsed
                      or "digitized" in parsed else "creation")
            issues.append(
                f"modified timestamp predates {anchor} - "
                "backdated edit or clock change"
            )

        # 4. Camera local vs GPS UTC -> inferred timezone, or a skew no
        #    timezone on Earth can explain.
        tz = None
        offset_h = _local_vs_utc_offset_h(parsed, timestamps, gps)
        if offset_h is not None:
            if _MIN_OFFSET_H <= offset_h <= _MAX_OFFSET_H:
                tz = _format_tz(round(offset_h * 4) / 4)
            else:
                issues.append(
                    f"capture time sits {offset_h:+.1f} h from GPS UTC - "
                    "outside UTC-12..UTC+14 (camera clock skew or "
                    "edited timestamps)"
                )

        verdict = ("no timestamp anomalies found" if not issues
                   else f"{len(issues)} timestamp issue(s)")
        return {"available": True, "issues": issues, "inferred_tz": tz,
                "verdict": verdict}


def _first_of(parsed: Dict[str, datetime],
              keys: tuple) -> Optional[datetime]:
    """First present timestamp among `keys` (capture/edit aliases)."""
    for key in keys:
        if key in parsed:
            return parsed[key]
    return None


def _parse(text: str) -> Optional[datetime]:
    """Parse the timestamp formats ExifEye's parsers emit.

    Handles EXIF 'YYYY:MM:DD HH:MM:SS', PDF/OOXML/OLE/MP4
    'YYYY-MM-DD HH:MM:SS [UTC|+HH:MM]', ISO with 'T', date-only and
    fractional seconds. The trailing zone marker is stripped (wall-clock
    kept as-is - every comparison here tolerates that).
    """
    cleaned = _TZ_SUFFIX.sub("", text).strip()
    if not cleaned:
        return None
    for fmt in ("%Y:%m:%d %H:%M:%S", "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S", "%Y:%m:%d %H:%M",
                "%Y-%m-%d %H:%M", "%Y:%m:%d", "%Y-%m-%d",
                "%Y-%m-%d %H:%M:%S.%f", "%Y:%m:%d %H:%M:%S.%f"):
        try:
            return datetime.strptime(cleaned, fmt)
        except ValueError:
            continue
    try:  # leftover ISO shapes fromisoformat accepts
        return datetime.fromisoformat(cleaned)
    except ValueError:
        return None


def _parse_clock(text: str) -> Optional[datetime]:
    """Parse a time-only value like '14:30:00 UTC' (date supplied by
    the caller). _parse rejects these - %Y demands four digits."""
    cleaned = _TZ_SUFFIX.sub("", text).strip()
    if not cleaned:
        return None
    for fmt in ("%H:%M:%S", "%H:%M"):
        try:
            return datetime.strptime(cleaned, fmt)
        except ValueError:
            continue
    return None


def _gps_utc(timestamps: Dict[str, Any],
             gps: Optional[Dict[str, Any]]) -> Optional[datetime]:
    """GPS date + time -> naive UTC datetime (both required).

    Tries result.timestamps first (where the EXIF parser puts them),
    then the GPS dict as a fallback.
    """
    for source in (timestamps, gps or {}):
        date_raw = str(source.get("gps_date") or "").strip()
        time_raw = str(source.get("gps_time") or "").strip()
        if not date_raw or not time_raw:
            continue
        day = _parse(date_raw)
        clock = _parse_clock(time_raw)
        if day is not None and clock is not None:
            return day.replace(hour=clock.hour, minute=clock.minute,
                               second=clock.second)
    return None


def _local_vs_utc_offset_h(parsed: Dict[str, datetime],
                           timestamps: Dict[str, Any],
                           gps: Optional[Dict[str, Any]]) -> Optional[float]:
    """Camera local capture time minus GPS UTC, in hours.

    Only EXIF-family capture tags count as local time: MP4 'creation'
    is already UTC and must not be compared against GPS UTC (it would
    read a constant ~0 h 'timezone'). Full-datetime subtraction already
    handles midnight date rolls, so no manual shifting here.
    """
    local = _first_of(parsed, ("original", "digitized"))
    gps_dt = _gps_utc(timestamps, gps)
    if local is None or gps_dt is None:
        return None
    return (local - gps_dt).total_seconds() / 3600.0


def _format_tz(offset_h: float) -> str:
    """6.0 -> 'UTC+06:00'; -3.5 -> 'UTC-03:30'."""
    sign = "+" if offset_h >= 0 else "-"
    hours = abs(offset_h)
    hh = int(hours)
    mm = int(round((hours - hh) * 60))
    if mm == 60:
        hh, mm = hh + 1, 0
    return f"UTC{sign}{hh:02d}:{mm:02d}"
