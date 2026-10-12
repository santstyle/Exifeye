"""
GPS Spoof Check: sanity-check decoded GPS coordinates for signs of
placeholder, fabrication or stripping. Flags Null Island, impossible
altitudes, integer-snap (hand-edited) coordinates, out-of-range GPS dates
and GPS-vs-EXIF timestamp drift.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

# Real-world bounds with margin: Everest is ~8849 m; the Dead Sea shore is
# ~-430 m. Anything outside this range was not recorded by a real receiver.
_MAX_ABS_ALTITUDE = 12000
_MIN_ABS_ALTITUDE = -500

# Day-level tolerance for GPS-vs-EXIF comparison. We only compare DATES
# (not clock times) because EXIF timestamps are local time and GPS is UTC -
# a multi-hour offset is normal for any non-UTC timezone, but a multi-DAY
# gap means the GPS block and the EXIF block disagree about when the
# photo was taken.
_DATE_DRIFT_TOLERANCE_DAYS = 1


class GpsSpoofCheck:
    """Sanity-check GPS data for spoof / placeholder / strip indicators."""

    def analyze(self, gps: Dict[str, Any],
                timestamps: Dict[str, Any]) -> Dict[str, Any]:
        """Return {plausible, issues, verdict} for the given GPS + timestamps."""
        issues: List[str] = []

        # No GPS block at all, or a parsed-but-empty one (stripped image):
        # only the zero-placeholder case still has something to report.
        if not gps or (not gps.get("available")
                       and not gps.get("zero_placeholder")):
            return {
                "plausible": True,
                "issues": [],
                "verdict": "No GPS data present - nothing to verify",
            }

        if gps.get("zero_placeholder"):
            issues.append(
                "GPS IFD present but all coordinates are (0, 0) - "
                "Null Island placeholder (location disabled at capture)"
            )

        lat = gps.get("latitude")
        lon = gps.get("longitude")

        if gps.get("available") and lat == 0 and lon == 0:
            issues.append("Coordinates are exactly (0, 0) - not a real position")

        if gps.get("available") and lat is not None and lon is not None:
            if lat == int(lat) and lon == int(lon) and (lat != 0 or lon != 0):
                issues.append(
                    f"Both latitude and longitude are whole degrees "
                    f"({lat}, {lon}) - possible hand-edit"
                )

            alt = gps.get("altitude_meters")
            if alt is not None:
                if alt > _MAX_ABS_ALTITUDE:
                    issues.append(
                        f"Altitude {alt} m is above the highest land on Earth "
                        f"(Everest ~8849 m) - implausible"
                    )
                elif alt < _MIN_ABS_ALTITUDE:
                    issues.append(
                        f"Altitude {alt} m is below the deepest land point "
                        f"(Dead Sea ~-430 m) - implausible"
                    )

            gps_date = gps.get("gps_date")
            if gps_date:
                year = _extract_year(str(gps_date))
                if year is not None and (year < 1990
                                         or year > datetime.now().year + 1):
                    issues.append(
                        f"GPS date {gps_date} is outside "
                        f"1990..{datetime.now().year + 1}"
                    )

        drift = _date_drift_days(gps, timestamps)
        if drift is not None and drift > _DATE_DRIFT_TOLERANCE_DAYS:
            issues.append(
                f"GPS date is {drift} day(s) away from the EXIF capture date "
                f"- the two blocks disagree about when the photo was taken"
            )

        plausible = not issues
        verdict = (
            "GPS data is internally consistent - no spoof indicators found"
            if plausible else
            f"{len(issues)} spoof indicator(s) - treat coordinates with caution"
        )
        return {"plausible": plausible, "issues": issues, "verdict": verdict}


def _extract_year(text: str) -> Optional[int]:
    """Pull a plausible 4-digit year out of a date-ish string."""
    for part in text.replace("/", ":").replace("-", ":").split(":"):
        part = part.strip()
        if len(part) == 4 and part.isdigit():
            return int(part)
    return None


def _parse_date_only(text: str) -> Optional[datetime]:
    """Parse just the YYYY:MM:DD part of a timestamp (tolerates '-' too)."""
    text = text.strip().replace("-", ":")
    try:
        return datetime.strptime(text[:10], "%Y:%m:%d")
    except ValueError:
        return None


def _date_drift_days(gps: Dict[str, Any],
                     timestamps: Dict[str, Any]) -> Optional[int]:
    """Absolute day gap between the GPS date and the EXIF capture date."""
    gps_date = gps.get("gps_date")
    if not gps_date:
        return None
    gps_day = _parse_date_only(str(gps_date))
    if gps_day is None:
        return None

    if not timestamps:
        return None
    for key in ("original", "digitized", "modified"):
        val = timestamps.get(key)
        if val:
            exif_day = _parse_date_only(str(val))
            if exif_day is not None:
                return abs((gps_day - exif_day).days)
    return None
