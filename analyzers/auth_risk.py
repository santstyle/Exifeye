"""
Authentication Risk Meter: combine independent forensic signals (ELA,
re-encode hints, JPEG structure, thumbnail-only recovery, GPS placeholder,
timestamp defaults, editor software tags and raw-byte software strings)
into a single 0-100 authenticity risk score with a severity level.

The score answers one question: how much does this file look like a
camera original versus something that passed through an editor, a social
platform pipeline, or an aggressive metadata stripper?
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List

# Software tags that indicate post-processing rather than camera capture.
_EDITING_SOFTWARE = (
    "photoshop", "lightroom", "gimp", "capture one", "snagit", "irfanview",
    "xnview", "paint.net", "affinity", "darktable", "rawtherapee", "snapseed",
)

# Default timestamps written when the camera clock was never set (or was
# factory-reset). 1980:01:01 is the EXIF epoch default; 1970/2000 are the
# Unix-epoch and Y2K-reset variants some firmwares use.
_DEFAULT_TIMESTAMPS = (
    "1980:01:01",
    "1970:01:01",
    "2000:01:01",
)


class AuthenticationRiskMeter:
    """Score how authentic / manipulated an image's metadata looks."""

    def analyze(self, result: Any, forensics: Dict[str, Any],
                deep: Dict[str, Any], extra: Dict[str, Any]) -> Dict[str, Any]:
        """Combine all signals into {score, level, signals, summary}.

        result     - ExtractionResult from MetadataExtractor.extract()
        forensics  - SocialMediaForensics.analyze() dict (may be {})
        deep       - {"ela": ..., "steganography": ..., "entropy": ...} (may be {})
        extra      - {"thumbnail": ..., "jpeg_structure": ..., "chunks": ...,
                      "strings": ...?}  (strings only present with --strings)
        """
        signals: List[Dict[str, Any]] = []

        self._check_exif_stripped(result, signals)
        self._check_editing_software(result, signals)
        self._check_timestamp_anomalies(result, signals)
        self._check_ela(deep, signals)
        self._check_reencode(forensics, extra, signals)
        self._check_platform(forensics, signals)
        self._check_thumbnail_only(result, extra, signals)
        self._check_gps_placeholder(result, signals)
        self._check_strings(extra, signals)

        score = min(100, sum(s["weight"] for s in signals))
        level = self._level_for(score)
        summary = self._summary_for(level, signals)

        return {
            "available": True,
            "score": score,
            "level": level,
            "signals": signals,
            "summary": summary,
        }

    # ------------------------------------------------------------------ #
    # Individual signal checks                                            #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _add(signals: List[Dict[str, Any]], name: str, weight: int,
             detail: str) -> None:
        signals.append({"name": name, "weight": weight, "detail": detail})

    def _check_exif_stripped(self, result: Any,
                             signals: List[Dict[str, Any]]) -> None:
        """No EXIF tags at all - either a stripped file or a non-camera source."""
        if not getattr(result, "exif_data", None):
            self._add(signals, "exif-stripped", 15,
                      "No EXIF tags present - metadata was stripped or the "
                      "file never carried any")

    def _check_editing_software(self, result: Any,
                                signals: List[Dict[str, Any]]) -> None:
        """Software tag names a known image editor."""
        sw = (getattr(result, "software", None) or "").lower()
        if not sw:
            return
        for token in _EDITING_SOFTWARE:
            if token in sw:
                self._add(
                    signals, "editor-software", 20,
                    f"Software tag names an editor ({result.software}) - "
                    f"image was saved by post-processing software",
                )
                return

    def _check_timestamp_anomalies(self, result: Any,
                                   signals: List[Dict[str, Any]]) -> None:
        """Missing, default (clock-never-set) or future timestamps."""
        ts = getattr(result, "timestamps", None) or {}
        if not ts:
            self._add(signals, "no-timestamps", 10,
                      "No capture timestamps found")
            return

        this_year = datetime.now().year
        for label in ("original", "digitized", "modified"):
            value = ts.get(label)
            if not value:
                continue
            text = str(value)
            if any(text.startswith(d) for d in _DEFAULT_TIMESTAMPS):
                self._add(
                    signals, "default-timestamp", 15,
                    f"{label} timestamp is a factory default ({text}) - "
                    f"camera clock was never set or was reset",
                )
                return
            year = _extract_year(text)
            if year is not None and (year < 1990 or year > this_year + 1):
                self._add(
                    signals, "implausible-timestamp", 12,
                    f"{label} timestamp is implausible ({text}) - "
                    f"year outside 1990..{this_year + 1}",
                )
                return

    @staticmethod
    def _check_ela(deep: Dict[str, Any],
                   signals: List[Dict[str, Any]]) -> None:
        """Error Level Analysis: high-error blocks suggest a splice/edit."""
        ela = (deep or {}).get("ela") or {}
        if not ela.get("available"):
            return
        max_diff = ela.get("max_difference") or 0
        if max_diff > 25:
            AuthenticationRiskMeter._add(
                signals, "ela-hotspots", 25,
                f"ELA max difference {max_diff} - high-error regions "
                f"consistent with a spliced or edited area",
            )
        elif max_diff > 10:
            AuthenticationRiskMeter._add(
                signals, "ela-moderate", 12,
                f"ELA max difference {max_diff} - moderate error levels, "
                f"possible light edit",
            )

    def _check_reencode(self, forensics: Dict[str, Any],
                        extra: Dict[str, Any],
                        signals: List[Dict[str, Any]]) -> None:
        """JPEG rebuilt by another encoder (multiple DQT / quality drop)."""
        jpeg = (extra or {}).get("jpeg_structure") or {}
        reencoded = bool(jpeg.get("reencoded_hint")) or bool(
            (forensics or {}).get("reencoded"))
        if reencoded:
            self._add(
                signals, "reencoded-jpeg", 12,
                "Multiple quantization tables - JPEG was rebuilt by a "
                "second encoder (platform or editor)",
            )
        quality = jpeg.get("quality_estimate")
        if quality is not None and quality < 70:
            self._add(
                signals, "quality-drop", 8,
                f"JPEG quality estimate {quality} - heavy recompression "
                f"typical of platform re-upload",
            )

    def _check_platform(self, forensics: Dict[str, Any],
                        signals: List[Dict[str, Any]]) -> None:
        """Social platform fingerprint or screenshot detection."""
        platform = (forensics or {}).get("detected_platform")
        if platform:
            conf = (forensics or {}).get("confidence") or 0.0
            self._add(
                signals, "platform-transfer", 10,
                f"Platform fingerprint: {platform} "
                f"(confidence {conf:.0%}) - image passed through a "
                f"social-media pipeline",
            )
        if (forensics or {}).get("is_screenshot"):
            self._add(signals, "screenshot", 8,
                      "Image is likely a screenshot, not a camera capture")

    def _check_thumbnail_only(self, result: Any, extra: Dict[str, Any],
                              signals: List[Dict[str, Any]]) -> None:
        """GPS/device recovered only from the embedded thumbnail = stripping."""
        thumb = (extra or {}).get("thumbnail") or {}
        if not thumb.get("available"):
            return

        main_gps = bool((getattr(result, "gps", None) or {}).get("available"))
        thumb_gps = bool((thumb.get("gps") or {}).get("available"))
        if thumb_gps and not main_gps:
            self._add(
                signals, "thumbnail-gps", 20,
                "GPS recovered only from the embedded thumbnail - main "
                "EXIF block was stripped",
            )

        main_device = getattr(result, "device", None) or {}
        thumb_device = thumb.get("device") or {}
        if thumb_device.get("make") and not main_device.get("make"):
            self._add(
                signals, "thumbnail-device", 10,
                "Device make recovered only from the embedded thumbnail - "
                "main EXIF was partially stripped",
            )

    @staticmethod
    def _check_gps_placeholder(result: Any,
                               signals: List[Dict[str, Any]]) -> None:
        """GPS block present but zeroed out (placeholder / partial scrub)."""
        gps = getattr(result, "gps", None) or {}
        if gps.get("zero_placeholder"):
            AuthenticationRiskMeter._add(
                signals, "gps-placeholder", 10,
                "GPS tags present but zeroed out - partial metadata scrub",
            )
        elif (gps.get("available")
              and gps.get("latitude") == 0 and gps.get("longitude") == 0):
            AuthenticationRiskMeter._add(
                signals, "gps-origin", 10,
                "GPS coordinates are exactly (0, 0) - placeholder, not a "
                "real location",
            )

    @staticmethod
    def _check_strings(extra: Dict[str, Any],
                       signals: List[Dict[str, Any]]) -> None:
        """Raw-byte scan found editor-software strings (only with --strings)."""
        strings = (extra or {}).get("strings") or {}
        for hit in strings.get("strings") or []:
            if hit.get("category") != "software":
                continue
            low = (hit.get("value") or "").lower()
            if any(tok in low for tok in _EDITING_SOFTWARE):
                AuthenticationRiskMeter._add(
                    signals, "editor-string", 10,
                    f"Embedded editor string survives in raw bytes: "
                    f"{hit.get('value')!r}",
                )
                return

    # ------------------------------------------------------------------ #
    # Scoring helpers                                                     #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _level_for(score: int) -> str:
        if score < 20:
            return "LOW"
        if score < 50:
            return "MEDIUM"
        if score < 80:
            return "HIGH"
        return "CRITICAL"

    @staticmethod
    def _summary_for(level: str, signals: List[Dict[str, Any]]) -> str:
        if not signals:
            return ("No risk indicators - metadata is consistent with a "
                    "camera original")
        top = max(signals, key=lambda s: s["weight"])
        verdicts = {
            "LOW": "minor inconsistencies only",
            "MEDIUM": "shows signs of post-processing or platform transfer",
            "HIGH": "strong indicators of editing or aggressive stripping",
            "CRITICAL": "multiple independent tampering indicators",
        }
        return (f"{len(signals)} risk signal(s); "
                f"strongest: {top['name']} (+{top['weight']}). "
                f"Verdict: {verdicts[level]}.")


def _extract_year(text: str) -> int | None:
    """Pull a plausible 4-digit year out of an EXIF timestamp string."""
    for part in text.replace("/", ":").replace("-", ":").split(":"):
        part = part.strip()
        if len(part) == 4 and part.isdigit():
            return int(part)
    return None
