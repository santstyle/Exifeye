"""Filename origin forensics: screenshots and device-default naming.

Pure name check (no file reads): pattern-matches the file name against
screenshot conventions (macOS / Windows / Android) and device-default
naming schemes (IMG_ iOS/Canon, DSC/DSCN cameras, PXL_ Pixel, ...).

Value for geolocation work:
- a screenshot has NO camera EXIF/GPS by design - when one shows up
  without coordinates that is expected, not metadata stripping;
- default device filenames (IMG_/DSC/PXL) suggest an unedited original
  exists that may still carry GPS and full EXIF.

WhatsApp media filenames (IMG-YYYYMMDD-WA####, "WhatsApp Image ... at
...") are owned by analyzers/social_media.py and are deliberately not
matched here to avoid double reporting.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, Tuple, Union

# (pattern, kind, label) - first match wins, so the specific dated
# screenshot forms must precede the generic "^screen ?shot" fallback.
_PATTERNS: Tuple[Tuple[re.Pattern, str, str], ...] = (
    # macOS: "Screenshot 2024-01-15 at 10.30.45.png" (and old "Screen Shot")
    (re.compile(r"^screen ?shot \d{4}-\d{2}-\d{2} at ", re.I),
     "screenshot", "macOS screenshot"),
    # Windows 10/11: "Screenshot 2024-01-15 103045.png"
    (re.compile(r"^screenshot \d{4}-\d{2}-\d{2} \d{4,8}", re.I),
     "screenshot", "Windows screenshot"),
    (re.compile(r"^screenshot \(\d+\)", re.I),
     "screenshot", "Windows screenshot"),
    # Android: "Screenshot_20240115_103045.png" (or "-103045")
    (re.compile(r"^screenshot_\d{8}[-_]\d{4,6}", re.I),
     "screenshot", "Android screenshot"),
    # Generic fallback for any other "Screenshot"/"Screen Shot" name.
    (re.compile(r"^screen ?shot(?:$|[\s(._\-])", re.I),
     "screenshot", "screenshot"),
    # Device-default naming (specific -> generic).
    (re.compile(r"^pxl_\d{8}_\d{9}", re.I),
     "phone-filename", "Google Pixel default naming"),
    (re.compile(r"^mvimg_\d{8}", re.I),
     "phone-filename", "Google Motion Photo naming"),
    (re.compile(r"^fullsizerender", re.I),
     "phone-filename", "iOS full-size render export"),
    (re.compile(r"^vid_", re.I),
     "phone-filename", "default video naming (Android-style)"),
    # IMG_20230415... (dated device export) before IMG_0618 (iOS/Canon
    # 4-digit sequence) so the 4-digit rule's (?!\d) can't mislabel it.
    (re.compile(r"^img_\d{8}", re.I),
     "camera-filename", "IMG_ dated default naming (device camera roll)"),
    (re.compile(r"^img_\d{4}(?!\d)", re.I),
     "camera-filename", "IMG_ default naming (iOS / Canon)"),
    (re.compile(r"^dscn\d{4}", re.I),
     "camera-filename", "Nikon DSCN default naming"),
    (re.compile(r"^_?dsc_?\d{4}", re.I),
     "camera-filename", "DCF DSC default naming (Sony/Nikon/etc.)"),
)

_VERDICTS = {
    "screenshot": ("no camera EXIF/GPS by design - geolocation must come "
                   "from the captured content or its source"),
    "camera-filename": ("default camera naming - an unedited original "
                        "from the device may still carry GPS/EXIF"),
    "phone-filename": ("default phone naming - look for the pre-upload "
                       "original to recover GPS/metadata"),
}


class FilenameOriginDetector:
    """Classify a file name as screenshot / device-default naming."""

    def analyze(self, file_path: Union[str, Path]) -> Dict[str, Any]:
        """Return {available, detected, kind, label, signals, verdict}."""
        name = Path(file_path).name
        for pattern, kind, label in _PATTERNS:
            if pattern.search(name):
                return {
                    "available": True,
                    "detected": True,
                    "kind": kind,
                    "label": label,
                    "signals": [f"filename pattern: {label}"],
                    "verdict": _VERDICTS[kind],
                }
        return {
            "available": True,
            "detected": False,
            "kind": None,
            "label": None,
            "signals": [],
            "verdict": "no filename origin pattern matched",
        }
