"""
Thumbnail Meta Mining: extract residual metadata from the EXIF embedded
thumbnail JPEG. A stripped main image often keeps GPS, device, timestamps
and software traces inside its own embedded thumbnail.
"""
from __future__ import annotations

import io
from pathlib import Path
from typing import Any, Dict

import exifread

from extractor.gps import GPSParser

_MAX_READ_BYTES = 64 * 1024 * 1024  # thumbnails live near the file start
_MAX_SOI_SCAN = 8192  # cameras write the offset absolute instead of TIFF-relative


class ThumbnailMiner:
    """Mine the embedded EXIF thumbnail JPEG for residual metadata."""

    def __init__(self) -> None:
        self._gps = GPSParser()

    def analyze(self, file_path: str | Path) -> Dict[str, Any]:
        """Locate and parse the embedded thumbnail; return recovered metadata."""
        result: Dict[str, Any] = {
            "available": False,
            "offset": None,
            "length": None,
            "dimensions": None,
            "gps": None,
            "device": {"make": None, "model": None},
            "timestamps": {"original": None, "digitized": None, "modified": None},
            "software": None,
            "errors": [],
        }

        path = Path(file_path)
        try:
            with open(path, "rb") as f:
                data = f.read(_MAX_READ_BYTES)
        except OSError as e:
            result["errors"].append(f"read error: {e}")
            return result

        exif_abs = _find_exif_app1(data)
        if exif_abs is None:
            result["errors"].append("no APP1 Exif segment found")
            return result

        try:
            tags = exifread.process_file(
                io.BytesIO(data), details=True, strict=False, debug=False
            )
        except Exception as e:
            result["errors"].append(f"exifread error: {e}")
            return result

        if not tags:
            result["errors"].append("no EXIF tags found")
            return result

        jif = tags.get("Thumbnail JPEGInterchangeFormat")
        if jif is None:
            result["errors"].append("no embedded thumbnail (JPEGInterchangeFormat missing)")
            return result

        try:
            jif_offset = int(jif.values[0])
        except (AttributeError, IndexError, TypeError, ValueError) as e:
            result["errors"].append(f"bad thumbnail offset: {e}")
            return result

        start = _locate_soi(data, exif_abs + 6 + jif_offset, _MAX_SOI_SCAN)
        if start is None:
            result["errors"].append("thumbnail SOI not found")
            return result

        end = _jpeg_end(data, start)
        if end is None:
            result["errors"].append("thumbnail EOI not found")
            return result

        thumb_raw = data[start:end + 2]
        result["offset"] = start
        result["length"] = end + 2 - start
        result["dimensions"] = _jpeg_dimensions(thumb_raw)

        try:
            thumb_tags = exifread.process_file(
                io.BytesIO(thumb_raw), details=True, strict=False, debug=False
            )
        except Exception as e:
            thumb_tags = {}
            result["errors"].append(f"thumbnail exifread error: {e}")

        if thumb_tags:
            self._extract_thumbnail_meta(result, thumb_tags)
        else:
            result["errors"].append("thumbnail has no parseable tags")

        result["available"] = True
        return result

    def _extract_thumbnail_meta(self, result: Dict[str, Any], tags: Dict[str, Any]) -> None:
        """Copy GPS / device / timestamps / software out of the thumbnail tags."""
        gps = self._gps.parse(tags)
        if gps.get("available") or gps.get("zero_placeholder"):
            result["gps"] = gps
            if gps.get("available"):
                # Mark the source so callers can report "recovered from thumbnail".
                result["gps"]["source"] = "Thumbnail"

        for tag, label in (("Image Make", "make"), ("Image Model", "model")):
            if tag in tags:
                result["device"][label] = str(tags[tag])

        for tag, label in (
            ("EXIF DateTimeOriginal", "original"),
            ("EXIF DateTimeDigitized", "digitized"),
            ("Image DateTime", "modified"),
        ):
            if tag in tags:
                result["timestamps"][label] = str(tags[tag])

        if "Image Software" in tags:
            result["software"] = str(tags["Image Software"])


def _find_exif_app1(data: bytes) -> int | None:
    """Walk JPEG markers; return the absolute offset of the b'Exif\\x00\\x00'
    payload inside the APP1 segment, or None when absent."""
    n = len(data)
    i = 2 if data[:2] == b"\xff\xd8" else 0
    while i + 1 < n:
        if data[i] != 0xFF:
            i += 1
            continue
        marker = data[i + 1]
        if marker == 0x00:  # stuffed byte
            i += 2
            continue
        if marker == 0xD8:  # another SOI
            i += 2
            continue
        if marker in (0x01, 0xD9):  # TEM / EOI
            return None
        if 0xD0 <= marker <= 0xD7:  # RSTn, standalone
            i += 2
            continue
        if i + 3 >= n:
            return None
        seg_len = (data[i + 2] << 8) | data[i + 3]
        if seg_len < 2 or i + 2 + seg_len > n:
            return None
        if marker == 0xE1 and seg_len >= 8 and data[i + 4:i + 10] == b"Exif\x00\x00":
            return i + 4
        if marker == 0xDA:  # SOS before any Exif APP1 -> no thumbnail here
            return None
        i += 2 + seg_len
    return None


def _locate_soi(data: bytes, pos: int, max_scan: int) -> int | None:
    """Return the thumbnail SOI offset at/after pos (with a bounded forward
    scan for cameras that write the offset absolute instead of TIFF-relative)."""
    if pos + 1 < len(data) and data[pos:pos + 2] == b"\xff\xd8":
        return pos
    end = min(len(data) - 1, pos + max_scan)
    for i in range(max(0, pos), end):
        if data[i:i + 2] == b"\xff\xd8":
            return i
    return None


def _jpeg_end(data: bytes, start: int) -> int | None:
    """Return the offset of the JPEG EOI (0xFFD9), walking markers and the
    entropy-coded SOS payload with the FF00 unstuffing rule."""
    n = len(data)
    i = start
    if data[i:i + 2] == b"\xff\xd8":
        i += 2
    while i + 1 < n:
        if data[i] != 0xFF:
            i += 1
            continue
        marker = data[i + 1]
        if marker == 0x00:  # stuffed
            i += 2
            continue
        if marker == 0xD9:  # EOI
            return i
        if marker == 0x01 or 0xD0 <= marker <= 0xD7:  # TEM / RSTn
            i += 2
            continue
        if i + 3 >= n:
            return None
        seg_len = (data[i + 2] << 8) | data[i + 3]
        if seg_len < 2 or i + 2 + seg_len > n:
            return None
        if marker == 0xDA:  # SOS: entropy-coded data until a non-stuffed marker
            i += 2 + seg_len
            while i + 1 < n:
                if data[i] == 0xFF:
                    if data[i + 1] == 0x00:  # stuffed
                        i += 2
                        continue
                    if data[i + 1] == 0xD9:  # EOI
                        return i
                    i += 2  # stray marker inside scan (rare), keep scanning
                    continue
                i += 1
            return None
        i += 2 + seg_len
    return None


def _jpeg_dimensions(jpeg: bytes) -> list[int] | None:
    """Read [width, height] from the first SOF marker of a JPEG byte blob."""
    n = len(jpeg)
    i = 2 if jpeg[:2] == b"\xff\xd8" else 0
    while i + 1 < n:
        if jpeg[i] != 0xFF:
            i += 1
            continue
        marker = jpeg[i + 1]
        if marker == 0x00:
            i += 2
            continue
        if marker in (0x01, 0xD8, 0xD9):
            i += 2
            continue
        if 0xD0 <= marker <= 0xD7:
            i += 2
            continue
        if i + 3 >= n:
            return None
        seg_len = (jpeg[i + 2] << 8) | jpeg[i + 3]
        if seg_len < 2 or i + 2 + seg_len > n:
            return None
        if 0xC0 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC):
            # SOF payload: precision(1) + height(2) + width(2) + ...
            if seg_len >= 7:
                h = (jpeg[i + 5] << 8) | jpeg[i + 6]
                w = (jpeg[i + 7] << 8) | jpeg[i + 8]
                return [w, h]
            return None
        i += 2 + seg_len
    return None