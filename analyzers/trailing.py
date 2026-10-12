"""
Trailing Data / Polyglot Detector: check for bytes appended after the
logical end of the image container (JPEG EOI, PNG IEND, GIF trailer,
WebP RIFF end) and sniff those bytes for known file signatures (ZIP,
PDF, ELF, PE, gzip, HTML, ...) that indicate a polyglot or an appended
payload (steganography drop, hidden archive, second document).
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Signatures sniffed in trailing bytes. Short signatures (like MZ) only
# trigger when they literally START the trailing data; 4+ byte signatures
# also trigger when found within the first 512 sniffed bytes.
_SIGNATURES: List[Tuple[bytes, str]] = [
    (b"PK\x03\x04", "ZIP archive"),
    (b"PK\x05\x06", "ZIP empty archive"),
    (b"PK\x07\x08", "ZIP spanned"),
    (b"%PDF", "PDF document"),
    (b"\x7fELF", "ELF binary"),
    (b"MZ", "PE/DOS executable"),
    (b"\x1f\x8b", "GZIP stream"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF87a", "GIF image"),
    (b"GIF89a", "GIF image"),
    (b"RIFF", "RIFF container"),
    (b"\x00\x00\x01\x00", "ICO icon"),
    (b"SQLite format 3\x00", "SQLite database"),
    (b"<!DOCTYPE", "HTML document"),
    (b"<html", "HTML document"),
    (b"<?xml", "XML document"),
    (b"\x00asm", "WebAssembly module"),
    (b"\xca\xfe\xba\xbe", "Java class / Mach-O fat binary"),
    (b"\xfe\xed\xfa", "Mach-O binary"),
]

_MAX_SNIFF_BYTES = 512


class TrailingDataDetector:
    """Detect bytes appended after the image's logical end + polyglot sniff."""

    def analyze(self, file_path: str | Path) -> Dict[str, Any]:
        """Return {trailing_bytes, polyglot, signatures, ...} for the file."""
        result: Dict[str, Any] = {
            "available": False,
            "format": None,
            "file_size": 0,
            "logical_end": None,
            "trailing_bytes": 0,
            "trailing_preview": None,
            "signatures": [],
            "polyglot": False,
            "errors": [],
        }

        path = Path(file_path)
        try:
            data = path.read_bytes()
        except OSError as e:
            result["errors"].append(f"read error: {e}")
            return result

        result["file_size"] = len(data)
        fmt, end = _find_logical_end(data)
        result["format"] = fmt
        result["logical_end"] = end
        result["available"] = fmt is not None

        if fmt is None:
            result["errors"].append("unsupported container (only JPEG/PNG/GIF/WebP)")
            return result

        if end is None or end >= len(data):
            return result  # no logical end found, or no trailing data

        trailing = data[end:]
        result["trailing_bytes"] = len(trailing)
        result["trailing_preview"] = trailing[:64].hex(" ")

        for sig, name in _SIGNATURES:
            hit = trailing.startswith(sig)
            if not hit and len(sig) >= 4:
                hit = sig in trailing[:_MAX_SNIFF_BYTES]
            if hit and name not in result["signatures"]:
                result["signatures"].append(name)

        result["polyglot"] = bool(result["signatures"])
        return result


def _find_logical_end(data: bytes) -> Tuple[Optional[str], Optional[int]]:
    """Return (format_name, offset_of_logical_end_exclusive)."""
    if data.startswith(b"\xff\xd8\xff"):
        return "JPEG", _jpeg_eoi(data)
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "PNG", _png_iend(data)
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "GIF", _gif_trailer(data)
    if data.startswith(b"RIFF") and len(data) >= 12 and data[8:12] == b"WEBP":
        riff_size = int.from_bytes(data[4:8], "little")
        end = 8 + riff_size
        if end > len(data):
            end = len(data)
        return "WebP", end
    return None, None


def _jpeg_eoi(data: bytes) -> Optional[int]:
    """Walk JPEG markers (with the SOS/FF00 unstuffing rule); return EOI offset."""
    n = len(data)
    i = 2
    while i + 1 < n:
        if data[i] != 0xFF:
            i += 1
            continue
        marker = data[i + 1]
        if marker == 0x00:  # stuffed
            i += 2
            continue
        if marker == 0xD8:  # SOI
            i += 2
            continue
        if marker == 0xD9:  # EOI
            return i + 2  # offset AFTER the 2-byte EOI marker
        if marker == 0x01 or 0xD0 <= marker <= 0xD7:  # TEM / RSTn
            i += 2
            continue
        if i + 3 >= n:
            break
        seg_len = (data[i + 2] << 8) | data[i + 3]
        if seg_len < 2 or i + 2 + seg_len > n:
            break
        if marker == 0xDA:  # SOS: entropy-coded scan until non-stuffed marker
            i += 2 + seg_len
            while i + 1 < n:
                if data[i] == 0xFF:
                    if data[i + 1] == 0x00:  # stuffed
                        i += 2
                        continue
                    if data[i + 1] == 0xD9:  # EOI
                        return i + 2  # offset AFTER the 2-byte EOI marker
                    if 0xD0 <= data[i + 1] <= 0xD7:  # RSTn inside scan
                        i += 2
                        continue
                    break  # unexpected marker - let outer loop handle it
                i += 1
            continue
        i += 2 + seg_len
    return None


def _png_iend(data: bytes) -> Optional[int]:
    """Walk PNG chunks; return offset just past the IEND chunk's CRC."""
    pos = 8
    n = len(data)
    while pos + 8 <= n:
        length = int.from_bytes(data[pos:pos + 4], "big")
        ctype = data[pos + 4:pos + 8]
        if pos + 12 + length > n:
            break
        if ctype == b"IEND":
            return pos + 12 + length  # len(4) + type(4) + data + crc(4)
        pos += 12 + length
    return None


def _gif_trailer(data: bytes) -> Optional[int]:
    """Walk GIF blocks; return offset of the 0x3B trailer byte."""
    pos = 6
    n = len(data)
    if pos + 7 > n:
        return None
    packed = data[pos + 4]
    pos += 7
    if packed & 0x80:  # global color table
        pos += 3 * (2 ** ((packed & 0x07) + 1))
    while pos < n:
        if data[pos] == 0x3B:  # trailer
            return pos + 1  # offset AFTER the 1-byte trailer
        if data[pos] == 0x21:  # extension
            pos += 2
            while pos < n:
                size = data[pos]
                pos += 1
                if size == 0:
                    break
                pos += size
        elif data[pos] == 0x2C:  # image descriptor
            pos += 9
            if pos < n:
                lzw = data[pos]
                pos += 1 + lzw
            while pos < n:
                size = data[pos]
                pos += 1
                if size == 0:
                    break
                pos += size
        else:
            pos += 1
    return None
