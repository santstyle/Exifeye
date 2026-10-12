"""
Chunk Mining: walk PNG / GIF / WebP container chunks and decode embedded
text + EXIF + XMP metadata. An eXIf / EXIF chunk is parsed like a camera
file, so GPS can be recovered from formats that normally show nothing.
"""
from __future__ import annotations

import io
import re
import struct
import zlib
from pathlib import Path
from typing import Any, Dict, List, Tuple

import exifread

from extractor.gps import GPSParser

# Exif chunk payloads may start with the TIFF header directly, or carry an
# "Exif\0\0" prefix. Normalize to the prefix-less form for exifread.
_EXIF_PREFIX = b"Exif\x00\x00"

_GPS_XMP_RE = re.compile(
    r"gps:GPS(?:Latitude|Longitude)>\s*([-+]?\d+(?:\.\d+)?)"
)
_GPS_ATTR_RE = re.compile(
    r"(?:exif:)?gps:(?:GPSLatitude|GPSLongitude)=\s*([-+]?\d+(?:\.\d+)?)"
)


class ChunkMiner:
    """Mine PNG / GIF / WebP container chunks for residual metadata."""

    def __init__(self) -> None:
        self._gps = GPSParser()

    def analyze(self, file_path: str | Path) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "available": False,
            "format": None,
            "chunks": [],
            "text_metadata": [],
            "exif_tags_present": False,
            "gps": None,
            "xmp_gps_hint": None,
            "errors": [],
        }

        path = Path(file_path)
        try:
            data = path.read_bytes()
        except OSError as e:
            result["errors"].append(f"read error: {e}")
            return result

        if data.startswith(b"\x89PNG\r\n\x1a\n"):
            result["available"] = True
            result["format"] = "PNG"
            self._mine_png(data, result)
        elif data.startswith((b"GIF87a", b"GIF89a")):
            result["available"] = True
            result["format"] = "GIF"
            self._mine_gif(data, result)
        elif data.startswith(b"RIFF") and data[8:12] == b"WEBP":
            result["available"] = True
            result["format"] = "WebP"
            self._mine_webp(data, result)
        else:
            result["errors"].append("unsupported container (only PNG/GIF/WebP)")

        if result["gps"]:
            result["gps"]["source"] = "Chunk"
        return result

    def _mine_png(self, data: bytes, result: Dict[str, Any]) -> None:
        """Walk PNG chunks; decode tEXt/iTXt/zTXt and the eXIf EXIF payload."""
        pos = 8
        n = len(data)
        while pos + 8 <= n:
            length = struct.unpack(">I", data[pos:pos + 4])[0]
            ctype = data[pos + 4:pos + 8]
            if pos + 12 + length > n:
                break
            payload = data[pos + 8:pos + 8 + length]
            result["chunks"].append({
                "type": ctype.decode("latin-1", errors="replace"),
                "length": length,
            })

            if ctype == b"tEXt" and b"\x00" in payload:
                key, _, value = payload.partition(b"\x00")
                self._add_text(result, key, value, "latin-1")
            elif ctype == b"iTXt" and b"\x00" in payload:
                key, rest = payload.split(b"\x00", 1)
                self._parse_itxt(result, key, rest)
            elif ctype == b"zTXt" and b"\x00" in payload:
                key, rest = payload.split(b"\x00", 1)
                if len(rest) >= 1:
                    self._add_text(result, key, rest[1:], "zlib")
            elif ctype == b"eXIf":
                result["exif_tags_present"] = True
                exif_bytes = payload
                if exif_bytes.startswith(_EXIF_PREFIX):
                    exif_bytes = exif_bytes[6:]
                self._parse_exif(result, exif_bytes)
            elif ctype == b"tIME" and len(payload) >= 7:
                y = (payload[0] << 8) | payload[1]
                self._add_text(result, "tIME", f"{y:04d}-{payload[2]:02d}-"
                                             f"{payload[3]:02d}", "latin-1")

            if ctype == b"IEND":
                break
            pos += 12 + length

    def _parse_itxt(self, result: Dict[str, Any], key: bytes, rest: bytes) -> None:
        """iTXt: keyword\0 flags(1) method(1) lang\0 translated\0 text."""
        if len(rest) < 4:
            return
        compression_flag = rest[0]
        compression_method = rest[1]
        tail = rest[2:]
        parts = tail.split(b"\x00", 2)
        if len(parts) < 3:
            return
        text_bytes = parts[2]
        try:
            if compression_flag == 1 and compression_method == 0:
                text_bytes = zlib.decompress(text_bytes)
            else:
                # Some writers (Pillow) put UTF-8 text without a null
                # terminator; interpret as UTF-8.
                pass
            self._add_text(result, key, text_bytes, "utf-8")
        except zlib.error:
            self._add_text(result, key, text_bytes, "utf-8")

    def _mine_gif(self, data: bytes, result: Dict[str, Any]) -> None:
        """GIF: walk blocks after the header; grab comment extensions (0xFE)
        and application extensions (0xFF)."""
        pos = 6
        n = len(data)
        # Logical screen descriptor
        if pos + 7 > n:
            return
        packed = data[pos + 4]
        pos += 7
        if packed & 0x80:  # global color table
            pos += 3 * (2 ** ((packed & 0x07) + 1))

        while pos < n:
            if data[pos] == 0x3B:  # trailer
                break
            if data[pos] == 0x21:  # extension
                label = data[pos + 1]
                pos += 2
                chunks, pos = self._read_gif_subblocks(data, pos)
                if label == 0xFE and chunks:
                    result["chunks"].append({"type": "Comment", "length": sum(
                        len(c) for c in chunks)})
                    self._add_text(result, b"Comment", b"".join(chunks), "latin-1")
                elif label == 0xFF and chunks:
                    app_id = chunks[0][:8].decode("latin-1", errors="replace")
                    result["chunks"].append({"type": f"App:{app_id}",
                                             "length": sum(len(c) for c in chunks)})
                else:
                    result["chunks"].append({"type": f"Ext:{label:02X}", "length": sum(
                        len(c) for c in chunks)})
            elif data[pos] == 0x2C:  # image descriptor
                result["chunks"].append({"type": "Image", "length": 0})
                pos += 9
                lzw = data[pos] if pos < n else 0
                pos += 1 + lzw
            else:
                pos += 1

    def _read_gif_subblocks(self, data: bytes, pos: int) -> Tuple[List[bytes], int]:
        chunks: List[bytes] = []
        n = len(data)
        while pos < n:
            size = data[pos]
            pos += 1
            if size == 0:
                break
            if pos + size > n:
                break
            chunks.append(data[pos:pos + size])
            pos += size
        return chunks, pos

    def _mine_webp(self, data: bytes, result: Dict[str, Any]) -> None:
        """Walk RIFF chunks; grab EXIF, XMP and ICCP payloads."""
        pos = 12
        n = len(data)
        while pos + 8 <= n:
            ctype = data[pos:pos + 4]
            size = struct.unpack("<I", data[pos + 4:pos + 8])[0]
            if pos + 8 + size > n:
                break
            payload = data[pos + 8:pos + 8 + size]
            result["chunks"].append({
                "type": ctype.decode("latin-1", errors="replace"),
                "length": size,
            })
            if ctype == b"EXIF":
                result["exif_tags_present"] = True
                exif_bytes = payload
                if exif_bytes.startswith(_EXIF_PREFIX):
                    exif_bytes = exif_bytes[6:]
                if exif_bytes and (exif_bytes[0:2] in (b"MM", b"II")):
                    self._parse_exif(result, exif_bytes)
            elif ctype == b"XMP ":
                self._parse_xmp(result, payload)
            pos += 8 + size + (size & 1)  # RIFF pads odd sizes

    def _parse_exif(self, result: Dict[str, Any], exif_bytes: bytes) -> None:
        """Parse a raw EXIF blob (TIFF header) and extract GPS coordinates."""
        try:
            tags = exifread.process_file(
                io.BytesIO(exif_bytes), details=True, strict=False, debug=False
            )
        except Exception as e:
            result["errors"].append(f"exif chunk parse error: {e}")
            return
        if not tags:
            return
        gps = self._gps.parse(tags)
        if gps.get("available") or gps.get("zero_placeholder"):
            result["gps"] = gps

    def _parse_xmp(self, result: Dict[str, Any], payload: bytes) -> None:
        """Scan an XMP packet for GPS tags (numeric decimal form)."""
        try:
            text = payload.decode("utf-8", errors="replace")
        except Exception:
            return
        lat = lon = None
        for m in _GPS_XMP_RE.finditer(text):
            if lat is None and "Latitude" in m.group(0):
                lat = _to_float(m.group(1))
            elif lon is None and "Longitude" in m.group(0):
                lon = _to_float(m.group(1))
        if lat is None or lon is None:
            for m in _GPS_ATTR_RE.finditer(text):
                if "Latitude" in m.group(0):
                    lat = _to_float(m.group(1))
                elif "Longitude" in m.group(0):
                    lon = _to_float(m.group(1))
        if lat is None or lon is None:
            return
        # XMP coords are already decimal degrees.
        result["xmp_gps_hint"] = f"{lat:.7f}, {lon:.7f}"
        self._gps = self._gps

    def _add_text(self, result: Dict[str, Any], key: bytes, value: bytes,
                  encoding: str) -> None:
        """Add a decoded text chunk, deduped by (key, value)."""
        try:
            if encoding == "zlib":
                value = zlib.decompress(value)
                text_encoding = "latin-1"
            elif encoding == "latin-1":
                text_encoding = "latin-1"
            else:
                text_encoding = "utf-8"
        except zlib.error:
            return
        text = value.decode(text_encoding, errors="replace").strip()
        if not text:
            return
        for existing in result["text_metadata"]:
            if existing["key"] == key.decode("latin-1", errors="replace") and \
                    existing["value"] == text[:400]:
                return
        result["text_metadata"].append({
            "key": key.decode("latin-1", errors="replace"),
            "value": text[:400],
        })


def _to_float(value: str):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None