"""
JPEG Structure: marker inventory, quantization-table quality estimate,
chroma subsampling and comments. A strong fingerprint for re-encoded
platform images (WhatsApp / Instagram / Telegram rebuild the tables).
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

_MAX_READ_BYTES = 16 * 1024 * 1024  # structure lives in the header

# Standard Izuba/independent JPEG Group luminance table for quality 50.
# The scale factor of the file's first DQT table relative to this one maps
# back to the approximate rendering quality the encoder used.
_STD_LUM_Q50 = [
    16, 11, 10, 16, 24, 40, 51, 61,
    12, 12, 14, 19, 26, 58, 60, 55,
    14, 13, 16, 24, 40, 57, 69, 56,
    14, 17, 22, 29, 51, 87, 80, 62,
    18, 22, 37, 56, 68, 109, 103, 77,
    24, 35, 55, 64, 81, 104, 113, 92,
    49, 64, 78, 87, 103, 121, 120, 101,
    72, 92, 95, 98, 112, 100, 103, 99,
]

_SOF_MARKERS = {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA,
                0xCB, 0xCD, 0xCE, 0xCF}


class JpegStructure:
    """Walk JPEG markers and estimate structure, quality and subsampling."""

    def analyze(self, file_path: str | Path) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "available": False,
            "dimensions": None,
            "progressive": False,
            "quality_estimate": None,
            "chroma_subsampling": None,
            "components": None,
            "markers": {
                "app_segments": {},
                "dqt_count": 0,
                "dht_count": 0,
                "sof_count": 0,
                "com_count": 0,
                "dri_count": 0,
            },
            "quantization_tables": [],
            "comments": [],
            "reencoded_hint": False,
            "errors": [],
        }

        path = Path(file_path)
        try:
            with open(path, "rb") as f:
                data = f.read(_MAX_READ_BYTES)
        except OSError as e:
            result["errors"].append(f"read error: {e}")
            return result

        if not data.startswith(b"\xff\xd8"):
            result["errors"].append("not a JPEG (no SOI marker)")
            return result

        markers = result["markers"]
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
            if marker == 0x01 or marker == 0xD9:  # TEM / EOI
                i += 2
                continue
            if 0xD0 <= marker <= 0xD7:  # RSTn
                i += 2
                continue
            if i + 3 >= n:
                break
            seg_len = (data[i + 2] << 8) | data[i + 3]
            if seg_len < 2 or i + 2 + seg_len > n:
                break
            payload = data[i + 4:i + 2 + seg_len]

            if 0xE0 <= marker <= 0xEF:
                app_name = f"APP{marker - 0xE0}"
                markers["app_segments"][app_name] = (
                    markers["app_segments"].get(app_name, 0) + 1
                )
            elif marker == 0xDB:  # DQT
                markers["dqt_count"] += 1
                self._parse_dqt(result, payload)
            elif marker == 0xC4:  # DHT
                markers["dht_count"] += 1
            elif marker in _SOF_MARKERS:
                markers["sof_count"] += 1
                self._parse_sof(result, payload)
                if marker == 0xC2:
                    result["progressive"] = True
            elif marker == 0xFE:  # COM
                markers["com_count"] += 1
                if payload and len(result["comments"]) < 5:
                    comment = payload.decode("utf-8", errors="replace").strip()
                    if comment:
                        result["comments"].append(comment[:200])
            elif marker == 0xDD:  # DRI
                markers["dri_count"] += 1
            elif marker == 0xDA:  # SOS: entropy-coded scan data
                # Skip the scan with the FF00 unstuffing rule.
                i += 2 + seg_len
                while i + 1 < n:
                    if data[i] == 0xFF:
                        if data[i + 1] == 0x00:
                            i += 2
                            continue
                        if data[i + 1] == 0xD9:
                            break
                        if data[i + 1] in (0xD0, 0xD1, 0xD2, 0xD3, 0xD4,
                                           0xD5, 0xD6, 0xD7):
                            i += 2
                            continue
                        # A real marker inside the scan -> stop, allow the
                        # outer loop to handle the next segment.
                        break
                    i += 1
                if i + 1 < n and data[i:i + 2] == b"\xff\xd9":
                    break  # EOI reached, done
                continue

            i += 2 + seg_len

        result["available"] = True
        result["reencoded_hint"] = (
            markers["dqt_count"] >= 4 or markers["sof_count"] > 1
        )
        return result

    def _parse_dqt(self, result: Dict[str, Any], payload: bytes) -> None:
        """Read quantization tables from a DQT segment payload."""
        pos = 0
        while pos + 1 < len(payload):
            info = payload[pos]
            precision = info >> 4
            table_id = info & 0x0F
            size = 64 if precision == 0 else 128
            if pos + 1 + size > len(payload):
                break
            if precision == 0:
                values = list(payload[pos + 1:pos + 1 + 64])
            else:
                values = [
                    (payload[pos + j] << 8) | payload[pos + j + 1]
                    for j in range(1, 129, 2)
                ]
            result["quantization_tables"].append({
                "id": table_id,
                "precision": precision,
                "values": values,
            })
            pos += 1 + size

        # Quality estimate from the FIRST luminance table (id 0), which all
        # JPEGs have. Scale factor in percent vs the standard Q50 luminance
        # row (100% == exactly the Q50 table). Inverse of the common
        # encoder mapping: q <= 50 -> scale = 5000/q, q > 50 -> 200 - 2q.
        lum = next((t for t in result["quantization_tables"]
                    if t["id"] == 0 and len(t["values"]) == 64), None)
        if lum:
            scale_percent = sum(
                100.0 * lum["values"][k] / ref
                for k, ref in enumerate(_STD_LUM_Q50) if ref > 0
            ) / sum(1 for ref in _STD_LUM_Q50 if ref > 0)
            if all(v == 1 for v in lum["values"]):
                quality = 100.0  # all-ones table == quality 100
            elif scale_percent <= 100.0:
                quality = (200.0 - scale_percent) / 2.0
            else:
                quality = 5000.0 / scale_percent
            result["quality_estimate"] = max(1.0, min(100.0, round(quality, 1)))

    def _parse_sof(self, result: Dict[str, Any], payload: bytes) -> None:
        """Read dimensions and chroma subsampling from an SOF segment."""
        if len(payload) < 6:
            return
        height = (payload[1] << 8) | payload[2]
        width = (payload[3] << 8) | payload[4]
        components = payload[5]
        result["components"] = components
        if result["dimensions"] is None:
            result["dimensions"] = [width, height]

        if components == 1:
            result["chroma_subsampling"] = "4:4:4 (grayscale)"
            return
        if len(payload) < 6 + 3 * min(components, 3):
            return
        # Sampling factors: component 0 is luminance (h<<4|v).
        luma = payload[7] if components >= 1 else 0
        chroma = payload[10] if components >= 2 else 0
        luma_h, luma_v = luma >> 4, luma & 0x0F
        chroma_h, chroma_v = chroma >> 4, chroma & 0x0F
        if luma_h == 2 and luma_v == 2 and chroma_h == 1 and chroma_v == 1:
            result["chroma_subsampling"] = "4:2:0"
        elif luma_h == 2 and luma_v == 1 and chroma_h == 1 and chroma_v == 1:
            result["chroma_subsampling"] = "4:2:2"
        elif luma_h == 1 and luma_v == 1 and chroma_h == 1 and chroma_v == 1:
            result["chroma_subsampling"] = "4:4:4"
        elif luma_h == 4 and luma_v == 1 and chroma_h == 1 and chroma_v == 1:
            result["chroma_subsampling"] = "4:1:1"
        else:
            result["chroma_subsampling"] = (
                f"{luma_h}x{luma_v} (chroma {chroma_h}x{chroma_v})"
            )