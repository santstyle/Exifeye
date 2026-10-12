"""
JSON export for metadata reports.
"""
from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict


class JSONExport:
    """Export extraction results to a JSON file."""

    def export(
        self,
        result: Any,
        forensics: Dict[str, Any],
        deep: Dict[str, Any],
        hashes: Dict[str, Any],
        output_dir: str | Path | None = None,
        filename: str | None = None,
        extra: Dict[str, Any] | None = None,
    ) -> Path:
        """Write the full report as JSON and return the output file path."""
        output_dir = Path(output_dir) if output_dir else result.file_path.parent
        output_dir.mkdir(parents=True, exist_ok=True)

        if filename is None:
            base = Path(result.file_path).stem
            filename = f"{base}_metadata_report.json"

        # Sanitize output filename: block path traversal via crafted file
        # names (e.g. "..\\evil.jpg" on POSIX where '\\' is a valid char).
        safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", filename).strip("._") or "report"
        output_path = output_dir / safe_name

        report = {
            "report_generated": datetime.now().isoformat(),
            "file": {
                "path": result.file_path,
                "name": result.file_name,
                "size_bytes": result.file_size,
                "type": result.file_type,
                "mime_type": result.mime_type,
                "dimensions": list(result.dimensions) if result.dimensions else None,
                "color_mode": result.mode,
                "dpi": list(result.dpi) if result.dpi else None,
                "orientation": result.orientation,
                "icc_profile": result.icc_profile,
                "embedded_thumbnail": result.has_embedded_thumbnail,
                "thumbnail_size": list(result.thumbnail_size) if result.thumbnail_size else None,
            },
            "device": result.device,
            "gps": result.gps,
            "timestamps": result.timestamps,
            "exif": result.exif_data,
            "social_media_forensics": forensics,
            "hashes": hashes,
            "deep_forensics": deep,
            # v2.0 / v2.1 analyzer outputs (each key only present when the
            # corresponding analyzer actually ran for this file).
            "thumbnail_recovery": (extra or {}).get("thumbnail"),
            "jpeg_structure": (extra or {}).get("jpeg_structure"),
            "meta_chunks": (extra or {}).get("chunks"),
            "embedded_strings": (extra or {}).get("strings"),
            "authentication_risk": (extra or {}).get("auth_risk"),
            "gps_spoof_check": (extra or {}).get("gps_spoof"),
            "timestamp_check": (extra or {}).get("timestamp_check"),
            "filename_origin": (extra or {}).get("filename_origin"),
            "ai_generated_check": (extra or {}).get("ai_generated"),
            "trailing_data": (extra or {}).get("trailing"),
            "panorama_detection": (extra or {}).get("panorama"),
            "errors": result.errors,
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        return output_path