"""Dump every raw EXIF tag exifread can see into a plain-text file.

Used by the CLI --dump-raw flag: a forensic-grade tag inventory (all IFDs,
including MakerNote strings and thumbnail pointers) for offline review or
diffing two copies of the same image.
"""
from __future__ import annotations

from pathlib import Path
from typing import Union

import exifread


class RawTagDumper:
    """Dump all raw EXIF tags to a text file next to the image."""

    def dump(
        self,
        file_path: Union[str, Path],
        output_path: Union[str, Path, None] = None,
    ) -> Path:
        """Write `{stem}_raw_tags.txt` (or output_path) and return its path.

        Raises RuntimeError when the file cannot be read.
        """
        path = Path(file_path)
        out = (
            Path(output_path)
            if output_path is not None
            else path.parent / f"{path.stem}_raw_tags.txt"
        )

        try:
            with open(path, "rb") as f:
                tags = exifread.process_file(f, details=True, debug=False)
        except OSError as e:
            raise RuntimeError(f"cannot read {path.name}: {e}") from e

        lines = [
            f"# ExifEye raw tag dump - {path.name}",
            f"# {len(tags)} tag(s)",
            "",
        ]
        for key in sorted(tags.keys()):
            tag = tags[key]
            try:
                lines.append(f"{key} = {tag}")
            except Exception:
                lines.append(f"{key} = <unreadable>")

        out.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return out

    def dump_result(self, result, file_path) -> Path:
        """Fallback dump for non-images: serialize the ExtractionResult's
        parsed categories (Document/Video tables, timestamps, GPS, flags)
        into the same `<stem>_raw_tags.txt` format, since exifread only
        understands JPEG/TIFF EXIF blocks.

        Returns the written path.
        """
        path = Path(file_path)
        out = path.parent / f"{path.stem}_raw_tags.txt"

        lines = [
            f"# ExifEye raw tag dump - {path.name}",
            "# non-image container: parsed metadata categories below",
            "",
        ]
        for category, tags in (result.exif_data or {}).items():
            lines.append(f"[{category}]")
            if isinstance(tags, dict):
                for key in sorted(tags.keys()):
                    try:
                        lines.append(f"{key} = {tags[key]}")
                    except Exception:
                        lines.append(f"{key} = <unreadable>")
            else:
                lines.append(str(tags))
            lines.append("")

        if result.timestamps:
            lines.append("[Timestamps]")
            for key, value in result.timestamps.items():
                lines.append(f"{key} = {value}")
            lines.append("")

        gps = result.gps or {}
        if gps.get("available"):
            lines.append("[GPS]")
            for key in ("latitude", "longitude", "altitude", "geohash",
                        "google_maps_link", "source"):
                if gps.get(key) is not None:
                    lines.append(f"{key} = {gps[key]}")
            lines.append("")

        if result.flags:
            lines.append("[Flags]")
            for key, value in result.flags.items():
                lines.append(f"{key} = {value}")
            lines.append("")

        if result.errors:
            lines.append("[Errors]")
            lines.extend(f"- {e}" for e in result.errors)
            lines.append("")

        out.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return out
