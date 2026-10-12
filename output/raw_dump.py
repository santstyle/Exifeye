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
