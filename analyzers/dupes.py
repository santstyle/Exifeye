"""
Near-Duplicate Hunter: group byte-identical (md5) and perceptually similar
(phash) images, and rank which copy is the most original
(GPS / resolution / timestamps / embedded thumbnail).
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Dict, List

import exifread
import imagehash
from PIL import Image

# Perceptual hashes within this Hamming distance are considered the same
# picture (re-encoded / resized copies).
_PHASH_THRESHOLD = 8

_SUPPORTED = {
    ".jpg", ".jpeg", ".jfif", ".png", ".gif", ".webp", ".bmp",
    ".tiff", ".tif",
}


class DupHunter:
    """Group exact + near-duplicate images and score originality."""

    def analyze(self, paths: List[str | Path]) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "analyzed": 0,
            "exact_groups": [],
            "near_groups": [],
            "scores": {},
            "errors": [],
        }

        entries: List[Dict[str, Any]] = []
        for raw in paths:
            path = Path(raw)
            try:
                entry = self._entry(path)
            except OSError as e:
                result["errors"].append(f"{path.name}: {e}")
                continue
            if entry is None:
                result["errors"].append(f"{path.name}: not a supported image")
                continue
            entries.append(entry)
            result["analyzed"] += 1

        # md5 exact groups
        by_md5: Dict[str, List[Dict[str, Any]]] = {}
        for entry in entries:
            by_md5.setdefault(entry["md5"], []).append(entry)
        for digest, group in by_md5.items():
            if len(group) >= 2:
                result["exact_groups"].append({
                    "hash": digest,
                    "count": len(group),
                    "files": [e["name"] for e in group],
                })

        # phash near groups: greedy clustering against each cluster's head
        phash_entries = [e for e in entries if e["phash"] is not None]
        clusters: List[List[Dict[str, Any]]] = []
        for entry in phash_entries:
            placed = False
            for cluster in clusters:
                if self._hamming(cluster[0]["phash"], entry["phash"]) <= _PHASH_THRESHOLD:
                    cluster.append(entry)
                    placed = True
                    break
            if not placed:
                clusters.append([entry])

        for cluster in clusters:
            if len(cluster) < 2:
                continue
            ranked = sorted(cluster,
                            key=lambda e: (e["originality"], e["dims_px"]),
                            reverse=True)
            result["near_groups"].append({
                "phash": str(cluster[0]["phash"]),
                "count": len(cluster),
                "best": ranked[0]["name"],
                "best_score": ranked[0]["originality"],
                "files": [e["name"] for e in ranked],
            })

        for entry in entries:
            result["scores"][entry["name"]] = {
                "score": entry["originality"],
                "reasons": entry["score_reasons"],
            }

        return result

    @staticmethod
    def _hamming(a, b) -> int:
        """Hamming distance between two imagehash hashes (bitwise XOR popcount)."""
        return bin(int(str(a), 16) ^ int(str(b), 16)).count("1")

    def _entry(self, path: Path) -> Dict[str, Any] | None:
        """Build a compare entry for one image; None for non-images/errors."""
        if path.suffix.lower() not in _SUPPORTED:
            return None

        md5 = hashlib.md5(path.read_bytes()).hexdigest()
        phash = None
        dims = (0, 0)

        try:
            with Image.open(path) as img:
                dims = img.size
                phash = imagehash.phash(img)
        except Exception:
            pass

        score = 0
        reasons: List[str] = []
        try:
            with open(path, "rb") as f:
                tags = exifread.process_file(
                    f, details=True, strict=False, debug=False
                )
            if any(str(k).startswith("GPS GPSLatitude") for k in tags):
                score += 4
                reasons.append("GPS coordinates embedded")
            if "Image Make" in tags or "Image Model" in tags:
                score += 2
                reasons.append("camera identity (Make/Model)")
            if "EXIF DateTimeOriginal" in tags or "EXIF DateTimeDigitized" in tags:
                score += 1
                reasons.append("capture timestamp")
            if "Thumbnail JPEGInterchangeFormat" in tags:
                score += 1
                reasons.append("embedded thumbnail present")
        except Exception:
            pass

        if dims[0] and dims[1]:
            score += 1
            reasons.append(f"resolution {dims[0]}x{dims[1]}")

        return {
            "path": str(path),
            "name": path.name,
            "md5": md5,
            "phash": phash,
            "dims_px": dims[0] * dims[1],
            "originality": min(score, 10),
            "score_reasons": reasons,
        }