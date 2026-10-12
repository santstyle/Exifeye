"""
File hashing utilities: MD5, SHA1, SHA256, and perceptual hash.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Dict, Optional


class HashCalculator:
    """Compute cryptographic and perceptual hashes for image files."""

    def __init__(self):
        self._phash = None
        try:
            import imagehash
            self._phash = imagehash
        except ImportError:
            self._phash = None

    def compute_all(self, file_path: str | Path) -> Dict[str, str]:
        """Compute MD5, SHA1, SHA256 and perceptual hashes."""
        path = Path(file_path)
        hashes: Dict[str, str] = {}

        hashes.update(self._compute_crypto_hashes(path))
        hashes.update(self._compute_perceptual_hash(path))

        return hashes

    def _compute_crypto_hashes(self, path: Path) -> Dict[str, str]:
        """Compute MD5, SHA1, SHA256 in one pass."""
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()

        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)

        return {
            "md5": md5.hexdigest(),
            "sha1": sha1.hexdigest(),
            "sha256": sha256.hexdigest(),
        }

    def _compute_perceptual_hash(self, path: Path) -> Dict[str, str]:
        """Compute perceptual hash if imagehash available."""
        if self._phash is None:
            return {}

        try:
            phash = self._phash.phash(path)
            dhash = self._phash.dhash(path)
            ahash = self._phash.average_hash(path)
            return {
                "perceptual_hash": str(phash),
                "difference_hash": str(dhash),
                "average_hash": str(ahash),
            }
        except Exception:
            return {}