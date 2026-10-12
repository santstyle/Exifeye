"""
Deep Forensics: ELA (Error Level Analysis), steganography hints, and entropy analysis.
"""
from __future__ import annotations

import io
from pathlib import Path
from typing import Any, Dict

from PIL import Image, ImageChops


class DeepForensics:
    """Advanced image forensics techniques."""

    def __init__(self):
        self._numpy = None
        try:
            import numpy
            self._numpy = numpy
        except ImportError:
            pass

    def run_ela(self, file_path: str | Path, quality: int = 90) -> Dict[str, Any]:
        """Error Level Analysis — detect edited regions in JPEG images."""
        result = {
            "available": False,
            "max_difference": None,
            "mean_difference": None,
            "regions": None,
            "interpretation": None,
        }

        if self._numpy is None:
            return result

        path = Path(file_path)
        try:
            with Image.open(path) as img:
                img = img.convert("RGB")

            # Re-save at specified JPEG quality
            buf = io.BytesIO()
            img.save(buf, format="JPEG", quality=quality)
            buf.seek(0)
            resaved = Image.open(buf).convert("RGB")

            # Compare original vs resaved
            diff = ImageChops.difference(img, resaved)

            # Analyze difference
            arr = self._numpy.asarray(diff)
            max_diff = int(arr.max())
            mean_diff = float(arr.mean())

            # Calculate per-region statistics (8x8 blocks)
            h, w = arr.shape[:2]
            bh, bw = 8, 8
            block_diffs = []
            for y in range(0, h - bh, bh):
                for x in range(0, w - bw, bw):
                    block = arr[y:y+bh, x:x+bw]
                    block_diffs.append(float(block.mean()))

            if not block_diffs:
                return result

            mean_block = sum(block_diffs) / len(block_diffs)
            high_error_blocks = [d for d in block_diffs if d > mean_block * 3]
            ratio = len(high_error_blocks) / len(block_diffs)

            result["available"] = True
            result["max_difference"] = max_diff
            result["mean_difference"] = round(mean_diff, 4)
            result["high_error_region_ratio"] = round(ratio, 4)

            # Interpretation
            if max_diff > 25:
                result["interpretation"] = "REGIONS WITH HIGH ERROR DETECTED — image may have been edited"
            elif max_diff > 10:
                result["interpretation"] = "Moderate error levels — image may have been lightly edited"
            elif max_diff <= 5:
                result["interpretation"] = "Uniform error levels — likely unedited original"
            else:
                result["interpretation"] = "Low error levels — consistent with single-encoding source"

            return result

        except Exception:
            return result

    def check_steganography(self, file_path: str | Path) -> Dict[str, Any]:
        """Check for basic steganography indicators (LSB analysis)."""
        result = {
            "available": False,
            "lsb_entropy": None,
            "anomaly_detected": False,
            "notes": [],
        }

        if self._numpy is None:
            return result

        path = Path(file_path)
        try:
            with Image.open(path) as img:
                img = img.convert("RGB")

            arr = self._numpy.asarray(img)

            # Extract LSB plane
            lsb = arr & 1
            zero_ratio = float((lsb == 0).mean())
            one_ratio = 1.0 - zero_ratio

            # Natural images have ~50% ones in LSB plane
            # Near-0% or near-100% ones suggests hidden data or manipulation
            result["available"] = True
            result["lsb_ones_ratio"] = round(one_ratio, 4)
            result["lsb_zeros_ratio"] = round(zero_ratio, 4)

            # Entropy of LSB plane (simple estimate)
            if one_ratio > 0 and one_ratio < 1:
                entropy = -(one_ratio * self._numpy.log2(one_ratio) +
                            zero_ratio * self._numpy.log2(zero_ratio))
                result["lsb_entropy"] = round(float(entropy), 4)
            else:
                result["lsb_entropy"] = 0.0

            if result["lsb_entropy"] < 0.5:
                result["anomaly_detected"] = True
                result["notes"].append(
                    "Very low LSB entropy — LSB plane is unusually uniform; possible hidden data"
                )

            if abs(one_ratio - 0.5) > 0.1:
                result["notes"].append(
                    f"LSB distribution skewed (ones={one_ratio:.2f}) — not typical of natural photos"
                )

            return result

        except Exception:
            return result

    def analyze_entropy(self, file_path: str | Path) -> Dict[str, Any]:
        """Analyze overall image entropy."""
        result = {"available": False, "entropy": None, "interpretation": None}

        if self._numpy is None:
            return result

        path = Path(file_path)
        try:
            with Image.open(path) as img:
                img = img.convert("L")  # Grayscale

            arr = self._numpy.asarray(img)

            # Full histogram entropy
            hist = self._numpy.histogram(arr, bins=256, range=(0, 256))[0]
            hist = hist[hist > 0]
            probs = hist / hist.sum()
            entropy = float(-(probs * self._numpy.log2(probs)).sum())

            result["available"] = True
            result["entropy"] = round(entropy, 4)

            if entropy > 7.0:
                result["interpretation"] = "Very high entropy — rich detail, likely photo"
            elif entropy > 5.0:
                result["interpretation"] = "Moderate entropy — photo or complex graphic"
            elif entropy > 3.0:
                result["interpretation"] = "Low entropy — likely graphic, screenshot, or flat-colored image"
            else:
                result["interpretation"] = "Very low entropy — flat image, possibly solid color or screenshot"

            return result

        except Exception:
            return result