"""360-degree / panorama image detection via XMP GPano markers, projection
type, and known 360-camera device hints. Cheap: one 512 KB head-read of the
raw file plus the already-parsed XMP dict - no re-encoding, no network.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Union

# Google Photo Sphere XMP namespace + well-known GPano property names.
# The namespace alone is a strong photosphere fingerprint; the property
# names survive even when Pillow drops the XMP block from parsed metadata.
_GPANO_MARKERS = (
    b"http://ns.google.com/photos/1.0/panorama",
    b"UsePanoramaViewer",
    b"PoseHeadingDegrees",
    b"FullPanoWidthPixels",
    b"FullPanoHeightPixels",
    b"CroppedAreaImageWidthPixels",
    b"InitialHorizontalFOVDegrees",
)

# Projection-type values that appear in equirectangular / spherical exports.
_PROJECTION_HINTS = (
    b"equirectangular",
    b"spherical",
)

# Device make/model hints for known 360 cameras (lowercased substring match).
_DEVICE_HINTS = (
    "insta360",
    "ricoh theta",
    "theta sc",
    "gopro max",
    "virb 360",
    "panono",
    "360fly",
    "pixii 360",
)


class PanoramaDetector:
    """Detect 360-degree panorama images from XMP + device hints."""

    def analyze(
        self,
        file_path: Union[str, Path],
        xmp_data: Optional[Dict[str, Any]] = None,
        device: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return {available, detected, kind, signals, verdict}."""
        signals: List[str] = []

        # 1. Raw-byte scan of the file head: XMP packets sit near the start
        #    (APP1 / XML chunk), so 512 KB covers every real-world layout.
        head = b""
        try:
            with open(file_path, "rb") as f:
                head = f.read(512 * 1024)
        except OSError:
            pass

        gpano_ns = False
        gpano_props = False
        projection = False
        for marker in _GPANO_MARKERS:
            if marker in head:
                decoded = marker.decode("ascii", "replace")
                if marker.startswith(b"http"):
                    gpano_ns = True
                    signals.append(f"XMP GPano namespace: {decoded}")
                else:
                    gpano_props = True
                    signals.append(f"XMP GPano property: {decoded}")
        for hint in _PROJECTION_HINTS:
            if hint in head:
                projection = True
                signals.append(f"Projection hint: {hint.decode('ascii')}")

        # 2. Parsed XMP dict (when the extractor already pulled it) - catches
        #    XMP that Pillow kept but the byte scan missed (e.g. compressed).
        if isinstance(xmp_data, dict) and xmp_data:
            flat = self._flatten(xmp_data)
            for key, val in flat.items():
                kl = key.lower()
                if "gpano" in kl or "panorama" in kl:
                    signals.append(f"XMP field: {key}={val}")
                elif "projectiontype" in kl:
                    signals.append(f"XMP ProjectionType: {val}")

        # 3. Device hints (known 360 cameras) - weak signal, counted alone.
        device_hit = False
        if device:
            blob = " ".join(
                str(v) for v in device.values() if isinstance(v, (str, int, float))
            ).lower()
            for hint in _DEVICE_HINTS:
                if hint in blob:
                    device_hit = True
                    signals.append(f"Device hint: {hint}")
                    break

        detected = bool(signals)
        if gpano_ns or gpano_props:
            kind = "photosphere"
        elif projection:
            kind = "equirectangular"
        elif device_hit:
            kind = "360-camera"
        else:
            kind = None

        verdict = (
            "Panorama / 360 image detected"
            if detected
            else "Standard photo - no panorama markers"
        )
        return {
            "available": True,
            "detected": detected,
            "kind": kind,
            "signals": signals,
            "verdict": verdict,
        }

    @staticmethod
    def _flatten(data: Any, prefix: str = "") -> Dict[str, Any]:
        """Flatten nested XMP dicts/lists into {'a:b:c': 'value'} pairs."""
        out: Dict[str, Any] = {}
        if isinstance(data, dict):
            for k, v in data.items():
                key = f"{prefix}.{k}" if prefix else str(k)
                out.update(PanoramaDetector._flatten(v, key))
        elif isinstance(data, (list, tuple)):
            for i, v in enumerate(data):
                out.update(PanoramaDetector._flatten(v, f"{prefix}[{i}]"))
        else:
            out[prefix] = data
        return out
