"""AI-generation & C2PA provenance detection.

Two cheap signal classes, both honest about what they prove:

1. Digital source type strings (IPTC/C2PA) in the raw bytes - an
   explicit ``trainedAlgorithmicMedia`` / ``compositelyGenerated`` claim.
2. Generator names (Midjourney, Stable Diffusion, ...) in attribution
   fields (Software / CreatorTool / UserComment) or, as a weaker
   context-unverified signal, anywhere in the raw bytes - PNG tEXt and
   PDF metadata streams are uncompressed, so the bytes carry them too.

C2PA manifests without an AI source type are reported as provenance
only: a manifest is not proof of AI, and its absence is not proof of
human authorship. C2PA signatures are NOT verified (cryptography is not
a dependency) - this is detection, not validation.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional, Union

# Head+tail window: C2PA writes JUMBF both near the start (APP11) and as
# a trailer after the image data, so one window alone can miss it.
_SCAN_WINDOW = 1024 * 1024

# Case-SENSITIVE byte markers: JUMBF brand, C2PA manifest labels, the
# PNG CA-BX box, and Adobe's Content Credentials string. The trailing
# dot on "c2pa." (claim/actions/assertions) keeps a random 4-byte
# collision in compressed data from reading as a manifest.
_C2PA_MARKERS = (
    b"jumbf",
    b"c2pa.",
    b"ContentCredentials",
    b"caBX",
)

# IPTC/C2PA digital source types - explicit declarations (case-insensitive).
_AI_SOURCE_TYPES: Dict[bytes, tuple] = {
    b"trainedalgorithmicmedia": (
        "high", "declares trained algorithmic media (AI-generated)"),
    b"compositelygenerated": (
        "medium", "declares composite generation (AI-assisted edit)"),
}

# Generator names, matched lowercase. Only compared against attribution
# fields (below) or the lowered raw bytes - never free-text descriptions,
# because "imagen" / "parti" are ordinary Spanish / French words there.
_GENERATORS = (
    "midjourney", "dall\u00b7e", "dall-e", "dalle", "stable diffusion",
    "stablediffusion", "sdxl", "comfyui", "automatic1111", "fooocus",
    "novelai", "firefly", "leonardo.ai", "leonardo", "chatgpt", "openai",
    "gpt-image", "gptimage", "imagen", "parti", "runwayml", "synthid",
    "waifu diffusion", "bing image creator", "microsoft designer",
)

# EXIF/XMP key fragments that mark attribution fields (case-insensitive
# substring check on the tag name).
_ATTRIB_KEYS = ("software", "comment", "creatortool", "processingsoftware")

_RANK = {"low": 0, "medium": 1, "high": 2}


def _bump(current: Optional[str], new: str) -> str:
    """Keep the strongest confidence seen so far."""
    if current is None or _RANK[new] > _RANK[current]:
        return new
    return current


class AiGeneratedDetector:
    """Detect AI-generator attribution and C2PA provenance markers."""

    def analyze(
        self,
        file_path: Union[str, Path],
        exif_data: Optional[Dict[str, Any]] = None,
        xmp_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return {available, detected, confidence, c2pa, signals, verdict}."""
        path = Path(file_path)
        try:
            size = path.stat().st_size
            with open(path, "rb") as f:
                if size <= 2 * _SCAN_WINDOW:
                    blob = f.read()
                else:
                    head = f.read(_SCAN_WINDOW)
                    f.seek(size - _SCAN_WINDOW)
                    blob = head + f.read(_SCAN_WINDOW)
        except OSError:
            return {"available": False, "detected": False, "confidence": None,
                    "c2pa": False, "signals": [],
                    "verdict": "file could not be read"}

        blob_low = blob.lower()
        signals = []

        # 1. C2PA / JUMBF presence (case-sensitive markers).
        c2pa_hits = [m.decode("ascii") for m in _C2PA_MARKERS if m in blob]
        c2pa = bool(c2pa_hits)
        if c2pa:
            signals.append(
                "C2PA/JUMBF marker(s) in bytes: " + ", ".join(c2pa_hits))

        # 2. AI digital source types (explicit declaration).
        conf: Optional[str] = None
        for marker, (level, desc) in _AI_SOURCE_TYPES.items():
            if marker in blob_low:
                signals.append(
                    f"digital source type {marker.decode('ascii')}: {desc}")
                conf = _bump(conf, level)

        # 3. Generator names in attribution fields -> strong signal.
        field_hits: Dict[str, str] = {}

        def attrib(text: str, where: str) -> None:
            low = text.lower()
            for name in _GENERATORS:
                if name in low and name not in field_hits:
                    field_hits[name] = where

        for tags in (exif_data or {}).values():
            if not isinstance(tags, dict):
                continue
            for key, val in tags.items():
                if isinstance(val, str) and any(
                        a in str(key).lower() for a in _ATTRIB_KEYS):
                    attrib(val, f"'{key}' field")

        for key, val in _flatten(xmp_data or {}).items():
            if isinstance(val, str) and any(
                    a in key.lower() for a in _ATTRIB_KEYS):
                attrib(val, f"XMP '{key}'")

        for name, where in field_hits.items():
            signals.append(f"generator name '{name}' in {where}")
            conf = _bump(conf, "high")

        # 4. Generator names in raw bytes (PNG tEXt / PDF metadata are
        #    uncompressed) - context unverified, so medium at best.
        for name in _GENERATORS:
            if name in field_hits:
                continue
            if name.encode("utf-8") in blob_low:
                signals.append(
                    f"generator name '{name}' in raw metadata bytes "
                    "(context not verified)")
                conf = _bump(conf, "medium")

        detected = conf is not None
        if detected:
            verdict = (f"AI involvement marker found ({conf} confidence) - "
                       "metadata attribution, not verified provenance")
        elif c2pa:
            verdict = ("C2PA manifest present - provenance recorded, "
                       "no AI source-type claim found")
        else:
            verdict = ("no AI markers found in metadata - not proof of "
                       "human authorship")

        return {"available": True, "detected": detected, "confidence": conf,
                "c2pa": c2pa, "signals": signals, "verdict": verdict}


def _flatten(data: Any, prefix: str = "") -> Dict[str, Any]:
    """Flatten nested XMP dicts/lists into {'a:b:c': 'value'} pairs."""
    out: Dict[str, Any] = {}
    if isinstance(data, dict):
        for k, v in data.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            out.update(_flatten(v, key))
    elif isinstance(data, (list, tuple)):
        for i, v in enumerate(data):
            out.update(_flatten(v, f"{prefix}[{i}]"))
    else:
        out[prefix] = data
    return out
