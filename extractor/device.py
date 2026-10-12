"""
Device identification from EXIF metadata.

Fully pattern-driven and extensible:
- Raw Make/Model values are ALWAYS preserved and reported (catches ANY device,
  including brand-new models never seen before).
- Brand / device-type detection uses regex prefix patterns, so a hypothetical
  "iPhone 99" or "SM-Z999" is classified without a database entry.
- An optional editable JSON file (device_db.json beside this module, or passed
  explicitly) can enrich results with friendly names and release years.
- OS / platform detection from the Software tag.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# Regex-based brand recognition. Order matters: first match wins.
# A device that is NOT listed here still works: raw Make/Model are reported
# verbatim, just without classification.
BRAND_PATTERNS: List[Tuple[str, str, str]] = [
    # Smartphone brands (prefix patterns catch every future model)
    (r"^iPhone", "Apple", "Smartphone"),
    (r"^iPad", "Apple", "Tablet"),
    (r"^iPod touch", "Apple", "Tablet"),
    (r"^SM-[A-Z]", "Samsung", "Smartphone"),        # Galaxy / any Samsung
    (r"^GT-[A-Z]", "Samsung", "Smartphone"),
    (r"^SC-[A-Z]", "Samsung", "Smartphone"),
    (r"^SH-[A-Z]", "Samsung", "Smartphone"),
    (r"^SPH-", "Samsung", "Smartphone"),
    (r"^Galaxy", "Samsung", "Smartphone"),
    (r"^Pixel", "Google", "Smartphone"),             # all Pixel generations
    (r"^Nexus", "Google", "Smartphone"),
    (r"^Redmi", "Xiaomi", "Smartphone"),
    (r"^POCO", "Xiaomi", "Smartphone"),
    (r"^Mi\s", "Xiaomi", "Smartphone"),
    (r"^M[0-9]{3}[A-Z0-9]*", "Xiaomi", "Smartphone"),  # Mi 11, M2007J3SG etc.
    (r"^22[0-9]{2}", "Xiaomi", "Smartphone"),        # Redmi model codes 2201xxx
    (r"^HUAWEI", "Huawei", "Smartphone"),
    (r"^HONOR", "Honor", "Smartphone"),
    (r"^CPH[0-9]{4}", "Oppo", "Smartphone"),
    (r"^RMX[0-9]{4}", "Realme", "Smartphone"),
    (r"^IN[0-9]{4}", "OnePlus", "Smartphone"),
    (r"^KB[0-9]{4}", "OnePlus", "Smartphone"),
    (r"^LE[0-9]{4}", "OnePlus", "Smartphone"),
    (r"^NE[0-9]{4}", "OnePlus", "Smartphone"),
    (r"^PHK[0-9]{3}", "OnePlus", "Smartphone"),
    (r"^V[0-9]{4}", "Vivo", "Smartphone"),
    (r"^I[0-9]{4}", "Vivo", "Smartphone"),
    (r"^LM-[A-Z]", "LG", "Smartphone"),
    (r"^LG-[A-Z]", "LG", "Smartphone"),
    (r"^XT[0-9]{4}", "Motorola", "Smartphone"),
    (r"^Moto", "Motorola", "Smartphone"),
    (r"^motorola", "Motorola", "Smartphone"),
    (r"^Nokia", "Nokia", "Smartphone"),
    (r"^ASUS", "Asus", "Smartphone"),
    (r"^ZTE", "ZTE", "Smartphone"),
    (r"^Lenovo", "Lenovo", "Smartphone"),
    (r"^TECNO", "Tecno", "Smartphone"),
    (r"^Infinix", "Infinix", "Smartphone"),
    (r"^itel", "Itel", "Smartphone"),
    (r"^Razer", "Razer", "Smartphone"),
    (r"^Nothing", "Nothing", "Smartphone"),
    (r"^BlackBerry", "BlackBerry", "Smartphone"),
    (r"^Sony Ericsson", "Sony Ericsson", "Smartphone"),
    (r"^Sony", "Sony", "Smartphone"),
    (r"^Ericsson", "Ericsson", "Smartphone"),
    (r"^LGE", "LG", "Smartphone"),
    # Cameras (prefix patterns catch all current + future bodies)
    (r"^Canon", "Canon", "Camera"),
    (r"^NIKON", "Nikon", "Camera"),
    (r"^Nikon", "Nikon", "Camera"),
    (r"^ILCE-", "Sony", "Camera"),          # Alpha mirrorless
    (r"^DSC-", "Sony", "Camera"),           # Cyber-shot
    (r"^SLT-", "Sony", "Camera"),           # Alpha SLT
    (r"^FUJIFILM", "Fujifilm", "Camera"),
    (r"^Panasonic", "Panasonic", "Camera"),
    (r"^DMC-", "Panasonic", "Camera"),
    (r"^DC-", "Panasonic", "Camera"),
    (r"^OLYMPUS", "Olympus", "Camera"),
    (r"^PENTAX", "Pentax", "Camera"),
    (r"^LEICA", "Leica", "Camera"),
    (r"^RICOH", "Ricoh", "Camera"),
    (r"^KODAK", "Kodak", "Camera"),
    (r"^Hasselblad", "Hasselblad", "Camera"),
    (r"^Phase One", "Phase One", "Camera"),
    (r"^Sigma", "Sigma", "Camera"),
    (r"^Yashica", "Yashica", "Camera"),
    (r"^CASIO", "Casio", "Camera"),
    (r"^Minolta", "Minolta", "Camera"),
    (r"^Konica", "Konica", "Camera"),
    (r"^Polaroid", "Polaroid", "Camera"),
    # Action cameras / drones / webcams
    (r"^GoPro", "GoPro", "Action Camera"),
    (r"^DJI", "DJI", "Drone"),
    (r"^FC[0-9]{4}", "DJI", "Drone"),       # DJI camera modules (FC3582 etc.)
    (r"^Logitech", "Logitech", "Webcam"),
    (r"^Microsoft LifeCam", "Microsoft", "Webcam"),
]


SOFTWARE_PATTERNS: List[Tuple[str, str]] = [
    (r"Android\s*[0-9.]*", "Android"),
    (r"Android", "Android"),
    (r"Windows\s*(Phone|Mobile)?\s*[0-9.]*", "Windows"),
    (r"iOS\s*[0-9._]*", "iOS"),
    (r"iPhone OS\s*[0-9._]*", "iOS"),
    (r"macOS\s*[0-9._]*", "macOS"),
    (r"Mac OS X\s*[0-9._]*", "macOS"),
    (r"Linux", "Linux"),
    (r"ChromeOS", "ChromeOS"),
    (r"MIUI", "MIUI"),
    (r"ColorOS", "ColorOS"),
    (r"OxygenOS", "OxygenOS"),
    (r"EMUI", "EMUI"),
    (r"HarmonyOS", "HarmonyOS"),
    (r"One UI", "One UI"),
    (r"iPadOS", "iPadOS"),
]


class DeviceIdentifier:
    """Identify the device that captured an image.

    The design is fully extensible:
    - Raw Make/Model are always returned verbatim.
    - Brand / device type come from regex prefix patterns (future-proof).
    - An optional JSON enrichment file can add friendly names / release years.
    """

    def __init__(self, enrichment_db: Optional[str | Path] = None):
        self._patterns = BRAND_PATTERNS
        self._enrichment: Dict[str, Dict[str, Any]] = {}
        if enrichment_db is None:
            # Look for device_db.json next to this module
            default_db = Path(__file__).parent / "device_db.json"
            if default_db.exists():
                enrichment_db = default_db
        if enrichment_db:
            self._load_enrichment(enrichment_db)

    def _load_enrichment(self, path: str | Path) -> None:
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                # Normalize keys to lowercase for case-insensitive lookup
                self._enrichment = {str(k).lower(): v for k, v in data.items()}
        except (OSError, json.JSONDecodeError):
            self._enrichment = {}  # Never crash on a bad enrichment file

    def identify(self, tags: Dict[str, Any], result: Any = None) -> Dict[str, Any]:
        """Extract device/camera information from EXIF tags."""
        make = self._clean(str(tags.get("Image Make", "")))
        model = self._clean(str(tags.get("Image Model", "")))
        software = self._clean(str(tags.get("Image Software", "")))

        info: Dict[str, Any] = {
            "make": make or None,
            "model": model or None,
            "model_name": None,
            "brand": None,
            "device_type": None,
            "software": software or None,
        }

        # 1. Brand + device type via regex (works for ANY device)
        brand, device_type = self._classify(make, model)
        if brand:
            info["brand"] = brand
        if device_type:
            info["device_type"] = device_type

        # 2. OS detection from Software tag
        if software:
            os_name = self._detect_os(software)
            if os_name:
                info["os"] = os_name

        # 3. Enrichment database lookup (best-effort, never overrides raw)
        self._apply_enrichment(info, make, model)

        # 4. Lens info
        lens_model = self._clean(str(tags.get("EXIF LensModel", "")))
        lens_make = self._clean(str(tags.get("EXIF LensMake", "")))
        if lens_model:
            info["lens_model"] = lens_model
        if lens_make:
            info["lens_make"] = lens_make

        # 5. Serial / unique IDs (valuable cross-referencing data)
        for tag_name, label in (
            ("Image ImageUniqueID", "image_unique_id"),
            ("EXIF BodySerialNumber", "body_serial"),
            ("EXIF SerialNumber", "serial_number"),
        ):
            val = self._clean(str(tags.get(tag_name, "")))
            if val and val != "None":
                info[label] = val

        return info

    def _classify(self, make: str, model: str) -> Tuple[Optional[str], Optional[str]]:
        """Classify brand + device type using regex patterns (case-insensitive)."""
        # Try model first (model codes are often more specific than make)
        for target in (model, make, f"{make} {model}"):
            if not target:
                continue
            for pattern, brand, dev_type in self._patterns:
                if re.match(pattern, target, re.IGNORECASE):
                    return brand, dev_type
        return None, None

    def _detect_os(self, software: str) -> Optional[str]:
        """Detect OS/platform from the Software tag."""
        for pattern, os_name in SOFTWARE_PATTERNS:
            if re.search(pattern, software, re.IGNORECASE):
                m = re.search(pattern, software, re.IGNORECASE)
                if m and m.group(0).strip().lower() in (os_name.lower(),):
                    return os_name
                if m:
                    return m.group(0).strip()
                return os_name
        return None

    def _apply_enrichment(self, info: Dict[str, Any], make: str, model: str) -> None:
        """Apply optional enrichment data without overriding raw values."""
        if not self._enrichment:
            return

        # Try full model, then make, then make+model combos
        candidates = []
        if model:
            candidates.append(model)
        if make:
            candidates.append(make)
        if make and model:
            candidates.append(f"{make} {model}")

        for key in candidates:
            entry = self._enrichment.get(key.lower())
            if not entry:
                continue
            if entry.get("model_name") and not info["model_name"]:
                info["model_name"] = entry["model_name"]
            if entry.get("brand") and not info["brand"]:
                info["brand"] = entry["brand"]
            if entry.get("device_type") and not info["device_type"]:
                info["device_type"] = entry["device_type"]
            if entry.get("year") and not info.get("year"):
                info["year"] = entry["year"]
            break

    @staticmethod
    def _clean(value: str) -> str:
        """Strip EXIF type noise (e.g. 'NIKON CORPORATION', byte arrays)."""
        if not value or value in ("None", "nan"):
            return ""
        value = value.replace("\x00", "").strip()
        # Some cameras report make as the full company name; keep as-is,
        # classification handles it.
        return value
