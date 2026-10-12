"""
Core metadata extraction engine.
Parses EXIF, XMP, IPTC, ICC profile, and embedded thumbnails from image files
using exifread primary and Pillow as fallback.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

import exifread
from PIL import Image

from .gps import GPSParser
from .device import DeviceIdentifier


@dataclass
class ExtractionResult:
    """Container for all extracted metadata from an image."""
    file_path: str
    file_name: str
    file_size: int
    file_type: str
    mime_type: str
    dimensions: tuple[int, int]
    mode: str
    exif_data: Dict[str, Any] = field(default_factory=dict)
    gps: Dict[str, Any] = field(default_factory=dict)
    device: Dict[str, Any] = field(default_factory=dict)
    timestamps: Dict[str, Any] = field(default_factory=dict)
    icc_profile: Optional[str] = None
    dpi: Optional[tuple[int, int]] = None
    has_embedded_thumbnail: bool = False
    thumbnail_size: Optional[tuple[int, int]] = None
    orientation: Optional[str] = None
    software: Optional[str] = None
    artist: Optional[str] = None
    copyright: Optional[str] = None
    xmp_data: Dict[str, Any] = field(default_factory=dict)
    iptc_data: Dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


# Categorization of EXIF tags into human-readable groups
TAG_CATEGORIES = {
    "Image": [
        "Image Make", "Image Model", "Image Orientation", "Image XResolution",
        "Image YResolution", "Image ResolutionUnit", "Image Software",
        "Image DateTime", "Image Artist", "Image Copyright", "Image ImageDescription",
    ],
    "Camera": [
        "EXIF ExposureTime", "EXIF FNumber", "EXIF ExposureProgram",
        "EXIF ISOSpeedRatings", "EXIF ExposureBiasValue", "EXIF MeteringMode",
        "EXIF Flash", "EXIF FocalLength", "EXIF FocalLengthIn35mmFilm",
        "EXIF MaxApertureValue", "EXIF SubjectDistance", "EXIF DigitalZoomRatio",
        "EXIF WhiteBalance", "EXIF SceneCaptureType", "EXIF GainControl",
        "EXIF Contrast", "EXIF Saturation", "EXIF Sharpness", "EXIF SensingMethod",
        "EXIF ColorSpace", "EXIF ExposureMode", "EXIF ExposureCompensation",
        "EXIF ShutterSpeedValue", "EXIF ApertureValue", "EXIF BrightnessValue",
    ],
    "Thumbnail": [
        "Thumbnail Compression", "Thumbnail XResolution", "Thumbnail YResolution",
        "Thumbnail ResolutionUnit", "Thumbnail JPEGInterchangeFormat",
        "Thumbnail JPEGInterchangeFormatLength",
    ],
    "GPS": [
        "GPS GPSLatitudeRef", "GPS GPSLatitude", "GPS GPSLongitudeRef",
        "GPS GPSLongitude", "GPS GPSAltitudeRef", "GPS GPSAltitude",
        "GPS GPSTimeStamp", "GPS GPSSatellites", "GPS GPSStatus",
        "GPS GPSMeasureMode", "GPS GPSDOP", "GPS GPSSpeedRef", "GPS GPSSpeed",
        "GPS GPSTrackRef", "GPS GPSTrack", "GPS GPSImgDirectionRef",
        "GPS GPSImgDirection", "GPS GPSMapDatum", "GPS GPSDestLatitudeRef",
        "GPS GPSDestLatitude", "GPS GPSDestLongitudeRef", "GPS GPSDestLongitude",
        "GPS GPSDestBearingRef", "GPS GPSDestBearing", "GPS GPSDate",
        "GPS GPSProcessingMethod",
    ],
    "Lens": [
        "EXIF LensModel", "EXIF LensMake", "EXIF LensSpecification",
    ],
    "DateTime": [
        "EXIF DateTimeOriginal", "EXIF DateTimeDigitized", "Image DateTime",
        "GPS GPSTimeStamp", "GPS GPSDate",
    ],
}


class MetadataExtractor:
    """Main engine that orchestrates all metadata extraction."""

    def __init__(self, file_path: str | Path):
        self.file_path = Path(file_path)
        self.gps_parser = GPSParser()
        self.device_identifier = DeviceIdentifier()

    def extract(self) -> ExtractionResult:
        """Run full metadata extraction pipeline."""
        result = ExtractionResult(
            file_path=str(self.file_path),
            file_name=self.file_path.name,
            file_size=self.file_path.stat().st_size,
            file_type=self.file_path.suffix.lower().lstrip('.'),
            mime_type=self._guess_mime_type(),
            dimensions=(0, 0),
            mode="",
        )

        try:
            with open(self.file_path, 'rb') as f:
                tags = exifread.process_file(
                    f, details=True, strict=False, debug=False
                )
            if not tags:
                result.errors.append("No EXIF tags found in file.")
        except Exception as e:
            result.errors.append(f"exifread error: {e}")
            tags = {}

        # Parse EXIF data with categorization
        for tag_key, tag_value in tags.items():
            category = self._categorize_tag(tag_key)
            if category:
                result.exif_data.setdefault(category, {})[tag_key] = str(tag_value)

        # Basic image info via Pillow
        self._extract_basic_info(result, tags)

        # GPS Coordinates
        result.gps = self.gps_parser.parse(tags)

        # Pillow fallback: exifread can silently miss the GPS IFD on some
        # files (odd byte order, malformed TIFF offsets) that Pillow still
        # decodes. Reuse the same parser on a normalized GPS tag dict.
        if not result.gps.get("available"):
            self._extract_gps_pillow(result)

        # XMP residual recovery: some pipelines strip the EXIF block but
        # leave an XMP packet behind that still carries GPS coordinates
        # (Google Camera / Photo Sphere GPano, Adobe exif:XMP mappings).
        if not result.gps.get("available"):
            self._extract_xmp_gps(result)

        # Device identification
        result.device = self.device_identifier.identify(tags, result)

        # Timestamps
        result.timestamps = self._extract_timestamps(tags)

        # ICC profile
        self._extract_icc_profile(result)

        # Embedded thumbnail
        self._check_embedded_thumbnail(result, tags)

        # Orientation
        if "Image Orientation" in tags:
            orientation_map = {
                1: "Horizontal (normal)",
                2: "Mirror horizontal",
                3: "Rotate 180",
                4: "Mirror vertical",
                5: "Mirror horizontal and rotate 270 CW",
                6: "Rotate 90 CW",
                7: "Mirror horizontal and rotate 90 CW",
                8: "Rotate 270 CW",
            }
            try:
                val = int(tags["Image Orientation"].values[0])
                result.orientation = orientation_map.get(val, f"Unknown ({val})")
            except (IndexError, TypeError, ValueError):
                result.orientation = str(tags["Image Orientation"])

        if "Image Software" in tags:
            result.software = str(tags["Image Software"])
        if "Image Artist" in tags:
            result.artist = str(tags["Image Artist"])
        if "Image Copyright" in tags:
            result.copyright = str(tags["Image Copyright"])

        return result

    def _extract_gps_pillow(self, result: ExtractionResult) -> None:
        """Recover GPS coordinates via Pillow when exifread misses them.

        exifread occasionally drops the GPS IFD (unusual byte order, broken
        TIFF offsets, vendor quirks). Pillow's own EXIF reader is more
        forgiving, so we normalize its numeric GPS tags into the same shape
        the GPS parser expects and parse again.
        """
        try:
            with Image.open(self.file_path) as img:
                exif = img.getexif()
                gps_ifd = exif.get_ifd(0x8825) if exif else None
        except Exception:
            return
        if not gps_ifd:
            return

        # GPS IFD numeric tag map -> exifread-style names.
        name_map = {
            1: "GPS GPSLatitudeRef",
            2: "GPS GPSLatitude",
            3: "GPS GPSLongitudeRef",
            4: "GPS GPSLongitude",
            5: "GPS GPSAltitudeRef",
            6: "GPS GPSAltitude",
            7: "GPS GPSTimeStamp",
            8: "GPS GPSSatellites",
            29: "GPS GPSDate",
        }

        normalized: Dict[str, Any] = {}
        for tag_id, value in gps_ifd.items():
            name = name_map.get(tag_id)
            if name:
                normalized[name] = value

        if not normalized:
            return

        gps = self.gps_parser.parse(normalized)
        if gps.get("available"):
            result.gps = gps

    def _extract_xmp_gps(self, result: ExtractionResult) -> None:
        """Recover GPS coordinates from XMP residual metadata.

        Some platforms / pipelines remove the EXIF block (APP1/Exif) during
        re-encoding but leave the XMP packet untouched. Google Camera and
        Photo Sphere (GPano) write coordinates there too, so a "stripped"
        file can sometimes still give away its location.
        """
        try:
            with Image.open(self.file_path) as img:
                xmp = img.getxmp()
        except Exception:
            return
        if not xmp:
            return

        lat = lon = alt = None

        def walk(node) -> None:
            nonlocal lat, lon, alt
            if isinstance(node, dict):
                for key, value in node.items():
                    kl = str(key).lower()
                    if isinstance(value, (str, int, float)):
                        if lat is None and "gpslatitude" in kl:
                            lat = self._xmp_num(value)
                        if lon is None and "gpslongitude" in kl:
                            lon = self._xmp_num(value)
                        if alt is None and "gpsaltitude" in kl:
                            alt = self._xmp_num(value)
                    walk(value)
            elif isinstance(node, list):
                for item in node:
                    walk(item)
            elif isinstance(node, (str, int, float)):
                # Flat key=value strings, e.g. GPano FullPanoPoseData parts.
                text = str(node)
                if "latitude" in text.lower() and lat is None:
                    lat = self._xmp_num(text.split("=", 1)[-1])
                elif "longitude" in text.lower() and lon is None:
                    lon = self._xmp_num(text.split("=", 1)[-1])

        walk(xmp)

        if lat is None or lon is None:
            return

        result.gps = {
            "available": True,
            "latitude": lat,
            "longitude": lon,
            "latitude_ref": "N" if lat >= 0 else "S",
            "longitude_ref": "E" if lon >= 0 else "W",
            "source": "XMP",
            "geohash": self.gps_parser._geohash(lat, lon),
            "google_maps_link": self.gps_parser._build_google_maps_link(lat, lon),
        }
        if alt is not None:
            result.gps["altitude_meters"] = alt

    @staticmethod
    def _xmp_num(value) -> Optional[float]:
        """Parse a decimal or rational (num/den) XMP numeric value."""
        if isinstance(value, bool):
            return None
        try:
            return float(value)
        except (TypeError, ValueError):
            text = str(value).strip("/ ").split()[0] if value else ""
            if "/" in text:
                try:
                    num, den = text.split("/", 1)
                    return float(num) / float(den)
                except (ValueError, ZeroDivisionError):
                    return None
            return None

    def _extract_basic_info(self, result: ExtractionResult, tags: Dict[str, Any]) -> None:
        """Extract basic image info using Pillow."""
        try:
            with Image.open(self.file_path) as img:
                result.dimensions = img.size
                result.mode = img.mode
                result.format = img.format
                if hasattr(img, "info"):
                    info = img.info
                    if "dpi" in info:
                        dpi = info["dpi"]
                        if isinstance(dpi, tuple) and len(dpi) == 2:
                            result.dpi = (int(dpi[0]), int(dpi[1]))
                    if "icc_profile" in info:
                        result.icc_profile = "Embedded ICC profile present"
        except Exception as e:
            result.errors.append(f"Pillow error: {e}")

    def _extract_icc_profile(self, result: ExtractionResult) -> None:
        """Try to extract ICC profile details."""
        try:
            with Image.open(self.file_path) as img:
                icc = img.info.get("icc_profile")
                if icc:
                    # Parse basic ICC profile info
                    try:
                        profile_text = icc[36:60].decode("latin-1", errors="replace").strip("\x00")
                        if profile_text:
                            result.icc_profile = f"{profile_text} (ICC v{icc[8]}.{icc[9] if len(icc) > 9 else 0})"
                    except Exception:
                        result.icc_profile = "Embedded ICC profile present"
        except Exception:
            pass

    def _check_embedded_thumbnail(self, result: ExtractionResult, tags: Dict[str, Any]) -> None:
        """Check for embedded thumbnail in EXIF data."""
        thumb_compression = tags.get("Thumbnail Compression")
        thumb_x = tags.get("Thumbnail XResolution")
        thumb_y = tags.get("Thumbnail YResolution")
        thumb_jpeg = tags.get("Thumbnail JPEGInterchangeFormat")

        if thumb_jpeg is not None:
            result.has_embedded_thumbnail = True
            x = str(thumb_x).split()[0] if thumb_x else "?"
            y = str(thumb_y).split()[0] if thumb_y else "?"
            if x != "?" and y != "?":
                try:
                    result.thumbnail_size = (int(float(x)), int(float(y)))
                except ValueError:
                    pass

    def _extract_timestamps(self, tags: Dict[str, Any]) -> Dict[str, Any]:
        """Extract all relevant timestamps from EXIF."""
        timestamps = {}
        ts_fields = [
            ("EXIF DateTimeOriginal", "original"),
            ("EXIF DateTimeDigitized", "digitized"),
            ("Image DateTime", "modified"),
            ("GPS GPSDate", "gps_date"),
            ("GPS GPSTimeStamp", "gps_time"),
        ]
        for tag_name, label in ts_fields:
            if tag_name in tags:
                if tag_name == "GPS GPSTimeStamp":
                    timestamps[label] = self.gps_parser._format_gps_time(tags[tag_name])
                else:
                    timestamps[label] = str(tags[tag_name])
        return timestamps

    def _categorize_tag(self, tag_key: str) -> Optional[str]:
        """Categorize an EXIF tag into a human-readable group."""
        for category, prefixes in TAG_CATEGORIES.items():
            for prefix in prefixes:
                if tag_key == prefix:
                    return category
        # Fallback by prefix
        if tag_key.startswith("GPS "):
            return "GPS"
        if tag_key.startswith("EXIF "):
            return "Camera"
        if tag_key.startswith("Image "):
            return "Image"
        if tag_key.startswith("Thumbnail "):
            return "Thumbnail"
        return None

    def _guess_mime_type(self) -> str:
        """Guess MIME type from file extension."""
        mime_map = {
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".png": "image/png",
            ".gif": "image/gif",
            ".webp": "image/webp",
            ".bmp": "image/bmp",
            ".tiff": "image/tiff",
            ".tif": "image/tiff",
            ".heic": "image/heic",
            ".heif": "image/heif",
            ".raw": "image/x-canon-cr2",
            ".cr2": "image/x-canon-cr2",
            ".nef": "image/x-nikon-nef",
            ".arw": "image/x-sony-arw",
        }
        return mime_map.get(self.file_path.suffix.lower(), "application/octet-stream")