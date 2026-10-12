"""
Social Media Forensics: detect platform origin of images, even when EXIF is stripped.
Uses structural heuristics, compression patterns, file signatures, and embedded marker analysis.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict

from PIL import Image


class SocialMediaForensics:
    """Detect which platform an image came from and extract residual traces."""

    # Platform signatures in binary data.
    # NOTE: only reasonably specific tokens are listed. Extremely short or
    # generic strings (e.g. "wx", "line", "ig") cause false positives because
    # they appear inside random byte sequences ("wxyz", "online", ...).
    PLATFORM_SIGNATURES = {
        "whatsapp": [
            b"whatsapp", b"WhatsApp", b"wa.me",
        ],
        "instagram": [
            b"instagram", b"Instagram", b"ig_thumbnail", b"instagram.com",
        ],
        "facebook": [
            b"facebook", b"Facebook", b"fbcdn",
        ],
        "twitter": [
            b"twitter", b"Twitter", b"twimg",
        ],
        "tiktok": [
            b"tiktok", b"TikTok", b"aweme", b"douyin",
        ],
        "telegram": [
            b"telegram", b"Telegram", b"tdata", b"telegram.org",
        ],
        "wechat": [
            b"wechat", b"WeChat", b"weixin",
        ],
        "discord": [
            b"discord", b"Discord", b"discordapp", b"cdn.discordapp",
        ],
        "snapchat": [
            b"snapchat", b"Snapchat", b"sc-cdn",
        ],
        "signal": [
            b"signalapp", b"Signal App",
        ],
        "pinterest": [
            b"pinterest", b"Pinterest", b"pinimg",
        ],
        "reddit": [
            b"reddit", b"Reddit", b"redd.it", b"i.redd.it",
        ],
        "linkedin": [
            b"linkedin", b"LinkedIn", b"licdn",
        ],
        "weibo": [b"weibo", b"Weibo", b"sinajs", b"wbimg"],
        "xiaohongshu": [b"xhscdn", b"xiaohongshu"],
    }

    def __init__(self):
        self._platform_signatures = self.PLATFORM_SIGNATURES
        # WhatsApp media filenames carry the received date: IMG-20230415-WA0001.jpg
        self._whatsapp_file_re = re.compile(
            r"^(?:IMG|VID|PTT)[-_](\d{8})[-_]?WA\d{3,4}", re.IGNORECASE
        )
        # Modern WhatsApp desktop downloader: "WhatsApp Image 2026-10-11 at 21.03.19.jpeg"
        # carries the FULL receive date AND time (the old WA#### suffix is gone).
        self._whatsapp_download_re = re.compile(
            r"^WhatsApp (?:Image|Video|Audio|Document|Sticker|Profile Photo) "
            r"(\d{4})-(\d{2})-(\d{2}) at (\d{2})\.(\d{2})\.(\d{2})",
            re.IGNORECASE,
        )
        # React Native image-picker temp cache: rn_image_picker_lib_temp_<uuid>.jpg
        # Discord Mobile is a React Native app (as are Instagram/Facebook clients),
        # so picked images get this exact temp name on the device before upload.
        self._rn_picker_re = re.compile(
            r"rn_image_picker_lib_temp_[0-9a-f-]+\.(?:jpe?g|png|webp)", re.IGNORECASE
        )

    def analyze(self, file_path: str | Path, extraction_result: Any = None) -> Dict[str, Any]:
        """Run social media forensics analysis on an image."""
        result: Dict[str, Any] = {
            "detected_platform": None,
            "confidence": 0.0,
            "detection_methods": [],
            "compression_signature": None,
            "embedded_strings": [],
            "residual_traces": [],
            "is_screenshot": False,
            "reencoded": False,
            "whatsapp_filename_date": None,
        }

        path = Path(file_path)

        # 0. WhatsApp filename pattern first - the received date survives
        # in the name even when every byte of EXIF is gone.
        wa_match = self._whatsapp_file_re.match(path.name)
        if wa_match:
            digits = wa_match.group(1)
            date_str = f"{digits[:4]}-{digits[4:6]}-{digits[6:]}"
            result["whatsapp_filename_date"] = date_str
            result["detection_methods"].append(
                "WhatsApp filename pattern (IMG/VID/PTT-YYYYMMDD-WA####)"
            )
            result["residual_traces"].append(
                f"WhatsApp media filename; received {date_str}"
            )
            if not result["detected_platform"]:
                result["detected_platform"] = "whatsapp"
                result["confidence"] = 0.9

        # 0b. Modern WhatsApp download filename - carries receive date AND time
        # even when every byte of EXIF is gone (desktop downloader pattern).
        wa_dl = self._whatsapp_download_re.match(path.name)
        if wa_dl:
            y, mo, d, h, mi, s = wa_dl.groups()
            date_str = f"{y}-{mo}-{d}"
            time_str = f"{h}:{mi}:{s}"
            result["whatsapp_filename_date"] = date_str
            result["whatsapp_filename_time"] = time_str
            result["whatsapp_filename_datetime"] = f"{date_str} {time_str}"
            result["detection_methods"].append(
                "WhatsApp download filename (receive date + time)"
            )
            result["residual_traces"].append(
                f"WhatsApp download; received {date_str} {time_str}"
            )
            if not result["detected_platform"]:
                result["detected_platform"] = "whatsapp"
                result["confidence"] = max(result["confidence"], 0.9)

        # 1. Binary signature detection
        sig_result = self._scan_binary_signatures(path)
        if sig_result["platform"]:
            result["detected_platform"] = sig_result["platform"]
            result["confidence"] = max(result["confidence"], sig_result["confidence"])
            result["detection_methods"].append(f"Binary signature: {sig_result['match']}")
            result["embedded_strings"].extend(sig_result["matches"])

        # 2. EXIF-based clues
        if extraction_result:
            exif_clues = self._check_exif_clues(extraction_result)
            if exif_clues["platform"]:
                if not result["detected_platform"] or exif_clues["platform"] != result["detected_platform"]:
                    result["detected_platform"] = result["detected_platform"] or exif_clues["platform"]
                    result["confidence"] = max(result["confidence"], exif_clues["confidence"])
                    result["detection_methods"].append(exif_clues["reason"])
                    result["residual_traces"].append(exif_clues["reason"])

        # 3. JPEG structure analysis for re-encoding detection
        if path.suffix.lower() in (".jpg", ".jpeg", ".jfif"):
            jpeg_info = self._analyze_jpeg_structure(path)
            result["compression_signature"] = jpeg_info["signature"]
            result["reencoded"] = jpeg_info["reencoded"]
            if jpeg_info["reencoded"]:
                result["detection_methods"].append(
                    "JPEG structure analysis: multiple quantization tables detected"
                )

        # 4. Software tag clues
        if extraction_result and extraction_result.software:
            sw = extraction_result.software.lower()
            platform_hints = {
                "instagram": ["instagram"],
                "facebook": ["facebook"],
                "whatsapp": ["whatsapp"],
                "telegram": ["telegram"],
                "twitter": ["twitter"],
                "tiktok": ["tiktok", "aweme"],
            }
            for platform, keywords in platform_hints.items():
                if any(kw in sw for kw in keywords):
                    result["detected_platform"] = platform
                    result["confidence"] = 0.95
                    result["detection_methods"].append(f"Software tag: {extraction_result.software}")
                    result["residual_traces"].append(f"Software tag references {platform}")
                    break

        # 5. Dimension heuristics (common social media sizes)
        if extraction_result and extraction_result.dimensions:
            dims = extraction_result.dimensions
            size_hints = {
                (1080, 1920): "Instagram story / TikTok full-screen",
                (1920, 1080): "Standard landscape social media",
                (1080, 1080): "Instagram feed post",
                (1080, 1350): "Instagram feed portrait",
                (1200, 630): "Facebook/Twitter link card",
                (720, 1280): "WhatsApp status / TikTok",
                (404, 720): "Ig thumbnail",
            }
            for dim, platform_hint in size_hints.items():
                if dims == dim:
                    result["residual_traces"].append(
                        f"Dimensions match: {platform_hint}"
                    )
                    break

        # 6. Screenshot detection
        if extraction_result:
            screenshot = self._detect_screenshot(extraction_result)
            result["is_screenshot"] = screenshot

        return result

    def _scan_binary_signatures(self, path: Path) -> Dict[str, Any]:
        """Scan binary data for platform signatures."""
        result = {"platform": None, "confidence": 0.0, "match": None, "matches": []}

        try:
            with open(path, "rb") as f:
                # Read first 16KB + last 4KB (platforms often add metadata at markers)
                head = f.read(16384)
                f.seek(max(0, path.stat().st_size - 4096))
                tail = f.read()

            data = head + tail
            hex_patterns = re.findall(rb"[A-Za-z0-9_\-.]{6,50}", data)

            for platform, signatures in self._platform_signatures.items():
                for sig in signatures:
                    if sig in data:
                        result["platform"] = platform
                        result["confidence"] = 0.8
                        result["match"] = sig.decode("utf-8", errors="replace")
                        # Find the actual string in data
                        for pattern in hex_patterns:
                            if sig.decode("utf-8", errors="replace").lower() in pattern.decode("utf-8", errors="replace").lower():
                                result["matches"].append(pattern.decode("utf-8", errors="replace"))
                        break
                if result["platform"]:
                    break

        except (OSError, IOError):
            pass

        return result

    def _check_exif_clues(self, extraction_result: Any) -> Dict[str, Any]:
        """Check EXIF data for platform-specific clues."""
        result = {"platform": None, "confidence": 0.0, "reason": None}

        # Check for MAKERNOTE / private tags from platforms
        exif_data = extraction_result.exif_data
        json_str = str(exif_data).lower()

        for platform, keywords in {
            "whatsapp": ["whatsapp", "whatsapp_"],
            "instagram": ["instagram", "ig_"],
            "facebook": ["facebook", "fb_"],
            "tiktok": ["tiktok", "aweme"],
            "telegram": ["telegram"],
        }.items():
            for kw in keywords:
                if kw in json_str:
                    result["platform"] = platform
                    result["confidence"] = 0.9
                    result["reason"] = f"Platform keyword '{kw}' found in EXIF data"
                    return result

        # Check DeviceID / UniqueID tags
        for tag in ["Image ImageUniqueID", "EXIF ExifImageUniqueID", "EXIF ImageID"]:
            if tag in exif_data:
                result["reason"] = f"Unique ID present ({tag}) — can be used for cross-referencing"
                # Keep platform None; this is just a trace

        return result

    def _analyze_jpeg_structure(self, path: Path) -> Dict[str, Any]:
        """Analyze JPEG structure to detect re-encoding and platform signatures.

        NOTE: this is deliberately conservative - a single DQT segment (one
        luminance + one chrominance table) is NORMAL for every JPEG. We only
        flag something as "re-encoded" when there are >= 4 quantization
        segments, which strongly suggests the file was stripped of its
        original tables and rebuilt by a platform/editor pipeline.
        """
        result = {"signature": None, "reencoded": False}

        try:
            with open(path, "rb") as f:
                data = f.read()

            # Walk JPEG markers
            app_markers = {}
            dqt_count = 0
            com_count = 0
            soft_markers = []
            i = 2  # Skip SOI
            while i < len(data) - 1:
                if data[i] != 0xFF:
                    i += 1
                    continue
                marker = data[i + 1]

                # Skip stuffed 0xFF sequences (FF 00)
                if marker == 0x00:
                    i += 2
                    continue

                if marker == 0xD8:  # SOI
                    i += 2
                    continue
                if marker == 0x01 or marker == 0xD9:  # TEM / EOI
                    i += 2
                    continue

                # Standalone markers without length
                if marker in (0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7):
                    i += 2
                    continue

                if marker == 0xDA:  # SOS - start of scan, stop parsing
                    break

                # Segment with length
                if i + 3 >= len(data):
                    break
                seg_len = (data[i + 2] << 8) | data[i + 3]
                if seg_len < 2 or i + 2 + seg_len > len(data):
                    break

                if 0xE0 <= marker <= 0xEF:  # APPn
                    app_markers[f"APP{marker - 0xE0}"] = app_markers.get(f"APP{marker - 0xE0}", 0) + 1
                    if seg_len > 2:
                        seg_content = data[i + 4:i + 2 + seg_len]
                        # Known APP marker signatures
                        known = {
                            b"JFIF": "JFIF header (older format)",
                            b"Exif": "EXIF data",
                            b"ICC_PROFILE": "ICC color profile",
                            b"Photoshop": "Photoshop/PhotoShop metadata",
                            b"Adobe": "Adobe optimized",
                            b"XMP": "XMP metadata",
                            b"MPF": "Multi-picture format",
                            b"CaptureOne": "Capture One metadata",
                            b"Luminance": "Luminance metadata",
                        }
                        for sig, label in known.items():
                            if seg_content.startswith(sig):
                                soft_markers.append(label)
                                break
                        if seg_content.startswith(b"com.adobe"):
                            soft_markers.append("Adobe XMP packet")
                elif marker == 0xDB:  # DQT
                    dqt_count += 1
                elif marker == 0xFE:  # COM comment
                    com_count += 1
                    if seg_len > 2:
                        comment = data[i + 4:i + 2 + seg_len]
                        soft_markers.append(f"Comment: {comment[:40].decode('utf-8', errors='replace')}")

                i += 2 + seg_len

            result["signature"] = {
                "app_markers": app_markers,
                "quantization_tables": dqt_count,
                "comments": com_count,
                "markers_detected": soft_markers,
            }

            # Conservative re-encoding detection
            if dqt_count >= 4:
                result["reencoded"] = True

        except (OSError, IOError):
            pass

        return result

    def _detect_screenshot(self, extraction_result: Any) -> bool:
        """Detect if image is likely a screenshot."""
        # Check software tag
        sw = (extraction_result.software or "").lower()
        screenshot_keywords = ["screenshot", "screen capture", "snagit", "greenshot", "lightshot"]
        if any(kw in sw for kw in screenshot_keywords):
            return True

        # Screenshots typically lack GPS, lack Make/Model
        if not extraction_result.device.get("make") and not extraction_result.device.get("model"):
            if not extraction_result.gps.get("available"):
                # Check dimensions for common screenshot sizes
                w, h = extraction_result.dimensions
                if h > w * 1.5 and (w in (1080, 1440, 2160, 2400) or h in (1920, 2340, 2400)):
                    return True

        return False