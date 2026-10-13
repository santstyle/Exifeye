"""
Rich console output for metadata reports.
Designed for visual clarity: banner, colored panels, layered sections,
and a punchy verdict summary. No emojis - pure typography + color.

Theme: hacker-green (Matrix style) — bright green accents, lime warnings.
Red is reserved for real risks/errors only.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from rich.console import Console, Group
from rich.markup import escape
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich import box

# Parser flag keys that indicate active/risky content in non-image files;
# the verdict panel shows these for documents/video instead of the
# image-authenticity score (which would be meaningless there).
_RISKY_FLAGS = (
    "macros", "encrypted_ooxml", "javascript", "javascript_raw",
    "external_rels", "path_leak", "suspicious_streams",
    "suspicious_parts", "ole_objects", "embedded_files",
)


class ConsoleOutput:
    """Render extraction results in a rich console format.

    One cohesive hacker-green palette instead of a per-panel rainbow:
      accent  - panel borders + titles (Matrix bright green)
      label   - field names (softer green)
      value   - data (pale mint green)
      good    - positive/high-value results (GPS, identified device)
      warn    - caution (low score, platform trace, recovered data)
      bad     - risk / errors (red — kept for danger only)
      muted   - secondary paths & hints
    """

    ACCENT = "#00ff41"
    LABEL = "#4fd68a"
    VALUE = "#c9ffe0"
    GOOD = "#00ff41"
    WARN = "#c8f542"
    BAD = "#ff5555"
    MUTED = "dim"

    def __init__(self, console: Console | None = None):
        self.console = console if console is not None else Console()
        self._row_style_alt = "dim"

    def render_banner(self) -> None:
        """Render the tool banner: the neon logo image (rich-pixels) whenever
        the terminal supports it, falling back to the classic ANSI Shadow
        text art so the banner never breaks on limited terminals."""
        if self._render_image_banner():
            return

        art = [
            "███████╗██╗  ██╗██╗███████╗███████╗██╗   ██╗███████╗",
            "██╔════╝╚██╗██╔╝██║██╔════╝██╔════╝╚██╗ ██╔╝██╔════╝",
            "█████╗   ╚███╔╝ ██║█████╗  █████╗   ╚████╔╝ █████╗",
            "██╔══╝   ██╔██╗ ██║██╔══╝  ██╔══╝    ╚██╔╝  ██╔══╝",
            "███████╗██╔╝ ██╗██║██║     ███████╗   ██║   ███████╗",
            "╚══════╝╚═╝  ╚═╝╚═╝╚═╝     ╚══════╝   ╚═╝   ╚══════╝",
        ]
        tagline = "IMAGE INTELLIGENCE | EXIF + GPS + DEVICE + FORENSICS"
        art_width = max(len(line.rstrip()) for line in art)
        indent = 2
        for line in art:
            self.console.print(" " * indent + line.rstrip(),
                               style=f"bold {self.ACCENT}")
        tag_pad = max(0, (art_width - len(tagline)) // 2)
        self.console.print(" " * (indent + tag_pad) + tagline,
                           style=f"bold {self.ACCENT}")
        self.console.print("")

    # The standard VGA / console 16-color palette. When the terminal can
    # only show 16 colors, the image is snapped to these exact RGB values
    # before rich-pixels sees it, so rich's own RGB->16 downgrade is a
    # lossless no-op and the logo keeps its shape instead of smearing.
    _ANSI16 = (
        (0, 0, 0), (170, 0, 0), (0, 170, 0), (170, 85, 0),
        (0, 0, 170), (170, 0, 170), (0, 170, 170), (170, 170, 170),
        (85, 85, 85), (255, 85, 85), (85, 255, 85), (255, 255, 85),
        (85, 85, 255), (255, 85, 255), (85, 255, 255), (255, 255, 255),
    )

    def _render_image_banner(self) -> bool:
        """Try to render the neon logo PNG in the terminal via rich-pixels.

        rich-pixels draws the image as colored half-block glyphs. Two things
        have to be done by hand first or the result looks broken: the logo
        PNG is mostly transparent padding (the actual art is a small island
        in the middle of a large canvas), and rich-pixels itself resamples
        with NEAREST, which shatters the thin neon strokes. So the image is
        cropped to its opaque bounds and resampled with LANCZOS here, then
        handed over already at final size (resize=None) so it is not
        resampled again.

        On 16-color terminals (legacy Windows consoles, color_system
        "windows" / "standard") the image is additionally snapped to the
        ANSI 16-color palette before hand-off — otherwise rich's own
        RGB->16 downgrade smears the neon strokes into a solid slab.

        Returns True when the image banner was printed; False otherwise so
        the caller falls back to the ASCII text banner. Never raises - pixel
        art is decorative and the text art is the guaranteed baseline.
        """
        try:
            banner = Path(__file__).resolve().parent / "banner.png"
            if not banner.is_file() or not self.console.is_terminal:
                return False
            if self.console.color_system is None:
                # No color at all — pixel art would be an unreadable slab.
                return False
            from PIL import Image
            from rich_pixels import Pixels

            with Image.open(banner) as img:
                img = img.convert("RGBA")
                # Drop the transparent padding so the resize budget goes to
                # the actual logo, not to empty space around it.
                bounds = img.getchannel("A").getbbox()
                if bounds:
                    img = img.crop(bounds)
                # Flatten onto the theme's near-black. Neon art drawn on a
                # transparent background leaves dark fringes when LANCZOS
                # blends the edge pixels, and a solid fill keeps the block
                # cells crisp.
                flat = Image.new("RGBA", img.size, (0, 0, 0, 255))
                flat.alpha_composite(img)
                img = flat.convert("RGB")

                aspect = img.width / img.height
                # Terminal real estate: keep the banner compact, never wider
                # than the console, and shrink gracefully on narrow screens.
                width = min((self.console.width or 100) - 4, 96)
                if width < 40:
                    return False
                # Half-cell renderer draws 2 image pixel rows per terminal
                # row, so the pixel height keeps the logo's aspect ratio.
                height = max(4, round(width / aspect))
                if height % 2:
                    height += 1
                # LANCZOS here; resize=None below so rich-pixels does not
                # re-resample this with its default NEAREST.
                img = img.resize((width, height), Image.LANCZOS)
                # 16-color terminals: snap to the ANSI palette so the
                # logo shape survives rich's RGB->16 downgrade.
                if self.console.legacy_windows or self.console.color_system in (
                    "windows", "standard",
                ):
                    img = self._quantize_ansi16(img)
                pixels = Pixels.from_image(img)
            self.console.print(pixels)
            self.console.print("")
            return True
        except Exception:
            return False

    def _quantize_ansi16(self, img):
        """Snap an RGB image to the 16 ANSI console colors (lossless
        downgrade on 16-color terminals)."""
        from PIL import Image

        palette = Image.new("P", (1, 1))
        flat = []
        for r, g, b in self._ANSI16:
            flat.extend((r, g, b))
        flat.extend((0, 0, 0) * (256 - 16))
        palette.putpalette(flat)
        return img.quantize(palette=palette, dither=Image.Dither.NONE).convert("RGB")

    def render(self, result: Any, forensics: Dict[str, Any] | None = None,
               deep: Dict[str, Any] | None = None,
               sections: set[str] | None = None,
               extra: Dict[str, Any] | None = None) -> None:
        """Render full report to console. `sections` filters the panels shown.

        `extra` carries the v2.0 analyzer outputs keyed by name:
        thumbnail, jpeg_structure, chunks, strings - each an optional dict.
        """
        all_sections = {"gps", "device", "social", "forensics", "exif",
                        "thumbnail", "jpeg_structure", "chunks", "strings",
                        "auth_risk", "gps_spoof", "timestamp_check",
                        "filename_origin", "ai_generated", "trailing",
                        "panorama"}
        s = sections if sections is not None else all_sections
        extra = extra or {}

        self._render_file_info(result)
        if "gps" in s:
            self._render_gps(result)
        if "device" in s:
            self._render_device(result)
        self._render_timestamps(result)
        if "timestamp_check" in s and extra.get("timestamp_check"):
            self._render_timestamp_check(extra["timestamp_check"])
        if "filename_origin" in s and extra.get("filename_origin"):
            self._render_filename_origin(extra["filename_origin"])
        if "ai_generated" in s and extra.get("ai_generated"):
            self._render_ai_generated(extra["ai_generated"])

        # v2.0 analyzer sections
        if "thumbnail" in s and extra.get("thumbnail"):
            self._render_thumbnail_recovery(extra["thumbnail"])
        if "jpeg_structure" in s and extra.get("jpeg_structure"):
            self._render_jpeg_structure(extra["jpeg_structure"])
        if "chunks" in s and extra.get("chunks"):
            self._render_meta_chunks(extra["chunks"])
        if "strings" in s and extra.get("strings"):
            self._render_embedded_strings(extra["strings"])
        if "gps_spoof" in s and extra.get("gps_spoof"):
            self._render_gps_spoof(extra["gps_spoof"])
        if "trailing" in s and extra.get("trailing"):
            self._render_trailing(extra["trailing"])
        if "panorama" in s and extra.get("panorama"):
            self._render_panorama(extra["panorama"])

        if forensics and (("social" in s) if sections is not None
                          else forensics.get("detected_platform")):
            self._render_social_media(forensics)

        if deep and "forensics" in s:
            self._render_deep_forensics(deep)

        if "exif" in s:
            self._render_exif_categories(result)
        if "auth_risk" in s and extra.get("auth_risk"):
            self._render_auth_risk(extra["auth_risk"])
        self._render_verdict(result, forensics, deep, extra)

        if (not result.gps.get("available")
                and getattr(result, "kind", "image") in ("image", "unknown")):
            # GPS missing -> point the user to find the ORIGINAL copy that
            # still holds the coordinates. Skip when GPS was already found.
            # Reverse-image-search advice only makes sense for images.
            stripped = self._gps_ifd_stripped(result)
            zero_placeholder = result.gps.get("zero_placeholder")
            self.console.print(Rule(" LOCATE THE ORIGINAL "))
            tail = (
                "this image's GPS IFD only holds zero coordinates - a placeholder "
                "written when location was disabled or GPS never locked at capture. "
                "Find the untouched ORIGINAL file (camera / SD card)"
                if zero_placeholder else
                "this image's GPS IFD is EMPTY - coordinates were likely removed "
                "by software. Find the untouched ORIGINAL file (camera / SD card)"
                if stripped else
                "find a copy of this image that kept its GPS (or check if "
                "original had location enabled)"
            )
            self.console.print(
                "[dim]Reverse image search: [link=https://lens.google.com/]Google Lens[/link] | "
                "[link=https://yandex.com/images/]Yandex[/link] | "
                "[link=https://tineye.com/]TinEye[/link] | "
                "[link=https://www.bing.com/visualsearch]Bing Visual[/link] - "
                f"{tail}[/dim]"
            )
            self.console.print(
                "[dim]Tip: [bold]exifeye --lens <image>[/bold] opens it locally in the "
                "browser - right-click the image, pick 'Search image with Google'. "
                "Nothing is uploaded by the tool.[/dim]"
            )

    def _render_file_info(self, result: Any) -> None:
        """Render basic file information as a header card."""
        is_image = getattr(result, "kind", "image") in ("image", "unknown")
        unit = " px" if is_image else ""
        dims = (f"{result.dimensions[0]:,} x {result.dimensions[1]:,}{unit}"
                if result.dimensions[0] else "Unknown")

        info = Table.grid(padding=(0, 2))
        info.add_column(style=self.LABEL, justify="right")
        info.add_column(style=self.VALUE)
        info.add_row("Format", f"[bold]{result.file_type.upper()}[/bold] ({result.mime_type})")
        info.add_row("File Size", f"{result.file_size:,} bytes  [dim]({result.file_size / 1024:.1f} KB)[/dim]")
        info.add_row("Dimensions", dims)
        if is_image:
            # Pixel-pipeline fields - meaningless for documents/video.
            info.add_row("Color Mode", result.mode or "[dim]Unknown[/dim]")
            info.add_row("DPI", f"{result.dpi[0]} x {result.dpi[1]}" if result.dpi else "[dim]not specified[/dim]")
            info.add_row("Orientation", result.orientation or "[dim]not specified[/dim]")
            info.add_row("ICC Profile", result.icc_profile or "[dim]none[/dim]")

        header = Panel(
            info,
            title=f"[bold {self.ACCENT}][ {escape(result.file_name)} ][/bold {self.ACCENT}]",
            subtitle=f"[dim]{escape(result.file_path)}[/dim]",
            border_style=self.ACCENT,
            padding=(1, 2),
        )
        self.console.print(header)

    def _render_gps(self, result: Any) -> None:
        """Render GPS information as a highlighted panel."""
        gps = result.gps
        if not gps.get("available"):
            # No data -> hide the panel entirely. The VERDICT section
            # already reports "NO GPS" so an empty red panel is just spam.
            return

        lat = gps["latitude"]
        lon = gps["longitude"]

        grid = Table.grid(padding=(0, 2))
        grid.add_column(style=self.LABEL, justify="right")
        grid.add_column(style=self.VALUE)

        grid.add_row("Latitude", f"[bold {self.GOOD}]{lat:.7f}[/bold {self.GOOD}]° {gps['latitude_ref']}")
        grid.add_row("Longitude", f"[bold {self.GOOD}]{lon:.7f}[/bold {self.GOOD}]° {gps['longitude_ref']}")
        if gps.get("altitude_meters") is not None:
            grid.add_row("Altitude", f"{gps['altitude_meters']} m")
        if gps.get("gps_time"):
            grid.add_row("GPS Time", gps["gps_time"])
        if gps.get("gps_date"):
            grid.add_row("GPS Date", gps["gps_date"])
        if gps.get("speed"):
            grid.add_row("Speed", gps["speed"])
        if gps.get("track"):
            grid.add_row("Track", gps["track"])
        if gps.get("source") == "XMP":
            grid.add_row("Source", f"[bold {self.WARN}]XMP residual metadata (recovered)[/bold {self.WARN}]")
        grid.add_row("Geohash", f"[bold]{gps.get('geohash', 'N/A')}[/bold]")

        panel = Panel(
            Group(grid, Rule(style=self.GOOD),
                  Text.from_markup(f"[bold]GOOGLE MAPS:[/bold] [link={gps.get('google_maps_link', '')} underline]{gps.get('google_maps_link', '')}[/link]")),
            title=f"[bold {self.GOOD}]GPS COORDINATES - GEOLOCATED[/bold {self.GOOD}]",
            border_style=self.GOOD,
            padding=(1, 2),
            subtitle=f"[bold {self.GOOD}]LOCATION CONFIRMED[/bold {self.GOOD}]",
        )
        self.console.print(panel)

    def _render_device(self, result: Any) -> None:
        """Render device/camera information - only rows with data."""
        device = result.device

        rows: list[tuple[str, str]] = []
        add = rows.append
        for key, label, style in (
            ("brand", "Brand", f"bold {self.GOOD}"),
            ("make", "Make", None),
            ("model", "Model", None),
            ("model_name", "Model Name", f"bold {self.GOOD}"),
            ("device_type", "Device Type", None),
            ("os", "Operating System", None),
            ("software", "Software", None),
            ("lens_model", "Lens Model", None),
            ("lens_make", "Lens Make", None),
            ("year", "Release Year", None),
            ("serial_number", "Camera Serial", self.WARN),
            ("image_unique_id", "Image Unique ID", self.MUTED),
        ):
            value = device.get(key)
            if not value:
                continue  # skip empty values - no "Unknown" spam
            display = f"[{style}]{value}[/{style}]" if style else str(value)
            add((label, display))

        if not rows:
            # No device data at all -> hide. VERDICT reports "ANONYMOUS DEVICE".
            return

        grid = Table.grid(padding=(0, 2))
        grid.add_column(style=self.LABEL, justify="right")
        grid.add_column(style=self.VALUE)
        for label, display in rows:
            grid.add_row(label, display)

        self.console.print(Panel(
            grid,
            title=f"[bold {self.ACCENT}]DEVICE / CAMERA[/bold {self.ACCENT}]",
            border_style=self.ACCENT,
            padding=(1, 2),
        ))

    def _render_timestamps(self, result: Any) -> None:
        """Render timestamps as a compact inline row."""
        if not result.timestamps:
            return
        parts = []
        label_map = {
            "original": "Taken",
            "digitized": "Digitized",
            "modified": "Modified",
            "gps_date": "GPS Date",
            "gps_time": "GPS Time",
        }
        for key, value in result.timestamps.items():
            label = label_map.get(key, key)
            parts.append(f"[bold {self.LABEL}]{escape(str(label))}:[/bold {self.LABEL}] {escape(str(value))}")

        self.console.print(Rule(f" TIMELINE ", style=self.ACCENT))
        self.console.print("  |  ".join(parts))

    def _render_social_media(self, forensics: Dict[str, Any]) -> None:
        """Render social media forensics results."""
        platform = forensics.get("detected_platform")

        grid = Table.grid(padding=(0, 2))
        grid.add_column(style=self.LABEL, justify="right")
        grid.add_column(style=self.VALUE)

        if platform:
            grid.add_row("Platform", f"[bold {self.WARN}]{platform.upper()}[/bold {self.WARN}]")
            conf = forensics.get("confidence", 0)
            bar = self._confidence_bar(conf)
            grid.add_row("Confidence", bar)
        else:
            grid.add_row("Platform", f"[dim]no platform signature detected[/dim]")

        grid.add_row("Screenshot", "yes" if forensics.get("is_screenshot") else "no")
        grid.add_row("Re-encoded", "yes" if forensics.get("reencoded") else "no")
        if forensics.get("whatsapp_filename_date"):
            grid.add_row("WA File Date",
                         f"[bold {self.WARN}]{forensics['whatsapp_filename_date']}[/bold {self.WARN}]")

        if forensics.get("detection_methods"):
            grid.add_row("Method", "\n".join(f"[dim]- {m}[/dim]" for m in forensics["detection_methods"]))
        if forensics.get("residual_traces"):
            grid.add_row("Traces", "\n".join(f"[dim]* {t}[/dim]" for t in forensics["residual_traces"]))

        color = self.WARN if platform else self.MUTED
        title = (f"[bold {self.WARN}]PLATFORM TRACE: {platform.upper()}"
                 f"[/bold {self.WARN}]" if platform else "[bold]PLATFORM TRACE[/bold]")
        self.console.print(Panel(
            grid,
            title=title,
            border_style=color,
            padding=(1, 2),
        ))

    @classmethod
    def _confidence_bar(cls, confidence: float) -> str:
        """Render a small textual confidence bar."""
        filled = int(round(confidence * 10))
        bar = "█" * filled + "░" * (10 - filled)
        return f"[bold]{confidence * 100:3.0f}%[/bold] [{cls.GOOD}]{bar}[/{cls.GOOD}]"

    @staticmethod
    def _ela_implies_editing(ela: Dict[str, Any]) -> bool:
        """Whether ELA results suggest the image was edited, based on numeric error levels.

        Uses max_difference thresholds from the analyzer (not fragile substring
        matching on the interpretation text, which would also match "unedited").
        """
        max_diff = (ela or {}).get("max_difference")
        if max_diff is None:
            return False
        return max_diff > 10

    def _render_deep_forensics(self, deep: Dict[str, Any]) -> None:
        """Render deep forensics results - only when data exists."""
        ela = deep.get("ela", {})
        stego = deep.get("steganography", {})
        entropy = deep.get("entropy", {})
        rows = []

        if ela.get("available"):
            interp = ela.get("interpretation", "")
            color = self.BAD if self._ela_implies_editing(ela) else self.GOOD
            rows.append(f"[bold]ELA:[/bold] max_diff={ela.get('max_difference')}, "
                        f"artifacts={ela.get('high_error_region_ratio', 0)*100:.1f}%")
            rows.append(f"      [{color}]{interp}[/{color}]")

        if stego.get("available"):
            anom = stego.get("anomaly_detected")
            flag = f"[{self.BAD}]ANOMALY DETECTED[/{self.BAD}]" if anom else f"[{self.GOOD}]clean[/{self.GOOD}]"
            rows.append(f"[bold]LSB plane:[/bold] entropy={stego.get('lsb_entropy')}, {flag}")
            if anom:
                for note in stego.get("notes", [])[:2]:
                    rows.append(f"      [{self.WARN}]! {note}[/{self.WARN}]")

        if entropy.get("available"):
            rows.append(f"[bold]Entropy:[/bold] {entropy.get('entropy')} - {entropy.get('interpretation')}")

        if not rows:
            # No forensics data at all -> hide. Nothing useful to show.
            return

        self.console.print(Panel(
            "\n".join(rows),
            title=f"[bold {self.ACCENT}]DEEP FORENSICS[/bold {self.ACCENT}]",
            border_style=self.ACCENT,
            padding=(1, 2),
        ))

    def _render_exif_categories(self, result: Any) -> None:
        """Render EXIF data by category in clean header tables."""
        if not result.exif_data:
            return

        accent = self.ACCENT

        for category, tags in result.exif_data.items():
            if not tags or category == "GPS":
                continue

            table = Table(
                title=f"[bold {accent}]{category.upper()} DATA[/bold {accent}]",
                show_header=True,
                header_style=f"bold {accent}",
                border_style=accent,
                pad_edge=False,
            )
            table.add_column("Attribute", style=self.LABEL, no_wrap=False, ratio=1)
            table.add_column("Value", style=self.VALUE, ratio=3, overflow="fold")

            for tag, value in sorted(tags.items()):
                display_tag = tag.split(" ", 1)[-1] if " " in tag else tag
                table.add_row(display_tag, str(value))

            self.console.print(table)
            self.console.print()

    def _render_thumbnail_recovery(self, thumb: Dict[str, Any]) -> None:
        """Render the embedded-thumbnail metadata recovery section."""
        if not thumb.get("available"):
            return  # nothing to show - no thumbnail block recovered

        grid = Table.grid(padding=(0, 2))
        grid.add_column(style=self.LABEL, justify="right")
        grid.add_column(style=self.VALUE)

        grid.add_row("Thumbnail", f"[bold]{thumb.get('length', 0):,} bytes[/bold] "
                                  f"at offset {thumb.get('offset', 0):,}")
        dims = thumb.get("dimensions")
        if dims:
            grid.add_row("Dimensions", f"{dims[0]} x {dims[1]} px")

        gps = thumb.get("gps") or {}
        if gps.get("available"):
            lat = gps["latitude"]
            lon = gps["longitude"]
            grid.add_row("GPS", f"[bold {self.GOOD}]{lat:.7f}, {lon:.7f}[/bold {self.GOOD}] "
                                f"[link={gps.get('google_maps_link', '')} underline]Google Maps[/link]")

        device = thumb.get("device") or {}
        if device.get("make") or device.get("model"):
            grid.add_row("Device", f"{device.get('make') or '?'} {device.get('model') or '?'}".strip())

        timestamps = thumb.get("timestamps") or {}
        if timestamps.get("original"):
            grid.add_row("Taken", str(timestamps["original"]))

        if thumb.get("software"):
            grid.add_row("Software", str(thumb["software"]))

        for err in (thumb.get("errors") or [])[:2]:
            grid.add_row("Note", f"[{self.MUTED}]{escape(str(err))}[/{self.MUTED}]")

        recovered = gps.get("available") or bool(device.get("make") or device.get("model"))
        color = self.WARN if recovered else self.MUTED
        title = (f"[bold {self.WARN}]THUMBNAIL RECOVERY[/bold {self.WARN}]"
                 if recovered else "[bold]THUMBNAIL PRESENT[/bold]")
        self.console.print(Panel(
            grid,
            title=title,
            border_style=color,
            padding=(1, 2),
        ))

    def _render_jpeg_structure(self, structure: Dict[str, Any]) -> None:
        """Render JPEG structure analysis (markers, quality, chroma)."""
        if not structure.get("available"):
            return  # only meaningful for JPEG files

        grid = Table.grid(padding=(0, 2))
        grid.add_column(style=self.LABEL, justify="right")
        grid.add_column(style=self.VALUE)

        quality = structure.get("quality_estimate")
        if quality is not None:
            qcolor = self.GOOD if quality >= 80 else (self.WARN if quality >= 50 else self.BAD)
            grid.add_row("Quality est.", f"[bold {qcolor}]{quality:.0f}/100[/bold {qcolor}]")
        if structure.get("chroma_subsampling"):
            grid.add_row("Subsampling", str(structure["chroma_subsampling"]))
        if structure.get("progressive"):
            grid.add_row("Progressive", "[bold]yes[/bold]")
        if structure.get("dimensions"):
            grid.add_row("Structure dims", f"{structure['dimensions'][0]} x {structure['dimensions'][1]} px")

        markers = structure.get("markers") or {}
        app_segs = markers.get("app_segments") or {}
        marker_row = ", ".join(
            [f"APP{n}={app_segs.get(f'APP{n}', 0)}" for n in range(1, 16) if app_segs.get(f'APP{n}', 0)]
            + [f"DQT={markers.get('dqt_count', 0)}", f"DHT={markers.get('dht_count', 0)}",
               f"SOF={markers.get('sof_count', 0)}", f"COM={markers.get('com_count', 0)}"]
        ) or "[dim]none[/dim]"
        grid.add_row("Markers", marker_row)

        for comment in (structure.get("comments") or [])[:3]:
            grid.add_row("Comment", f"[{self.MUTED}]{escape(str(comment))}[/{self.MUTED}]")

        if structure.get("reencoded_hint"):
            grid.add_row("Warning", f"[{self.WARN}]re-encoded file structure - "
                                    f"platform re-compression suspected[/{self.WARN}]")

        self.console.print(Panel(
            grid,
            title=f"[bold {self.ACCENT}]JPEG STRUCTURE[/bold {self.ACCENT}]",
            border_style=self.ACCENT,
            padding=(1, 2),
        ))

    def _render_meta_chunks(self, chunks: Dict[str, Any]) -> None:
        """Render PNG / GIF / WebP chunk mining results."""
        if not chunks.get("available"):
            return  # unsupported container or nothing to decode

        grid = Table.grid(padding=(0, 2))
        grid.add_column(style=self.LABEL, justify="right")
        grid.add_column(style=self.VALUE)

        grid.add_row("Format", f"[bold]{chunks.get('format', '?')}[/bold]")

        chunk_types = [c.get("type") for c in (chunks.get("chunks") or [])]
        if chunk_types:
            grid.add_row("Chunks", ", ".join(f"[dim]{t}[/dim]" for t in chunk_types[:12])
                                  + ("..." if len(chunk_types) > 12 else ""))

        for meta in (chunks.get("text_metadata") or [])[:8]:
            key = meta.get("key", "?")
            value = str(meta.get("value", ""))[:120]
            grid.add_row(f"Text [{key}]", f"[{self.MUTED}]{escape(value)}[/{self.MUTED}]")

        gps = chunks.get("gps") or {}
        if gps.get("available"):
            lat = gps["latitude"]
            lon = gps["longitude"]
            grid.add_row("GPS", f"[bold {self.GOOD}]{lat:.7f}, {lon:.7f}[/bold {self.GOOD}] "
                                f"[link={gps.get('google_maps_link', '')} underline]Google Maps[/link]")

        if chunks.get("xmp_gps_hint"):
            grid.add_row("XMP GPS", f"[{self.WARN}]raw GPS coordinates present in XMP[/{self.WARN}]")

        has_meta = bool(chunks.get("text_metadata")) or bool(gps.get("available")) \
            or bool(chunks.get("xmp_gps_hint"))
        color = self.WARN if has_meta else self.MUTED
        title = (f"[bold {self.WARN}]META CHUNKS[/bold {self.WARN}]"
                 if has_meta else "[bold]META CHUNKS[/bold]")
        self.console.print(Panel(
            grid,
            title=title,
            border_style=color,
            padding=(1, 2),
        ))

    def _render_embedded_strings(self, strs: Dict[str, Any]) -> None:
        """Render raw-byte embedded string hits (high-signal categories first)."""
        if not strs.get("available"):
            return

        counts = strs.get("counts") or {}
        strings = strs.get("strings") or []
        if not strings:
            return  # nothing found

        # High-signal categories lead; paths + other trail quietly.
        priority = ["url", "email", "ip_address", "phone", "gps_hint",
                    "social_platform", "device", "software", "path"]
        grid = Table.grid(padding=(0, 2))
        grid.add_column(style=self.LABEL, justify="right")
        grid.add_column(style=self.VALUE)

        total_shown = 0
        for cat in priority:
            if cat not in counts or counts[cat] == 0:
                continue
            for hit in [s for s in strings if s.get("category") == cat][:6]:
                value = escape(str(hit.get("value", "")))[:140]
                grid.add_row(f"{cat.upper()}", f"[{self.GOOD if cat != 'path' else self.MUTED}]{value}[/"
                                               f"{self.GOOD if cat != 'path' else self.MUTED}]")
                total_shown += 1
            if counts[cat] > 6:
                grid.add_row("", f"[{self.MUTED}]... +{counts[cat] - 6} more {cat}[/{self.MUTED}]")
                total_shown += 1

        other_count = counts.get("other", 0)
        if other_count:
            grid.add_row("Other strings", f"[{self.MUTED}]{other_count} generic fragment(s) "
                                          f"(compressed-data noise likely)[/{self.MUTED}]")

        if strs.get("scanned_bytes"):
            grid.add_row("Scanned", f"[{self.MUTED}]{strs['scanned_bytes']:,} bytes[/{self.MUTED}]")
        if strs.get("cap_hit"):
            grid.add_row("Capped", f"[{self.WARN}]more strings found - "
                                   f"showing first {len(strings)}[/{self.WARN}]")

        high_signal = any(counts.get(c, 0) for c in
                          ("url", "email", "ip_address", "phone", "gps_hint", "device", "software"))
        color = self.WARN if high_signal else self.MUTED
        title = (f"[bold {self.WARN}]EMBEDDED STRINGS[/bold {self.WARN}]"
                 if high_signal else "[bold]EMBEDDED STRINGS[/bold]")
        self.console.print(Panel(
            grid,
            title=title,
            border_style=color,
            padding=(1, 2),
        ))

    def _render_auth_risk(self, auth: Dict[str, Any]) -> None:
        """Render the authentication risk meter (score, level, signal list)."""
        if not auth.get("available"):
            return

        score = auth.get("score", 0)
        level = auth.get("level", "LOW")
        signals = auth.get("signals") or []
        summary = auth.get("summary", "")

        level_colors = {
            "LOW": self.GOOD,
            "MEDIUM": self.WARN,
            "HIGH": self.BAD,
            "CRITICAL": self.BAD,
        }
        color = level_colors.get(level, self.MUTED)

        grid = Table.grid(padding=(0, 2))
        grid.add_column(style=self.LABEL, justify="right")
        grid.add_column(style=self.VALUE)

        filled = int(round(score / 10))
        bar = "█" * filled + "░" * (10 - filled)
        grid.add_row("Risk Score", f"[bold {color}]{score}/100  {bar}[/bold {color}]")
        grid.add_row("Level", f"[bold {color}]{level}[/bold {color}]")

        if signals:
            rows = []
            for sig in signals:
                rows.append(
                    f"[dim]+{sig.get('weight', 0)}[/dim] "
                    f"[bold]{escape(str(sig.get('name', '?')))}[/bold] - "
                    f"{escape(str(sig.get('detail', '')))}"
                )
            grid.add_row("Signals", "\n".join(rows))

        if summary:
            grid.add_row("Summary", f"[{self.MUTED}]{escape(summary)}[/{self.MUTED}]")

        title = (f"[bold {color}]AUTHENTICATION RISK: {level}[/bold {color}]"
                 if signals else "[bold]AUTHENTICATION RISK: CLEAN[/bold]")
        self.console.print(Panel(
            grid,
            title=title,
            border_style=color,
            padding=(1, 2),
        ))

    def _render_gps_spoof(self, spoof: Dict[str, Any]) -> None:
        """Render the GPS spoof-check section (compact when clean)."""
        issues = spoof.get("issues") or []
        verdict = str(spoof.get("verdict", ""))
        if "nothing to verify" in verdict:
            return  # no GPS at all - skip, the NO GPS verdict already covers it

        if not issues:
            self.console.print(
                f"[{self.GOOD}]GPS SPOOF CHECK: plausible[/{self.GOOD}] - {escape(verdict)}"
            )
            return

        lines = [f"  [dim]-[/dim] {escape(str(issue))}" for issue in issues]
        self.console.print(Panel(
            "\n".join(lines) + f"\n\n[{self.BAD}]{escape(verdict)}[/{self.BAD}]",
            title=f"[bold {self.BAD}]GPS SPOOF CHECK: {len(issues)} ISSUE(S)[/bold {self.BAD}]",
            border_style=self.BAD,
            padding=(1, 2),
        ))

    def _render_timestamp_check(self, check: Dict[str, Any]) -> None:
        """Render timestamp consistency (compact when clean)."""
        if not check.get("available"):
            return  # no timestamps at all - nothing worth showing

        issues = check.get("issues") or []
        verdict = str(check.get("verdict", ""))
        if not issues:
            line = (f"[{self.GOOD}]TIMESTAMP CHECK: consistent"
                    f"[/{self.GOOD}]")
            tz = check.get("inferred_tz")
            if tz:
                line += (f" [- capture timezone {escape(str(tz))} "
                         f"(inferred from GPS UTC)]")
            self.console.print(line)
            return

        lines = [f"  [dim]-[/dim] {escape(str(issue))}" for issue in issues]
        self.console.print(Panel(
            "\n".join(lines) + f"\n\n[{self.BAD}]{escape(verdict)}[/{self.BAD}]",
            title=f"[bold {self.BAD}]TIMESTAMP CHECK: {len(issues)} ISSUE(S)"
                  f"[/bold {self.BAD}]",
            border_style=self.BAD,
            padding=(1, 2),
        ))

    def _render_ai_generated(self, info: Dict[str, Any]) -> None:
        """Render AI-generation / C2PA findings (silent when clean)."""
        if not info.get("available"):
            return
        if info.get("detected"):
            conf = str(info.get("confidence") or "medium").upper()
            lines = [f"  [dim]-[/dim] {escape(str(sig))}"
                     for sig in info.get("signals") or []]
            verdict = str(info.get("verdict", ""))
            # Finding, not a security risk - red stays reserved for risks.
            color = self.WARN
            self.console.print(Panel(
                "\n".join(lines) + f"\n\n[{color}]{escape(verdict)}[/{color}]",
                title=f"[bold {color}]AI GENERATION MARKERS ({conf})"
                      f"[/bold {color}]",
                border_style=color,
                padding=(1, 2),
            ))
            return
        if info.get("c2pa"):
            verdict = str(info.get("verdict", ""))
            self.console.print(
                f"[{self.LABEL}]C2PA PROVENANCE[/{self.LABEL}] - "
                f"[{self.MUTED}]{escape(verdict)}[/{self.MUTED}]"
            )

    def _render_filename_origin(self, origin: Dict[str, Any]) -> None:
        """Render filename origin (screenshot / default naming) hint."""
        if not origin.get("detected"):
            return  # ordinary name - no hint worth printing
        label = str(origin.get("label", ""))
        verdict = str(origin.get("verdict", ""))
        self.console.print(
            f"[{self.GOOD}]FILENAME ORIGIN: {escape(label)}[/{self.GOOD}]"
            f" - {escape(verdict)}"
        )

    def _render_trailing(self, trailing: Dict[str, Any]) -> None:
        """Render trailing-data / polyglot detection (only when bytes exist)."""
        if not trailing.get("available"):
            return  # unsupported container or read error
        if trailing.get("trailing_bytes", 0) <= 0:
            return  # clean file - no trailing data, skip

        grid = Table.grid(padding=(0, 2))
        grid.add_column(style=self.LABEL, justify="right")
        grid.add_column(style=self.VALUE)

        grid.add_row("Format", str(trailing.get("format", "?")))
        end = trailing.get("logical_end")
        if end is not None:
            grid.add_row("Logical end", f"offset {end:,}")
        grid.add_row("Trailing bytes",
                     f"[bold {self.BAD}]{trailing.get('trailing_bytes'):,}[/bold {self.BAD}]")
        sigs = trailing.get("signatures") or []
        if sigs:
            grid.add_row("Signatures",
                         f"[bold {self.BAD}]{', '.join(escape(s) for s in sigs)}[/bold {self.BAD}]")
        grid.add_row("Polyglot",
                     f"[bold {self.BAD}]yes[/bold {self.BAD}]" if trailing.get("polyglot") else "no")
        preview = trailing.get("trailing_preview")
        if preview:
            grid.add_row("Preview", f"[{self.MUTED}]{escape(str(preview))}[/{self.MUTED}]")

        self.console.print(Panel(
            grid,
            title=f"[bold {self.BAD}]TRAILING DATA DETECTED[/bold {self.BAD}]",
            border_style=self.BAD,
            padding=(1, 2),
        ))

    def _render_panorama(self, pano: Dict[str, Any]) -> None:
        """Render panorama / 360 detection (only when markers are found)."""
        if not pano.get("available") or not pano.get("detected"):
            return  # standard photo - skip panel

        grid = Table.grid(padding=(0, 2))
        grid.add_column(style=self.LABEL, justify="right")
        grid.add_column(style=self.VALUE)

        grid.add_row("Kind",
                     f"[bold {self.GOOD}]'{escape(str(pano.get('kind')))}'"
                     f"[/bold {self.GOOD}]")
        for sig in (pano.get("signals") or [])[:8]:
            grid.add_row("", f"[{self.MUTED}]- {escape(str(sig))}[/{self.MUTED}]")

        self.console.print(Panel(
            grid,
            title=f"[bold {self.GOOD}]PANORAMA / 360 IMAGE[/bold {self.GOOD}]",
            border_style=self.GOOD,
            padding=(1, 2),
        ))

    @staticmethod
    def _gps_ifd_stripped(result: Any) -> bool:
        """Detect a stripped-GPS fingerprint: a GPS IFD exists but holds no
        coordinates (leftover `GPS GPSVersionID`, or a residual GPSInfo
        pointer). Some cameras with location disabled simply omit the GPS
        IFD entirely; others (e.g. Samsung) write an all-zero placeholder
        IFD - that case is flagged separately as `zero_placeholder`.
        """
        for cat_tags in result.exif_data.values():
            for key in cat_tags:
                if key.startswith("GPS "):
                    return True
        return "Image GPSInfo" in result.exif_data.get("Image", {})

    def _render_verdict(self, result: Any, forensics: Dict[str, Any] | None,
                        deep: Dict[str, Any] | None,
                        extra: Dict[str, Any] | None = None) -> None:
        """Render the final verdict panel - the memorable takeaway."""
        extra = extra or {}
        thumb = extra.get("thumbnail") or {}
        thumb_gps = (thumb.get("gps") or {})
        thumb_gps_ok = thumb_gps.get("available", False)
        thumb_device = (thumb.get("device") or {})
        thumb_device_ok = bool(thumb_device.get("make") or thumb_device.get("model"))

        is_image = getattr(result, "kind", "image") in ("image", "unknown")

        gps_ok = result.gps.get("available", False)
        device_ok = bool(result.device.get("make") or result.device.get("model"))
        platform = (forensics or {}).get("detected_platform")

        lines = []
        if gps_ok:
            lat = result.gps["latitude"]
            lon = result.gps["longitude"]
            lines.append(f"  [bold {self.GOOD}]GEOLOCATED[/bold {self.GOOD}]  {lat:.5f}, {lon:.5f}  "
                         f"-> [link={result.gps.get('google_maps_link', '')} underline]open in Google Maps[/link]")
        else:
            if not is_image:
                gps_note = "no location metadata in this file"
            elif result.gps.get("zero_placeholder"):
                gps_note = ("GPS IFD present but coordinates are (0,0) - "
                            "placeholder (location disabled or GPS not locked when taken)")
            else:
                gps_note = (
                    "GPS IFD found but empty - coordinates likely stripped"
                    if self._gps_ifd_stripped(result)
                    else "location not embedded (check camera/location permissions when taken)"
                )
            gps_note += (f" [bold {self.WARN}]BUT recovered from embedded "
                        f"thumbnail: {thumb_gps['latitude']:.5f}, {thumb_gps['longitude']:.5f}[/bold {self.WARN}]"
                        if thumb_gps_ok else "")
            lines.append(f"  [bold {self.BAD}]NO GPS[/bold {self.BAD}]  {gps_note}")

        if device_ok:
            parts = [result.device.get("brand"), result.device.get("model_name"), result.device.get("model")]
            desc = " ".join(dict.fromkeys(p for p in parts if p))  # dedupe, preserve order
            lines.append(f"  [bold {self.GOOD}]DEVICE IDENTIFIED[/bold {self.GOOD}]  {desc}")
        else:
            tail = (f" [bold {self.WARN}]BUT embedded thumbnail says "
                    f"{thumb_device.get('make') or '?'} {thumb_device.get('model') or '?'}"
                    f"[/bold {self.WARN}]" if thumb_device_ok else "")
            if is_image:
                lines.append(f"  [bold {self.BAD}]ANONYMOUS DEVICE[/bold {self.BAD}]  EXIF stripped - "
                             f"device unknown{tail}")
            else:
                lines.append(f"  [bold {self.BAD}]NO DEVICE METADATA[/bold {self.BAD}]  "
                             f"no author/device information found")

        if is_image:
            if platform:
                lines.append(f"  [bold {self.WARN}]PLATFORM TRACE[/bold {self.WARN}]  image shows {platform} transit signatures")
            else:
                lines.append(f"  [bold {self.GOOD}]NO PLATFORM TRACE[/bold {self.GOOD}]  no social media re-encoding detected")

        if result.has_embedded_thumbnail:
            if thumb_gps_ok:
                lines.append(f"  [bold {self.WARN}]GPS RECOVERED FROM THUMBNAIL[/bold {self.WARN}]  "
                             f"coordinates {thumb_gps['latitude']:.5f}, {thumb_gps['longitude']:.5f} "
                             f"survived inside the embedded preview")
            elif thumb_device_ok:
                lines.append(f"  [bold {self.WARN}]DEVICE RECOVERED FROM THUMBNAIL[/bold {self.WARN}]  "
                             f"embedded preview says {thumb_device.get('make') or '?'} "
                             f"{thumb_device.get('model') or '?'}")
            else:
                lines.append(f"  [{self.WARN}]THUMBNAIL RECOVERY[/{self.WARN}]  embedded thumbnail exists - possible lead")

        if deep and deep.get("ela", {}).get("available") and self._ela_implies_editing(deep["ela"]):
            lines.append(f"  [bold {self.BAD}]EDITING DETECTED[/bold {self.BAD}]  ELA suggests manipulation - treat with caution")

        if is_image:
            # Overall score: simple 0-10 heuristic (image authenticity)
            score = 0
            if gps_ok:
                score += 4
            elif thumb_gps_ok:
                score += 2  # partial win: coords survived in the thumbnail
            if device_ok:
                score += 3
            elif thumb_device_ok:
                score += 1
            if not platform:
                score += 1
            elif forensics and forensics.get("reencoded"):
                score += 1
            if result.timestamps:
                score += 1
            if result.has_embedded_thumbnail:
                score += 1

            score_line = Text()
            score_line.append(f"  FORENSIC SCORE: {score}/10  ", style="bold")
            score_bar = "█" * score + "░" * (10 - score)
            score_color = self.GOOD if score >= 7 else (self.WARN if score >= 4 else self.BAD)
            score_line.append(score_bar, style=score_color)
            body = "\n" + "\n".join(lines) + "\n\n" + str(score_line) + "\n"
        else:
            # Non-image containers: surface parser risk flags instead of the
            # image-authenticity score (meaningless for PDF/MP4/DOCX/...).
            notable = sorted(k for k in _RISKY_FLAGS
                             if (result.flags or {}).get(k))
            if notable:
                lines.append(f"  [bold {self.WARN}]NOTABLE[/bold {self.WARN}]  "
                             + ", ".join(notable))
            else:
                lines.append(f"  [bold {self.GOOD}]NO RISK FLAGS[/bold {self.GOOD}]  "
                             "no macros/JS/encryption detected")
            body = "\n" + "\n".join(lines) + "\n"

        self.console.print(Panel(
            body,
            title=f"[bold {self.ACCENT}]VERDICT[/bold {self.ACCENT}]",
            border_style=self.ACCENT,
            padding=(0, 1),
        ))

    def render_batch(self, batch: Dict[str, Any]) -> None:
        """Render batch intelligence (device clusters, timeline, sessions)."""
        clusters = batch.get("device_clusters") or []
        timeline = batch.get("timeline") or []
        sessions = batch.get("sessions") or []
        insights = batch.get("insights") or []

        lines = []

        if clusters:
            lines.append("Device clusters:")
            for c in clusters:
                serial = c.get("serial") or "no serial"
                lines.append(
                    f"  [bold {self.GOOD}]{c.get('make') or '?'} {c.get('model') or '?'}[/bold {self.GOOD}]"
                    f" x{c.get('count')}  [dim]({serial})[/dim]"
                )

        if timeline:
            lines.append("Capture timeline:")
            for t in timeline[:10]:
                lines.append(
                    f"  [{self.LABEL}]{t.get('timestamp')}[/{self.LABEL}]  {t.get('file')}"
                    f"  [dim]({t.get('source')})[/dim]"
                )
            if len(timeline) > 10:
                lines.append(f"  [dim]... {len(timeline) - 10} more[/dim]")

        if sessions:
            lines.append("Sessions (gap > 1h = new session):")
            for s in sessions[:8]:
                lines.append(
                    f"  [{self.LABEL}]{s.get('start')}[/{self.LABEL}] -> "
                    f"[{self.LABEL}]{s.get('end')}[/{self.LABEL}]  "
                    f"[bold]{s.get('count')}[/bold] image(s): "
                    f"[dim]{', '.join(s.get('files', [])[:4])}[/dim]"
                )
            if len(sessions) > 8:
                lines.append(f"  [dim]... {len(sessions) - 8} more[/dim]")

        if insights:
            lines.append("Insights:")
            for item in insights:
                lines.append(f"  [dim]*[/dim] {escape(str(item))}")

        if not lines:
            return  # nothing useful

        self.console.print(Panel(
            "\n".join(lines),
            title=f"[bold {self.ACCENT}]BATCH INTELLIGENCE[/bold {self.ACCENT}]"
                  f" [dim]({batch.get('total', 0)} images)[/dim]",
            border_style=self.ACCENT,
            padding=(1, 2),
        ))

    def render_dupes(self, dupes: Dict[str, Any]) -> None:
        """Render near-duplicate grouping results."""
        exact = dupes.get("exact_groups") or []
        near = dupes.get("near_groups") or []
        scores = dupes.get("scores") or {}

        if not exact and not near:
            return  # no duplicate groups found

        lines = []

        if exact:
            lines.append(f"Byte-identical groups ({len(exact)}):")
            for g in exact[:8]:
                lines.append(
                    f"  [bold {self.WARN}]{g.get('count')} copies[/bold {self.WARN}]  "
                    f"[dim]md5 {str(g.get('hash'))[:12]}…[/dim]  "
                    f"{', '.join(g.get('files', [])[:4])}"
                )

        if near:
            lines.append(f"Perceptually similar groups ({len(near)}):")
            for g in near[:8]:
                lines.append(
                    f"  [bold {self.WARN}]{g.get('count')} look-alikes[/bold {self.WARN}]  "
                    f"best: [bold {self.GOOD}]{g.get('best')}[/bold {self.GOOD}] "
                    f"[dim](originality {g.get('best_score', 0)}/10)[/dim]"
                )
                for f in g.get("files", [])[:5]:
                    sc = scores.get(f, {})
                    reason_txt = ", ".join(sc.get("reasons", [])[:3])
                    lines.append(f"    - {f}  [dim]({sc.get('score', 0)}/10"
                                 f"{' - ' + reason_txt if reason_txt else ''})[/dim]")

        self.console.print(Panel(
            "\n".join(lines),
            title=f"[bold {self.WARN}]NEAR-DUPLICATE GROUPS[/bold {self.WARN}]"
                  f" [dim]({dupes.get('analyzed', 0)} analyzed)[/dim]",
            border_style=self.WARN,
            padding=(1, 2),
        ))
