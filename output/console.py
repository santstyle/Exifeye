"""
Rich console output for metadata reports.
Designed for visual clarity: banner, colored panels, layered sections,
and a punchy verdict summary. No emojis - pure typography + color.

Theme: hacker-green (Matrix style) — bright green accents, lime warnings.
Red is reserved for real risks/errors only.
"""
from __future__ import annotations

from typing import Any, Dict

from rich.console import Console, Group
from rich.markup import escape
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich import box


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
        """Render the tool banner: EXIFEYE in ANSI Shadow, borderless, Matrix green."""
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

    def render(self, result: Any, forensics: Dict[str, Any] | None = None,
               deep: Dict[str, Any] | None = None,
               sections: set[str] | None = None) -> None:
        """Render full report to console. `sections` filters the panels shown."""
        all_sections = {"gps", "device", "social", "forensics", "exif"}
        s = sections if sections is not None else all_sections

        self._render_file_info(result)
        if "gps" in s:
            self._render_gps(result)
        if "device" in s:
            self._render_device(result)
        self._render_timestamps(result)

        if forensics and (("social" in s) if sections is not None
                          else forensics.get("detected_platform")):
            self._render_social_media(forensics)

        if deep and "forensics" in s:
            self._render_deep_forensics(deep)

        if "exif" in s:
            self._render_exif_categories(result)
        self._render_verdict(result, forensics, deep)

        if not result.gps.get("available"):
            # GPS missing -> point the user to find the ORIGINAL copy that
            # still holds the coordinates. Skip when GPS was already found.
            self.console.print(Rule(" LOCATE THE ORIGINAL "))
            self.console.print(
                "[dim]Reverse image search: [link=https://lens.google.com/]Google Lens[/link] | "
                "[link=https://yandex.com/images/]Yandex[/link] | "
                "[link=https://tineye.com/]TinEye[/link] | "
                "[link=https://www.bing.com/visualsearch]Bing Visual[/link] - "
                "find a copy of this image that kept its GPS (or check if original had location enabled)[/dim]"
            )

    def _render_file_info(self, result: Any) -> None:
        """Render basic file information as a header card."""
        dims = f"{result.dimensions[0]:,} x {result.dimensions[1]:,} px" if result.dimensions[0] else "Unknown"

        info = Table.grid(padding=(0, 2))
        info.add_column(style=self.LABEL, justify="right")
        info.add_column(style=self.VALUE)
        info.add_row("Format", f"[bold]{result.file_type.upper()}[/bold] ({result.mime_type})")
        info.add_row("File Size", f"{result.file_size:,} bytes  [dim]({result.file_size / 1024:.1f} KB)[/dim]")
        info.add_row("Dimensions", dims)
        info.add_row("Color Mode", result.mode or "[dim]Unknown[/dim]")
        info.add_row("DPI", f"{result.dpi[0]} x {result.dpi[1]}" if result.dpi else "[dim]not specified[/dim]")
        info.add_row("Orientation", result.orientation or "[dim]not specified[/dim]")
        info.add_row("ICC Profile", result.icc_profile or "[dim]none[/dim]")

        header = Panel(
            info,
            title=f"[bold {self.ACCENT}][ {result.file_name} ][/bold {self.ACCENT}]",
            subtitle=f"[dim]{result.file_path}[/dim]",
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

    def _render_verdict(self, result: Any, forensics: Dict[str, Any] | None,
                        deep: Dict[str, Any] | None) -> None:
        """Render the final verdict panel - the memorable takeaway."""
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
            lines.append(f"  [bold {self.BAD}]NO GPS[/bold {self.BAD}]  location not embedded (check camera/location permissions when taken)")

        if device_ok:
            parts = [result.device.get("brand"), result.device.get("model_name"), result.device.get("model")]
            desc = " ".join(dict.fromkeys(p for p in parts if p))  # dedupe, preserve order
            lines.append(f"  [bold {self.GOOD}]DEVICE IDENTIFIED[/bold {self.GOOD}]  {desc}")
        else:
            lines.append(f"  [bold {self.BAD}]ANONYMOUS DEVICE[/bold {self.BAD}]  EXIF stripped - device unknown")

        if platform:
            lines.append(f"  [bold {self.WARN}]PLATFORM TRACE[/bold {self.WARN}]  image shows {platform} transit signatures")
        else:
            lines.append(f"  [bold {self.GOOD}]NO PLATFORM TRACE[/bold {self.GOOD}]  no social media re-encoding detected")

        if result.has_embedded_thumbnail:
            lines.append(f"  [{self.WARN}]THUMBNAIL RECOVERY[/{self.WARN}]  embedded thumbnail exists - possible lead")

        if deep and deep.get("ela", {}).get("available") and self._ela_implies_editing(deep["ela"]):
            lines.append(f"  [bold {self.BAD}]EDITING DETECTED[/bold {self.BAD}]  ELA suggests manipulation - treat with caution")

        # Overall score: simple 0-10 heuristic
        score = 0
        if gps_ok:
            score += 4
        if device_ok:
            score += 3
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

        self.console.print(Panel(
            "\n" + "\n".join(lines) + "\n\n" + str(score_line) + "\n",
            title=f"[bold {self.ACCENT}]VERDICT[/bold {self.ACCENT}]",
            border_style=self.ACCENT,
            padding=(0, 1),
        ))
