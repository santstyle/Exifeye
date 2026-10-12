"""
ExifEye - OSINT image metadata extractor (EXIF + GPS + device + forensics).

Usage:
    python exifeye.py image.jpg
    python exifeye.py folder/ --recursive
    python exifeye.py image.jpg --json --html
    python exifeye.py image.jpg --lens     # private Google Lens search (local, no upload)
    python exifeye.py -h             # show all options
"""
from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

# Force UTF-8 output on Windows consoles so box characters / degree symbols
# render properly instead of raising 'charmap' encode errors.
if sys.platform == "win32":
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

from extractor.core import MetadataExtractor
from extractor.hashes import HashCalculator
from extractor.lens import open_for_lens
from analyzers.social_media import SocialMediaForensics
from analyzers.deep_forensics import DeepForensics
from analyzers.thumbnail_meta import ThumbnailMiner
from analyzers.jpeg_structure import JpegStructure
from analyzers.chunks import ChunkMiner
from analyzers.strings import StringMiner
from analyzers.dupes import DupHunter
from analyzers.batch_intel import BatchIntelligence
from analyzers.auth_risk import AuthenticationRiskMeter
from analyzers.gps_spoof import GpsSpoofCheck
from analyzers.trailing import TrailingDataDetector
from analyzers.panorama import PanoramaDetector
from output.console import ConsoleOutput
from output.json_export import JSONExport
from output.html_report import HTMLReport
from output.geo_export import GeoExporter
from output.raw_dump import RawTagDumper


console = Console()

# Hacker-green theme (Matrix style): bright green accent, lime warnings,
# red kept only for errors. Everything else stays in the green family.
GREEN = "#00ff41"    # Matrix accent green
LIME = "#c8f542"     # warnings / notices
MINT = "#9effb0"     # success / exported

SUPPORTED_EXTENSIONS = {
    ".jpg", ".jpeg", ".jfif", ".png", ".gif", ".webp", ".bmp", ".tiff",
    ".tif", ".heic", ".heif", ".cr2", ".nef", ".arw", ".raw",
}


def _collect_images(paths: list[str], recursive: bool) -> list[Path]:
    """Collect image files from provided paths (files or directories)."""
    images: list[Path] = []
    for raw in paths:
        p = Path(raw)
        if p.is_file():
            if p.suffix.lower() in SUPPORTED_EXTENSIONS:
                images.append(p)
            else:
                console.print(f"[{LIME}]Skipping unsupported file: {p}[/{LIME}]")
        elif p.is_dir():
            iterator = p.rglob("*") if recursive else p.glob("*")
            found = [f for f in iterator if f.is_file() and f.suffix.lower() in SUPPORTED_EXTENSIONS]
            images.extend(sorted(found))
        else:
            console.print(f"[red]Path not found: {p}[/red]")
    return images


def _prompt_for_target() -> str:
    """Ask interactively for an image/folder when no CLI targets are given.

    Returns the entered path (stripped, surrounding quotes removed), or ""
    when the user exits (empty line, Ctrl+C or EOF).
    """
    renderer = ConsoleOutput()
    try:
        raw = renderer.console.input(
            f"[bold {GREEN}]Target (image or folder, empty to exit) >[/bold {GREEN}] "
        )
    except (EOFError, KeyboardInterrupt):
        renderer.console.print("")
        return ""
    path = raw.strip()
    # Windows users often paste paths WITH quotes (from Explorer / cmd). The
    # interactive prompt never goes through a shell, so those quotes would be
    # literal characters and the path would not resolve. Strip one pair.
    if len(path) >= 2 and path[0] == path[-1] and path[0] in ('"', "'"):
        path = path[1:-1]
    return path


def _run_analysis(paths: list[str], recursive: bool, export_json: bool,
                  export_html: bool, output_dir: str | None, no_hashes: bool,
                  no_deep: bool, no_social: bool, quiet: bool,
                  sections: set[str] | None = None,
                  show_banner: bool = True, lens: bool = False,
                  show_strings: bool = False, find_dupes: bool = False,
                  diff: bool = False, export_geo: str | None = None,
                  extract_thumb: bool = False,
                  extract_thumb_dir: str | None = None,
                  scrub: bool = False,
                  html_index: bool = False,
                  dump_raw: bool = False) -> int:
    """Analyze the given paths and print reports. Returns process exit code."""
    images = _collect_images(paths, recursive)

    if not images:
        console.print("[red]No supported image files found.[/red]")
        return 1

    if lens and len(images) != 1:
        console.print("[red]--lens works with exactly one image.[/red]")
        return 1

    if diff and len(images) != 2:
        console.print("[red]--diff compares exactly two images.[/red]")
        return 1

    if find_dupes and len(images) < 2:
        console.print("[red]--find-dupes needs at least two images.[/red]")
        return 1

    if html_index:
        export_html = True  # index links per-image HTML reports
        if output_dir is None:
            # Keep every report (and the index) in one folder so relative
            # links resolve; default to the first image's directory.
            output_dir = str(images[0].parent)

    console_renderer = ConsoleOutput()
    if show_banner:
        console_renderer.render_banner()

    console.print(f"[bold {GREEN}]Found {len(images)} image(s) to analyze[/bold {GREEN}]\n")

    hash_calc = HashCalculator()
    social_fx = SocialMediaForensics()
    deep_fx = DeepForensics()
    thumbnail_miner = ThumbnailMiner()
    jpeg_struct = JpegStructure()
    chunk_miner = ChunkMiner()
    string_miner = StringMiner() if show_strings else None
    auth_meter = AuthenticationRiskMeter()
    gps_spoof_check = GpsSpoofCheck()
    trailing_detector = TrailingDataDetector()
    panorama_detector = PanoramaDetector()
    raw_dumper = RawTagDumper()
    json_exporter = JSONExport()
    html_exporter = HTMLReport()

    failed = 0
    used_stems: set[str] = set()
    results: list[Any] = []  # collected for batch intelligence / dupes
    index_entries: list[dict] = []  # for --html-index

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Analyzing...", total=len(images))

        for image_path in images:
            progress.update(task, description=f"Analyzing: {image_path.name}")

            try:
                # 1. Core extraction
                extractor = MetadataExtractor(image_path)
                result = extractor.extract()

                # 2. Forensics
                forensics = {} if no_social else social_fx.analyze(image_path, result)

                deep = {}
                if not no_deep:
                    deep = {
                        "ela": deep_fx.run_ela(image_path),
                        "steganography": deep_fx.check_steganography(image_path),
                        "entropy": deep_fx.analyze_entropy(image_path),
                    }

                # 3. Hashes
                hashes = {} if no_hashes else hash_calc.compute_all(image_path)

                # 4. v2.0 analyzers: thumbnail recovery, JPEG structure and
                #    chunk mining run always-on; embedded strings only when
                #    requested (it reads raw bytes and is the slowest one).
                extra = {
                    "thumbnail": thumbnail_miner.analyze(image_path),
                    "jpeg_structure": jpeg_struct.analyze(image_path),
                    "chunks": chunk_miner.analyze(image_path),
                }
                if string_miner is not None:
                    extra["strings"] = string_miner.analyze(image_path)

                # 4b. Authentication risk meter: combine all signals above
                #     into a single authenticity score.
                extra["auth_risk"] = auth_meter.analyze(
                    result, forensics, deep, extra
                )

                # 4c. GPS spoof-check + trailing-data / polyglot detection.
                extra["gps_spoof"] = gps_spoof_check.analyze(
                    result.gps, result.timestamps
                )
                extra["trailing"] = trailing_detector.analyze(image_path)

                # 4c2. Panorama / 360 detection (XMP GPano + device hints).
                extra["panorama"] = panorama_detector.analyze(
                    image_path, result.xmp_data, result.device
                )

                # 4d. Dump the embedded EXIF thumbnail to a standalone file
                #     when requested (reuses the offset/length the miner
                #     already located - no second JPEG walk needed).
                if extract_thumb:
                    thumb = extra["thumbnail"]
                    if thumb.get("available") and thumb.get("offset") is not None \
                            and thumb.get("length"):
                        thumb_path = _extract_thumbnail(
                            image_path, thumb, extract_thumb_dir
                        )
                        if thumb_path and not quiet:
                            console.print(
                                f"[{MINT}]Thumbnail extracted:[/{MINT}] {thumb_path}"
                            )
                    elif not quiet:
                        console.print(
                            f"[{LIME}]No embedded thumbnail to extract "
                            f"in {image_path.name}[/{LIME}]"
                        )

                # 4e. Scrub: write a metadata-free copy when requested.
                if scrub:
                    scrubbed = _scrub_image(image_path)
                    if scrubbed and not quiet:
                        console.print(
                            f"[{MINT}]Scrubbed copy:[/{MINT}] {scrubbed}"
                        )

                # 4f. Raw tag dump: full exifread inventory to a text file.
                if dump_raw:
                    try:
                        dump_path = raw_dumper.dump(image_path)
                        if not quiet:
                            console.print(
                                f"[{MINT}]Raw tag dump:[/{MINT}] {dump_path}"
                            )
                    except RuntimeError as e:
                        console.print(
                            f"[{LIME}]Raw dump failed for "
                            f"{image_path.name}: {e}[/{LIME}]"
                        )

                # 5. Output
                if quiet:
                    _print_quiet_summary(result, forensics, extra)
                else:
                    console_renderer.render(
                        result, forensics, deep, sections=sections, extra=extra
                    )

                # 6. Exports
                if export_json or export_html:
                    out_dir = (Path(output_dir) if output_dir
                               else Path(result.file_path).parent)
                    stem = Path(result.file_path).stem
                    if stem in used_stems:
                        # Same stem from different dirs/extensions (empty.jpg vs
                        # empty.webp) - disambiguate to prevent overwriting.
                        candidate = f"{stem}__{Path(result.file_path).parent.name}"
                        counter = 2
                        while candidate in used_stems:
                            candidate = f"{stem}__{counter}"
                            counter += 1
                        stem = candidate
                    used_stems.add(stem)

                    exported = []
                    if export_json:
                        json_path = json_exporter.export(
                            result, forensics, deep, hashes, out_dir,
                            filename=f"{stem}_metadata_report.json",
                            extra=extra,
                        )
                        exported.append(str(json_path))
                    if export_html:
                        html_path = html_exporter.export(
                            result, forensics, deep, hashes, out_dir,
                            filename=f"{stem}_report.html",
                            extra=extra,
                        )
                        exported.append(str(html_path))
                        if html_index:
                            thumb_gps = (
                                (extra.get("thumbnail") or {}).get("gps") or {}
                            ).get("available")
                            if result.gps.get("available"):
                                gps_flag = "YES"
                            elif thumb_gps:
                                gps_flag = "THUMB"
                            else:
                                gps_flag = "NO"
                            auth = extra.get("auth_risk") or {}
                            index_entries.append({
                                "file_name": result.file_name,
                                "report_href": html_path.name,
                                "device": " ".join(filter(
                                    None,
                                    [result.device.get("make"),
                                     result.device.get("model")],
                                )) or None,
                                "gps": gps_flag,
                                "risk": (auth.get("level")
                                         if auth.get("available") else None),
                            })
                    if exported:
                        console.print(f"[{MINT}]Exported:[/{MINT}] {', '.join(exported)}")

                if forensics.get("detected_platform"):
                    console.print(
                        f"[{LIME}]Note: platform '{forensics['detected_platform']}' detected - "
                        f"EXIF may be stripped, residual traces analyzed above[/{LIME}]"
                    )

                results.append(result)

            except PermissionError:
                console.print(f"[red]Permission denied: {image_path}[/red]")
                failed += 1
            except Exception as e:
                console.print(f"[red]Error analyzing {image_path.name}: {e}[/red]")
                failed += 1
            finally:
                progress.update(task, advance=1)

    # Post-loop intelligence: batch overview when scanning several images,
    # near-duplicate groups when requested, field-by-field diff when given
    # exactly two images.
    if export_geo and results:
        geo_path = GeoExporter().export(results, output_dir, export_geo)
        if geo_path:
            console.print(
                f"[{MINT}]Geo export ({export_geo.upper()}):[/{MINT}] {geo_path}"
            )
        else:
            console.print(
                f"[{LIME}]No geolocated images found - geo export skipped[/{LIME}]"
            )

    if html_index:
        if len(index_entries) >= 2:
            idx_path = html_exporter.write_index(index_entries, output_dir)
            console.print(f"[{MINT}]Batch index:[/{MINT}] {idx_path}")
        else:
            console.print(
                f"[{LIME}]--html-index needs 2+ HTML reports "
                f"(got {len(index_entries)}) - skipped[/{LIME}]"
            )

    if not quiet and len(results) >= 2 and not diff:
        batch = BatchIntelligence().analyze(results)
        console_renderer.render_batch(batch)

    if not quiet and find_dupes and len(results) >= 2:
        dupes = DupHunter().analyze([r.file_path for r in results])
        console_renderer.render_dupes(dupes)

    if diff and len(results) == 2 and not quiet:
        _render_diff(results[0], results[1])

    if lens:
        _run_lens_search(images[0])

    console.print(
        f"\n[bold {GREEN}]Done: {len(images) - failed}/{len(images)} analyzed"
        f"{', ' + str(failed) + ' failed' if failed else ''}[/bold {GREEN}]"
    )
    return 1 if failed else 0


def _extract_thumbnail(image_path: Path, thumb: dict,
                       extract_dir: str | None) -> Path | None:
    """Write the embedded thumbnail JPEG (located by ThumbnailMiner) to disk.

    Returns the written path, or None when the byte range is not a valid
    JPEG (defensive - a corrupted offset must never produce a broken file).
    """
    offset = thumb["offset"]
    length = thumb["length"]
    try:
        with open(image_path, "rb") as f:
            f.seek(offset)
            data = f.read(length)
    except OSError:
        return None
    if len(data) < 4 or data[:2] != b"\xff\xd8":
        return None

    target_dir = Path(extract_dir) if extract_dir else image_path.parent
    target_dir.mkdir(parents=True, exist_ok=True)
    stem = image_path.stem
    out = target_dir / f"{stem}_thumb.jpg"
    counter = 2
    while out.exists():
        out = target_dir / f"{stem}_thumb_{counter}.jpg"
        counter += 1
    out.write_bytes(data)
    return out


def _scrub_jpeg_bytes(data: bytes) -> bytes | None:
    """Strip EXIF / XMP / IPTC / comment segments from a JPEG, keeping the
    quantization tables, Huffman tables, frame header, ICC profile (APP2)
    and the entropy-coded image data byte-for-byte identical.

    Returns the scrubbed bytes, or None when the stream is malformed.
    """
    n = len(data)
    if n < 4 or data[:2] != b"\xff\xd8":
        return None
    out = bytearray(b"\xff\xd8")
    i = 2
    while i + 1 < n:
        if data[i] != 0xFF:
            return None
        marker = data[i + 1]
        if marker == 0xD9:  # EOI
            out += b"\xff\xd9"
            return bytes(out)
        if marker == 0xDA:  # SOS - copy header + entropy data up to EOI
            if i + 3 >= n:
                return None
            seg_len = (data[i + 2] << 8) | data[i + 3]
            if seg_len < 2 or i + 2 + seg_len > n:
                return None
            out += data[i:i + 2 + seg_len]
            j = i + 2 + seg_len
            scan_start = j
            while j + 1 < n:
                if data[j] == 0xFF:
                    nxt = data[j + 1]
                    if nxt == 0x00 or 0xD0 <= nxt <= 0xD7:
                        j += 2  # stuffed byte / RSTn - still inside the scan
                        continue
                    out += data[scan_start:j]  # entropy bytes up to this marker
                    if nxt == 0xD9:  # EOI
                        out += b"\xff\xd9"
                        return bytes(out)
                    i = j  # next marker (progressive multi-scan)
                    break
                j += 1
            else:
                return None
            continue
        if marker in (0x01, 0xD8) or (0xD0 <= marker <= 0xD7) or marker == 0x00:
            i += 2
            continue
        if i + 3 >= n:
            return None
        seg_len = (data[i + 2] << 8) | data[i + 3]
        if seg_len < 2 or i + 2 + seg_len > n:
            return None
        seg = data[i:i + 2 + seg_len]
        if marker == 0xE0:  # APP0 JFIF - harmless, keep for decoder compat
            out += seg
        elif marker == 0xE2:  # APP2 - keep ONLY the ICC profile chunks
            payload = data[i + 4:i + 2 + seg_len]
            if payload.startswith(b"ICC_PROFILE\x00"):
                out += seg
        elif marker in (0xC4, 0xC8, 0xCC):  # DHT / JPG / DAC
            out += seg
        elif 0xC0 <= marker <= 0xCF:  # SOF frame header
            out += seg
        elif marker == 0xDB:  # DQT
            out += seg
        elif marker == 0xDD:  # DRI
            out += seg
        # APP1(EXIF/XMP/MPF), APP3-15, COM and anything else: dropped.
        i += 2 + seg_len
    return None


def _scrub_png_bytes(data: bytes) -> bytes | None:
    """Drop text / eXIf chunks from a PNG, keeping pixel data (IDAT) and
    color-critical chunks (iCCP, sRGB, gAMA, ...) byte-for-byte identical."""
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        return None
    keep = {b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tRNS", b"gAMA", b"cHRM",
            b"sRGB", b"iCCP", b"sBIT"}
    out = bytearray(data[:8])
    i = 8
    n = len(data)
    while i + 8 <= n:
        length = int.from_bytes(data[i:i + 4], "big")
        ctype = data[i + 4:i + 8]
        total = 12 + length
        if i + total > n:
            return None
        if ctype in keep:
            out += data[i:i + total]
        if ctype == b"IEND":
            break
        i += total
    return bytes(out)


def _scrub_webp_bytes(data: bytes) -> bytes | None:
    """Drop EXIF / XMP chunks from a WebP container, keeping the image
    bitstream (VP8/VP8L) and ICC profile (ICCP) byte-for-byte identical."""
    if len(data) < 12 or data[:4] != b"RIFF" or data[8:12] != b"WEBP":
        return None
    keep = {b"VP8 ", b"VP8L", b"VP8X", b"ALPH", b"ICCP", b"ANIM", b"ANMF"}
    out = bytearray(b"RIFF\x00\x00\x00\x00WEBP")
    i = 12
    n = len(data)
    while i + 8 <= n:
        fourcc = data[i:i + 4]
        size = int.from_bytes(data[i + 4:i + 8], "little")
        total = 8 + size + (size % 2)
        if i + total > n:
            return None
        if fourcc in keep:
            out += data[i:i + 8 + size]
            if size % 2:
                out += b"\x00"
        i += total
    riff_size = len(out) - 8
    out[4:8] = riff_size.to_bytes(4, "little")
    return bytes(out)


def _scrub_image(image_path: Path) -> Path | None:
    """Write a metadata-stripped copy of the image next to the original.

    JPEG / PNG / WebP are scrubbed at the container level so the pixel data
    stays bit-for-bit identical. Other formats are re-saved through Pillow
    (lossless for GIF-palette / BMP / TIFF). Returns the new path, or None
    on failure.
    """
    try:
        data = image_path.read_bytes()
    except OSError as e:
        console.print(f"[red]Scrub failed for {image_path.name}: {e}[/red]")
        return None

    scrubbed: bytes | None = None
    if data[:3] == b"\xff\xd8\xff":
        scrubbed = _scrub_jpeg_bytes(data)
    elif data[:8] == b"\x89PNG\r\n\x1a\n":
        scrubbed = _scrub_png_bytes(data)
    elif data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        scrubbed = _scrub_webp_bytes(data)
    else:
        # GIF / BMP / TIFF / ... : re-save through Pillow (best effort).
        try:
            import io

            from PIL import Image

            img = Image.open(io.BytesIO(data))
            buf = io.BytesIO()
            save_kwargs = {}
            icc = img.info.get("icc_profile")
            if icc:
                save_kwargs["icc_profile"] = icc
            fmt = (img.format or "").upper()
            if fmt == "WEBP":
                save_kwargs["quality"] = "keep"
            img.save(buf, format=fmt, **save_kwargs)
            scrubbed = buf.getvalue()
            img.close()
        except Exception as e:
            console.print(f"[red]Scrub failed for {image_path.name}: {e}[/red]")
            return None

    if not scrubbed:
        console.print(
            f"[red]Scrub failed for {image_path.name}: malformed container[/red]"
        )
        return None

    stem = image_path.stem
    ext = image_path.suffix.lower() or ".jpg"
    out_path = image_path.parent / f"{stem}_scrubbed{ext}"
    counter = 2
    while out_path.exists():
        out_path = image_path.parent / f"{stem}_scrubbed_{counter}{ext}"
        counter += 1
    out_path.write_bytes(scrubbed)
    return out_path


def _run_lens_search(image_path: Path) -> None:
    """Open the local image for a Google Lens search - private by default.

    ExifEye does NOT upload the image anywhere. It opens the local file in
    the browser; the user right-clicks it and picks "Search image with
    Google" (Chrome/Edge), which sends the picture to Google Lens exactly
    once, through the user's own browser, with the image pre-selected.
    """
    if open_for_lens(image_path):
        console.print(f"\n[{MINT}]Opened in browser (local copy, nothing uploaded):[/{MINT}] {image_path}")
        console.print(f"[{LIME}]Right-click the image -> 'Search image with Google'[/{LIME}]")
        console.print(
            f"[{LIME}]Google Lens opens with this image pre-selected - the image only "
            f"leaves your machine when YOU search it.[/{LIME}]"
        )
    else:
        console.print("[red]Could not open the browser.[/red]")


@click.command(name="exifeye", context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("paths", nargs=-1, required=False)
@click.option("-r", "--recursive", is_flag=True, help="Scan directories recursively")
@click.option("--json", "export_json", is_flag=True, help="Export report as JSON")
@click.option("--html", "export_html", is_flag=True, help="Export report as HTML")
@click.option("--output-dir", type=click.Path(), default=None, help="Directory for exported reports")
@click.option("--no-hashes", is_flag=True, help="Skip file hash calculation")
@click.option("--no-deep", is_flag=True, help="Skip deep forensics (ELA, steganography)")
@click.option("--no-social", is_flag=True, help="Skip social media forensics")
@click.option("--quiet", "-q", is_flag=True, help="Only print the summary, not full report")
@click.option("--device-db", type=click.Path(exists=True), default=None,
              help="Path to custom device enrichment JSON database")
@click.option("--lens", is_flag=True,
              help="Open the local image for Google Lens search (no upload - "
                   "right-click the image in the browser to search)")
@click.option("--strings", "show_strings", is_flag=True,
              help="Scan raw bytes for embedded strings (URLs, emails, phones, "
                   "IPs, device/software names, GPS hints)")
@click.option("--find-dupes", "find_dupes", is_flag=True,
              help="Group exact + near-duplicate images and rank the most "
                   "original copy (needs 2+ images)")
@click.option("--diff", is_flag=True,
              help="Compare two images field-by-field (EXIF, GPS, device)")
@click.option("--export-geo", type=click.Choice(["kml", "gpx", "csv"]), default=None,
              help="Export geolocated image coordinates to KML/GPX/CSV "
                   "(one file with all GPS points)")
@click.option("--extract-thumb", is_flag=True,
              help="Save the embedded EXIF thumbnail to a standalone .jpg file")
@click.option("--extract-thumb-dir", type=click.Path(), default=None,
              help="Directory for extracted thumbnails (default: image folder)")
@click.option("--scrub", is_flag=True,
              help="Write a metadata-stripped copy (<name>_scrubbed.<ext>): "
                   "EXIF/XMP/IPTC/GPS removed, pixel data + ICC profile "
                   "preserved bit-for-bit")
@click.option("--html-index", is_flag=True,
              help="Write one index.html linking all HTML reports (needs 2+ "
                   "images; auto-enables --html and defaults output to the "
                   "first image's folder)")
@click.option("--dump-raw", is_flag=True,
              help="Dump every raw EXIF tag to <name>_raw_tags.txt next to "
                   "the image (full exifread inventory)")
def main(paths, recursive, export_json, export_html, output_dir, no_hashes,
         no_deep, no_social, quiet, device_db, lens, show_strings,
         find_dupes, diff, export_geo, extract_thumb, extract_thumb_dir,
         scrub, html_index, dump_raw):
    """ExifEye - read EXIF, GPS, device info and more from images.

    Run without arguments to enter the interactive prompt and choose an
    image or folder to analyze.
    """
    show_banner = True
    if not paths:
        ConsoleOutput().render_banner()
        target = _prompt_for_target()
        if not target:
            click.echo("No target given - exiting.")
            return
        paths = (target,)
        show_banner = False

    sys.exit(_run_analysis(
        list(paths), recursive, export_json, export_html, output_dir,
        no_hashes, no_deep, no_social, quiet, show_banner=show_banner,
        lens=lens, show_strings=show_strings, find_dupes=find_dupes,
        diff=diff, export_geo=export_geo,
        extract_thumb=extract_thumb, extract_thumb_dir=extract_thumb_dir,
        scrub=scrub, html_index=html_index, dump_raw=dump_raw,
    ))


def _print_quiet_summary(result, forensics, extra=None):
    """Print a one-line summary per image."""
    gps = "GPS:YES"
    if not result.gps.get("available"):
        # GPS may still have survived inside the embedded thumbnail.
        thumb = (extra or {}).get("thumbnail") or {}
        if (thumb.get("gps") or {}).get("available"):
            gps = "GPS:THUMB"
        else:
            gps = "GPS:NO"
    device = result.device
    dev = " ".join(filter(None, [device.get("make"), device.get("model")])) or "unknown"
    platform = forensics.get("detected_platform") or "-"
    if forensics.get("whatsapp_filename_date"):
        platform = f"whatsapp({forensics['whatsapp_filename_date']})"
    risk = (extra or {}).get("auth_risk") or {}
    risk_part = (f" | Risk: {risk.get('level')} ({risk.get('score')})"
                 if risk.get("available") else "")
    console.print(
        f"[bold]{result.file_name}[/bold] | {gps} | Device: {dev} | "
        f"Platform: {platform}{risk_part}"
    )


def _render_diff(left, right) -> None:
    """Render a field-by-field comparison of two extraction results."""
    from rich.table import Table

    table = Table(title=f"[bold {GREEN}]FIELD-BY-FIELD DIFF[/bold {GREEN}]",
                  header_style=f"bold {GREEN}", border_style=GREEN,
                  pad_edge=False)
    table.add_column("Field", style=LIME, no_wrap=False, ratio=1)
    table.add_column(Path(left.file_path).name, style="white", ratio=2,
                     overflow="fold")
    table.add_column(Path(right.file_path).name, style="white", ratio=2,
                     overflow="fold")

    def cell(result, name):
        if name == "GPS":
            gps = result.gps
            if gps.get("available"):
                return (f"YES {gps['latitude']:.6f}, {gps['longitude']:.6f}"
                        f" ({gps.get('source', 'EXIF')})")
            return "NO"
        if name == "Device":
            d = result.device
            parts = [d.get("make"), d.get("model"), d.get("model_name")]
            desc = " ".join(dict.fromkeys(p for p in parts if p))
            return desc or "unknown"
        if name == "Taken":
            return (result.timestamps.get("original")
                    or result.timestamps.get("digitized")
                    or result.timestamps.get("modified") or "-")
        if name == "Dimensions":
            return f"{result.dimensions[0]}x{result.dimensions[1]}" if result.dimensions[0] else "-"
        if name == "Software":
            return result.software or result.device.get("software") or "-"
        if name == "Size":
            return f"{result.file_size:,} bytes"
        if name == "Platform":
            return result.file_type.upper()
        return "-"

    def differs(a, b):
        return str(a) != str(b)

    for field in ("Platform", "Dimensions", "Size", "Taken", "Device", "Software", "GPS"):
        left_val = cell(left, field)
        right_val = cell(right, field)
        if differs(left_val, right_val):
            table.add_row(f"[bold {LIME}]{field}[/bold {LIME}]",
                          f"[{LIME}]{left_val}[/{LIME}]",
                          f"[{LIME}]{right_val}[/{LIME}]")
        else:
            table.add_row(f"{field}", left_val, right_val)

    console.print(table)


if __name__ == "__main__":
    main()
