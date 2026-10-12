"""
ExifEye - OSINT image metadata extractor (EXIF + GPS + device + forensics).

Usage:
    python exifeye.py image.jpg
    python exifeye.py folder/ --recursive
    python exifeye.py image.jpg --json --html
    python exifeye.py image.jpg --lens     # reverse-image search (Lens/Yandex/...)
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
from extractor.lens import open_reverse_search, upload_image
from analyzers.social_media import SocialMediaForensics
from analyzers.deep_forensics import DeepForensics
from output.console import ConsoleOutput
from output.json_export import JSONExport
from output.html_report import HTMLReport


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
                  show_banner: bool = True, lens: bool = False) -> int:
    """Analyze the given paths and print reports. Returns process exit code."""
    images = _collect_images(paths, recursive)

    if not images:
        console.print("[red]No supported image files found.[/red]")
        return 1

    if lens and len(images) != 1:
        console.print("[red]--lens works with exactly one image.[/red]")
        return 1

    console_renderer = ConsoleOutput()
    if show_banner:
        console_renderer.render_banner()

    console.print(f"[bold {GREEN}]Found {len(images)} image(s) to analyze[/bold {GREEN}]\n")

    hash_calc = HashCalculator()
    social_fx = SocialMediaForensics()
    deep_fx = DeepForensics()
    json_exporter = JSONExport()
    html_exporter = HTMLReport()

    failed = 0
    used_stems: set[str] = set()

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

                # 4. Output
                if quiet:
                    _print_quiet_summary(result, forensics)
                else:
                    console_renderer.render(result, forensics, deep, sections=sections)

                # 5. Exports
                if export_json or export_html:
                    out_dir = Path(output_dir) if output_dir else result.file_path.parent
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
                        )
                        exported.append(str(json_path))
                    if export_html:
                        html_path = html_exporter.export(
                            result, forensics, deep, hashes, out_dir,
                            filename=f"{stem}_report.html",
                        )
                        exported.append(str(html_path))
                    if exported:
                        console.print(f"[{MINT}]Exported:[/{MINT}] {', '.join(exported)}")

                if forensics.get("detected_platform"):
                    console.print(
                        f"[{LIME}]Note: platform '{forensics['detected_platform']}' detected - "
                        f"EXIF may be stripped, residual traces analyzed above[/{LIME}]"
                    )

            except PermissionError:
                console.print(f"[red]Permission denied: {image_path}[/red]")
                failed += 1
            except Exception as e:
                console.print(f"[red]Error analyzing {image_path.name}: {e}[/red]")
                failed += 1
            finally:
                progress.update(task, advance=1)

    if lens:
        _run_reverse_search(images[0])

    console.print(
        f"\n[bold {GREEN}]Done: {len(images) - failed}/{len(images)} analyzed"
        f"{', ' + str(failed) + ' failed' if failed else ''}[/bold {GREEN}]"
    )
    return 1 if failed else 0


def _run_reverse_search(image_path: Path) -> None:
    """Upload a single image and open Google Lens / Yandex / Bing / TinEye.

    The classic OSINT bypass for a picture with missing GPS: an online copy
    of the same image often kept its coordinates.
    """
    console.print(f"\n[{LIME}]Reverse image search: uploading {image_path.name} ...[/{LIME}]")
    try:
        hosted = upload_image(image_path)
    except Exception as e:
        console.print(f"[red]Reverse image search failed: {e}[/red]")
        return
    console.print(f"[{MINT}]Uploaded to public host:[/{MINT}] {hosted}")
    opened = open_reverse_search(hosted)
    if opened:
        console.print(f"[{MINT}]Opened in browser:[/{MINT}] {', '.join(opened)}")
    else:
        console.print("[red]Could not open the browser.[/red]")
    console.print(
        f"[{LIME}]Tip: run search hits through ExifEye - a copy that still has "
        f"GPS is the fastest way to a location.[/{LIME}]"
    )


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
              help="Reverse-image search the image via Google Lens / Yandex / Bing / TinEye "
                   "(uploads it to a public host first)")
def main(paths, recursive, export_json, export_html, output_dir, no_hashes,
         no_deep, no_social, quiet, device_db, lens):
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
        lens=lens,
    ))


def _print_quiet_summary(result, forensics):
    """Print a one-line summary per image."""
    gps = "GPS:YES" if result.gps.get("available") else "GPS:NO"
    device = result.device
    dev = " ".join(filter(None, [device.get("make"), device.get("model")])) or "unknown"
    platform = forensics.get("detected_platform") or "-"
    if forensics.get("whatsapp_filename_date"):
        platform = f"whatsapp({forensics['whatsapp_filename_date']})"
    console.print(f"[bold]{result.file_name}[/bold] | {gps} | Device: {dev} | Platform: {platform}")


if __name__ == "__main__":
    main()
