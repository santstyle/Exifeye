<p align="center">
  <img src="thumbnail.png" alt="ExifEye - Neon Forensic Intelligence">
</p>

# ExifEye

**IMAGE INTELLIGENCE | EXIF + GPS + DEVICE + FORENSICS**

[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](#requirements)
[![CLI](https://img.shields.io/badge/interface-CLI-brightgreen.svg)](#usage)

An OSINT command-line tool that mines a single file — an image, a document,
or a video — or a whole folder for every trace a camera, phone, or office
app leaves behind: EXIF metadata, embedded GPS coordinates, device/camera
identification, editing and steganography forensics, platform re-encoding
fingerprints, and cryptographic hashes for cross-referencing.

> **Legal note:** the target image does **not** need to be inside this folder.
> Point the tool at any path — absolute or relative — from anywhere on disk.

---

## Table of Contents

- [Features](#features)
- [Supported Formats](#supported-formats)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Options](#options)
- [Report Sections](#report-sections)
- [Custom Device Database](#custom-device-database)
- [How It Works](#how-it-works)
- [Testing](#testing)
- [Disclaimer](#disclaimer)

---

## Features

- **EXIF metadata extraction** — make, model, lens, focal length, aperture,
  shutter speed, ISO, timestamps (taken / digitized / modified), software,
  serial numbers, unique image IDs, and more.
- **GPS geolocation** — decodes EXIF GPS tags, converts to decimal degrees,
  derives a [geohash](https://en.wikipedia.org/wiki/Geohash), and prints a
  one-click Google Maps link.
- **XMP GPS recovery** — when EXIF has been stripped but a residual XMP
  description survives (common with Google Camera / Photosphere pipelines),
  coordinates are recovered from the XMP block and reported as
  *"XMP residual metadata (recovered)"*.
- **Device / camera identification** — pattern-driven brand and device-type
  recognition (smartphone, camera, drone, action cam, webcam) that works even
  for brand-new models. Raw `Make` / `Model` values are always preserved.
- **OS / platform detection** — reads the `Software` tag to detect Android,
  iOS, macOS, Windows, MIUI, One UI, etc.
- **Device enrichment database** — an editable JSON file adds friendly model
  names and release years without ever overriding raw values.
- **Social media forensics** — analyzes re-encoding artifacts, JPEG
  structure, platform signature strings, dimension heuristics and text
  artifacts to suggest which platform an image may have traveled through.
- **WhatsApp filename detection** — WhatsApp media files follow the
  `IMG-YYYYMMDD-WA####.jpg` pattern; the received date is extracted
  automatically (`IMG-20230415-WA0001.jpg` -> `2023-04-15`). The modern
  desktop downloader pattern is recognized too: `WhatsApp Image
  2026-10-11 at 21.03.19.jpeg` reveals the exact receive date + time.
- **Thumbnail metadata mining** — cameras embed a small JPEG preview
  inside the EXIF block; even when the main image is stripped, that
  thumbnail can still carry GPS, device, timestamp and software traces
  (reported as recovered metadata).
- **JPEG structure analysis** — marker inventory (APPn / DQT / DHT /
  SOF / COM), estimated rendering quality, chroma subsampling
  (4:2:0 / 4:2:2 / 4:4:4), progressive flag and comments — a strong
  fingerprint for re-encoded platform images.
- **Container chunk mining** — PNG `tEXt` / `iTXt` / `zTXt` / `eXIf`,
  GIF comment + application extensions, and WebP `EXIF` / `XMP` chunks
  are decoded; an `eXIf` / `EXIF` chunk is parsed like a camera file, so
  GPS can be recovered from formats that normally show nothing.
- **Embedded strings miner** — `--strings` scans the raw bytes for URLs,
  emails, phone numbers, IPs, device/software names and GPS hints that
  survive full metadata stripping (also catches Windows UTF-16 strings).
- **Near-duplicate hunter** — `--find-dupes` groups byte-identical and
  perceptually similar images (phash) and ranks which copy is the most
  original (GPS / resolution / timestamps / embedded thumbnail).
- **Batch intelligence** — analyzing a folder clusters images by device
  serial, builds a capture timeline, splits photo sessions by gaps, and
  surfaces insights (same physical camera across files, timeline spans,
  largest gap, fully-stripped batch warnings).
- **Private reverse image search** — `--lens` opens the image locally in
  your browser with a Google Lens tab ready: one right-click →
  "Search image with Google" sends it to Lens with the image pre-selected,
  through your own browser. The tool itself **never uploads** the picture
  anywhere — nothing leaves your machine unless you choose to search it.
- **Deep forensics** — Error Level Analysis (ELA) to spot edited regions,
  basic LSB steganography detection, and image entropy analysis.
- **Multi-format support** — automatic magic-byte detection: images
  (JPEG/PNG/GIF/WebP/BMP/TIFF/HEIC/RAW), documents (PDF, DOCX/XLSX/PPTX,
  legacy DOC/XLS/PPT/MSI via OLE), and video (MP4/MOV container metadata
  with creation time, dimensions and GPS when present).
- **Timestamp consistency check** — cross-references EXIF local time,
  GPS UTC, document and video container clocks: infers the capture
  timezone, flags zero/epoch placeholders, future dates, impossible field
  ordering and unexplainable camera-clock skew.
- **Filename origin forensics** — recognizes screenshot naming (macOS,
  Windows, Android) and device-default camera/phone filenames (IMG_ iOS/
  Canon, DSC/DSCN, PXL_ Pixel), so "no GPS on a screenshot" reads as
  expected rather than stripped metadata.
- **AI generation & C2PA detection** — scans EXIF/XMP attribution fields
  and raw bytes for generator names (Midjourney, Stable Diffusion,
  DALL·E, ...), IPTC digital source types (`trainedAlgorithmicMedia` /
  `compositelyGenerated`) and C2PA/JUMBF provenance manifests. Honest
  verdicts: detection, not cryptographic validation.
- **GPS exports** — `--export-geo` writes KML / GPX / GeoJSON / CSV with
  every geolocated point plus a capture-path track when 2+ images carry
  coordinates; `--map` writes a standalone interactive Leaflet map of the
  whole batch.
- **OCR & web probes** — `--ocr` extracts printed text from images using
  a locally installed Tesseract binary (prints an install hint if missing);
  `--web` fetches HTTP response headers from a URL (GET only — the tool
  itself never uploads anything).
- **Exports** — JSON and standalone HTML reports (GPS map embedded), raw
  EXIF tag dumps (`--dump-raw`), metadata-scrubbed copies (`--scrub`),
  extracted thumbnails (`--extract-thumb`) and a batch HTML index
  (`--html-index`).
- **Hacker-green theme** — Matrix-style output: bright green accents, lime
  warnings, red reserved for risks only.
- **Batch + recursive scans**, quiet mode, granular feature toggles, and an
  interactive prompt when run without arguments.

---

## Supported Formats

```
Images:     .jpg  .jpeg  .jfif  .png  .gif  .webp  .bmp  .tif  .tiff
            .heic  .heif  .cr2  .nef  .arw  .raw
Documents:  .pdf  .docx  .xlsx  .pptx  .doc  .xls  .ppt  .msi
Video:      .mp4  .mov
```

The file type is auto-detected from magic bytes — the extension is only a
hint. Unsupported files are skipped with a notice; missing paths are
reported without aborting the batch.

---

## Requirements

- Python **3.10+**
- Dependencies (install via `requirements.txt`):

```
exifread>=3.0.0
Pillow>=10.0.0
pillow-heif>=1.0.0
rich>=13.0.0
click>=8.1.0
imagehash>=4.3.0
numpy>=1.24.0
defusedxml>=0.7.1
pypdf>=4.0.0
olefile>=0.46
```

`defusedxml` enables Pillow's `getxmp()` XMP reading; `pillow-heif`
enables HEIC/HEIF; `pypdf` and `olefile` cover PDF and legacy OLE
document metadata.

---

## Installation

**Windows** — double-click `install.bat` (or run it in a terminal). It
installs dependencies, registers the global `exifeye` command, and adds it to
your PATH automatically.

**Linux / macOS** — use the manual setup below (no shell installer is bundled).

**Manual / custom setup:**

```bash
cd ExifEye
pip install -r requirements.txt
pip install -e .        # creates the global `exifeye` command
```

`pip install -e .` reads `pyproject.toml` and installs an entry point, so
`exifeye` becomes callable from any directory. The default device database
ships inside the package.

`start.bat` is the single Windows launcher: it tries the global `exifeye`
command first and falls back to `py exifeye.py`. Use it only if `exifeye`
isn't on your PATH yet — the global command is the primary way to run the tool.

> **Tip — `exifeye` not found?** On Windows the command lives in your Python
> **Scripts** folder. If it isn't recognized after installing, the terminal
> was almost certainly **open before** the install — PATH changes only reach
> newly-opened windows. Close and reopen your terminal (or start a new tab).
>
> This matters most in **Git Bash / MINGW64 / MSYS**: a bash session snapshots
> its PATH at startup and won't see the new `Scripts` folder. Open a **new Git
> Bash window** and it will work. `install.bat` registers the PATH at the
> Windows user level for cmd / PowerShell / Windows Terminal.

---

## Usage

```bash
exifeye <file-or-folder> [options]
```

The target can be **anywhere on disk** — it does not need to live inside the
project folder. Absolute or relative paths both work:

```bash
exifeye "D:\photos\IMG_0001.jpg"   # a single file anywhere
exifeye ..\downloads --recursive   # a folder anywhere
```

Run without arguments to enter the interactive prompt and pick an image or
folder:

```bash
exifeye
```

### Examples

Analyze a single image:

```bash
exifeye photo.jpg
```

Analyze several images at once:

```bash
exifeye photo1.jpg photo2.jpg photo3.png
```

Scan a whole folder recursively:

```bash
exifeye ./photos --recursive
```

Export JSON + HTML reports into a folder:

```bash
exifeye photo.jpg --json --html --output-dir ./reports
```

Quiet mode — only the one-line summary per image:

```bash
exifeye ./photos --recursive --quiet
```

Reverse-image search — private, local-first: opens the image in your
browser with a Google Lens tab ready; right-click the image → "Search
image with Google". The tool uploads nothing:

```bash
exifeye photo.jpg --lens
```

Mine residual traces + raw strings from a platform-stripped image:

```bash
exifeye "WhatsApp Image 2026-10-11 at 21.03.19.jpeg" --strings
```

Find the most original copy among look-alikes:

```bash
exifeye ./photos --recursive --find-dupes
```

Compare two versions field-by-field:

```bash
exifeye original.jpg reencoded.jpg --diff
```

Use a custom device database:

```bash
exifeye photo.jpg --device-db ./my_devices.json
```

---

## Options

| Option | Description |
| --- | --- |
| `-r, --recursive` | Scan directories recursively |
| `--json` | Export a JSON report per image |
| `--html` | Export a standalone HTML report per image |
| `--output-dir DIR` | Directory for exported reports (default: image folder) |
| `--no-hashes` | Skip file hash calculation (MD5/SHA-1/SHA-256) |
| `--no-deep` | Skip deep forensics (ELA, steganography) |
| `--no-social` | Skip social media forensics |
| `-q, --quiet` | Print only the one-line summary, not the full report |
| `--device-db FILE` | Path to a custom device enrichment JSON database |
| `--lens` | Private Google Lens search: open the local image in the browser for a right-click → "Search image with Google" (no upload by the tool) |
| `--strings` | Scan raw bytes for embedded strings (URLs, emails, phones, IPs, device/software names, GPS hints) |
| `--find-dupes` | Group exact + near-duplicate images and rank the most original copy (needs 2+ images) |
| `--diff` | Compare two images field-by-field (EXIF, GPS, device, forensics, hashes) |
| `--export-geo [kml\|gpx\|geojson\|csv]` | Export geolocated coordinates to one KML / GPX / GeoJSON / CSV file (plus a path track when 2+ points) |
| `--map` | Write a standalone interactive GPS map (Leaflet + OpenStreetMap tiles load when you open it) |
| `--ocr` | Extract printed text from images with Tesseract (needs the `tesseract` binary on PATH; prints an install hint if missing) |
| `--web URL` | Fetch HTTP response headers from a URL (GET only — nothing is uploaded; http/https only) |
| `--extract-thumb` | Save the embedded EXIF thumbnail to a standalone `.jpg` file |
| `--extract-thumb-dir DIR` | Directory for extracted thumbnails (default: image folder) |
| `--scrub` | Write a metadata-stripped copy (`<name>_scrubbed.<ext>`): EXIF/XMP/IPTC/GPS removed, pixels + ICC preserved bit-for-bit |
| `--html-index` | Write one `index.html` linking all HTML reports (needs 2+ images; auto-enables `--html`) |
| `--dump-raw` | Dump every raw EXIF tag to `<name>_raw_tags.txt` (full exifread inventory) |
| `-h, --help` | Show all options |

---

## Report Sections

For every file the tool prints the sections that apply to its type:

1. **General information** — format, dimensions, color mode, DPI, orientation,
   ICC profile, file size.
2. **EXIF core** — camera settings, lens, timestamps, software, serials.
3. **GPS coordinates** — `GEOLOCATED` / `NO GPS DATA` status, decimal
   coordinates, geohash, Google Maps link.
4. **Device / Camera** — brand, make, model, device type, OS, enrichment data,
   lens and serial information.
5. **Timestamp check** — cross-clock consistency (EXIF local vs GPS UTC vs
   document/video containers), inferred capture timezone, placeholder epochs,
   future dates and ordering violations.
6. **Filename origin** — screenshot (macOS / Windows / Android) or
   device-default naming (IMG_ / DSC / PXL_) detection.
7. **AI generation / C2PA** — generator attribution, IPTC digital source
   types and C2PA/JUMBF provenance manifests (detection only, no crypto
   verification).
8. **Deep forensics** — ELA error-level analysis, steganography and entropy
   checks.
9. **Social media** — platform fingerprint from re-encoding, artifacts and
   WhatsApp filename patterns (both the `WA####` and the `WhatsApp Image
   ... at ...` patterns).
10. **Document / video metadata** — PDF, OOXML and OLE document properties;
    MP4/MOV creation time, dimensions and embedded GPS.
11. **Hashes** — MD5, SHA-1, SHA-256 for file matching across datasets.
12. **Thumbnail recovery** — when the main image is stripped but an
    embedded thumbnail survives, its GPS / device / timestamps are reported
    as recovered metadata.
13. **JPEG structure** — quantization tables, quality estimate, chroma
    subsampling, comments and marker inventory.
14. **Meta chunks** — decoded PNG / GIF / WebP text + EXIF chunks.
15. **Embedded strings** — raw-byte string hits (with `--strings`).
16. **Batch intelligence / duplicates** — device clustering, timeline,
    sessions and near-duplicate groups (3+ images).

A **forensic score (0–10)** summarizes the findings, and when GPS is missing a
**reverse image search** footer (Google Lens / Yandex / TinEye / Bing Visual)
points to finding a copy of the image that kept its coordinates — the
practical path to geolocating a stripped image.

---

## Custom Device Database

`--device-db` replaces the bundled enrichment file. Keys are the raw
`Make` / `Model` strings (case-insensitive); lookups are best-effort and never
override raw EXIF values. Example:

```json
{
  "NIKON CORPORATION": {
    "model_name": "Nikon D3000",
    "brand": "Nikon",
    "device_type": "Camera",
    "year": 2009
  }
}
```

Brand / device-type classification itself is regex-driven and does **not**
need a database entry — a never-seen `iPhone 30` or `SM-Z999` is still
classified correctly.

---

## How It Works

```
exifeye.py                  entry point, click CLI with options
pyproject.toml              packaging + global `exifeye` command entry point
install.bat                 one-command setup (deps + command + PATH)
start.bat                   Windows launcher (tries `exifeye`, falls back to `py exifeye.py`)
extractor/sniff.py          magic-byte file type detection (image / document / video)
extractor/core.py           tag extraction, hashes, timestamps, general info, XMP GPS
extractor/gps.py            GPS tag decoding, coordinate math, geohash
extractor/hashes.py         MD5 / SHA-1 / SHA-256
extractor/lens.py           private Google Lens helper: opens local file only, never uploads
extractor/device.py         regex classification + enrichment database
extractor/device_db.json    bundled device enrichment data
extractor/doc_pdf.py        PDF metadata (pypdf)
extractor/doc_ooxml.py      OOXML (docx / xlsx / pptx) properties
extractor/doc_ole.py        legacy OLE (doc / xls / ppt) + MSI SummaryInformation
extractor/video_mp4.py      MP4 / MOV container metadata (creation time, GPS)
analyzers/social_media.py   platform re-encoding / WhatsApp filename analysis
analyzers/deep_forensics.py ELA + steganography checks
analyzers/thumbnail_meta.py embedded-thumbnail metadata recovery (GPS/device)
analyzers/jpeg_structure.py JPEG marker / quality / subsampling structure analysis
analyzers/chunks.py         PNG / GIF / WebP chunk + text metadata mining
analyzers/strings.py        raw-byte embedded string extraction
analyzers/dupes.py          exact + perceptual near-duplicate grouping
analyzers/batch_intel.py    device clustering, timeline & session analysis
analyzers/timestamps.py     cross-clock consistency + timezone inference
analyzers/screenshot.py     screenshot / device-default filename origin
analyzers/ai_generated.py   AI-generator attribution + C2PA/JUMBF detection
analyzers/gps_spoof.py      GPS plausibility (Null Island, altitude, hand-edits)
analyzers/panorama.py       360° / photosphere detection
analyzers/trailing.py       trailing-data / polyglot detection
analyzers/auth_risk.py      authentication-risk scoring
output/console.py           rich console rendering (+ toolbar banner)
output/json_export.py       JSON report export
output/html_report.py       standalone HTML report export (map for GPS)
output/geo_export.py        KML / GPX / GeoJSON / CSV exports + interactive map
output/raw_dump.py          raw EXIF tag dump
```

All exports use sanitized, URI-safe filenames; HTML reports HTML-escape every
EXIF-derived value to prevent XSS; JSON exports reject invalid image files
gracefully instead of crashing.

---

## Testing

The repo ships a self-contained pytest suite (analyzer unit tests + CLI
smoke tests, synthetic fixtures — no external corpus needed):

```bash
python -m pytest tests/test_all.py
```

A smoke-test corpus (real camera images with GPS, an EXIF-stripped copy, an
XMP-only GPS file, a WhatsApp-named file, and corrupt/empty edges) is kept
outside the project tree:

```bash
exifeye <corpus-dir> --recursive --json --html --output-dir <reports-dir>
```

Reference samples are downloadable from the public
[ianare/exif-samples](https://github.com/ianare/exif-samples) repository
(`jpg/gps/DSCN0010.jpg`, `jpg/Nikon_COOLPIX_P1.jpg`,
`jpg/Olympus_C8080WZ.jpg`).

---

## Disclaimer

ExifEye is an OSINT / digital-forensics **learning tool**. Use it only on
images you own or have permission to analyze. Embedded GPS coordinates and
device serials are sensitive information — stripping this metadata (or not
uploading originals) is the only reliable way to keep it private. The tool
detects traces; it cannot reliably "prove" the origin of a heavily re-encoded
image.