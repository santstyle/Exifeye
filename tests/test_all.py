"""ExifEye test suite: analyzer unit tests + CLI smoke tests.

Fixtures are synthetic Pillow images (plus byte-injected XMP / trailing
payloads) so the suite is self-contained - no external corpus required.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from analyzers.gps_spoof import GpsSpoofCheck
from analyzers.panorama import PanoramaDetector
from analyzers.trailing import TrailingDataDetector
from output.geo_export import GeoExporter
from output.raw_dump import RawTagDumper

# ---------------------------------------------------------------- fixtures


@pytest.fixture
def plain_jpeg(tmp_path: Path) -> Path:
    """A minimal JPEG with no EXIF (stripped / non-camera source)."""
    p = tmp_path / "plain.jpg"
    Image.new("RGB", (32, 24), (10, 20, 30)).save(p, quality=90)
    return p


@pytest.fixture
def exif_jpeg(tmp_path: Path) -> Path:
    """A minimal JPEG carrying basic IFD0 EXIF tags."""
    p = tmp_path / "exif.jpg"
    exif = Image.Exif()
    exif[271] = "NIKON"                  # Make
    exif[272] = "COOLPIX P6000"          # Model
    exif[306] = "2024:01:02 12:00:00"    # DateTime
    Image.new("RGB", (32, 24), (40, 50, 60)).save(p, quality=90, exif=exif)
    return p


_GPANO_XMP = (
    b'<?xpacket begin="\xef\xbb\xbf" id="W5M0MpCehiHzreSzNTczkc9d"?>\n'
    b'<x:xmpmeta xmlns:x="adobe:ns:meta/">\n'
    b' <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">\n'
    b'  <rdf:Description rdf:about=""\n'
    b'    xmlns:GPano="http://ns.google.com/photos/1.0/panorama/"\n'
    b'    GPano:UsePanoramaViewer="True"\n'
    b'    GPano:ProjectionType="equirectangular"\n'
    b'    GPano:FullPanoWidthPixels="6000"\n'
    b'    GPano:FullPanoHeightPixels="3000"/>\n'
    b' </rdf:RDF>\n'
    b'</x:xmpmeta>\n'
    b'<?xpacket end="w"?>'
)


def _make_jpeg(path: Path) -> Path:
    Image.new("RGB", (32, 24), (10, 20, 30)).save(path, quality=90)
    return path


@pytest.fixture
def gpano_jpeg(tmp_path: Path) -> Path:
    """JPEG with a GPano XMP packet injected as APP1 after SOI."""
    p = _make_jpeg(tmp_path / "pano.jpg")
    data = p.read_bytes()
    payload = b"http://ns.adobe.com/xap/1.0/\x00" + _GPANO_XMP
    seg = b"\xff\xe1" + (len(payload) + 2).to_bytes(2, "big") + payload
    i = 2
    if data[i:i + 2] == b"\xff\xe0":
        i += 2 + int.from_bytes(data[i + 2:i + 4], "big")
    p.write_bytes(data[:i] + seg + data[i:])
    return p


@pytest.fixture
def polyglot_jpeg(tmp_path: Path) -> Path:
    """JPEG with a ZIP local-file header appended after EOI."""
    p = _make_jpeg(tmp_path / "poly.jpg")
    with open(p, "ab") as f:
        f.write(b"PK\x03\x04" + b"\x00" * 64)
    return p


# ---------------------------------------------------- TrailingDataDetector


def test_trailing_clean_jpeg(plain_jpeg: Path):
    r = TrailingDataDetector().analyze(plain_jpeg)
    assert r["available"] is True
    assert r["trailing_bytes"] == 0
    assert r["polyglot"] is False
    assert r["signatures"] == []


def test_trailing_polyglot_zip(polyglot_jpeg: Path):
    r = TrailingDataDetector().analyze(polyglot_jpeg)
    assert r["trailing_bytes"] > 0
    assert r["polyglot"] is True
    assert "ZIP archive" in r["signatures"]


# --------------------------------------------------------- PanoramaDetector


def test_panorama_plain_jpeg_not_detected(plain_jpeg: Path):
    r = PanoramaDetector().analyze(plain_jpeg)
    assert r["available"] is True
    assert r["detected"] is False
    assert r["kind"] is None


def test_panorama_gpano_detected(gpano_jpeg: Path):
    r = PanoramaDetector().analyze(gpano_jpeg)
    assert r["detected"] is True
    assert r["kind"] == "photosphere"
    assert any("GPano" in s for s in r["signals"])


def test_panorama_device_hint_only():
    # Missing file: byte scan yields nothing, but the device hint still fires.
    r = PanoramaDetector().analyze("nonexistent.jpg",
                                   device={"make": "Insta360"})
    assert r["detected"] is True
    assert r["kind"] == "360-camera"


# ----------------------------------------------------------- GpsSpoofCheck


def test_gps_spoof_no_gps():
    r = GpsSpoofCheck().analyze({}, {})
    assert r["plausible"] is True
    assert "No GPS data" in r["verdict"]


def test_gps_spoof_zero_placeholder():
    r = GpsSpoofCheck().analyze(
        {"available": False, "zero_placeholder": True}, {})
    assert r["plausible"] is False
    assert any("Null Island" in i for i in r["issues"])


def test_gps_spoof_implausible_altitude():
    r = GpsSpoofCheck().analyze(
        {"available": True, "latitude": 43.467, "longitude": 11.885,
         "altitude_meters": 20000}, {})
    assert r["plausible"] is False
    assert any("altitude" in i.lower() for i in r["issues"])


def test_gps_spoof_whole_degree_hand_edit():
    r = GpsSpoofCheck().analyze(
        {"available": True, "latitude": 43.0, "longitude": 11.0}, {})
    assert r["plausible"] is False
    assert any("whole degrees" in i for i in r["issues"])


# ------------------------------------------------------------- GeoExporter


def test_geo_export_csv(tmp_path: Path):
    results = [SimpleNamespace(
        file_name="a.jpg",
        gps={"available": True, "latitude": 43.4674483,
             "longitude": 11.8851267, "altitude_meters": 100,
             "geohash": "sr8rq3n2p", "source": "EXIF",
             "google_maps_link": "https://maps.example/x"},
        timestamps={"original": "2024:01:02 12:00:00"},
    )]
    out = GeoExporter().export(results, tmp_path, "csv")
    assert out is not None and out.exists()
    text = out.read_text(encoding="utf-8")
    assert "a.jpg" in text
    assert "43.4674483" in text


def test_geo_export_no_gps_returns_none(tmp_path: Path):
    results = [SimpleNamespace(
        file_name="b.jpg", gps={"available": False}, timestamps={})]
    assert GeoExporter().export(results, tmp_path, "kml") is None


# ------------------------------------------------------------- RawTagDumper


def test_raw_dump_creates_file(exif_jpeg: Path):
    out = RawTagDumper().dump(exif_jpeg)
    assert out.exists()
    text = out.read_text(encoding="utf-8")
    assert "tag(s)" in text
    assert "NIKON" in text


def test_raw_dump_missing_file_raises(tmp_path: Path):
    with pytest.raises(RuntimeError):
        RawTagDumper().dump(tmp_path / "nope.jpg")


# ----------------------------------------------------------------- CLI


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(ROOT / "exifeye.py"), *args],
        capture_output=True, text=True, cwd=str(ROOT), timeout=120,
        encoding="utf-8", errors="replace",
    )


def test_cli_help():
    proc = _run("--help")
    assert proc.returncode == 0
    assert "--dump-raw" in proc.stdout
    assert "--scrub" in proc.stdout
    assert "--html-index" in proc.stdout
    assert "--export-geo" in proc.stdout
    assert "--extract-thumb" in proc.stdout


def test_cli_single_file_quiet(plain_jpeg: Path):
    proc = _run(str(plain_jpeg), "--quiet", "--no-deep")
    assert proc.returncode == 0
    assert "plain.jpg" in proc.stdout


def test_cli_json_html_default_dir(exif_jpeg: Path):
    # Regression: export WITHOUT --output-dir must work (file_path is str).
    proc = _run(str(exif_jpeg), "--no-deep", "--json", "--html")
    assert proc.returncode == 0
    assert (exif_jpeg.parent / "exif_metadata_report.json").exists()
    assert (exif_jpeg.parent / "exif_report.html").exists()


def test_cli_dump_raw(exif_jpeg: Path):
    proc = _run(str(exif_jpeg), "--no-deep", "--dump-raw")
    assert proc.returncode == 0
    dump = exif_jpeg.parent / "exif_raw_tags.txt"
    assert dump.exists()
    assert "NIKON" in dump.read_text(encoding="utf-8")


def test_cli_scrub(plain_jpeg: Path):
    proc = _run(str(plain_jpeg), "--no-deep", "--scrub")
    assert proc.returncode == 0
    assert (plain_jpeg.parent / "plain_scrubbed.jpg").exists()
    assert plain_jpeg.exists()  # original untouched


def test_cli_html_index(exif_jpeg: Path, plain_jpeg: Path):
    out = exif_jpeg.parent / "reports"
    proc = _run(str(exif_jpeg), str(plain_jpeg), "--no-deep",
                "--html-index", "--output-dir", str(out))
    assert proc.returncode == 0
    assert (out / "index.html").exists()
    assert (out / "exif_report.html").exists()
    assert (out / "plain_report.html").exists()


def test_cli_panorama_panel(gpano_jpeg: Path):
    proc = _run(str(gpano_jpeg), "--no-deep")
    assert proc.returncode == 0
    assert "PANORAMA" in proc.stdout


def test_cli_auth_risk_stripped_is_medium(plain_jpeg: Path):
    # Pillow JPEG without EXIF: exif-stripped (+15) + no-timestamps (+10)
    # = 25 -> MEDIUM.
    proc = _run(str(plain_jpeg), "--no-deep")
    assert proc.returncode == 0
    assert "AUTHENTICATION RISK: MEDIUM" in proc.stdout
