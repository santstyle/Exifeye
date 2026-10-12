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

from analyzers.ai_generated import AiGeneratedDetector
from analyzers.gps_spoof import GpsSpoofCheck
from analyzers.panorama import PanoramaDetector
from analyzers.screenshot import FilenameOriginDetector
from analyzers.timestamps import TimestampAnalyzer
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


# -------------------------------------------------------- TimestampAnalyzer


def test_timestamp_clean_no_issues():
    r = TimestampAnalyzer().analyze(
        {"original": "2024:01:02 12:00:00",
         "modified": "2024:01:02 13:00:00"})
    assert r["available"] is True
    assert r["issues"] == []
    assert r["inferred_tz"] is None
    assert "no timestamp anomalies" in r["verdict"]


def test_timestamp_empty_unavailable():
    r = TimestampAnalyzer().analyze({})
    assert r["available"] is False


def test_timestamp_zero_placeholder():
    r = TimestampAnalyzer().analyze({"original": "0000:00:00 00:00:00"})
    assert r["available"] is True
    assert any("zero placeholder" in i for i in r["issues"])


def test_timestamp_unix_epoch():
    r = TimestampAnalyzer().analyze({"original": "1970:01:01 00:00:00"})
    assert any("1970-01-01 placeholder epoch" in i for i in r["issues"])


def test_timestamp_qt_epoch():
    r = TimestampAnalyzer().analyze({"creation": "1904-01-01 00:00:00"})
    assert any("1904 QuickTime-epoch" in i for i in r["issues"])


def test_timestamp_future_date():
    r = TimestampAnalyzer().analyze({"original": "2099:01:01 12:00:00"})
    assert any("future" in i for i in r["issues"])


def test_timestamp_modified_predates_capture():
    r = TimestampAnalyzer().analyze(
        {"original": "2024:01:02 12:00:00",
         "modified": "2024:01:01 12:00:00"})
    assert any("modified timestamp predates" in i for i in r["issues"])


def test_timestamp_tz_inference():
    # Camera 12:00 local vs GPS 05:00 UTC same day -> UTC+07:00.
    r = TimestampAnalyzer().analyze(
        {"original": "2024:01:02 12:00:00",
         "gps_date": "2024-01-02", "gps_time": "05:00:00 UTC"})
    assert r["issues"] == []
    assert r["inferred_tz"] == "UTC+07:00"


def test_timestamp_skew_outside_bounds():
    # 20 h offset: no real timezone explains it.
    r = TimestampAnalyzer().analyze(
        {"original": "2024:01:02 12:00:00",
         "gps_date": "2024-01-01", "gps_time": "16:00:00 UTC"})
    assert any("outside UTC-12..UTC+14" in i for i in r["issues"])
    assert r["inferred_tz"] is None


# -------------------------------------------------- FilenameOriginDetector


def test_filename_macos_screenshot():
    r = FilenameOriginDetector().analyze("Screenshot 2024-01-15 at 10.30.45.png")
    assert r["detected"] is True
    assert r["kind"] == "screenshot"
    assert r["label"] == "macOS screenshot"


def test_filename_windows_screenshot():
    r = FilenameOriginDetector().analyze("Screenshot 2024-01-15 103045.png")
    assert r["detected"] is True
    assert r["label"] == "Windows screenshot"


def test_filename_android_screenshot():
    r = FilenameOriginDetector().analyze("Screenshot_20240115_103045.png")
    assert r["detected"] is True
    assert r["label"] == "Android screenshot"


def test_filename_ios_img_default():
    r = FilenameOriginDetector().analyze("IMG_0618.JPG")
    assert r["detected"] is True
    assert r["kind"] == "camera-filename"


def test_filename_nikon_dscn_default():
    r = FilenameOriginDetector().analyze("DSCN0010.jpg")
    assert r["detected"] is True
    assert r["label"] == "Nikon DSCN default naming"


def test_filename_pixel_default():
    r = FilenameOriginDetector().analyze("PXL_20240115_123456789.jpg")
    assert r["detected"] is True
    assert r["kind"] == "phone-filename"


def test_filename_whatsapp_not_matched_here():
    # WhatsApp patterns are owned by analyzers/social_media.py.
    r = FilenameOriginDetector().analyze("IMG-20230415-WA0001.jpg")
    assert r["detected"] is False


def test_filename_generic_name_not_detected():
    r = FilenameOriginDetector().analyze("vacation.jpg")
    assert r["detected"] is False
    assert r["verdict"] == "no filename origin pattern matched"


# ------------------------------------------------------ AiGeneratedDetector


def test_ai_clean_jpeg_not_detected(plain_jpeg: Path):
    r = AiGeneratedDetector().analyze(plain_jpeg)
    assert r["available"] is True
    assert r["detected"] is False
    assert r["c2pa"] is False
    assert "not proof of human authorship" in r["verdict"]


def test_ai_c2pa_only_is_provenance_not_ai(plain_jpeg: Path, tmp_path: Path):
    p = tmp_path / "c2pa_only.jpg"
    p.write_bytes(plain_jpeg.read_bytes() + b"\x00jumbf\x00c2pa.claim.test\x00")
    r = AiGeneratedDetector().analyze(p)
    assert r["c2pa"] is True
    assert r["detected"] is False
    assert "provenance recorded" in r["verdict"]


def test_ai_trained_algorithmic_media_high(plain_jpeg: Path, tmp_path: Path):
    p = tmp_path / "ai_high.jpg"
    p.write_bytes(plain_jpeg.read_bytes() + b"\x00trainedAlgorithmicMedia\x00")
    r = AiGeneratedDetector().analyze(p)
    assert r["detected"] is True
    assert r["confidence"] == "high"
    assert any("trainedalgorithmicmedia" in s for s in r["signals"])


def test_ai_composite_generated_medium(plain_jpeg: Path, tmp_path: Path):
    p = tmp_path / "ai_comp.jpg"
    p.write_bytes(plain_jpeg.read_bytes() + b"\x00compositelyGenerated\x00")
    r = AiGeneratedDetector().analyze(p)
    assert r["detected"] is True
    assert r["confidence"] == "medium"


def test_ai_software_field_high(plain_jpeg: Path):
    exif = {"IFD0": {"Software": "Midjourney v6"}}
    r = AiGeneratedDetector().analyze(plain_jpeg, exif_data=exif)
    assert r["detected"] is True
    assert r["confidence"] == "high"
    assert any("midjourney" in s and "'Software'" in s for s in r["signals"])


def test_ai_xmp_creatortool_high(plain_jpeg: Path):
    xmp = {"xmp": {"CreatorTool": "Stable Diffusion XL"}}
    r = AiGeneratedDetector().analyze(plain_jpeg, xmp_data=xmp)
    assert r["detected"] is True
    assert r["confidence"] == "high"


def test_ai_non_attrib_field_ignored(plain_jpeg: Path):
    # "imagen" only trips generator checks in attribution fields - a
    # plain description key must not fire.
    exif = {"IFD0": {"ImageDescription": "una imagen bonita"}}
    r = AiGeneratedDetector().analyze(plain_jpeg, exif_data=exif)
    assert r["detected"] is False


def test_ai_missing_file_unavailable(tmp_path: Path):
    r = AiGeneratedDetector().analyze(tmp_path / "nope.jpg")
    assert r["available"] is False
    assert r["detected"] is False


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


def _gps_result(name: str, lat: float, lon: float,
                iso: str = "2023:04:15 10:00:00") -> SimpleNamespace:
    return SimpleNamespace(
        file_name=name,
        file_path=str(Path(name)),
        gps={"available": True, "latitude": lat, "longitude": lon,
             "altitude_meters": 10.0, "geohash": "sr8rq3n2p",
             "source": "EXIF", "google_maps_link": "https://maps.example/x"},
        timestamps={"original": iso},
        device={"make": "NIKON", "model": "COOLPIX P1"},
    )


def test_geo_export_gpx_track(tmp_path: Path):
    import xml.etree.ElementTree as ET
    results = [
        _gps_result("a.jpg", -6.2088, 106.8456, "2023:04:15 10:00:00"),
        _gps_result("b.jpg", -6.2100, 106.8500, "2023:04:15 10:05:00"),
        _gps_result("c.jpg", -6.2150, 106.8550, "2023:04:15 09:00:00"),
    ]
    out = GeoExporter().export(results, tmp_path, "gpx")
    root = ET.parse(out).getroot()
    ns = {"g": "http://www.topografix.com/GPX/1/1"}
    assert len(root.findall("g:wpt", ns)) == 3
    assert len(root.findall("g:trk", ns)) == 1
    trkpts = root.findall("g:trk/g:trkseg/g:trkpt", ns)
    assert len(trkpts) == 3
    # out-of-order input: track sorts by time (09:00 file first)
    assert trkpts[0].get("lat") == "-6.2150000"
    assert trkpts[0].find("g:time", ns) is not None


def test_geo_export_gpx_single_point_no_track(tmp_path: Path):
    out = GeoExporter().export([_gps_result("a.jpg", -6.2, 106.8)],
                               tmp_path, "gpx")
    text = out.read_text(encoding="utf-8")
    assert "<wpt" in text
    assert "<trk" not in text


def test_geo_export_kml_linestring(tmp_path: Path):
    import xml.etree.ElementTree as ET
    results = [
        _gps_result("a.jpg", -6.2088, 106.8456, "2023:04:15 10:00:00"),
        _gps_result("b.jpg", -6.2100, 106.8500, "2023:04:15 10:05:00"),
        _gps_result("c.jpg", -6.2150, 106.8550, "2023:04:15 09:00:00"),
    ]
    out = GeoExporter().export(results, tmp_path, "kml")
    root = ET.parse(out).getroot()
    ns = {"k": "http://www.opengis.net/kml/2.2"}
    lines = root.findall(".//k:LineString", ns)
    assert len(lines) == 1
    coords = lines[0].find("k:coordinates", ns).text or ""
    verts = coords.split()
    assert len(verts) == 3
    assert verts[0].startswith("106.8550000,-6.2150000")  # time-ordered


def test_geo_export_kml_single_no_linestring(tmp_path: Path):
    out = GeoExporter().export([_gps_result("a.jpg", -6.2, 106.8)],
                               tmp_path, "kml")
    assert "LineString" not in out.read_text(encoding="utf-8")


def test_geo_export_geojson_collection(tmp_path: Path):
    import json
    results = [
        _gps_result("a.jpg", -6.2088, 106.8456, "2023:04:15 10:00:00"),
        _gps_result("b.jpg", -6.2100, 106.8500, "2023:04:15 10:05:00"),
        _gps_result("c.jpg", -6.2150, 106.8550, "2023:04:15 09:00:00"),
    ]
    out = GeoExporter().export(results, tmp_path, "geojson")
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["type"] == "FeatureCollection"
    pts = [f for f in doc["features"] if f["geometry"]["type"] == "Point"]
    lines = [f for f in doc["features"]
             if f["geometry"]["type"] == "LineString"]
    assert len(pts) == 3
    assert len(lines) == 1
    # Point coordinates carry altitude as a 3rd element.
    assert pts[0]["geometry"]["coordinates"] == [106.8456, -6.2088, 10.0]
    assert lines[0]["geometry"]["coordinates"][0] == [106.855, -6.215]
    assert "file" in pts[0]["properties"]
    assert "google_maps_link" in pts[0]["properties"]


def test_geo_export_geojson_partial_times_keep_order(tmp_path: Path):
    import json
    results = [
        _gps_result("d.jpg", -6.3, 106.9, ""),
        _gps_result("e.jpg", -6.4, 107.0, "2023:05:01 08:00:00"),
    ]
    out = GeoExporter().export(results, tmp_path, "geojson")
    doc = json.loads(out.read_text(encoding="utf-8"))
    line = [f for f in doc["features"] if f["geometry"]["type"] == "LineString"]
    assert line and line[0]["geometry"]["coordinates"][0] == [106.9, -6.3]


def test_geo_export_map_html(tmp_path: Path):
    results = [
        _gps_result("a.jpg", -6.2088, 106.8456),
        _gps_result("b.jpg", -6.2100, 106.8500, "2023:04:15 10:05:00"),
    ]
    out = GeoExporter().export_map(results, tmp_path)
    assert out is not None and out.exists()
    text = out.read_text(encoding="utf-8")
    assert "leaflet" in text.lower()
    assert "L.marker" in text
    assert "polyline" in text
    assert "\\u003c" in text  # script-breakout guard present
    assert "a.jpg" in text


def test_geo_export_map_no_gps_returns_none(tmp_path: Path):
    results = [SimpleNamespace(
        file_name="x.jpg", file_path="x.jpg",
        gps={"available": False}, timestamps={}, device={})]
    assert GeoExporter().export_map(results, tmp_path) is None


def test_geo_export_map_single_point_no_polyline(tmp_path: Path):
    out = GeoExporter().export_map([_gps_result("a.jpg", -6.2, 106.8)],
                                   tmp_path)
    text = out.read_text(encoding="utf-8")
    assert "L.marker" in text
    # Template always contains the polyline call; the data blob's empty
    # path is what stops it rendering.
    assert '"path": []' in text


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
    assert "--ocr" in proc.stdout
    assert "--web" in proc.stdout
    assert "--map" in proc.stdout


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
