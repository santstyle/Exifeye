"""Magic-byte format sniffing.

Detects the real container type from file content (never trust the
extension alone) and classifies it into a kind that drives the analysis
pipeline:

    image     - raster images (JPEG/PNG/GIF/WebP/BMP/TIFF/HEIC/AVIF/...)
    video     - ISO-BMFF video (MP4/MOV/M4V/3GP)
    document  - PDF, OOXML (docx/xlsx/pptx), ODF (odt/ods/odp), legacy OLE
    archive   - plain ZIP archives
    unknown   - content not recognized (still analyzable: hashes/strings)
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

# (offset, magic, format, mime, kind)
_MAGIC_EXACT: tuple[tuple[int, bytes, str, str, str], ...] = (
    (0, b"\xff\xd8\xff", "jpg", "image/jpeg", "image"),
    (0, b"\x89PNG\r\n\x1a\n", "png", "image/png", "image"),
    (0, b"GIF87a", "gif", "image/gif", "image"),
    (0, b"GIF89a", "gif", "image/gif", "image"),
    (0, b"BM", "bmp", "image/bmp", "image"),
    (0, b"%PDF-", "pdf", "application/pdf", "document"),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole", "application/x-ole-storage", "document"),
    (0, b"PK\x03\x04", "zip", "application/zip", "archive"),
    (0, b"fLaC", "flac", "audio/flac", "audio"),
    (0, b"ID3", "mp3", "audio/mpeg", "audio"),
)

# TIFF-family (II*\0 / MM\0*) - includes CR2/NEF/ARW raw variants.
_TIFF_MAGICS = (b"II*\x00", b"MM\x00*")

# ISO-BMFF brands -> (format, mime, kind) checked against ftyp major brand
# and compatible brand list.
_BMFF_BRANDS: dict[bytes, tuple[str, str, str]] = {
    b"heic": ("heic", "image/heic", "image"),
    b"heix": ("heic", "image/heic", "image"),
    b"hevc": ("heic", "image/heic", "image"),
    b"hevx": ("heic", "image/heic", "image"),
    b"heim": ("heic", "image/heic", "image"),
    b"heis": ("heic", "image/heic", "image"),
    b"avic": ("heic", "image/heic", "image"),
    b"avif": ("avif", "image/avif", "image"),
    b"avis": ("avif", "image/avif", "image"),
    b"mif1": ("heif", "image/heif", "image"),  # HEIF sequence container
    b"msf1": ("heif", "image/heif", "image"),
    b"mp41": ("mp4", "video/mp4", "video"),
    b"mp42": ("mp4", "video/mp4", "video"),
    b"isom": ("mp4", "video/mp4", "video"),
    b"iso2": ("mp4", "video/mp4", "video"),
    b"iso4": ("mp4", "video/mp4", "video"),
    b"iso5": ("mp4", "video/mp4", "video"),
    b"iso6": ("mp4", "video/mp4", "video"),
    b"avc1": ("mp4", "video/mp4", "video"),
    b"dash": ("mp4", "video/mp4", "video"),
    b"M4V ": ("m4v", "video/mp4", "video"),
    b"M4A ": ("m4a", "audio/mp4", "audio"),
    b"M4B ": ("m4a", "audio/mp4", "audio"),
    b"qt  ": ("mov", "video/quicktime", "video"),
    b"3gp4": ("3gp", "video/3gpp", "video"),
    b"3gp5": ("3gp", "video/3gpp", "video"),
    b"3gp6": ("3gp", "video/3gpp", "video"),
    b"3g2a": ("3g2", "video/3gpp2", "video"),
}


@dataclass
class SniffResult:
    """What the file content actually is."""
    format: str      # short id: jpg, png, pdf, docx, mp4, ...
    mime: str
    kind: str        # image / video / document / archive / audio / unknown
    detail: str = "" # sub-type hint (ooxml word/xlsx/pptx, odf text, ole doc/xls/ppt)

    @property
    def is_image(self) -> bool:
        return self.kind == "image"


def sniff_path(path: str | Path) -> SniffResult:
    """Sniff a file on disk. Falls back to extension for TIFF-family raws."""
    path = Path(path)
    try:
        head = path.read_bytes()[:65536]
    except OSError:
        return SniffResult("bin", "application/octet-stream", "unknown")
    result = sniff_bytes(head, suffix=path.suffix.lower())
    # ZIP-based formats need the central directory (at the file end) to
    # tell docx/xlsx/pptx/odt apart from a plain archive.
    if result.format == "zip":
        return _sniff_zip_container(path) or result
    return result


def sniff_bytes(head: bytes, suffix: str = "") -> SniffResult:
    """Sniff from leading bytes (>= 16 bytes recommended, 64KB max)."""
    if len(head) < 4:
        return SniffResult("bin", "application/octet-stream", "unknown")

    # ISO-BMFF: [size:4][b'ftyp'][major brand:4][minor:4][compatible...]
    if len(head) >= 12 and head[4:8] == b"ftyp":
        brand = head[8:12]
        hit = _BMFF_BRANDS.get(brand)
        if hit:
            fmt, mime, kind = hit
            return SniffResult(fmt, mime, kind)
        # Unknown major brand - scan compatible brand list (up to 16 entries).
        pos, end = 16, min(len(head), 16 + 4 * 16)
        while pos + 4 <= end:
            compat = head[pos:pos + 4]
            hit = _BMFF_BRANDS.get(compat)
            if hit:
                fmt, mime, kind = hit
                return SniffResult(fmt, mime, kind)
            pos += 4
        # ftyp present but no known brand: treat as generic mp4 (video keeps
        # working via the atom parser; if it really is HEIC the PIL opener
        # still handles it when kind gets corrected by extension below).
        if suffix in (".heic", ".heif"):
            return SniffResult("heic", "image/heic", "image")
        return SniffResult("mp4", "video/mp4", "video")

    for offset, magic, fmt, mime, kind in _MAGIC_EXACT:
        if head[offset:offset + len(magic)] == magic:
            if fmt == "zip":
                return SniffResult("zip", mime, "archive")
            if fmt == "ole":
                return _sniff_ole_kind(head, suffix)
            return SniffResult(fmt, mime, kind)

    if head[:4] in _TIFF_MAGICS:
        # Raw camera formats are TIFF at heart; refine via extension only
        # for display (content stays TIFF-parseable either way).
        raw = {".cr2": "cr2", ".nef": "nef", ".arw": "arw", ".raw": "raw",
               ".dng": "dng", ".rw2": "rw2", ".orf": "orf", ".pef": "pef"}
        fmt = raw.get(suffix, "tiff")
        return SniffResult(fmt, "image/tiff", "image")

    # WebP: RIFF container with 'WEBP' fourcc at offset 8.
    if head[:4] == b"RIFF" and len(head) >= 12 and head[8:12] == b"WEBP":
        return SniffResult("webp", "image/webp", "image")
    if head[:4] == b"RIFF" and len(head) >= 12 and head[8:12] == b"AVI ":
        return SniffResult("avi", "video/x-msvideo", "video")

    # SVG - XML starting with <svg or an XML decl later containing <svg.
    if head[:1] in (b"<", b"\xef\xbb\xbf") or head.lstrip()[:5] in (b"<?xml", b"<svg "):
        lower = head.lower()
        if b"<svg" in lower:
            return SniffResult("svg", "image/svg+xml", "image")

    return SniffResult("bin", "application/octet-stream", "unknown")


def sniff_format(path: str | Path) -> str:
    """Convenience: just the short format id."""
    return sniff_path(path).format


def _sniff_ole_kind(head: bytes, suffix: str) -> SniffResult:
    """Classify a legacy OLE compound file by extension (doc/xls/ppt/msg)."""
    fmt = {".doc": "doc", ".xls": "xls", ".ppt": "ppt", ".pps": "pps",
           ".msg": "msg", ".vsd": "vsd", ".one": "one",
           ".msi": "msi", ".pub": "pub", ".mdb": "mdb", ".accdb": "accdb",
           }.get(suffix, "ole")
    return SniffResult(fmt, "application/x-ole-storage", "document", detail="ole")


def _sniff_zip_container(path: Path) -> SniffResult | None:
    """Tell OOXML / ODF / plain ZIP apart by peeking at the entry list."""
    try:
        import zipfile

        if not zipfile.is_zipfile(path):
            return None
        with zipfile.ZipFile(path) as zf:
            names = set(zf.namelist())
    except (OSError, Exception):  # noqa: BLE001 - corrupt zip must not crash
        return None

    if "[Content_Types].xml" in names:
        if any(n.startswith("word/") for n in names):
            return SniffResult("docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                               "document", detail="ooxml")
        if any(n.startswith("xl/") for n in names):
            return SniffResult("xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                               "document", detail="ooxml")
        if any(n.startswith("ppt/") for n in names):
            return SniffResult("pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation",
                               "document", detail="ooxml")
        return SniffResult("ooxml", "application/vnd.openxmlformats-officedocument", "document", detail="ooxml")

    if "mimetype" in names:
        try:
            with zipfile.ZipFile(path) as zf:
                mt = zf.read("mimetype").decode("ascii", errors="replace")
        except Exception:  # noqa: BLE001
            mt = ""
        odf = {"text": "odt", "spreadsheet": "ods", "presentation": "odp",
               "drawing": "odg", "chart": "odc", "formula": "odf"}
        for key, fmt in odf.items():
            if f"opendocument.{key}" in mt:
                mime = ("application/vnd.oasis.opendocument."
                        + {"odt": "text", "ods": "spreadsheet", "odp": "presentation",
                           "odg": "drawing", "odc": "chart", "odf": "formula"}[fmt])
                return SniffResult(fmt, mime, "document", detail="odf")

    return None  # plain zip - caller keeps kind=archive
