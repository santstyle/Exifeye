"""ISO-BMFF video (MP4 / MOV / M4V / 3GP / M4A) metadata extraction.

Walks the ftyp + moov atom tree by seeking past media data (mdat), so even
multi-gigabyte videos parse in milliseconds. Mines:

- ftyp brands, mvhd creation/modification times, duration, timescale
- udta text atoms (classic QuickTime ``©mak`` / ``©mod`` / ``©swr`` / ``©xyz``)
- iTunes-style ``meta/keys`` + ``ilst`` (how iPhones report
  ``com.apple.quicktime.location.ISO6709`` and friends)
- ``----`` freeform atoms (mean/name/data)
- tkhd track dimensions + hdlr track types (video/audio counts)

GPS from an ISO6709 location string is decoded into the same shape the
image pipeline uses (geohash + Google Maps links via GPSParser helpers).
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .gps import GPSParser

_QT_EPOCH = datetime(1904, 1, 1, tzinfo=timezone.utc)
_MAX_MOOV = 64 * 1024 * 1024      # refuse to buffer an absurd moov
_MAX_ATOMS = 20000                # traversal safety valve
_ISO6709 = re.compile(
    r"([+-]\d{1,3}(?:\.\d+)?)([+-]\d{1,3}(?:\.\d+)?)([+-]\d+(?:\.\d+)?)?/"
)
_PRINTABLE_RUN = re.compile(rb"[\x20-\x7e]{2,}")

# Classic QuickTime udta fourccs -> display labels.
_TEXT_ATOMS: Dict[bytes, str] = {
    b"\xa9mak": "Make",
    b"\xa9mod": "Model",
    b"\xa9swr": "Software",
    b"\xa9too": "Encoder",
    b"\xa9day": "Date",
    b"\xa9cmt": "Comment",
    b"\xa9nam": "Title",
    b"\xa9ART": "Artist",
    b"\xa9gen": "Genre",
    b"\xa9alb": "Album",
    b"\xa9xyz": "Location",
    b"\xa9ope": "OpenURL",
}

# Containers whose body is more atoms. trak is handled separately
# (its tkhd/hdlr children are collected by _parse_trak, not recursed).
_CONTAINERS = {b"moov", b"mdia", b"minf", b"stbl", b"udta", b"edts", b"dinf"}


def parse(path: str | Path, gps_parser: Optional[GPSParser] = None) -> Dict[str, Any]:
    """Extract video metadata. Returns an ExtractionResult-shaped payload dict.

    Keys: exif_data, gps, timestamps, device, dimensions, errors.
    """
    gps_parser = gps_parser or GPSParser()
    out: Dict[str, Any] = {
        "exif_data": {"Video": {}},
        "gps": {"available": False},
        "timestamps": {},
        "device": {},
        "dimensions": (0, 0),
        "errors": [],
    }
    path = Path(path)

    try:
        file_size = path.stat().st_size
        with open(path, "rb") as f:
            _walk_file(f, file_size, out, gps_parser)
    except OSError as e:
        out["errors"].append(f"video read error: {e}")
        return out

    _finalize(out)
    return out


def _walk_file(f, file_size: int, out: Dict[str, Any], gps_parser: GPSParser) -> None:
    """Seek through top-level atoms; only ftyp/moov payloads are read."""
    tags: Dict[str, str] = out["exif_data"]["Video"]
    moov_bytes: Optional[bytes] = None

    while f.tell() + 8 <= file_size:
        pos = f.tell()
        header = f.read(8)
        if len(header) < 8:
            break
        size = int.from_bytes(header[:4], "big")
        typ = header[4:8]
        hdr = 8
        if size == 1:  # 64-bit extent
            ext = f.read(8)
            if len(ext) < 8:
                break
            size = int.from_bytes(ext, "big")
            hdr = 16
        elif size == 0:  # extends to EOF
            size = file_size - pos
        if size < hdr or pos + size > file_size:
            out["errors"].append("video: truncated atom table")
            break
        body_len = size - hdr

        if typ == b"ftyp":
            _parse_ftyp(f.read(min(body_len, 4096)), tags)
        elif typ == b"moov":
            if body_len > _MAX_MOOV:
                out["errors"].append("video: moov atom too large, skipped")
            else:
                moov_bytes = f.read(body_len)
        else:
            f.seek(pos + size)  # mdat / free / moof / ... never loaded
            continue
        # Keep cursor consistent for atoms we partially read.
        if f.tell() < pos + size:
            f.seek(pos + size)
        if f.tell() <= pos:  # zero-advance guard
            break

    if moov_bytes is None:
        out["errors"].append("video: no moov atom (streamed/fragmented file?)")
        return

    ctx = _Ctx()
    _walk(moov_bytes, 0, len(moov_bytes), 0, ctx, tags, out)
    _apply_ctx(ctx, out, tags)


class _Ctx:
    """Mutable traversal state shared across the moov walk."""

    def __init__(self) -> None:
        self.keys: List[str] = []          # meta/keys index -> name
        self.timestamps: Dict[str, str] = {}
        self.duration_s: Optional[float] = None
        self.track_dims: List[Tuple[int, int]] = []
        self.track_kinds: List[str] = []
        self.location_raw: str = ""
        self.count = 0


def _parse_ftyp(body: bytes, tags: Dict[str, str]) -> None:
    if len(body) < 8:
        return
    major = body[:4].decode("latin-1", errors="replace")
    brands = [major]
    for i in range(8, len(body) - 3, 4):
        b = body[i:i + 4].decode("latin-1", errors="replace")
        if b and b not in brands:
            brands.append(b)
    tags["Brand"] = major
    tags["Compatible brands"] = " ".join(brands[:12])


def _walk(buf: bytes, start: int, end: int, depth: int, ctx: _Ctx,
          tags: Dict[str, str], out: Dict[str, Any]) -> None:
    if depth > 6:
        return
    pos = start
    while pos + 8 <= end and ctx.count < _MAX_ATOMS:
        ctx.count += 1
        size = int.from_bytes(buf[pos:pos + 4], "big")
        typ = buf[pos + 4:pos + 8]
        hdr = 8
        if size == 1:
            if pos + 16 > end:
                break
            size = int.from_bytes(buf[pos + 8:pos + 16], "big")
            hdr = 16
        elif size == 0:
            size = end - pos
        if size < hdr or pos + size > end:
            break
        body = buf[pos + hdr:pos + size]

        if typ in _CONTAINERS:
            _walk(body, 0, len(body), depth + 1, ctx, tags, out)
        elif typ == b"meta":  # 4-byte version/flags prefix
            if len(body) > 4:
                _walk(body[4:], 0, len(body) - 4, depth + 1, ctx, tags, out)
        elif typ == b"mvhd":
            _parse_mvhd(body, ctx)
        elif typ == b"trak":
            _parse_trak(body, ctx)
        elif typ == b"keys":
            _parse_keys(body, ctx)
        elif typ == b"ilst":
            _parse_ilst(body, ctx, tags, out, depth)
        elif typ in _TEXT_ATOMS or typ.startswith(b"com.apple."):
            _store_text(_label_for(typ), body, tags, ctx)
        elif typ == b"\xa9xyz" or b"ISO6709" in typ:
            _store_text("Location", body, tags, ctx)

        pos += size


def _label_for(typ: bytes) -> str:
    if typ in _TEXT_ATOMS:
        return _TEXT_ATOMS[typ]
    name = typ.decode("latin-1", errors="replace")
    if name.startswith("com.apple.quicktime."):
        name = name[len("com.apple.quicktime."):]
    return name.replace(".", " ").strip().capitalize() or name


def _parse_trak(body: bytes, ctx: _Ctx) -> None:
    """Collect one track's (width, height) and handler type."""
    dims = (0, 0)
    handler = ""
    pos = 0
    while pos + 8 <= len(body):
        size = int.from_bytes(body[pos:pos + 4], "big")
        typ = body[pos + 4:pos + 8]
        if size < 8 or pos + size > len(body):
            break
        payload = body[pos + 8:pos + size]
        if typ == b"tkhd":
            dims = _tkhd_dims(payload)
        elif typ == b"mdia":
            handler = _mdia_handler(payload)
        pos += size
    if dims != (0, 0) or handler:
        ctx.track_dims.append(dims)
        ctx.track_kinds.append(handler)


def _tkhd_dims(p: bytes) -> Tuple[int, int]:
    try:
        ver = p[0] if p else 0
        # width/height are the trailing 8 bytes (two 16.16 fixed-point u32).
        w = int.from_bytes(p[-8:-4], "big") >> 16
        h = int.from_bytes(p[-4:], "big") >> 16
        if ver not in (0, 1):
            return (0, 0)
        return (w, h)
    except (IndexError, ValueError):
        return (0, 0)


def _mdia_handler(body: bytes) -> str:
    pos = 0
    while pos + 8 <= len(body):
        size = int.from_bytes(body[pos:pos + 4], "big")
        typ = body[pos + 4:pos + 8]
        if size < 8 or pos + size > len(body):
            break
        if typ == b"hdlr" and len(body) >= pos + 20:
            # header(8) + version/flags(4) + pre_defined(4) -> handler_type
            return body[pos + 16:pos + 20].decode("latin-1", errors="replace")
        pos += size
    return ""


def _parse_mvhd(body: bytes, ctx: _Ctx) -> None:
    try:
        ver = body[0]
        if ver == 1:
            ct = int.from_bytes(body[4:12], "big")
            mt = int.from_bytes(body[12:20], "big")
            timescale = int.from_bytes(body[20:24], "big")
            duration = int.from_bytes(body[24:32], "big")
        else:
            ct = int.from_bytes(body[4:8], "big")
            mt = int.from_bytes(body[8:12], "big")
            timescale = int.from_bytes(body[12:16], "big")
            duration = int.from_bytes(body[16:20], "big")
        created = _qt_time(ct)
        modified = _qt_time(mt)
        if created:
            ctx.timestamps["creation"] = created
        if modified:
            ctx.timestamps["modification"] = modified
        if timescale > 0 and duration != 0xFFFFFFFF:
            ctx.duration_s = round(duration / timescale, 3)
    except (IndexError, ValueError, ZeroDivisionError):
        pass


def _qt_time(seconds: int) -> str:
    """QuickTime epoch (1904-01-01 UTC) seconds -> 'YYYY-MM-DD HH:MM:SS UTC'."""
    if seconds <= 0:
        return ""
    try:
        dt = _QT_EPOCH.timestamp() + seconds
        return datetime.fromtimestamp(dt, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OverflowError, OSError, ValueError):
        return ""


def _parse_keys(body: bytes, ctx: _Ctx) -> None:
    """meta/keys: version(4) + count(4) + [size(4) namespace(4) name]."""
    try:
        if len(body) < 8:
            return
        count = int.from_bytes(body[4:8], "big")
        pos = 8
        for _ in range(min(count, 512)):
            if pos + 8 > len(body):
                break
            size = int.from_bytes(body[pos:pos + 4], "big")
            if size < 8 or pos + size > len(body):
                break
            name = body[pos + 8:pos + size].decode("utf-8", errors="replace")
            ctx.keys.append(name)
            pos += size
    except (IndexError, ValueError):
        pass


def _parse_ilst(body: bytes, ctx: _Ctx, tags: Dict[str, str],
                out: Dict[str, Any], depth: int) -> None:
    """iTunes-style tag list; atom types are 4ccs or 1-based key indexes."""
    pos = 0
    while pos + 8 <= len(body):
        size = int.from_bytes(body[pos:pos + 4], "big")
        typ = body[pos + 4:pos + 8]
        if size < 8 or pos + size > len(body):
            break
        child = body[pos + 8:pos + size]

        label = None
        if typ in _TEXT_ATOMS:
            label = _TEXT_ATOMS[typ]
        elif typ == b"----":
            label = _freeform_name(child)
        elif all(b < 0x20 or b > 0x7e for b in typ):  # numeric key index
            idx = int.from_bytes(typ, "big")
            if 1 <= idx <= len(ctx.keys):
                label = _label_for(ctx.keys[idx - 1].encode("utf-8", errors="replace")) \
                    if not ctx.keys[idx - 1].startswith("com.apple") else \
                    _label_for(ctx.keys[idx - 1].encode("latin-1", errors="replace"))

        payload = _data_payload(child)
        if label and payload is not None:
            _store_text(label, payload, tags, ctx)
        pos += size


def _freeform_name(child: bytes) -> Optional[str]:
    """---- atoms carry mean/name/data children; return the name."""
    pos = 0
    name = ""
    while pos + 8 <= len(child):
        size = int.from_bytes(child[pos:pos + 4], "big")
        typ = child[pos + 4:pos + 8]
        if size < 8 or pos + size > len(child):
            break
        payload = child[pos + 8:pos + size]
        if typ == b"name" and len(payload) >= 4:
            name = payload[4:].decode("utf-8", errors="replace")
        pos += size
    return name or None


def _data_payload(child: bytes) -> Optional[bytes]:
    """Extract the 'data' atom payload (version/flags + locale + value)."""
    pos = 0
    while pos + 8 <= len(child):
        size = int.from_bytes(child[pos:pos + 4], "big")
        typ = child[pos + 4:pos + 8]
        if size < 8 or pos + size > len(child):
            break
        if typ == b"data":
            payload = child[pos + 8:pos + size]
            return payload[8:] if len(payload) > 8 else b""
        pos += size
    return None


def _store_text(label: str, raw: bytes, tags: Dict[str, str], ctx: _Ctx) -> None:
    text = _clean_text(raw)
    if not text:
        return
    if label == "Location":
        ctx.location_raw = text
        tags["Location (ISO6709)"] = text
        return
    tags[label] = text


def _clean_text(raw: bytes) -> str:
    """Decode a udta payload that may carry version/flags or a length prefix."""
    if not raw:
        return ""
    if raw[:2] in (b"\xfe\xff", b"\xff\xfe"):
        try:
            return raw.decode("utf-16", errors="replace").strip("\x00").strip()
        except UnicodeDecodeError:
            pass
    candidates = [raw, raw[2:], raw[4:]]  # raw / len+lang prefix / ver+flags
    for cand in candidates:
        try:
            text = cand.decode("utf-8").strip("\x00").strip()
        except UnicodeDecodeError:
            continue
        if text and all(ch.isprintable() or ch in "\r\n\t" for ch in text):
            return text
    # Fall back to the longest printable ASCII run (binary-embedded strings).
    runs = _PRINTABLE_RUN.findall(raw)
    if runs:
        return max(runs, key=len).decode("ascii", errors="replace").strip()
    return ""


def _gps_from_iso(iso: str, gps_parser: GPSParser) -> Optional[Dict[str, Any]]:
    """Parse an ISO6709 location string like '+37.7749-122.4194+010.000/'."""
    m = _ISO6709.search(iso) or _ISO6709.search(iso + "/")
    if not m:
        return None
    try:
        lat, lon = float(m.group(1)), float(m.group(2))
    except ValueError:
        return None
    if not (-90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0):
        return None
    if lat == 0.0 and lon == 0.0:
        return None  # placeholder, same rule as GPSParser
    gps: Dict[str, Any] = {
        "available": True,
        "latitude": round(lat, 7),
        "longitude": round(lon, 7),
        "latitude_ref": "S" if lat < 0 else "N",
        "longitude_ref": "W" if lon < 0 else "E",
        "source": "QuickTime ISO6709",
        "geohash": gps_parser._geohash(lat, lon, precision=9),
        "google_maps_link": gps_parser._build_google_maps_link(lat, lon),
        "google_maps_zoom_link": gps_parser._build_google_maps_link(lat, lon, zoom=17),
    }
    if m.group(3):
        try:
            gps["altitude_meters"] = float(m.group(3))
        except ValueError:
            pass
    return gps


def _apply_ctx(ctx: _Ctx, out: Dict[str, Any], tags: Dict[str, str]) -> None:
    """Fold traversal state into the result payload."""
    if ctx.duration_s is not None:
        tags["Duration (s)"] = f"{ctx.duration_s:g}"
    if ctx.timestamps:
        tags["Creation time"] = ctx.timestamps.get("creation", "")
        tags["Modification time"] = ctx.timestamps.get("modification", "")
        out["timestamps"] = dict(ctx.timestamps)

    video_dims = [d for d, k in zip(ctx.track_dims, ctx.track_kinds)
                  if k in ("vide", "") and d != (0, 0)]
    audio_tracks = sum(1 for k in ctx.track_kinds if k == "soun")
    video_tracks = sum(1 for k in ctx.track_kinds if k == "vide")
    if video_tracks:
        tags["Video tracks"] = str(video_tracks)
    if audio_tracks:
        tags["Audio tracks"] = str(audio_tracks)
    if video_dims:
        # Largest track is the main picture (heuristic, matches ffprobe habit).
        w, h = max(video_dims, key=lambda d: d[0] * d[1])
        out["dimensions"] = (w, h)

    # GPS from whatever carried the ISO6709 string.
    location = ctx.location_raw or tags.get("Location (ISO6709)", "")
    if location:
        gps = _gps_from_iso(location, GPSParser())
        if gps:
            out["gps"] = gps

    # Minimal device dict from metadata (console renderer is .get-based).
    device: Dict[str, Any] = {}
    if tags.get("Make"):
        device["make"] = tags["Make"]
    if tags.get("Model"):
        device["model"] = tags["Model"]
    if tags.get("Software"):
        device["software"] = tags["Software"]
    if device:
        device["device_type"] = "Video"
        out["device"] = device


def _finalize(out: Dict[str, Any]) -> None:
    out["exif_data"]["Video"] = {
        k: v for k, v in out["exif_data"]["Video"].items() if v not in ("", None)
    }
