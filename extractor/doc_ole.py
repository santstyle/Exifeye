"""Legacy OLE compound file metadata extraction (.doc / .xls / .ppt / .msg).

Reads OLE Property Storage streams with olefile and mines:

- \\x05SummaryInformation      - title, author, last saved by, create/save
                                 times, app name, revision, template
- \\x05DocumentSummaryInformation - company, manager, category, counts
- Macro / VBA presence          - Macros/, _VBA_PROJECT, VBA/ dir streams
                                 (same stream-name signal oletools uses)
- OLE object pool               - embedded OLE objects (ObjectPool)
- Encrypted OOXML               - CFB-wrapped Office files expose
                                 EncryptionInfo / EncryptedPackage streams
- Stream inventory              - FOCA-style hidden stream listing

Output mirrors the image pipeline: exif_data["Document"] renders through
the existing EXIF category loop, timestamps feed the timestamp analyzer.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import olefile
    _HAVE_OLEFILE = True
except ImportError:  # pragma: no cover - declared in requirements
    _HAVE_OLEFILE = False

# SummaryInformation property IDs (MS-OLEPS).
_SUMMARY_MAP = {
    2: "Title",
    3: "Subject",
    4: "Author",
    5: "Keywords",
    6: "Comments",
    7: "Template",
    8: "Last saved by",
    9: "Revision number",
    12: "Created",
    13: "Modified",
    14: "Pages",
    15: "Words",
    16: "Characters",
    18: "Application",
    19: "Security",
}
_DOC_SUMMARY_MAP = {
    2: "Company",
    14: "Manager",
    15: "Category",
    11: "Presentation target",
    5: "Line count",
    6: "Paragraph count",
    7: "Slides",
    8: "Notes",
    10: "Multimedia clips",
}
_TIME_KEYS = {"Created", "Modified"}

# Stream-name macro signals (oletools-style).
_MACRO_MARKERS = ("macros/", "_vba_project", "vba/", "projectwm", "_vba_project_cur")


def parse(path: str | Path) -> Dict[str, Any]:
    """Extract OLE metadata. Returns ExtractionResult-shaped payload."""
    out: Dict[str, Any] = {
        "exif_data": {"Document": {}},
        "gps": {"available": False},
        "timestamps": {},
        "device": {},
        "dimensions": (0, 0),
        "errors": [],
        "flags": {},
    }
    path = Path(path)
    if not _HAVE_OLEFILE:
        out["errors"].append("olefile not installed - run: pip install olefile")
        return out
    if not olefile.isOleFile(str(path)):
        out["errors"].append("not an OLE compound file")
        return out

    try:
        ole = olefile.OleFileIO(str(path))
    except Exception as e:  # noqa: BLE001 - malformed CFB must not crash batch
        out["errors"].append(f"ole open error: {e}")
        return out

    try:
        streams = ["/".join(entry) for entry in ole.listdir()]
        out["flags"]["streams"] = streams
        tags = out["exif_data"]["Document"]
        tags["Container"] = "OLE compound file (CFB)"
        tags["Streams"] = str(len(streams))

        _read_summary(ole, out)
        _read_doc_summary(ole, out)
        _detect_macros(streams, out)
        _detect_encryption(streams, out)
        _detect_objects(streams, out)
        _stream_inventory(streams, out)
    finally:
        try:
            ole.close()
        except Exception:  # noqa: BLE001
            pass

    _finalize(out)
    return out


def _as_text(value: Any) -> str:
    """Normalize a property-set value to a display string."""
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", errors="replace").strip()
        except Exception:  # noqa: BLE001
            return repr(value)
    return str(value).strip()


def _as_time_text(value: Any) -> str:
    """Show time properties readably, decoding the raw integer encodings.

    olefile converts VT_FILETIME to datetime itself, but writers like WiX
    store time as an integer with a different epoch - the MSI smoke test
    showed '13434395888' (= seconds since 1601, i.e. FILETIME/10^7, which
    lands in 2026). Raw epoch integers must never leak into the report.
    """
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        val = int(value)
        candidates = []
        if val > 10**14:  # FILETIME: 100ns ticks since 1601
            candidates.append(datetime(1601, 1, 1, tzinfo=timezone.utc)
                               + timedelta(microseconds=val / 10))
        if val > 10**9:  # seconds since 1601 (FILETIME/10^7 producers)
            candidates.append(datetime(1601, 1, 1, tzinfo=timezone.utc)
                               + timedelta(seconds=val))
        if val > 10**9:  # Unix seconds
            candidates.append(datetime.fromtimestamp(val, tz=timezone.utc))
        for dt in candidates:
            if 1990 <= dt.year <= 2100:
                return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        return str(value)
    return str(value).strip()


def _read_summary(ole, out: Dict[str, Any]) -> None:
    """\\x05SummaryInformation property set."""
    tags = out["exif_data"]["Document"]
    try:
        props = ole.getproperties("\x05SummaryInformation")
    except Exception:  # noqa: BLE001 - missing/corrupt property set is normal
        return
    if not props:
        return
    for pid, label in _SUMMARY_MAP.items():
        value = props.get(pid)
        if value in (None, b"", ""):
            continue
        if label in _TIME_KEYS:
            text = _as_time_text(value)
            if text:
                tags[label] = text
                out["timestamps"][label.lower()] = text
            continue
        text = _as_text(value)
        if text:
            tags[label] = text


def _read_doc_summary(ole, out: Dict[str, Any]) -> None:
    """\\x05DocumentSummaryInformation property set (company, manager...)."""
    tags = out["exif_data"]["Document"]
    try:
        props = ole.getproperties("\x05DocumentSummaryInformation")
    except Exception:  # noqa: BLE001
        return
    if not props:
        return
    for pid, label in _DOC_SUMMARY_MAP.items():
        value = props.get(pid)
        if value in (None, b"", ""):
            continue
        if isinstance(value, bytes):
            try:
                value = value.decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                value = repr(value)
        text = str(value).strip()
        if text:
            tags[label] = text


def _detect_macros(streams: List[str], out: Dict[str, Any]) -> None:
    """Stream-name based VBA/macro detection (oletools signal)."""
    lowered = [s.lower() for s in streams]
    hits = [s for s, low in zip(streams, lowered)
            if any(marker in low for marker in _MACRO_MARKERS)]
    if hits:
        shown = ", ".join(hits[:6])
        out["flags"]["macros"] = hits
        out["exif_data"]["Document"]["Macros"] = (
            f"DETECTED ({shown}) - review required"
        )


def _detect_encryption(streams: List[str], out: Dict[str, Any]) -> None:
    """Encrypted OOXML (CFB wrapper) and OLE-encrypted documents."""
    lowered = {s.lower() for s in streams}
    if "encryptioninfo" in lowered or "encryptedpackage" in lowered:
        out["flags"]["encrypted_ooxml"] = True
        out["exif_data"]["Document"]["Encrypted"] = "yes (CFB-wrapped OOXML)"
    elif "encryptedstream" in lowered or "\x05encryptedstream" in lowered:
        out["exif_data"]["Document"]["Encrypted"] = "yes (OLE)"


def _detect_objects(streams: List[str], out: Dict[str, Any]) -> None:
    """ObjectPool = embedded OLE objects (classic malware drop vector)."""
    pool = [s for s in streams if s.lower().startswith("objectpool")]
    if pool:
        out["flags"]["ole_objects"] = pool
        out["exif_data"]["Document"]["Embedded OLE objects"] = (
            f"{len(pool)} in ObjectPool"
        )


def _stream_inventory(streams: List[str], out: Dict[str, Any]) -> None:
    """FOCA-style stream listing with suspicious entries highlighted."""
    suspicious = [s for s in streams
                  if s.lower().endswith((".exe", ".dll", ".bin", ".ps1", ".js", ".vbs"))
                  or "macro" in s.lower() or "vba" in s.lower()
                  or s.lower().endswith("oleread")]
    if suspicious:
        shown = ", ".join(suspicious[:6])
        out["flags"]["suspicious_streams"] = suspicious
        out["exif_data"]["Document"]["Suspicious streams"] = (
            f"{len(suspicious)}: {shown}"
        )


def _finalize(out: Dict[str, Any]) -> None:
    out["exif_data"]["Document"] = {
        k: v for k, v in out["exif_data"]["Document"].items() if v not in ("", None)
    }
