"""PDF metadata extraction (pypdf).

Mines everything an OSINT analyst wants from a PDF without rendering it:

- Document Info dictionary (Producer, Creator, Author, Title, Subject,
  Keywords, CreationDate / ModDate) and PDF header version
- XMP packet (dc creator, xmp dates, xmpMM document ID) when present
- Page count, encrypted flag + attempt to unlock with the empty password
- JavaScript detection (document-level /Names tree, per-page /AA, and a
  raw-byte fallback count) - a classic malware/phishing signal
- Embedded files (attachments) list - FOCA-style hidden-payload hunting
- File attachment annotations

Output mirrors the image pipeline shape: ``exif_data["Document"]`` renders
through the existing EXIF category loop, timestamps feed the timestamp
analyzer, and D: dates are normalized to ISO-ish strings.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from pypdf import PdfReader
    from pypdf.generic import ArrayObject, DictionaryObject, IndirectObject
    _HAVE_PYPDF = True
except ImportError:  # pragma: no cover - dependency declared in requirements
    _HAVE_PYPDF = False

# D:20240131120000+07'00' / D:20240131120000Z / D:20240131 ...
_PDF_DATE = re.compile(
    r"D:(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?"
    r"([+-Z])(?:'?(\d{2})'?'?(\d{2})'?)?"
)

# Raw-byte JS fallback signals (deflate streams hide some, that is fine -
# we are counting visible evidence, labelled honestly).
_JS_MARKERS = (b"/JavaScript", b"/JS ", b"/JS(", b"app.alert", b"this.exportDataObject")


def parse(path: str | Path) -> Dict[str, Any]:
    """Extract PDF metadata. Returns an ExtractionResult-shaped payload dict."""
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
    if not _HAVE_PYPDF:
        out["errors"].append("pypdf not installed - run: pip install pypdf")
        return out

    try:
        raw = path.read_bytes()
    except OSError as e:
        out["errors"].append(f"pdf read error: {e}")
        return out

    # Header version straight from the magic line (works even for
    # damaged files pypdf refuses).
    head = raw[:16]
    if head.startswith(b"%PDF-"):
        out["exif_data"]["Document"]["PDF Version"] = head[5:9].decode(
            "latin-1", errors="replace"
        ).strip()

    reader = None
    encrypted = False
    try:
        reader = PdfReader(path, strict=False)
        encrypted = bool(reader.is_encrypted)
        if encrypted:
            out["exif_data"]["Document"]["Encrypted"] = "yes (empty-password tried)"
            try:
                if reader.decrypt("") == 0:
                    out["exif_data"]["Document"]["Encrypted"] = (
                        "yes (password required - metadata may be partial)"
                    )
            except Exception:  # noqa: BLE001 - pypdf raises many types here
                out["exif_data"]["Document"]["Encrypted"] = (
                    "yes (could not attempt decryption)"
                )
    except Exception as e:  # noqa: BLE001 - corrupt PDF must not crash the batch
        out["errors"].append(f"pdf parse error: {e}")

    if reader is not None:
        _read_info(reader, out)
        _read_xmp(reader, out)
        _read_pages(reader, out)
        _read_javascript(reader, out)
        _read_embedded_files(reader, out)

    _raw_fallback(raw, out)
    _finalize(out)
    return out


def _read_info(reader, out: Dict[str, Any]) -> None:
    tags = out["exif_data"]["Document"]
    try:
        info = reader.metadata
    except Exception:  # noqa: BLE001
        info = None
    if not info:
        return

    # pypdf keys are '/Producer' style; map to display labels.
    label_map = {
        "/Producer": "Producer",
        "/Creator": "Creator",
        "/Author": "Author",
        "/Title": "Title",
        "/Subject": "Subject",
        "/Keywords": "Keywords",
        "/CreationDate": "CreationDate",
        "/ModDate": "ModDate",
        "/Trapped": "Trapped",
    }
    for key, label in label_map.items():
        try:
            value = info.get(key) if hasattr(info, "get") else None
        except Exception:  # noqa: BLE001
            value = None
        if value:
            text = str(value).strip()
            if label in ("CreationDate", "ModDate"):
                iso = _normalize_pdf_date(text)
                tags[label] = iso or text
            elif label == "Keywords":
                tags[label] = text
            else:
                tags[label] = text

    # Timestamps feed the timestamps analyzer.
    created = tags.get("CreationDate")
    modified = tags.get("ModDate")
    if created:
        out["timestamps"]["created"] = created
    if modified:
        out["timestamps"]["modified"] = modified


def _read_xmp(reader, out: Dict[str, Any]) -> None:
    """Best-effort XMP packet extraction (dc/xmp/xmpMM essentials)."""
    try:
        xmp = reader.xmp_metadata
    except Exception:  # noqa: BLE001
        xmp = None
    if xmp is None:
        return
    fields = {
        "dc_creator": "XMP Creator",
        "xmp_create_date": "XMP CreateDate",
        "xmp_modify_date": "XMP ModifyDate",
        "xmpmm_document_id": "XMP DocumentID",
        "xmpmm_instance_id": "XMP InstanceID",
        "pdf_producer": "XMP Producer",
    }
    xmp_out: Dict[str, str] = {}
    for attr, label in fields.items():
        try:
            value = getattr(xmp, attr, None)
        except Exception:  # noqa: BLE001
            value = None
        if value:
            text = str(value).strip()
            if text:
                xmp_out[label] = text
    if xmp_out:
        out["exif_data"]["Document"].update(xmp_out)


def _read_pages(reader, out: Dict[str, Any]) -> None:
    tags = out["exif_data"]["Document"]
    try:
        tags["Pages"] = str(len(reader.pages))
    except Exception:  # noqa: BLE001
        tags["Pages"] = "(unreadable)"
        return
    # First page box gives an approximate media size (points -> pixels at 72dpi).
    try:
        box = reader.pages[0].mediabox
        w, h = float(box.width), float(box.height)
        if w > 0 and h > 0:
            tags["Page size (pt)"] = f"{w:g} x {h:g}"
            out["dimensions"] = (int(w * 72 / 72), int(h * 72 / 72))  # points ~= px at 72dpi
    except Exception:  # noqa: BLE001
        pass


def _read_javascript(reader, out: Dict[str, Any]) -> None:
    """Document JS (names tree), page AA JS, honest count only."""
    hits: List[str] = []
    try:
        root = reader.trailer.get("/Root")
        if isinstance(root, IndirectObject):
            root = root.get_object()
        if isinstance(root, DictionaryObject):
            names = root.get("/Names")
            if isinstance(names, IndirectObject):
                names = names.get_object()
            if isinstance(names, DictionaryObject):
                js = names.get("/JavaScript")
                if isinstance(js, IndirectObject):
                    js = js.get_object()
                if isinstance(js, DictionaryObject):
                    js_names = js.get("/Names")
                    if isinstance(js_names, IndirectObject):
                        js_names = js_names.get_object()
                    if isinstance(js_names, ArrayObject):
                        for i in range(0, len(js_names) - 1, 2):
                            name = js_names[i]
                            if isinstance(name, str):
                                hits.append(name)
            # OpenAction running code is another common trigger.
            oa = root.get("/OpenAction")
            if oa is not None:
                oa_obj = oa.get_object() if isinstance(oa, IndirectObject) else oa
                if isinstance(oa_obj, DictionaryObject) and (
                    "/JS" in oa_obj or "/S" in oa_obj and str(oa_obj.get("/S")) == "/JavaScript"
                ):
                    hits.append("OpenAction")
    except Exception:  # noqa: BLE001
        pass

    try:
        for page in reader.pages[:50]:  # bounded scan
            aa = page.get("/AA")
            if aa is not None:
                aa_obj = aa.get_object() if isinstance(aa, IndirectObject) else aa
                if isinstance(aa_obj, DictionaryObject) and "/JS" in aa_obj:
                    hits.append("Page /AA")
                    break
    except Exception:  # noqa: BLE001
        pass

    if hits:
        out["flags"]["javascript"] = hits
        out["exif_data"]["Document"]["JavaScript"] = (
            f"DETECTED ({', '.join(sorted(set(hits))[:5])})"
        )


def _read_embedded_files(reader, out: Dict[str, Any]) -> None:
    """FOCA-style attachment inventory from the /Names /EmbeddedFiles tree."""
    attached: List[str] = []
    try:
        root = reader.trailer.get("/Root")
        if isinstance(root, IndirectObject):
            root = root.get_object()
        if not isinstance(root, DictionaryObject):
            return
        names = root.get("/Names")
        if isinstance(names, IndirectObject):
            names = names.get_object()
        if not isinstance(names, DictionaryObject):
            return
        ef = names.get("/EmbeddedFiles")
        if isinstance(ef, IndirectObject):
            ef = ef.get_object()
        if not isinstance(ef, DictionaryObject):
            return
        entries = ef.get("/Names")
        if isinstance(entries, IndirectObject):
            entries = entries.get_object()
        if isinstance(entries, ArrayObject):
            for i in range(0, len(entries) - 1, 2):
                name = entries[i]
                if isinstance(name, str):
                    attached.append(name)
                elif isinstance(name, bytes):
                    attached.append(name.decode("latin-1", errors="replace"))
    except Exception:  # noqa: BLE001
        pass

    if attached:
        out["flags"]["embedded_files"] = attached
        shown = ", ".join(attached[:8])
        more = f" (+{len(attached) - 8} more)" if len(attached) > 8 else ""
        out["exif_data"]["Document"]["Embedded files"] = f"{len(attached)}: {shown}{more}"


def _raw_fallback(raw: bytes, out: Dict[str, Any]) -> None:
    """JS/embedded evidence from raw bytes when the object tree is opaque."""
    tags = out["exif_data"]["Document"]
    if "JavaScript" not in tags:
        visible = sum(raw.count(m) for m in _JS_MARKERS)
        if visible:
            out["flags"]["javascript_raw"] = visible
            tags["JavaScript"] = f"suspected ({visible} raw marker(s))"
    if "Producer" not in tags and b"/Producer" in raw:
        # Damaged Info dict - surface that the key exists at least.
        tags["Producer"] = "(present but unreadable)"


def _normalize_pdf_date(text: str) -> Optional[str]:
    """D:20240131120000+07'00' -> '2024-01-31 12:00:00 +07:00'."""
    m = _PDF_DATE.search(text)
    if not m:
        return None
    year, month, day, hour, minute, second, sign, tzh, tzm = m.groups()
    month = month or "01"
    day = day or "01"
    hour = hour or "00"
    minute = minute or "00"
    second = second or "00"
    out = f"{year}-{month}-{day} {hour}:{minute}:{second}"
    if sign == "Z":
        out += " +00:00"
    elif sign:
        out += f" {sign}{tzh or '00'}:{tzm or '00'}"
    return out


def _finalize(out: Dict[str, Any]) -> None:
    out["exif_data"]["Document"] = {
        k: v for k, v in out["exif_data"]["Document"].items() if v not in ("", None)
    }
