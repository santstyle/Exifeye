"""OOXML / ODF document metadata extraction (FOCA-style).

Opens .docx / .xlsx / .pptx (OOXML) and .odt / .ods / .odp (ODF) as zip
containers and mines:

- docProps/core.xml   - title, creator, lastModifiedBy, revision, keywords,
                        created / modified dates (dcterms)
- docProps/app.xml    - Application, AppVersion, Company, Manager, Template
                        (template often leaks a local filesystem path - FOCA),
                        Pages/Words/Characters/TotalTime
- docProps/custom.xml - vendor custom properties (vt: typed values)
- Macro presence       - word|xl|ppt/vbaProject.bin (stream-name based, the
                        same signal oletools reports for OOXML)
- External relationships - TargetMode="External" targets in every *.rels
                        (hidden links / attacker infrastructure / template
                        paths - classic FOCA finding)
- Embedded thumbnail    - docProps/thumbnail.*
- ODF meta.xml          - generator, creation date, editing duration

Output mirrors the image pipeline: exif_data["Document"] renders through
the existing EXIF category loop.
"""
from __future__ import annotations

import re
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from defusedxml.ElementTree import fromstring as _xml_fromstring
    _HAVE_XML = True
except ImportError:  # pragma: no cover - defusedxml is a declared dep
    _HAVE_XML = False

# dcterms ISO timestamps: 2024-01-31T12:00:00Z / with fractional seconds
_ISO_TS = re.compile(r"(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})")

# Local filesystem path leaks inside template/hyperlink values.
_PATH_LEAK = re.compile(
    r"[A-Za-z]:\\Users\\[^\"<>|]+|/(?:Users|home)/[^/\"<> ]+/"
)

_MACRO_PARTS = ("word/vbaProject.bin", "xl/vbaProject.bin", "ppt/vbaProject.bin",
                "word/vbaData.xml", "xl/vbaData.xml", "ppt/vbaData.xml")

_THUMB_PARTS = ("docProps/thumbnail.jpeg", "docProps/thumbnail.jpg",
                "docProps/thumbnail.png", "docProps/thumbnail.emf",
                "docProps/thumbnail.wmf")


def parse(path: str | Path) -> Dict[str, Any]:
    """Extract OOXML/ODF metadata. Returns ExtractionResult-shaped payload."""
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

    if not zipfile.is_zipfile(path):
        out["errors"].append("not a zip container (encrypted OOXML?)")
        return out

    try:
        with zipfile.ZipFile(path) as zf:
            names = set(zf.namelist())
            _mine(zf, names, out)
    except (OSError, zipfile.BadZipFile) as e:
        out["errors"].append(f"zip open error: {e}")
        return out

    _finalize(out)
    return out


def _mine(zf: zipfile.ZipFile, names: set, out: Dict[str, Any]) -> None:
    tags = out["exif_data"]["Document"]

    if "[Content_Types].xml" in names:
        tags["Container"] = "OOXML (Office Open XML)"
        if "docProps/core.xml" in names:
            _read_core(zf.read("docProps/core.xml"), out)
        if "docProps/app.xml" in names:
            _read_app(zf.read("docProps/app.xml"), out)
        if "docProps/custom.xml" in names:
            _read_custom(zf.read("docProps/custom.xml"), out)
        _detect_macros(names, out)
        _read_external_rels(zf, names, out)
    elif "mimetype" in names:
        try:
            mt = zf.read("mimetype").decode("ascii", errors="replace")
        except (OSError, KeyError):
            mt = "unknown"
        tags["Container"] = f"ODF ({mt})"
        if "meta.xml" in names:
            _read_odf_meta(zf.read("meta.xml"), out)
    else:
        tags["Container"] = "ZIP archive"

    thumb = [n for n in _THUMB_PARTS if n in names]
    if thumb:
        out["flags"]["thumbnail"] = thumb[0]
        tags["Embedded thumbnail"] = thumb[0]

    # Inventory count - FOCA always lists what is inside.
    total = len(names)
    suspicious = [n for n in names
                  if n.endswith((".bin", ".vba", ".exe", ".dll", ".js", ".ole"))
                  or "vba" in n.lower() or "macro" in n.lower()]
    if suspicious:
        shown = ", ".join(suspicious[:6])
        tags["Suspicious parts"] = f"{len(suspicious)}: {shown}"
        out["flags"]["suspicious_parts"] = suspicious
    out["flags"]["part_count"] = total


def _read_core(data: bytes, out: Dict[str, Any]) -> None:
    if not _HAVE_XML:
        out["errors"].append("defusedxml not installed - core.xml skipped")
        return
    tags = out["exif_data"]["Document"]
    try:
        root = _xml_fromstring(data)
    except Exception:  # noqa: BLE001 - malformed XML must not crash
        out["errors"].append("core.xml: malformed XML")
        return

    # localname -> display label
    wanted = {
        "title": "Title",
        "subject": "Subject",
        "creator": "Author",
        "keywords": "Keywords",
        "description": "Comments",
        "lastModifiedBy": "Last modified by",
        "revision": "Revision",
        "category": "Category",
        "contentStatus": "Content status",
        "created": "Created",
        "modified": "Modified",
    }
    for elem in root.iter():
        local = _localname(elem.tag)
        label = wanted.get(local)
        if not label or elem.text is None:
            continue
        value = elem.text.strip()
        if not value:
            continue
        if label in ("Created", "Modified"):
            value = _normalize_iso(value)
            out["timestamps"][label.lower()] = value
        tags[label] = value


def _read_app(data: bytes, out: Dict[str, Any]) -> None:
    if not _HAVE_XML:
        return
    tags = out["exif_data"]["Document"]
    try:
        root = _xml_fromstring(data)
    except Exception:  # noqa: BLE001
        return

    wanted = {
        "Application": "Application",
        "AppVersion": "App version",
        "Company": "Company",
        "Manager": "Manager",
        "Template": "Template",
        "Pages": "Pages",
        "Words": "Words",
        "Characters": "Characters",
        "TotalTime": "Editing time (min)",
        "HyperlinkBase": "Hyperlink base",
        "DocSecurity": "Doc security",
        "SharedDoc": "Shared document",
        "HyperlinksChanged": "Hyperlinks changed",
    }
    for elem in root.iter():
        local = _localname(elem.tag)
        label = wanted.get(local)
        if not label or elem.text is None:
            continue
        value = elem.text.strip()
        if not value:
            continue
        tags[label] = value
        # FOCA flag: template leaking a local user path.
        if label == "Template" and _PATH_LEAK.search(value):
            out["flags"]["path_leak"] = value
            tags[label] = f"{value}  [PATH LEAK]"


def _read_custom(data: bytes, out: Dict[str, Any]) -> None:
    if not _HAVE_XML:
        return
    tags = out["exif_data"]["Document"]
    try:
        root = _xml_fromstring(data)
    except Exception:  # noqa: BLE001
        return

    # Each property: <property fmtid=... pid=... name="X"><vt:...>value
    for prop in root.iter():
        if _localname(prop.tag) != "property":
            continue
        name = prop.get("name") or ""
        if not name:
            continue
        for child in prop:
            if child.text is not None and child.text.strip():
                tags[f"Custom: {name}"] = child.text.strip()
                break


def _detect_macros(names: set, out: Dict[str, Any]) -> None:
    """Stream-name based macro detection (oletools signal for OOXML)."""
    found = [n for n in _MACRO_PARTS if n in names]
    # Any vbaProject anywhere (e.g. under customUI) still counts.
    if not found:
        found = [n for n in names
                 if n.endswith("vbaProject.bin") or n.endswith("vbaData.xml")]
    if found:
        out["flags"]["macros"] = found
        out["exif_data"]["Document"]["Macros"] = (
            f"DETECTED ({', '.join(found)}) - review required"
        )


def _read_external_rels(zf: zipfile.ZipFile, names: set, out: Dict[str, Any]) -> None:
    """Collect TargetMode=External targets - FOCA-style link harvesting."""
    if not _HAVE_XML:
        return
    externals: List[str] = []
    for name in sorted(n for n in names if n.endswith(".rels")):
        if "/_rels/" not in name and not name.startswith("_rels/"):
            continue
        try:
            root = _xml_fromstring(zf.read(name))
        except Exception:  # noqa: BLE001
            continue
        for rel in root.iter():
            if _localname(rel.tag) != "Relationship":
                continue
            if str(rel.get("TargetMode", "")).lower() != "external":
                continue
            target = (rel.get("Target") or "").strip()
            if target:
                externals.append(target)

    if not externals:
        return
    out["flags"]["external_rels"] = externals
    shown = "; ".join(externals[:5])
    more = f" (+{len(externals) - 5} more)" if len(externals) > 5 else ""
    out["exif_data"]["Document"]["External links"] = f"{len(externals)}: {shown}{more}"


def _read_odf_meta(data: bytes, out: Dict[str, Any]) -> None:
    if not _HAVE_XML:
        return
    tags = out["exif_data"]["Document"]
    try:
        root = _xml_fromstring(data)
    except Exception:  # noqa: BLE001
        return

    wanted = {
        "generator": "Generator",
        "creation-date": "Created",
        "date": "Modified",
        "editing-cycles": "Editing cycles",
        "editing-duration": "Editing duration (s)",
    }
    for elem in root.iter():
        local = _localname(elem.tag)
        label = wanted.get(local)
        if not label or elem.text is None:
            continue
        value = elem.text.strip()
        if not value:
            continue
        if label in ("Created", "Modified"):
            value = _normalize_iso(value)
            out["timestamps"][label.lower()] = value
        tags[label] = value


def _localname(tag: str) -> str:
    """'{ns}local' -> 'local'."""
    if "}" in tag:
        return tag.rsplit("}", 1)[1]
    return tag


def _normalize_iso(value: str) -> str:
    """2024-01-31T12:00:00Z -> '2024-01-31 12:00:00 UTC'."""
    m = _ISO_TS.search(value)
    if not m:
        return value
    out = f"{m.group(1)} {m.group(2)}"
    if value.rstrip().endswith("Z") or "Z" in value[m.end():m.end() + 2]:
        out += " UTC"
    return out


def _finalize(out: Dict[str, Any]) -> None:
    out["exif_data"]["Document"] = {
        k: v for k, v in out["exif_data"]["Document"].items() if v not in ("", None)
    }
