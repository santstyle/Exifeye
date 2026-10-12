"""
Geo export: write geolocated image coordinates to KML (Google Earth),
GPX (GPS devices / OsmAnd / Garmin), GeoJSON (web maps / QGIS) or CSV
(spreadsheets / QGIS).

One output file per run, containing every geolocated image in the batch.
With 2+ points a path is emitted too: a KML LineString, a GPX <trk> and a
GeoJSON LineString - ordered by capture time when every point has one,
otherwise kept in input order (no invented chronology).
GPS recovered from a thumbnail or XMP block is included and labelled with
its source so the consumer knows it may not be the primary EXIF block.
"""
from __future__ import annotations

import csv
import json
import re
from html import escape as html_escape
from pathlib import Path
from typing import Any, List
from xml.sax.saxutils import escape

# Standalone Leaflet map: raw string so {z}/{x}/{y} in the tile URL and
# CSS braces survive - only __MAP_DATA__ / __COUNT__ get substituted.
_MAP_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ExifEye GPS Map</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<style>
  html, body { margin: 0; height: 100%; background: #0a0f0a; }
  #map { height: 100%; }
  .footer { position: fixed; bottom: 0; left: 0; right: 0; z-index: 1000;
            background: rgba(10, 15, 10, .88); color: #9effb0;
            font: 12px ui-monospace, Consolas, monospace; padding: 6px 10px; }
  .footer a { color: #00ff41; }
  .leaflet-popup-content-wrapper { background: #0a0f0a; color: #c9ffe0;
            border: 1px solid #00ff41; border-radius: 4px;
            font: 12px ui-monospace, Consolas, monospace; }
  .leaflet-popup-tip { background: #00ff41; }
</style>
</head>
<body>
<div id="map"></div>
<div class="footer">__COUNT__ point(s) &middot; Leaflet + OpenStreetMap tiles
load from the internet when you open this file &middot; the coordinates were
written locally and left your machine only now.</div>
<script>
const data = __MAP_DATA__;
const map = L.map('map');
L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png', {
  maxZoom: 19,
  attribution: '&copy; OpenStreetMap contributors'
}).addTo(map);
const coords = [];
for (const p of data.points) {
  L.marker([p.lat, p.lon]).addTo(map).bindPopup(p.popup);
  coords.push([p.lat, p.lon]);
}
if (data.path && data.path.length > 1) {
  L.polyline(data.path, { color: '#00ff41', weight: 3, opacity: 0.8 }).addTo(map);
}
if (coords.length > 1) {
  map.fitBounds(coords, { padding: [30, 30] });
} else if (coords.length === 1) {
  map.setView(coords[0], 15);
} else {
  map.setView([0, 0], 2);
}
</script>
</body>
</html>
"""


class GeoExporter:
    """Export a batch of extraction results' GPS to KML / GPX / GeoJSON / CSV."""

    def export(self, results: List[Any], output_dir: str | Path | None,
               fmt: str) -> Path | None:
        """Write one file with every geolocated image; None when no GPS."""
        geotagged = [r for r in results if (getattr(r, "gps", None) or {}).get("available")]
        if not geotagged:
            return None

        output_dir = (Path(output_dir) if output_dir
                      else Path(geotagged[0].file_path).parent)
        output_dir.mkdir(parents=True, exist_ok=True)
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", f"exifeye_geo.{fmt}").strip("._")
        out = output_dir / (safe or f"exifeye_geo.{fmt}")

        if fmt == "kml":
            self._write_kml(geotagged, out)
        elif fmt == "gpx":
            self._write_gpx(geotagged, out)
        elif fmt == "geojson":
            self._write_geojson(geotagged, out)
        elif fmt == "csv":
            self._write_csv(geotagged, out)
        else:
            raise ValueError(f"unsupported geo format: {fmt}")
        return out

    # Interactive Leaflet map (standalone HTML)                           #

    def export_map(self, results: List[Any],
                   output_dir: str | Path | None = None) -> Path | None:
        """Write a standalone Leaflet HTML map of every geolocated point.

        The file is fully local; opening it in a browser loads map tiles
        from OpenStreetMap (tile fetch only, no image data). Returns None
        when no image has GPS.
        """
        geotagged = [r for r in results if (getattr(r, "gps", None) or {}).get("available")]
        if not geotagged:
            return None

        output_dir = (Path(output_dir) if output_dir
                      else Path(geotagged[0].file_path).parent)
        output_dir.mkdir(parents=True, exist_ok=True)
        out = output_dir / "exifeye_map.html"

        points = []
        for r in geotagged:
            gps = r.gps
            parts = [f"<b>{html_escape(r.file_name)}</b>"]
            make = (r.device or {}).get("make") or ""
            model = (r.device or {}).get("model") or ""
            if make or model:
                parts.append(html_escape(f"{make} {model}".strip()))
            taken = (r.timestamps or {}).get("original") or ""
            if taken:
                parts.append(html_escape(str(taken)))
            link = gps.get("google_maps_link") or ""
            if link:
                parts.append(
                    f'<a href="{html_escape(str(link))}" '
                    f'target="_blank" rel="noopener">Google Maps</a>'
                )
            points.append({
                "lat": gps["latitude"],
                "lon": gps["longitude"],
                "popup": "<br>".join(parts),
            })

        path: list[list[float]] = []
        if len(geotagged) >= 2:
            path = [[r.gps["latitude"], r.gps["longitude"]]
                    for r in _ordered_for_track(geotagged)]

        # "\u003c" keeps a crafted "</script>" inside EXIF strings from
        # breaking out of the data blob; json.dumps escapes the rest.
        # Count is substituted first so a filename that literally contains
        # "__COUNT__" cannot be corrupted by the second replace.
        blob = json.dumps({"points": points, "path": path},
                          ensure_ascii=False).replace("<", "\\u003c")
        html_doc = (_MAP_TEMPLATE
                    .replace("__COUNT__", str(len(points)))
                    .replace("__MAP_DATA__", blob))
        out.write_text(html_doc, encoding="utf-8")
        return out

    # KML (Google Earth)                                                  #

    @staticmethod
    def _write_kml(geotagged: List[Any], out: Path) -> None:
        placemarks = []
        for r in geotagged:
            gps = r.gps
            alt = gps.get("altitude_meters") or 0
            coords = f"{gps['longitude']:.7f},{gps['latitude']:.7f},{alt}"
            desc_parts = []
            make = (r.device or {}).get("make") or ""
            model = (r.device or {}).get("model") or ""
            if make or model:
                desc_parts.append(f"Device: {make} {model}".strip())
            if gps.get("source"):
                desc_parts.append(f"GPS source: {gps['source']}")
            if (r.timestamps or {}).get("original"):
                desc_parts.append(f"Taken: {r.timestamps['original']}")
            placemarks.append(
                f"    <Placemark>\n"
                f"      <name>{escape(r.file_name)}</name>\n"
                f"      <description>{escape('; '.join(desc_parts))}</description>\n"
                f"      <Point>\n"
                f"        <coordinates>{coords}</coordinates>\n"
                f"      </Point>\n"
                f"    </Placemark>"
            )

        if len(geotagged) >= 2:
            line = " ".join(
                f"{r.gps['longitude']:.7f},{r.gps['latitude']:.7f},"
                f"{r.gps.get('altitude_meters') or 0}"
                for r in _ordered_for_track(geotagged)
            )
            placemarks.append(
                "    <Placemark>\n"
                "      <name>Capture path</name>\n"
                "      <LineString>\n"
                f"        <coordinates>{line}</coordinates>\n"
                "      </LineString>\n"
                "    </Placemark>"
            )

        kml = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<kml xmlns="http://www.opengis.net/kml/2.2">\n'
            '  <Document>\n'
            '    <name>ExifEye GPS Export</name>\n'
            f'    <description>{len(geotagged)} geolocated image(s)</description>\n'
            + "\n".join(placemarks) + "\n"
            '  </Document>\n'
            '</kml>\n'
        )
        out.write_text(kml, encoding="utf-8")

    # GPX (waypoints + track)                                             #

    @staticmethod
    def _write_gpx(geotagged: List[Any], out: Path) -> None:
        wpts = []
        for r in geotagged:
            gps = r.gps
            lines = [f'  <wpt lat="{gps["latitude"]:.7f}" lon="{gps["longitude"]:.7f}">']
            if gps.get("altitude_meters") is not None:
                lines.append(f"    <ele>{gps['altitude_meters']}</ele>")
            iso = _exif_to_iso((r.timestamps or {}).get("original"))
            if iso:
                lines.append(f"    <time>{iso}</time>")
            lines.append(f"    <name>{escape(r.file_name)}</name>")
            if gps.get("source"):
                lines.append(f"    <desc>GPS source: {escape(str(gps['source']))}</desc>")
            lines.append("  </wpt>")
            wpts.append("\n".join(lines))

        # A track turns the points into a route (OsmAnd / Garmin can draw
        # it); skipped for a single point - a path needs 2+ vertices.
        trk = ""
        if len(geotagged) >= 2:
            trkpts = []
            for r in _ordered_for_track(geotagged):
                gps = r.gps
                p = [f'      <trkpt lat="{gps["latitude"]:.7f}" '
                     f'lon="{gps["longitude"]:.7f}">']
                if gps.get("altitude_meters") is not None:
                    p.append(f"        <ele>{gps['altitude_meters']}</ele>")
                iso = _exif_to_iso((r.timestamps or {}).get("original"))
                if iso:
                    p.append(f"        <time>{iso}</time>")
                p.append("      </trkpt>")
                trkpts.append("\n".join(p))
            trk = (
                "  <trk>\n"
                "    <name>ExifEye capture path</name>\n"
                "    <trkseg>\n" + "\n".join(trkpts) + "\n"
                "    </trkseg>\n"
                "  </trk>\n"
            )

        gpx = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<gpx version="1.1" creator="ExifEye" '
            'xmlns="http://www.topografix.com/GPX/1/1">\n'
            + "\n".join(wpts) + "\n" + trk +
            '</gpx>\n'
        )
        out.write_text(gpx, encoding="utf-8")

    # GeoJSON (web maps / QGIS)                                           #

    @staticmethod
    def _write_geojson(geotagged: List[Any], out: Path) -> None:
        features = []
        for r in geotagged:
            gps = r.gps
            coords = [gps["longitude"], gps["latitude"]]
            if gps.get("altitude_meters") is not None:
                coords.append(gps["altitude_meters"])
            props = {
                "file": r.file_name,
                "geohash": gps.get("geohash", ""),
                "gps_source": gps.get("source", "EXIF"),
                "taken": (r.timestamps or {}).get("original") or "",
                "google_maps_link": gps.get("google_maps_link", ""),
            }
            make = (r.device or {}).get("make") or ""
            model = (r.device or {}).get("model") or ""
            if make or model:
                props["device"] = f"{make} {model}".strip()
            features.append({
                "type": "Feature",
                "properties": props,
                "geometry": {"type": "Point", "coordinates": coords},
            })

        # A LineString turns the points into a route; skipped for a single
        # point - a path needs 2+ vertices.
        if len(geotagged) >= 2:
            line = [
                [r.gps["longitude"], r.gps["latitude"]]
                for r in _ordered_for_track(geotagged)
            ]
            features.append({
                "type": "Feature",
                "properties": {"file": "ExifEye capture path"},
                "geometry": {"type": "LineString", "coordinates": line},
            })

        doc = {"type": "FeatureCollection", "features": features}
        out.write_text(json.dumps(doc, indent=2, ensure_ascii=False),
                       encoding="utf-8")

    # CSV (spreadsheets)                                                  #

    @staticmethod
    def _write_csv(geotagged: List[Any], out: Path) -> None:
        with open(out, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "file", "latitude", "longitude", "altitude_m",
                "geohash", "gps_source", "taken", "google_maps_link",
            ])
            for r in geotagged:
                gps = r.gps
                writer.writerow([
                    r.file_name,
                    f"{gps['latitude']:.7f}",
                    f"{gps['longitude']:.7f}",
                    gps.get("altitude_meters", ""),
                    gps.get("geohash", ""),
                    gps.get("source", "EXIF"),
                    (r.timestamps or {}).get("original") or "",
                    gps.get("google_maps_link", ""),
                ])


def _ordered_for_track(geotagged: List[Any]) -> List[Any]:
    """Order points for path geometry: capture time when known, else input.

    Route geometry implies chronology, so points are sorted by their ISO
    time when every point has one; a partial or missing set keeps the
    original order rather than inventing a plausible-looking timeline.
    """
    isos = [_exif_to_iso((r.timestamps or {}).get("original"))
            for r in geotagged]
    if all(isos):
        return [r for _, r in sorted(zip(isos, geotagged),
                                     key=lambda p: p[0])]
    return list(geotagged)


def _exif_to_iso(value: Any) -> str | None:
    """Convert an EXIF 'YYYY:MM:DD HH:MM:SS' string to GPX time (ISO 8601).

    EXIF timestamps are timezone-naive; GPX <time> wants a full instant,
    so they are emitted as UTC (the convention most converters use when the
    original timezone is unknown).
    """
    if not value:
        return None
    text = str(value).strip()
    if len(text) < 19:
        return None
    date_part = text[:10].replace(":", "-", 2)
    time_part = text[11:19]
    if not date_part[4] == "-" or not date_part[7] == "-":
        return None
    return f"{date_part}T{time_part}Z"
