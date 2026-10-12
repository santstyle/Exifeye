"""
Geo export: write geolocated image coordinates to KML (Google Earth),
GPX (GPS devices / OsmAnd / Garmin) or CSV (spreadsheets / QGIS).

One output file per run, containing every geolocated image in the batch.
GPS recovered from a thumbnail or XMP block is included and labelled with
its source so the consumer knows it may not be the primary EXIF block.
"""
from __future__ import annotations

import csv
import re
from pathlib import Path
from typing import Any, List
from xml.sax.saxutils import escape


class GeoExporter:
    """Export a batch of extraction results' GPS to KML / GPX / CSV."""

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
        elif fmt == "csv":
            self._write_csv(geotagged, out)
        else:
            raise ValueError(f"unsupported geo format: {fmt}")
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

    # GPX (waypoints)                                                     #

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

        gpx = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<gpx version="1.1" creator="ExifEye" '
            'xmlns="http://www.topografix.com/GPX/1/1">\n'
            + "\n".join(wpts) + "\n"
            '</gpx>\n'
        )
        out.write_text(gpx, encoding="utf-8")

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
