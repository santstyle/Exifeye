"""
HTML report export with interactive map.
"""
from __future__ import annotations

import html
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict


class HTMLReport:
    """Generate a standalone HTML report with interactive Google Maps embedding."""

    def export(
        self,
        result: Any,
        forensics: Dict[str, Any],
        deep: Dict[str, Any],
        hashes: Dict[str, Any],
        output_dir: str | Path | None = None,
        filename: str | None = None,
        extra: Dict[str, Any] | None = None,
    ) -> Path:
        """Generate the HTML report file and return its path."""
        output_dir = Path(output_dir) if output_dir else result.file_path.parent
        output_dir.mkdir(parents=True, exist_ok=True)

        if filename is None:
            base = Path(result.file_path).stem
            filename = f"{base}_report.html"

        # Sanitize output filename: block path traversal via crafted file
        # names (e.g. "..\\evil.jpg" on POSIX where '\\' is a valid char).
        safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", filename).strip("._") or "report"
        output_path = output_dir / safe_name

        gps = result.gps
        device = result.device
        timestamps = result.timestamps

        # GPS section
        if gps.get("available"):
            lat = html.escape(str(gps["latitude"]))
            lon = html.escape(str(gps["longitude"]))
            altitude = html.escape(str(gps.get("altitude_meters", "N/A")))
            geohash = html.escape(str(gps.get("geohash", "N/A")))
            gmaps_link = html.escape(str(gps.get("google_maps_link", "#")))
            maps_embed = f"""
            <div class="map-container">
                <iframe
                    width="100%" height="400" style="border:0"
                    loading="lazy" allowfullscreen
                    src="https://www.google.com/maps?q={lat},{lon}&z=16&output=embed">
                </iframe>
            </div>
            """
            gps_html = f"""
            <div class="card gps-card">
                <h2>GPS Coordinates - FOUND</h2>
                <p><strong>Latitude:</strong> {lat}° {html.escape(str(gps.get('latitude_ref', '')))}</p>
                <p><strong>Longitude:</strong> {lon}° {html.escape(str(gps.get('longitude_ref', '')))}</p>
                <p><strong>Altitude:</strong> {altitude} m</p>
                <p><strong>Geohash:</strong> <code>{geohash}</code></p>
                <p><strong>Google Maps Link:</strong> <a href="{gmaps_link}" target="_blank">{gmaps_link}</a></p>
                {maps_embed}
            </div>
            """
        else:
            gps_html = """
            <div class="card gps-card missing">
                <h2>GPS Coordinates - NOT FOUND</h2>
                <p>No GPS data in this image. It was likely stripped by a platform or never recorded.</p>
            </div>
            """

        # Device section
        device_html = f"""
        <div class="card">
            <h2>Device / Camera</h2>
            <table>
                <tr><th>Make</th><td>{html.escape(str(device.get('make') or 'Unknown'))}</td></tr>
                <tr><th>Model</th><td>{html.escape(str(device.get('model') or 'Unknown'))}</td></tr>
                <tr><th>Model Name</th><td>{html.escape(str(device.get('model_name') or 'Unknown'))}</td></tr>
                <tr><th>Device Type</th><td>{html.escape(str(device.get('device_type') or 'Unknown'))}</td></tr>
                <tr><th>Software</th><td>{html.escape(str(device.get('software') or 'Unknown'))}</td></tr>
                <tr><th>Lens</th><td>{html.escape(str(device.get('lens_model') or 'Unknown'))}</td></tr>
                <tr><th>Device Year</th><td>{html.escape(str(device.get('year') or 'Unknown'))}</td></tr>
            </table>
        </div>
        """

        # Social media section
        platform = forensics.get("detected_platform")
        if platform:
            platform_badge = f'<span class="badge detected">{platform.upper()} DETECTED</span>'
        else:
            platform_badge = '<span class="badge none">No platform detected</span>'

        forensics_html = f"""
        <div class="card">
            <h2>Social Media Forensics {platform_badge}</h2>
            <table>
                <tr><th>Detected Platform</th><td>{html.escape(str(platform or 'None'))}</td></tr>
                <tr><th>Confidence</th><td>{forensics.get('confidence', 0)*100:.0f}%</td></tr>
                <tr><th>Screenshot</th><td>{'Yes' if forensics.get('is_screenshot') else 'No'}</td></tr>
                <tr><th>Re-encoded</th><td>{'Yes' if forensics.get('reencoded') else 'No'}</td></tr>
            </table>
        </div>
        """

        # Timestamps
        if timestamps:
            ts_rows = "".join(
                f"<tr><th>{html.escape(k)}</th><td>{html.escape(str(v))}</td></tr>"
                for k, v in timestamps.items()
            )
            ts_html = f"""
            <div class="card">
                <h2>Timestamps</h2>
                <table>{ts_rows}</table>
            </div>
            """
        else:
            ts_html = ""

        # Hashes
        hash_rows = "".join(
            f"<tr><th>{html.escape(k)}</th><td><code>{html.escape(str(v))}</code></td></tr>"
            for k, v in hashes.items()
        )
        hashes_html = f"""
        <div class="card">
            <h2>File Hashes</h2>
            <table>{hash_rows}</table>
        </div>
        """

        # EXIF data
        if result.exif_data:
            exif_sections = ""
            for category, tags in result.exif_data.items():
                if category == "GPS" or not tags:
                    continue
                rows = "".join(
                    f"<tr><th>{html.escape(tag)}</th><td>{html.escape(str(val))}</td></tr>"
                    for tag, val in sorted(tags.items())
                )
                exif_sections += f"""
                <div class="card">
                    <h2>{html.escape(category)} Data</h2>
                    <table>{rows}</table>
                </div>
                """
            exif_html = exif_sections
        else:
            exif_html = """
            <div class="card missing">
                <h2>No EXIF Data</h2>
                <p>EXIF was not found in this image.</p>
            </div>
            """

        # Deep forensics
        ela = deep.get("ela", {})
        deep_html = f"""
        <div class="card">
            <h2>Deep Forensics</h2>
            <table>
                <tr><th>ELA Analysis</th><td>{'Analyzed' if ela.get('available') else 'Not available'}</td></tr>
                <tr><th>ELA Interpretation</th><td>{html.escape(str(ela.get('interpretation') or 'N/A'))}</td></tr>
                <tr><th>LSB Anomaly</th><td>{'Yes' if deep.get('steganography', {}).get('anomaly_detected') else 'No'}</td></tr>
                <tr><th>Image Entropy</th><td>{html.escape(str(deep.get('entropy', {}).get('entropy', 'N/A')))}</td></tr>
            </table>
        </div>
        """

        # Authentication risk meter (v2.1)
        auth = (extra or {}).get("auth_risk") or {}
        if auth.get("available"):
            level = auth.get("level", "LOW")
            score = auth.get("score", 0)
            badge_cls = {"LOW": "detected", "MEDIUM": "warn"}.get(level, "none")
            signal_rows = "".join(
                f"<tr><th>+{sig.get('weight', 0)} {html.escape(str(sig.get('name', '?')))}</th>"
                f"<td>{html.escape(str(sig.get('detail', '')))}</td></tr>"
                for sig in auth.get("signals") or []
            )
            auth_html = f"""
            <div class="card">
                <h2>Authentication Risk <span class="badge {badge_cls}">{html.escape(level)}</span></h2>
                <p><strong>Score:</strong> {score}/100</p>
                <p><strong>Summary:</strong> {html.escape(str(auth.get('summary', '')))}</p>
                {f'<table>{signal_rows}</table>' if signal_rows else '<p>No risk signals detected.</p>'}
            </div>
            """
        else:
            auth_html = ""

        # GPS spoof check (v2.1)
        spoof = (extra or {}).get("gps_spoof") or {}
        if spoof.get("issues"):
            issue_rows = "".join(
                f"<tr><td>{html.escape(str(issue))}</td></tr>"
                for issue in spoof.get("issues") or []
            )
            spoof_html = f"""
            <div class="card missing">
                <h2>GPS Spoof Check <span class="badge none">ISSUES</span></h2>
                <p><strong>Verdict:</strong> {html.escape(str(spoof.get('verdict', '')))}</p>
                <table>{issue_rows}</table>
            </div>
            """
        elif spoof.get("plausible"):
            spoof_html = f"""
            <div class="card gps-card">
                <h2>GPS Spoof Check <span class="badge detected">CLEAN</span></h2>
                <p>{html.escape(str(spoof.get('verdict', '')))}</p>
            </div>
            """
        else:
            spoof_html = ""

        # Trailing data / polyglot check (v2.1)
        trailing = (extra or {}).get("trailing") or {}
        if trailing.get("trailing_bytes", 0) > 0:
            sigs = trailing.get("signatures") or []
            sig_str = ", ".join(html.escape(s) for s in sigs) if sigs else "none detected"
            trailing_html = f"""
            <div class="card missing">
                <h2>Trailing Data <span class="badge none">APPENDED</span></h2>
                <table>
                    <tr><th>Format</th><td>{html.escape(str(trailing.get('format', '?')))}</td></tr>
                    <tr><th>Trailing bytes</th><td>{trailing.get('trailing_bytes')}</td></tr>
                    <tr><th>Signatures</th><td>{sig_str}</td></tr>
                    <tr><th>Polyglot</th><td>{'Yes' if trailing.get('polyglot') else 'No'}</td></tr>
                    <tr><th>Preview (hex)</th><td><code>{html.escape(str(trailing.get('trailing_preview') or ''))}</code></td></tr>
                </table>
            </div>
            """
        else:
            trailing_html = ""

        # Panorama / 360 detection (v2.1) - informational finding, green card
        pano = (extra or {}).get("panorama") or {}
        if pano.get("detected"):
            pano_sigs = pano.get("signals") or []
            pano_sig_html = "".join(
                f"<li>{html.escape(str(sg))}</li>" for sg in pano_sigs[:8]
            )
            pano_html = f"""
            <div class="card gps-card">
                <h2>Panorama / 360 <span class="badge detected">{html.escape(str(pano.get('kind') or 'detected')).upper()}</span></h2>
                <p>{html.escape(str(pano.get('verdict', '')))}</p>
                <ul>{pano_sig_html}</ul>
            </div>
            """
        else:
            pano_html = ""

        file_html = f"""
        <div class="card">
            <h2>File Information</h2>
            <table>
                <tr><th>File</th><td>{html.escape(result.file_name)}</td></tr>
                <tr><th>Type</th><td>{html.escape(result.file_type)}</td></tr>
                <tr><th>Size</th><td>{result.file_size:,} bytes</td></tr>
                <tr><th>Dimensions</th><td>{result.dimensions[0]} x {result.dimensions[1]} px</td></tr>
                <tr><th>Color Mode</th><td>{html.escape(result.mode or 'N/A')}</td></tr>
                <tr><th>Orientation</th><td>{html.escape(result.orientation or 'N/A')}</td></tr>
                <tr><th>ICC Profile</th><td>{html.escape(result.icc_profile or 'None')}</td></tr>
                <tr><th>Embedded Thumbnail</th><td>{'Yes' if result.has_embedded_thumbnail else 'No'}</td></tr>
            </table>
        </div>
        """

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Metadata Report — {html.escape(result.file_name)}</title>
<style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        background: #0f1117;
        color: #e4e6eb;
        padding: 20px;
        line-height: 1.6;
    }}
    .container {{ max-width: 1000px; margin: 0 auto; }}
    h1 {{
        color: #58a6ff;
        margin-bottom: 10px;
        border-bottom: 2px solid #30363d;
        padding-bottom: 10px;
    }}
    .subtitle {{ color: #8b949e; margin-bottom: 30px; font-size: 0.9em; }}
    .card {{
        background: #161b22;
        border: 1px solid #30363d;
        border-radius: 8px;
        padding: 20px;
        margin-bottom: 20px;
    }}
    .card h2 {{ color: #58a6ff; margin-bottom: 15px; font-size: 1.2em; }}
    .card.gps-card {{ border-color: #2ea043; }}
    .card.gps-card h2 {{ color: #3fb950; }}
    .card.missing {{ border-color: #f85149; }}
    .card.missing h2 {{ color: #f85149; }}
    .map-container {{ margin-top: 15px; border-radius: 8px; overflow: hidden; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{
        padding: 8px 12px;
        text-align: left;
        border-bottom: 1px solid #30363d;
        vertical-align: top;
    }}
    th {{ color: #8b949e; width: 200px; font-weight: 600; }}
    td {{ word-break: break-all; }}
    code {{
        background: #0d1117;
        padding: 2px 6px;
        border-radius: 4px;
        font-size: 0.85em;
        color: #79c0ff;
    }}
    a {{ color: #58a6ff; }}
    .badge {{
        display: inline-block;
        padding: 2px 10px;
        border-radius: 12px;
        font-size: 0.75em;
        font-weight: bold;
        margin-left: 10px;
        vertical-align: middle;
    }}
    .badge.detected {{ background: #2ea04333; color: #3fb950; border: 1px solid #2ea043; }}
    .badge.none {{ background: #f8514933; color: #f85149; border: 1px solid #f85149; }}
    .badge.warn {{ background: #d2992222; color: #d29922; border: 1px solid #d29922; }}
    @media print {{
        body {{ background: white; color: black; }}
        .card {{ background: white; border-color: #ddd; }}
    }}
</style>
</head>
<body>
<div class="container">
    <h1>OSINT Metadata Report</h1>
    <div class="subtitle">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} — Source: {html.escape(result.file_name)}</div>
    {file_html}
    {gps_html}
    {spoof_html}
    {device_html}
    {ts_html}
    {forensics_html}
    {exif_html}
    {deep_html}
    {trailing_html}
    {pano_html}
    {auth_html}
    {hashes_html}
</div>
</body>
</html>"""

        output_path.write_text(html_content, encoding="utf-8")
        return output_path

    def write_index(self, entries: list[dict], output_dir: str | Path) -> Path:
        """Write a batch index.html linking every per-image HTML report.

        Each entry needs: file_name, report_href (same-folder filename), and
        optionally device / gps ("YES"|"THUMB"|"NO") / risk (level string).
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        rows = []
        gps_count = 0
        for i, e in enumerate(entries, 1):
            name = html.escape(str(e.get("file_name", "?")))
            href = html.escape(str(e.get("report_href", "#")))
            device = html.escape(str(e.get("device") or "Unknown"))
            gps = str(e.get("gps") or "NO")
            if gps == "YES":
                gps_count += 1
            gps_cls = {"YES": "detected", "THUMB": "warn"}.get(gps, "none")
            risk = e.get("risk")
            if risk:
                risk_cls = {"LOW": "detected", "MEDIUM": "warn"}.get(
                    str(risk), "none"
                )
                risk_cell = (
                    f'<span class="badge {risk_cls}">{html.escape(str(risk))}</span>'
                )
            else:
                risk_cell = "-"
            rows.append(
                f'<tr><td>{i}</td><td><a href="{href}">{name}</a></td>'
                f"<td>{device}</td>"
                f'<td><span class="badge {gps_cls}">{gps}</span></td>'
                f"<td>{risk_cell}</td></tr>"
            )

        subtitle = (
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} — "
            f"{len(entries)} image(s), {gps_count} with GPS"
        )
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ExifEye — Batch Index</title>
<style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        background: #0f1117;
        color: #e4e6eb;
        padding: 20px;
        line-height: 1.6;
    }}
    .container {{ max-width: 1000px; margin: 0 auto; }}
    h1 {{
        color: #58a6ff;
        margin-bottom: 10px;
        border-bottom: 2px solid #30363d;
        padding-bottom: 10px;
    }}
    .subtitle {{ color: #8b949e; margin-bottom: 30px; font-size: 0.9em; }}
    .card {{
        background: #161b22;
        border: 1px solid #30363d;
        border-radius: 8px;
        padding: 20px;
        margin-bottom: 20px;
    }}
    .card h2 {{ color: #58a6ff; margin-bottom: 15px; font-size: 1.2em; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{
        padding: 8px 12px;
        text-align: left;
        border-bottom: 1px solid #30363d;
        vertical-align: top;
    }}
    th {{ color: #8b949e; font-weight: 600; }}
    a {{ color: #58a6ff; }}
    .badge {{
        display: inline-block;
        padding: 2px 10px;
        border-radius: 12px;
        font-size: 0.75em;
        font-weight: bold;
        vertical-align: middle;
    }}
    .badge.detected {{ background: #2ea04333; color: #3fb950; border: 1px solid #2ea043; }}
    .badge.none {{ background: #f8514933; color: #f85149; border: 1px solid #f85149; }}
    .badge.warn {{ background: #d2992222; color: #d29922; border: 1px solid #d29922; }}
</style>
</head>
<body>
<div class="container">
    <h1>ExifEye — Batch Index</h1>
    <div class="subtitle">{subtitle}</div>
    <div class="card">
        <h2>Analyzed Images</h2>
        <table>
            <tr><th>#</th><th>Report</th><th>Device</th><th>GPS</th><th>Risk</th></tr>
            {"".join(rows)}
        </table>
    </div>
</div>
</body>
</html>"""

        path = output_dir / "index.html"
        path.write_text(html_content, encoding="utf-8")
        return path