"""
Batch Intelligence: cluster analyzed images by device serial, build a
capture timeline, split photo sessions by gaps, and surface insights
(same physical camera across files, timeline spans, largest gap,
fully-stripped batch warnings).
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

_GAP_SECONDS = 3600  # a new "session" starts when the gap exceeds 1 hour
_TS_FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y:%m:%d %H:%M:%S")


class BatchIntelligence:
    """Aggregate multiple extraction results into batch-level intelligence."""

    def analyze(self, results: List[Any]) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "total": len(results),
            "device_clusters": [],
            "timeline": [],
            "sessions": [],
            "insights": [],
            "errors": [],
        }

        # 1. Device clusters grouped by (make, model, serial)
        clusters: Dict[tuple, Dict[str, Any]] = {}
        for item in results:
            device = self._attr(item, "device") or {}
            make = str(device.get("make") or "").strip()
            model = str(device.get("model") or "").strip()
            serial = str(device.get("serial_number") or "").strip() or None
            if not make and not model:
                continue  # anonymous / fully stripped
            key = (make.lower(), model.lower(), serial)
            cluster = clusters.setdefault(key, {
                "make": make,
                "model": model,
                "serial": serial,
                "count": 0,
                "files": [],
            })
            cluster["count"] += 1
            cluster["files"].append(self._attr(item, "file_name") or
                                    Path(self._attr(item, "file_path") or "").name)

        result["device_clusters"] = sorted(
            clusters.values(), key=lambda c: c["count"], reverse=True
        )

        # 2. Timeline (best EXIF timestamp, else file mtime)
        timeline: List[Dict[str, Any]] = []
        for item in results:
            resolved = self._best_timestamp(item)
            if resolved is None:
                continue
            ts, source = resolved
            name = self._attr(item, "file_name") or \
                Path(self._attr(item, "file_path") or "").name
            timeline.append({
                "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
                "file": name,
                "source": source,
            })

        timeline.sort(key=lambda t: t["timestamp"])
        # dedupe exact (timestamp, file) pairs
        seen: set = set()
        unique = []
        for t in timeline:
            pair = (t["timestamp"], t["file"])
            if pair not in seen:
                seen.add(pair)
                unique.append(t)
        result["timeline"] = unique

        # 3. Sessions: break where the gap exceeds the threshold
        if len(unique) >= 2:
            session: List[Dict[str, Any]] = []
            prev = self._parse_ts(unique[0]["timestamp"])
            for entry in unique:
                cur = self._parse_ts(entry["timestamp"])
                if cur is None:
                    continue
                if session and (cur - prev).total_seconds() > _GAP_SECONDS:
                    self._flush_session(result, session)
                    session = []
                session.append(entry)
                prev = cur
            if session:
                self._flush_session(result, session)

        # 4. Insights
        self._build_insights(result)

        return result

    @staticmethod
    def _flush_session(result: Dict[str, Any], session: List[Dict[str, Any]]) -> None:
        """Append one photo session to the results."""
        result["sessions"].append({
            "start": session[0]["timestamp"],
            "end": session[-1]["timestamp"],
            "count": len(session),
            "files": [s["file"] for s in session],
        })

    def _build_insights(self, result: Dict[str, Any]) -> None:
        """Generate human-readable insights (max ~6, only the ones that apply)."""
        clusters = result["device_clusters"]
        timeline = result["timeline"]
        insights: List[str] = []

        shared = [c for c in clusters if c["count"] > 1 and c["serial"]]
        if shared:
            c = shared[0]
            insights.append(
                f"{c['count']} images share camera serial {c['serial']} "
                f"({c['make']} {c['model']}) - same physical device"
            )

        if len(clusters) == 1 and clusters[0]["count"] == result["total"]:
            c = clusters[0]
            insights.append(
                f"All {result['total']} images from one device: "
                f"{c['make']} {c['model']}"
            )
        elif not clusters:
            insights.append(
                "No device identity across the batch - fully stripped images"
            )

        if timeline:
            n = len(timeline)
            insights.append(
                f"Timeline spans {timeline[0]['timestamp']} to "
                f"{timeline[-1]['timestamp']} ({n} image(s) with timestamps)"
            )
            # Camera clock reset: a 1980-01-01 EXIF date is the classic
            # sign of a dead camera battery (many vendors reset to the
            # 1980 epoch). That makes every timestamp untrustworthy.
            reset_files = [t["file"] for t in timeline
                           if t["timestamp"].startswith("1980-01-01")]
            if reset_files:
                insights.append(
                    f"Camera clock reset (1980-01-01) on {len(reset_files)} "
                    f"image(s): {', '.join(reset_files[:3])} - timestamps unreliable"
                )
            # largest gap
            prev = self._parse_ts(timeline[0]["timestamp"])
            largest: tuple[float, str, str] = (0.0, "", "")
            for entry in timeline[1:]:
                cur = self._parse_ts(entry["timestamp"])
                if cur is None:
                    continue
                gap = (cur - prev).total_seconds()
                if gap > largest[0]:
                    largest = (gap, prev.strftime("%Y-%m-%d %H:%M:%S"),
                               cur.strftime("%Y-%m-%d %H:%M:%S"))
                prev = cur
            if largest[0] > _GAP_SECONDS:
                h, m = divmod(int(largest[0]), 3600)
                insights.append(
                    f"Largest gap {h}h {m // 60}m between {largest[1]} and {largest[2]}"
                )

        if len(clusters) > 1:
            distinct = len({(c["make"], c["model"]) for c in clusters})
            if distinct > 1:
                insights.append(
                    f"{distinct} distinct device model(s) seen in the batch"
                )

        result["insights"] = insights[:6]

    @staticmethod
    def _attr(item: Any, name: str) -> Any:
        """Tolerant attribute access for duck-typed objects."""
        try:
            return getattr(item, name)
        except Exception:
            return None

    @staticmethod
    def _parse_ts(text: str) -> datetime | None:
        """Parse a normalized timestamp string."""
        for fmt in _TS_FORMATS:
            try:
                return datetime.strptime(text, fmt)
            except (ValueError, TypeError):
                continue
        return None

    def _best_timestamp(self, item: Any) -> tuple | None:
        """Resolve the best capture timestamp for one result.

        Priority: original > digitized > modified > gps_date+gps_time.
        Falls back to file mtime. Returns (datetime, source-label) or None.
        """
        timestamps = self._attr(item, "timestamps") or {}
        for key in ("original", "digitized", "modified"):
            raw = timestamps.get(key)
            if raw:
                parsed = self._parse_ts(str(raw))
                if parsed is not None:
                    return (parsed, "EXIF")

        gps_date = timestamps.get("gps_date")
        gps_time = timestamps.get("gps_time")
        if gps_date and gps_time:
            text = f"{gps_date} {gps_time}".replace(":UTC", "").strip()
            parsed = self._parse_ts(text)
            if parsed is not None:
                return (parsed, "EXIF")

        # mtime fallback
        file_path = self._attr(item, "file_path")
        if file_path:
            try:
                mtime = Path(file_path).stat().st_mtime
                parsed = datetime.fromtimestamp(mtime)
                return (parsed, "FILE_MTIME")
            except OSError:
                return None
        return None