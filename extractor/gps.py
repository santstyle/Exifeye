"""
GPS coordinate parsing and Google Maps link generation.
"""
from __future__ import annotations

from typing import Any, Dict, Optional


class GPSParser:
    """Parse GPS EXIF tags and convert to decimal degrees + Google Maps links."""

    def parse(self, tags: Dict[str, Any]) -> Dict[str, Any]:
        """Parse GPS data from raw EXIF tags.
        Returns a dict with:
        - latitude / longitude (decimal degrees)
        - latitude_ref / longitude_ref
        - altitude
        - accuracy
        - google_maps_link (https://maps.google.com/...)
        - geohash
        """
        result: Dict[str, Any] = {"available": False}

        lat = self._get_coordinate(
            tags, coord_keys=("GPS GPSLatitude", "GPSLatitude"),
            ref_keys=("GPS GPSLatitudeRef", "GPSLatitudeRef"),
            positive_ref="N", negative_ref="S",
        )
        lon = self._get_coordinate(
            tags, coord_keys=("GPS GPSLongitude", "GPSLongitude"),
            ref_keys=("GPS GPSLongitudeRef", "GPSLongitudeRef"),
            positive_ref="E", negative_ref="W",
        )

        if lat is None or lon is None:
            return result

        result["available"] = True
        result["latitude"] = lat
        result["longitude"] = lon
        result["latitude_ref"] = "S" if lat < 0 else "N"
        result["longitude_ref"] = "W" if lon < 0 else "E"

        # Altitude
        alt = self._get_altitude(tags)
        if alt is not None:
            result["altitude_meters"] = alt

        # Timestamp
        ts = self._first_tag(tags, ("GPS GPSTimeStamp", "GPSTimeStamp"))
        if ts is not None:
            result["gps_time"] = self._format_gps_time(ts)
        gd = self._first_tag(tags, ("GPS GPSDate", "GPSDate"))
        if gd is not None:
            result["gps_date"] = str(gd)

        # Speed, bearing
        speed = self._first_tag(tags, ("GPS GPSSpeed", "GPSSpeed"))
        if speed is not None:
            result["speed"] = str(speed)
        track = self._first_tag(tags, ("GPS GPSTrack", "GPSTrack"))
        if track is not None:
            result["track"] = str(track)
        direction = self._first_tag(tags, ("GPS GPSImgDirection", "GPSImgDirection"))
        if direction is not None:
            result["img_direction"] = str(direction)

        # Geohash
        result["geohash"] = self._geohash(lat, lon, precision=9)

        # Google Maps links
        result["google_maps_link"] = self._build_google_maps_link(lat, lon)
        result["google_maps_zoom_link"] = self._build_google_maps_link(lat, lon, zoom=17)

        return result

    def _get_coordinate(
        self,
        tags: Dict[str, Any],
        coord_keys: tuple[str, ...],
        ref_keys: tuple[str, ...],
        positive_ref: str,
        negative_ref: str,
    ) -> Optional[float]:
        """Extract a GPS coordinate, tolerating the shapes different parsers emit.

        Accepts:
        - a 3-part rational list (degrees, minutes, seconds) -> D + M/60 + S/3600
        - a 1-part list already in decimal degrees
        - a raw string like "43 28 1407/500" or "43/1, 28/1, 1407/500"
        """
        tag = self._first_tag(tags, coord_keys)
        if tag is None:
            return None

        try:
            parts = self._to_numbers(getattr(tag, "values", tag))
            if not parts:
                return None
            if len(parts) >= 3:
                decimal = parts[0] + parts[1] / 60.0 + parts[2] / 3600.0
            elif len(parts) == 2:
                decimal = parts[0] + parts[1] / 60.0
            else:
                decimal = parts[0]

            ref = str(self._first_tag(tags, ref_keys) or positive_ref).strip().upper()
            if ref.startswith(negative_ref):
                decimal = -decimal
            if not (-180.0 <= decimal <= 180.0):
                return None
            return round(decimal, 7)
        except (AttributeError, IndexError, TypeError, ValueError, ZeroDivisionError):
            return None

    @staticmethod
    def _to_numbers(value: Any) -> list[float]:
        """Normalize a parser value (list / Ratio / string) into floats."""
        if value is None:
            return []
        if isinstance(value, (list, tuple)):
            raw_items = list(value)
        else:
            text = str(value).replace(",", " ")
            raw_items = text.split() or [text]

        numbers: list[float] = []
        for item in raw_items:
            text = str(item).strip()
            if "/" in text:
                num, _, den = text.partition("/")
                try:
                    denominator = float(den)
                    numbers.append(float(num) / denominator if denominator else 0.0)
                except (TypeError, ValueError):
                    pass
            else:
                try:
                    numbers.append(float(text))
                except (TypeError, ValueError):
                    pass
        return numbers

    @staticmethod
    def _first_tag(tags: Dict[str, Any], keys: tuple[str, ...]) -> Any:
        """Return the first present tag among several candidate names."""
        for key in keys:
            if key in tags:
                return tags[key]
        return None

    def _format_gps_time(self, tag) -> str:
        """Format GPS timestamp tag like '[14, 30, 0]' -> '14:30:00 UTC'."""
        try:
            parts = []
            for v in self._to_numbers(getattr(tag, "values", tag))[:3]:
                parts.append(f"{int(v):02d}")
            if not parts:
                return str(tag)
            return ":".join(parts) + " UTC"
        except (AttributeError, IndexError, TypeError, ValueError):
            return str(tag)

    def _get_altitude(self, tags: Dict[str, Any]) -> Optional[float]:
        """Extract altitude from EXIF."""
        tag = self._first_tag(tags, ("GPS GPSAltitude", "GPSAltitude"))
        if tag is None:
            return None
        try:
            numbers = self._to_numbers(getattr(tag, "values", tag))
            if not numbers:
                return None
            alt = numbers[0]
            ref = self._first_tag(tags, ("GPS GPSAltitudeRef", "GPSAltitudeRef"))
            if self._ref_is_set(ref):
                alt = -alt
            return round(alt, 2)
        except (AttributeError, IndexError, TypeError, ValueError):
            return None

    @staticmethod
    def _ref_is_set(ref: Any) -> bool:
        """Interpret a GPS ref tag as "1"/below-sea-level.

        Ref values arrive as int, list, bytes or string depending on the
        parser (exifread gives [0]/[1], Pillow gives b"\\x00"/b"\\x01").
        """
        if ref is None:
            return False
        if isinstance(ref, (bytes, bytearray)):
            return len(ref) > 0 and ref[0] == 1
        if isinstance(ref, (list, tuple)):
            if not ref:
                return False
            ref = ref[0]
            if isinstance(ref, (bytes, bytearray)):
                return len(ref) > 0 and ref[0] == 1
        try:
            return int(float(str(ref).strip())) == 1
        except (TypeError, ValueError):
            return False

    def _build_google_maps_link(self, lat: float, lon: float, zoom: int = 15) -> str:
        """Build a Google Maps link with the given coordinates."""
        # Use the standard Google Maps query format
        return f"https://www.google.com/maps?q={lat:.7f},{lon:.7f}&z={zoom}"

    # Geohash implementation (pure Python, no dependency)
    _BASE32 = "0123456789bcdefghjkmnpqrstuvwxyz"

    def _geohash(self, lat: float, lon: float, precision: int = 9) -> str:
        """Compute geohash for the given coordinates."""
        lat_range = (-90.0, 90.0)
        lon_range = (-180.0, 180.0)
        geohash = ""
        bit = 0
        ch = 0
        even = True

        while len(geohash) < precision:
            if even:
                mid = (lon_range[0] + lon_range[1]) / 2
                if lon >= mid:
                    ch |= (1 << (4 - bit))
                    lon_range = (mid, lon_range[1])
                else:
                    lon_range = (lon_range[0], mid)
            else:
                mid = (lat_range[0] + lat_range[1]) / 2
                if lat >= mid:
                    ch |= (1 << (4 - bit))
                    lat_range = (mid, lat_range[1])
                else:
                    lat_range = (lat_range[0], mid)

            even = not even
            bit += 1
            if bit == 5:
                geohash += self._BASE32[ch]
                bit = 0
                ch = 0

        return geohash
