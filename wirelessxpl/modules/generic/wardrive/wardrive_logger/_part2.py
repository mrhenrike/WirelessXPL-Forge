class WardriveLogger:
    """GPS-tagged WiFi network discovery logger.

    Collects WiFi sightings with optional GPS coordinates from gpsd or NMEA
    source. Exports to CSV, JSON, and KML formats for map visualization.

    Attributes:
        __info__: Module metadata.

    Args:
        output_dir: Directory where export files are saved.
        session_id: Optional session identifier; auto-generated if omitted.
        gps_source: GPS backend config:
            - None: no GPS (lat/lon always None)
            - "gpsd": use local gpsd daemon
            - "gpsd://host:port": use remote gpsd
            - "/dev/ttyUSB0" or path to .nmea file: NMEA source
        simulate: When True, sightings are recorded in memory only.
        on_sighting: Optional callback called with each new WardriveSighting.
    """

    __info__ = {
        "name": "Wardrive Logger",
        "category": "wardrive",
        "type": "logger",
        "description": (
            "GPS-tagged WiFi network discovery logger with CSV, JSON, KML export. "
            "Supports gpsd daemon, NMEA serial, or static coordinates. "
            "Integrate with Wigle, Google Maps, or custom heat-map tools."
        ),
        "hw_req": [
            "WiFi adapter with monitor-mode support",
            "Optional: GPS receiver (gpsd or NMEA serial)",
        ],
        "authors": ["Andre Henrique (@mrhenrike) | Uniao Geek"],
    }

    def __init__(
        self,
        output_dir: str | Path,
        session_id: str | None = None,
        gps_source: str | None = None,
        simulate: bool = True,
        on_sighting: Callable[[WardriveSighting], None] | None = None,
    ) -> None:
        self.output_dir = Path(output_dir).resolve()
        self.session_id = session_id or str(uuid.uuid4())[:8]
        self.simulate = simulate
        self.on_sighting = on_sighting
        self._sightings: list[WardriveSighting] = []
        self._lock = threading.Lock()
        self._gps: _GpsdBackend | _NmeaBackend | None = None

        if not self.simulate:
            self.output_dir.mkdir(parents=True, exist_ok=True)

        self._init_gps(gps_source)

    # ------------------------------------------------------------------
    # GPS init
    # ------------------------------------------------------------------

    def _init_gps(self, source: str | None) -> None:
        if source is None:
            logger.info("[Wardrive] No GPS source - lat/lon will be None")
            return

        if source == "gpsd" or source.startswith("gpsd://"):
            host, port = "127.0.0.1", 2947
            if source.startswith("gpsd://"):
                rest = source[len("gpsd://"):]
                if ":" in rest:
                    host, p = rest.rsplit(":", 1)
                    with suppress(ValueError):
                        port = int(p)
                else:
                    host = rest
            backend = _GpsdBackend(host=host, port=port)
            if backend.start():
                self._gps = backend
            else:
                logger.warning("[Wardrive] gpsd unavailable - falling back to no GPS")
        else:
            backend = _NmeaBackend(source=source)
            if backend.start():
                self._gps = backend
            else:
                logger.warning("[Wardrive] NMEA source unavailable - falling back to no GPS")

    # ------------------------------------------------------------------
    # Current GPS fix
    # ------------------------------------------------------------------

    def _current_gps(self) -> _GpsPosition:
        if self._gps is None:
            return _GpsPosition()
        return self._gps.position()

    # ------------------------------------------------------------------
    # Record
    # ------------------------------------------------------------------

    def record(
        self,
        ssid: str,
        bssid: str,
        channel: int,
        rssi: int,
        security: str,
        hidden: bool = False,
        gps_override: tuple[float, float] | None = None,
    ) -> WardriveSighting:
        """Record a WiFi network sighting.

        Args:
            ssid: Network SSID (empty string or '<hidden>' for hidden networks).
            bssid: AP MAC address.
            channel: WiFi channel number.
            rssi: Signal strength in dBm.
            security: Security type string (e.g. 'WPA2', 'Open').
            hidden: True if SSID is not broadcast.
            gps_override: Optional (lat, lon) tuple to bypass GPS backend.

        Returns:
            The created WardriveSighting record.
        """
        pos = self._current_gps()

        if gps_override is not None:
            lat, lon = gps_override
        elif pos.fix:
            lat, lon = pos.lat, pos.lon
        else:
            lat, lon = None, None

        sighting = WardriveSighting(
            ssid=ssid or "<hidden>",
            bssid=bssid.upper(),
            channel=channel,
            rssi=rssi,
            security=security,
            timestamp=datetime.now(UTC).isoformat(),
            latitude=lat,
            longitude=lon,
            altitude=pos.alt if pos.fix else None,
            speed=pos.speed if pos.fix else None,
            vendor=_resolve_vendor(bssid),
            band=_channel_to_band(channel),
            hidden=hidden,
        )

        with self._lock:
            self._sightings.append(sighting)

        if self.on_sighting:
            with suppress(Exception):
                self.on_sighting(sighting)

        if self.simulate:
            logger.debug("[Wardrive] simulate record: %s (%s)", ssid, bssid)
        return sighting

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def stats(self) -> dict:
        """Return basic session statistics."""
        with self._lock:
            total = len(self._sightings)
            with_gps = sum(1 for s in self._sightings if s.latitude is not None)
            unique_bssid = len({s.bssid for s in self._sightings})

        return {
            "session": self.session_id,
            "total_sightings": total,
            "unique_aps": unique_bssid,
            "with_gps": with_gps,
            "without_gps": total - with_gps,
        }

    # ------------------------------------------------------------------
    # Export - CSV
    # ------------------------------------------------------------------

    def export_csv(self, path: str | Path | None = None) -> str:
        """Export sightings to a CSV file.

        Args:
            path: Output file path. Defaults to output_dir/wardrive_<session>.csv.

        Returns:
            Absolute path to the written CSV file.
        """
        out = self._default_path(path, "csv")

        if self.simulate:
            logger.info("[Wardrive] simulate=True - skipping CSV export to %s", out)
            return str(out)

        with self._lock:
            records = [asdict(s) for s in self._sightings]

        with open(str(out), "w", newline="", encoding="utf-8") as fh:
            if records:
                writer = csv.DictWriter(fh, fieldnames=list(records[0].keys()))
                writer.writeheader()
                writer.writerows(records)

        logger.info("[Wardrive] CSV exported: %s (%d rows)", out, len(records))
        return str(out)

    # ------------------------------------------------------------------
    # Export - JSON
    # ------------------------------------------------------------------

    def export_json(self, path: str | Path | None = None) -> str:
        """Export sightings to a JSON file.

        Args:
            path: Output file path. Defaults to output_dir/wardrive_<session>.json.

        Returns:
            Absolute path to the written JSON file.
        """
        out = self._default_path(path, "json")

        if self.simulate:
            logger.info("[Wardrive] simulate=True - skipping JSON export to %s", out)
            return str(out)

        with self._lock:
            data = {
                "session": self.session_id,
                "exported": datetime.now(UTC).isoformat(),
                "sightings": [asdict(s) for s in self._sightings],
            }

        with open(str(out), "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, default=str)

        logger.info("[Wardrive] JSON exported: %s (%d sightings)", out, len(self._sightings))
        return str(out)

    # ------------------------------------------------------------------
    # Export - KML
    # ------------------------------------------------------------------

    def export_kml(self, path: str | Path | None = None) -> str:
        """Export sightings with GPS coordinates to a KML file.

        Networks without GPS coordinates are skipped. The KML file can be
        loaded in Google Maps, Google Earth, or JOSM for map visualization.

        Args:
            path: Output file path. Defaults to output_dir/wardrive_<session>.kml.

        Returns:
            Absolute path to the written KML file.
        """
        out = self._default_path(path, "kml")

        if self.simulate:
            logger.info("[Wardrive] simulate=True - skipping KML export to %s", out)
            return str(out)

        with self._lock:
            geo_sightings = [s for s in self._sightings if s.latitude is not None]

        kml = ET.Element("kml", xmlns="http://www.opengis.net/kml/2.2")
        doc = ET.SubElement(kml, "Document")
        ET.SubElement(doc, "name").text = f"Wardrive Session {self.session_id}"

        style_ids = {
            "WPA3": ("#ff00aa00", "wpa3"),
            "WPA2": ("#ff0000ff", "wpa2"),
            "WPA": ("#ff00aaff", "wpa"),
            "Open": ("#ff0000cc", "open"),
        }
        for label, (color, sid) in style_ids.items():
            style = ET.SubElement(doc, "Style", id=sid)
            icon = ET.SubElement(style, "IconStyle")
            ET.SubElement(icon, "color").text = color
            ET.SubElement(icon, "scale").text = "1.0"

        for s in geo_sightings:
            pm = ET.SubElement(doc, "Placemark")
            ET.SubElement(pm, "name").text = s.ssid
            desc_lines = [
                f"BSSID: {s.bssid}",
                f"Security: {s.security}",
                f"Channel: {s.channel} ({s.band})",
                f"RSSI: {s.rssi} dBm",
                f"Vendor: {s.vendor or 'Unknown'}",
                f"Time: {s.timestamp}",
            ]
            ET.SubElement(pm, "description").text = "\n".join(desc_lines)

            style_ref = "wpa2"
            for key, (_, sid) in style_ids.items():
                if key in s.security:
                    style_ref = sid
                    break
            if s.security.lower() in ("open", ""):
                style_ref = "open"
            ET.SubElement(pm, "styleUrl").text = f"#{style_ref}"

            point = ET.SubElement(pm, "Point")
            alt = s.altitude or 0.0
            ET.SubElement(point, "coordinates").text = (
                f"{s.longitude},{s.latitude},{alt}"
            )

        tree = ET.ElementTree(kml)
        ET.indent(tree, space="  ")
        with open(str(out), "wb") as fh:
            fh.write(b'<?xml version="1.0" encoding="UTF-8"?>\n')
            tree.write(fh, encoding="utf-8", xml_declaration=False)

        logger.info("[Wardrive] KML exported: %s (%d geotagged)", out, len(geo_sightings))
        return str(out)

    # ------------------------------------------------------------------
    # Export - GeoJSON (bonus, for Leaflet/Folium)
    # ------------------------------------------------------------------

    def export_geojson(self, path: str | Path | None = None) -> str:
        """Export geotagged sightings as GeoJSON for Leaflet/Folium maps.

        Args:
            path: Output file path. Defaults to output_dir/wardrive_<session>.geojson.

        Returns:
            Absolute path to the written GeoJSON file.
        """
        out = self._default_path(path, "geojson")

        if self.simulate:
            logger.info("[Wardrive] simulate=True - skipping GeoJSON export to %s", out)
            return str(out)

        with self._lock:
            geo = [s for s in self._sightings if s.latitude is not None]

        features = []
        for s in geo:
            features.append({
                "type": "Feature",
                "geometry": {
                    "type": "Point",
                    "coordinates": [s.longitude, s.latitude],
                },
                "properties": {
                    "ssid": s.ssid,
                    "bssid": s.bssid,
                    "security": s.security,
                    "channel": s.channel,
                    "rssi": s.rssi,
                    "band": s.band,
                    "vendor": s.vendor,
                    "timestamp": s.timestamp,
                },
            })

        geojson = {
            "type": "FeatureCollection",
            "metadata": {
                "session": self.session_id,
                "exported": datetime.now(UTC).isoformat(),
                "count": len(features),
            },
            "features": features,
        }

        with open(str(out), "w", encoding="utf-8") as fh:
            json.dump(geojson, fh, indent=2)

        logger.info("[Wardrive] GeoJSON exported: %s (%d features)", out, len(features))
        return str(out)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _default_path(self, path: str | Path | None, ext: str) -> Path:
        if path is not None:
            return Path(path).resolve()
        return self.output_dir / f"wardrive_{self.session_id}.{ext}"

    def stop(self) -> None:
        """Stop GPS backends and flush data."""
        if self._gps:
            self._gps.stop()

    @property
    def sightings(self) -> list[WardriveSighting]:
        """Read-only snapshot of current sightings."""
        with self._lock:
            return list(self._sightings)
