def _write_wigle_csv(records: list[dict[str, Any]], output_path: str) -> None:
    """Write records in WiGLE CSV format (WigleWifi-1.4).

    Args:
        records: List of AP dicts.
        output_path: Destination file path.
    """
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        f.write(_WIGLE_HEADER + "\n")
        writer = csv.DictWriter(f, fieldnames=_WIGLE_COLUMNS)
        writer.writeheader()

        for rec in records:
            auth = rec.get("encryption", "")
            if not auth:
                auth = "[OPEN]"
            elif "WPA2" in auth.upper():
                auth = "[WPA2-PSK-CCMP][ESS]"
            elif "WPA" in auth.upper():
                auth = "[WPA-PSK-TKIP][ESS]"
            elif "WEP" in auth.upper():
                auth = "[WEP][ESS]"
            elif "OPN" in auth.upper():
                auth = "[OPEN][ESS]"

            writer.writerow({
                "MAC": rec.get("bssid", ""),
                "SSID": rec.get("ssid", ""),
                "AuthMode": auth,
                "FirstSeen": rec.get("first_seen", ""),
                "Channel": rec.get("channel", ""),
                "RSSI": rec.get("signal", ""),
                "CurrentLatitude": rec.get("lat", "0.0"),
                "CurrentLongitude": rec.get("lon", "0.0"),
                "AltitudeMeters": "0",
                "AccuracyMeters": "0",
                "Type": "WIFI",
            })


def _write_kml(records: list[dict[str, Any]], output_path: str) -> None:
    """Write records as KML placemarks for Google Earth.

    Args:
        records: List of AP dicts (must have lat/lon).
        output_path: Destination .kml file path.
    """
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    kml_ns = "http://www.opengis.net/kml/2.2"
    kml = ET.Element("kml", xmlns=kml_ns)
    doc = ET.SubElement(kml, "Document")
    name_el = ET.SubElement(doc, "name")
    name_el.text = "WXF Wardrive Export"

    for rec in records:
        lat = rec.get("lat", "")
        lon = rec.get("lon", "")
        if not lat or not lon:
            continue
        try:
            float(lat)
            float(lon)
        except ValueError:
            continue

        pm = ET.SubElement(doc, "Placemark")
        pm_name = ET.SubElement(pm, "name")
        pm_name.text = rec.get("ssid", "") or rec.get("bssid", "Unknown")
        desc = ET.SubElement(pm, "description")
        desc.text = "BSSID: {}, CH: {}, Signal: {}, Enc: {}".format(
            rec.get("bssid", ""),
            rec.get("channel", ""),
            rec.get("signal", ""),
            rec.get("encryption", ""),
        )
        point = ET.SubElement(pm, "Point")
        coords = ET.SubElement(point, "coordinates")
        coords.text = f"{lon},{lat},0"

    tree = ET.ElementTree(kml)
    ET.indent(tree, space="  ")
    tree.write(output_path, xml_declaration=True, encoding="UTF-8")


class Exploit(Exploit):
    """WiGLE CSV and KML export from WXF wardrive captures."""

    __info__ = {
        "name": "WiGLE Export",
        "description": (
            "Convert WXF wardrive data (airodump-ng CSV, kismetdb, PCAP) to WiGLE "
            "upload format (WigleWifi-1.4) and KML for Google Earth visualization. "
            "Supports GPS enrichment from NMEA or GPX files."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://wigle.net/",
            "https://api.wigle.net/csvFormat.html",
        ),
        "devices": ("wifi", "802.11"),
    }

    mode = OptString("info", "Mode: info, pcap_to_wigle, kismetdb_to_wigle, csv_to_kml")
    input_file = OptString("", "Input file path (airodump CSV, .kismet, or .pcap)")
    output_file = OptString("", "Output file path (auto-generated if empty)")
    format = OptString("wigle_csv", "Output format: wigle_csv or kml")
    gps_file = OptString("", "GPS file for coordinate enrichment (.gpx or .nmea)")
    output_dir = OptString(".tmp", "Output directory (used when output_file is empty)")

    def _outdir(self) -> str:
        d = str(self.output_dir).strip() or ".tmp"
        os.makedirs(d, exist_ok=True)
        return d

    def _enrich_with_gps(self, records: list[dict[str, Any]]) -> None:
        """Add GPS coordinates from gps_file to records missing lat/lon."""
        gps_path = str(self.gps_file).strip()
        if not gps_path:
            return

        points = _parse_gps_file(gps_path)
        if not points:
            print_info(f"No GPS points extracted from {gps_path}")
            return

        print_info(f"Loaded {len(points)} GPS trackpoints from {gps_path}")

        idx = 0
        for rec in records:
            if rec.get("lat") and rec.get("lon"):
                continue
            if idx < len(points):
                rec["lat"] = points[idx]["lat"]
                rec["lon"] = points[idx]["lon"]
                idx += 1

    def _info(self) -> None:
        print_info("WiGLE Export")
        print_info("=" * 50)
        print_info("")
        print_info("Convert wardrive captures to WiGLE CSV or KML:")
        print_info("  - Airodump-ng CSV -> WiGLE CSV")
        print_info("  - Kismetdb (SQLite) -> WiGLE CSV")
        print_info("  - Any parsed data -> KML (Google Earth)")
        print_info("")
        print_info("Modes:")
        print_info("  info              - Show this help")
        print_info("  pcap_to_wigle     - Parse airodump CSV to WiGLE format")
        print_info("  kismetdb_to_wigle - Parse kismetdb to WiGLE format")
        print_info("  csv_to_kml        - Convert airodump CSV to KML")
        print_info("")
        print_info("Quick start:")
        print_info("  set input_file scan-01.csv; set mode pcap_to_wigle; run")

    def _pcap_to_wigle(self) -> None:
        infile = str(self.input_file).strip()
        if not infile:
            print_error("Set input_file (airodump CSV path).")
            return
        if not os.path.isfile(infile):
            print_error(f"File not found: {infile}")
            return

        print_status(f"Parsing airodump CSV: {infile}")
        records = _parse_airodump_csv(infile)
        if not records:
            print_error("No AP records found in CSV.")
            return

        print_info(f"Parsed {len(records)} AP(s)")
        self._enrich_with_gps(records)

        outfile = str(self.output_file).strip()
        if not outfile:
            base = os.path.splitext(os.path.basename(infile))[0]
            outfile = os.path.join(self._outdir(), f"{base}_wigle.csv")

        _write_wigle_csv(records, outfile)
        print_success(f"WiGLE CSV written: {outfile} ({len(records)} records)")

    def _kismetdb_to_wigle(self) -> None:
        infile = str(self.input_file).strip()
        if not infile:
            print_error("Set input_file (kismetdb path).")
            return
        if not os.path.isfile(infile):
            print_error(f"File not found: {infile}")
            return

        print_status(f"Parsing kismetdb: {infile}")
        records = _parse_kismetdb(infile)
        if not records:
            print_error("No AP records found in kismetdb.")
            return

        print_info(f"Parsed {len(records)} device(s)")
        self._enrich_with_gps(records)

        outfile = str(self.output_file).strip()
        if not outfile:
            base = os.path.splitext(os.path.basename(infile))[0]
            outfile = os.path.join(self._outdir(), f"{base}_wigle.csv")

        _write_wigle_csv(records, outfile)
        print_success(f"WiGLE CSV written: {outfile} ({len(records)} records)")

    def _csv_to_kml(self) -> None:
        infile = str(self.input_file).strip()
        if not infile:
            print_error("Set input_file (airodump CSV path).")
            return
        if not os.path.isfile(infile):
            print_error(f"File not found: {infile}")
            return

        print_status(f"Parsing CSV for KML export: {infile}")
        records = _parse_airodump_csv(infile)
        if not records:
            print_error("No AP records found in CSV.")
            return

        print_info(f"Parsed {len(records)} AP(s)")
        self._enrich_with_gps(records)

        geo_count = sum(1 for r in records if r.get("lat") and r.get("lon"))
        if geo_count == 0:
            print_error("No records with GPS coordinates. Provide gps_file for enrichment.")
            return

        outfile = str(self.output_file).strip()
        if not outfile:
            base = os.path.splitext(os.path.basename(infile))[0]
            outfile = os.path.join(self._outdir(), f"{base}.kml")

        _write_kml(records, outfile)
        print_success(f"KML written: {outfile} ({geo_count} placemarks)")


    def check(self) -> str:
        """Verify wireless interface is in monitor mode and ready."""
        import shutil
        import subprocess
        iface = getattr(self, "iface", None) or getattr(self, "interface", None) or "wlan0"
        if shutil.which("iwconfig"):
            try:
                out = subprocess.check_output(
                    ["iwconfig", str(iface)], stderr=subprocess.STDOUT, timeout=5
                ).decode("utf-8", "replace")
                if "Monitor" in out:
                    return f"Interface {iface} is in Monitor mode - prerequisites OK"
                if "no wireless extensions" not in out.lower():
                    return f"Interface {iface} found but NOT in Monitor mode - run airmon-ng start {iface}"
            except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
                pass
        if shutil.which("iw"):
            try:
                out = subprocess.check_output(
                    ["iw", "dev"], stderr=subprocess.STDOUT, timeout=5
                ).decode("utf-8", "replace")
                if str(iface) in out:
                    return f"Interface {iface} detected via iw - verify monitor mode"
            except Exception:
                pass
        return f"Interface {iface} not found - connect wireless adapter and enable monitor mode"

    def run(self) -> None:
        op = str(self.mode).strip().lower()

        if op == "info":
            self._info()
        elif op == "pcap_to_wigle":
            self._pcap_to_wigle()
        elif op == "kismetdb_to_wigle":
            self._kismetdb_to_wigle()
        elif op == "csv_to_kml":
            self._csv_to_kml()
        else:
            print_error(f"Unknown mode: {op}. Valid: info, pcap_to_wigle, "
                        "kismetdb_to_wigle, csv_to_kml")
