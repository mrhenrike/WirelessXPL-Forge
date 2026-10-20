class Exploit(Exploit):
    """GSM frequency scanner using Kalibrate-rtl and gr-gsm."""

    __info__ = {
        "name": "GSM Frequency Scanner (kal + gr-gsm)",
        "description": (
            "Scan for active GSM base stations using kalibrate-rtl (kal) and/or "
            "grgsm_scanner. Identifies ARFCN, frequency, signal strength, MCC, MNC, "
            "LAC, and Cell ID. Supports GSM900, GSM1800, GSM850, and PCS1900 bands. "
            "Includes ARFCN-to-frequency conversion and System Information decoding."
        ),
        "authors": (
            "Andre Henrique (@mrhenrike) | Uniao Geek",
            "kalibrate-rtl / gr-gsm (subprocess)",
        ),
        "references": (
            "https://github.com/steve-m/kalibrate-rtl",
            "https://osmocom.org/projects/gr-gsm/wiki",
            "3GPP TS 05.05 (GSM band definitions)",
        ),
        "devices": ("gsm", "rtl-sdr", "hackrf", "bladerf", "usrp"),
    }

    mode = OptString(
        "info",
        "Mode: info, kal_scan, grgsm_scan, band_info, parse_results, "
        "export, monitor_cell",
    )
    band = OptString("GSM900", "Band: GSM900, GSM1800, GSM850, PCS1900, all")
    gain = OptInteger(30, "SDR gain (0-50)")
    ppm = OptInteger(0, "Frequency correction in PPM")
    sdr_device = OptInteger(0, "SDR device index")
    output_dir = OptString(".tmp/gsm_scan", "Output directory for scan results")
    frequency = OptString("", "Specific frequency for monitor_cell (e.g. 940.8M)")
    dry_run = OptBool(False, "Print commands without executing")
    i_know_scope = OptBool(
        False,
        "Confirm authorized lab, shielded environment, and spectrum license",
    )

    def _outdir(self) -> str:
        d = str(self.output_dir).strip() or ".tmp/gsm_scan"
        os.makedirs(d, exist_ok=True)
        return d

    def _run_cmd(self, cmd: list[str], label: str = "") -> str | None:
        cmd_str = " ".join(cmd)
        if bool(self.dry_run):
            print_info(f"[dry-run] {label}: {cmd_str}")
            return None
        print_status(f"{label}: {cmd_str}")
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=120,
            )
            output = result.stdout.decode("utf-8", errors="replace")
            return output
        except subprocess.TimeoutExpired:
            print_status("Command timed out.")
            return None
        except FileNotFoundError:
            print_error(f"Binary not found: {cmd[0]}")
            return None

    def _info(self) -> None:
        print_info("GSM Frequency Scanner")
        print_info("=" * 50)
        print_info("")
        print_info("Scans for active GSM base stations using kalibrate-rtl (kal)")
        print_info("and/or grgsm_scanner. Identifies frequencies, signal strength,")
        print_info("and cell identity (MCC, MNC, LAC, Cell ID).")
        print_info("")
        print_info("Modes:")
        print_info("  info          - This help screen")
        print_info("  kal_scan      - Scan with kalibrate-rtl by band")
        print_info("  grgsm_scan    - Comprehensive scan with grgsm_scanner")
        print_info("  band_info     - Display GSM band frequency information")
        print_info("  parse_results - Parse and display previous scan results")
        print_info("  export        - Export results to CSV/JSON")
        print_info("  monitor_cell  - Decode BCCH of a specific cell (SI messages)")
        print_info("")
        print_info("GSM Bands:")
        for name, info in _GSM_BANDS.items():
            print_info("  {:<10s} {}".format(name, info["description"]))
        print_info("")
        print_info("Tool availability:")
        for tool in ("kal", "grgsm_scanner", "grgsm_livemon", "rtl_test"):
            p = _which(tool)
            status = f"[+] {tool}" if p else f"[-] {tool}: not found"
            (print_success if p else print_error)(f"  {status}")

    def _band_info(self) -> None:
        target = str(self.band).strip().upper()
        bands_to_show = (
            list(_GSM_BANDS.keys()) if target == "ALL"
            else [target] if target in _GSM_BANDS else []
        )
        if not bands_to_show:
            print_error(
                f"Unknown band: {target}. Valid: GSM900, GSM1800, GSM850, PCS1900, all"
            )
            return

        for band_name in bands_to_show:
            info = _GSM_BANDS[band_name]
            print_info("")
            print_info("{} - {}".format(band_name, info["description"]))
            print_info("-" * 50)
            print_info(
                "  Uplink:   {:.1f} - {:.1f} MHz".format(
                    info["ul_start"], info["ul_end"]
                )
            )
            print_info(
                "  Downlink: {:.1f} - {:.1f} MHz".format(
                    info["dl_start"], info["dl_end"]
                )
            )
            print_info(
                "  Duplex offset: {:.1f} MHz".format(info["offset"])
            )
            print_info(
                "  ARFCN range: {} - {}".format(
                    info["arfcn_start"], info["arfcn_end"]
                )
            )
            print_info("  Channel spacing: 200 kHz")
            print_info("")
            print_info("  Sample ARFCN-to-frequency (first 10 channels):")
            start = info["arfcn_start"]
            for arfcn in range(start, min(start + 10, info["arfcn_end"] + 1)):
                freq = _arfcn_to_freq_dl(arfcn, band_name)
                if freq > 0:
                    print_info(
                        f"    ARFCN {arfcn:>4d} -> {freq:.1f} MHz (DL)"
                    )

    def _kal_scan(self) -> list[dict[str, Any]]:
        if not _which("kal"):
            print_error("kalibrate-rtl (kal) not found in PATH.")
            return []

        target = str(self.band).strip().upper()
        bands_to_scan = (
            list(_GSM_BANDS.keys()) if target == "ALL"
            else [target] if target in _GSM_BANDS else []
        )
        if not bands_to_scan:
            print_error(f"Unknown band: {target}")
            return []

        all_results: list[dict[str, Any]] = []
        for band_name in bands_to_scan:
            print_status(f"Scanning {band_name} with kalibrate-rtl...")
            cmd = [
                "kal",
                "-s", band_name,
                "-g", str(int(self.gain)),
                "-e", str(int(self.ppm)),
            ]
            dev = int(self.sdr_device)
            if dev > 0:
                cmd.extend(["-d", str(dev)])

            output = self._run_cmd(cmd, f"kal ({band_name})")
            if output:
                parsed = _parse_kal_output(output)
                for r in parsed:
                    r["band"] = band_name
                all_results.extend(parsed)

        if all_results:
            all_results.sort(key=lambda r: r.get("power", 0), reverse=True)
            print_success(
                f"Found {len(all_results)} channel(s) across {len(bands_to_scan)} band(s)."
            )
            for r in all_results[:20]:
                print_info(
                    "  ARFCN {:>4d} | {:>8.1f} MHz | power {:>12.1f} | {}".format(
                        r["arfcn"], r["frequency"], r["power"],
                        r.get("band", ""),
                    )
                )
            if len(all_results) > 20:
                print_info(f"  ... and {len(all_results) - 20} more.")

            outfile = os.path.join(self._outdir(), "kal_scan.json")
            with open(outfile, "w", encoding="utf-8") as f:
                json.dump(all_results, f, indent=2, ensure_ascii=False)
            print_status(f"Results saved to {outfile}")
        else:
            print_status("No channels found.")

        return all_results

    def _grgsm_scan(self) -> list[dict[str, Any]]:
        scanner = _which("grgsm_scanner")
        if not scanner:
            print_error("grgsm_scanner not found in PATH.")
            return []

        target = str(self.band).strip().upper()
        cmd = [scanner]
        if target != "ALL" and target in _GSM_BANDS:
            cmd.extend(["-b", target])
        cmd.extend(["-g", str(int(self.gain))])
        cmd.extend(["-p", str(int(self.ppm))])

        dev = int(self.sdr_device)
        if dev > 0:
            cmd.extend(["-a", f"rtl={dev}"])

        output = self._run_cmd(cmd, "grgsm_scanner")
        if not output:
            return []

        results = _parse_grgsm_output(output)
        if results:
            print_success(f"Found {len(results)} cell(s).")
            header = (
                "  {:>5s} | {:>8s} | {:>7s} | {:>3s} | {:>3s} | {:>5s} | {:>6s}"
            )
            print_info(
                header.format("ARFCN", "Freq MHz", "dBm", "MCC", "MNC", "LAC", "CID")
            )
            print_info("  " + "-" * 56)
            for r in results[:30]:
                print_info(
                    "  {:>5d} | {:>8.1f} | {:>7.1f} | {:>3d} | {:>3d} | {:>5d} | {:>6d}".format(
                        r["arfcn"], r["frequency"], r["power"],
                        r["mcc"], r["mnc"], r["lac"], r["cid"],
                    )
                )
            if len(results) > 30:
                print_info(f"  ... and {len(results) - 30} more cells.")

            outfile = os.path.join(self._outdir(), "grgsm_scan.json")
            with open(outfile, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            print_status(f"Results saved to {outfile}")
        else:
            print_status("No cells found.")

        return results

    def _monitor_cell(self) -> None:
        freq = str(self.frequency).strip()
        if not freq:
            print_error("Set frequency for the cell to monitor (e.g. 940.8M).")
            return

        livemon = _which("grgsm_livemon")
        if not livemon:
            print_error("grgsm_livemon not found in PATH.")
            return

        cmd = [
            livemon,
            "-f", freq,
            "-g", str(int(self.gain)),
            "-p", str(int(self.ppm)),
            "-s", "2e6",
        ]

        print_status(
            f"Decoding BCCH on {freq} to extract System Information messages..."
        )
        print_info("Press Ctrl+C to stop.")

        output = self._run_cmd(cmd, "grgsm_livemon (monitor)")
        if output:
            si_lines = [
                ln for ln in output.splitlines()
                if "System Information" in ln or "SI " in ln
            ]
            if si_lines:
                print_success(
                    f"Extracted {len(si_lines)} System Information message(s):"
                )
                for ln in si_lines[:30]:
                    print_info(f"  {ln.strip()}")
            else:
                print_status(
                    "No System Information messages decoded. "
                    "Verify frequency and signal strength."
                )

    def _parse_results(self) -> None:
        outdir = self._outdir()
        for fname in ("grgsm_scan.json", "kal_scan.json"):
            fpath = os.path.join(outdir, fname)
            if not os.path.isfile(fpath):
                continue
            try:
                with open(fpath, encoding="utf-8") as f:
                    data = json.load(f)
                print_success(f"Loaded {len(data)} records from {fname}")
                for r in data[:20]:
                    parts = []
                    if "arfcn" in r:
                        parts.append("ARFCN {}".format(r["arfcn"]))
                    if "frequency" in r:
                        parts.append("{:.1f} MHz".format(r["frequency"]))
                    if "power" in r:
                        parts.append("{:.1f} dBm".format(r["power"]))
                    if r.get("mcc"):
                        parts.append("MCC/MNC {}/{}".format(r["mcc"], r.get("mnc", 0)))
                    print_info("  {}".format(" | ".join(parts)))
                if len(data) > 20:
                    print_info(f"  ... and {len(data) - 20} more.")
            except (json.JSONDecodeError, OSError) as exc:
                print_error(f"Failed to parse {fname}: {exc}")

    def _export(self) -> None:
        outdir = self._outdir()
        all_data: list[dict[str, Any]] = []
        for fname in ("grgsm_scan.json", "kal_scan.json"):
            fpath = os.path.join(outdir, fname)
            if os.path.isfile(fpath):
                try:
                    with open(fpath, encoding="utf-8") as f:
                        all_data.extend(json.load(f))
                except (json.JSONDecodeError, OSError):
                    pass

        if not all_data:
            print_error("No scan results to export. Run a scan first.")
            return

        csv_path = os.path.join(outdir, "gsm_scan_export.csv")
        all_keys = set()
        for r in all_data:
            all_keys.update(r.keys())
        fieldnames = sorted(all_keys)

        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(all_data)

        json_path = os.path.join(outdir, "gsm_scan_export.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(all_data, f, indent=2, ensure_ascii=False)

        print_success(
            f"Exported {len(all_data)} records to {csv_path} and {json_path}"
        )


    def check(self) -> str:
        """Verify SDR hardware and cellular tools are available."""
        import shutil
        sdr_tools = ["uhd_find_devices", "osmocom_fft", "gr-gsm", "gnuradio-companion"]
        gsm_tools = ["grgsm_livemon", "grgsm_decode", "kalibrate"]
        found = [t for t in sdr_tools + gsm_tools if shutil.which(t)]
        if found:
            return f"SDR tools found: {', '.join(found)} - verify hardware connection"
        return "No SDR tools found in PATH - install gnuradio, gr-osmosdr, gr-gsm"

    def run(self) -> None:
        op = str(self.mode).strip().lower()

        if op == "info":
            self._info()
            return

        if op == "band_info":
            self._band_info()
            return

        if not bool(self.i_know_scope):
            print_error(
                "Set i_know_scope = true to confirm authorized lab, "
                "shielded environment, and spectrum license."
            )
            return
        require_authorised_lab()
        self._exploit()

    def _exploit(self) -> None:
        """E2E GSM frequency scan: use kal/grgsm-scanner to enumerate
        GSM base stations, parse ARFCN results, and export cell data."""
        op = str(self.mode).strip().lower()

        if op == "kal_scan":
            self._kal_scan()

        elif op == "grgsm_scan":
            self._grgsm_scan()

        elif op == "parse_results":
            self._parse_results()

        elif op == "export":
            self._export()

        elif op == "monitor_cell":
            self._monitor_cell()

        else:
            print_error(
                f"Unknown mode: {op}. Valid: kal_scan, grgsm_scan, "
                "parse_results, export, monitor_cell"
            )
