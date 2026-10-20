# Author: André Henrique (LinkedIn/X: @mrhenrike)
import os
import shutil
import struct
import subprocess
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """DVB-S2 Satellite Downlink Signal Interception.

    Passively intercepts Digital Video Broadcasting via Satellite
    second generation (DVB-S2) downlink signals.  Satellite TV and
    data services use DVB-S2 in the Ku-band (10.7-12.75 GHz) and
    C-band (3.4-4.2 GHz).  The downlink is unencrypted for free-to-air
    channels and many data carriers.

    This module captures raw DVB-S2 baseband frames using an SDR
    receiver or a dedicated DVB-S2 USB tuner, then extracts
    MPEG-TS streams and metadata.

    Hardware necessario:
      - Antena parabolica de pelo menos 1.2m de diametro (Ku-band)
        ou 1.8m (C-band) apontada para o satelite alvo
      - LNB (Low Noise Block downconverter) compativel com a banda
      - Receptor: TBS 5927 USB DVB-S2 tuner (recomendado) ou
        RTL-SDR V3 com downconverter (limitado a canais estreitos)
      - Cabo coaxial RG-6 com conectores tipo F
      - (Opcional) spectrum analyzer para alinhar antena

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "DVB-S2 Satellite Downlink Signal Interception",
        "description": (
            "Passive interception of DVB-S2 satellite downlink signals.  "
            "Captures baseband frames and extracts MPEG-TS streams from "
            "free-to-air and unencrypted data carriers in Ku-band "
            "(10.7-12.75 GHz) and C-band (3.4-4.2 GHz).  Hardware: "
            "antena parabolica >= 1.2m + LNB + TBS 5927 DVB-S2 USB tuner "
            "(ou RTL-SDR com downconverter).  Ataque passivo."
        ),
        "authors": (
            "DVB Project (DVB-S2 standard ETSI EN 302 307)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://www.etsi.org/deliver/etsi_en/302300_302399/302307/01.02.01_60/en_302307v010201p.pdf",
            "https://www.tbsdtv.com/products/tbs5927-dvb-s2-tv-tuner-usb.html",
        ),
        "disclosure_date": "2005-03-01",
        "platform": "linux",
        "arch": "all",
        "privileged": True,
        "targets": (
            "Free-to-air DVB-S2 satellite channels",
            "Unencrypted satellite data carriers (SCPC/MCPC)",
            "VSAT return channel data (DVB-RCS2)",
            "Maritime and aviation satellite feeds",
        ),
    }

    target = OptIP("", "Not used (passive RF capture)")
    port = OptPort(1, "Not used (passive RF capture)")
    timeout = OptFloat(30.0, "Capture duration in seconds")
    frequency = OptFloat(11700.0, "Transponder frequency in MHz (L-band after LNB)")
    symbol_rate = OptInteger(27500, "Symbol rate in ksps")
    lnb_lo = OptFloat(9750.0, "LNB local oscillator frequency in MHz")
    polarization = OptString("H", "Polarization: H (horizontal) or V (vertical)")
    fec = OptString("auto", "FEC rate: auto, 1/2, 2/3, 3/4, 5/6, 7/8, 8/9, 9/10")
    modulation = OptString("auto", "Modulation: auto, QPSK, 8PSK, 16APSK, 32APSK")
    adapter = OptInteger(0, "DVB adapter number (/dev/dvb/adapterN)")
    output_dir = OptString("/tmp/dvbs2_capture", "Output directory for captured data")
    use_rtlsdr = OptBool(False, "Use RTL-SDR instead of DVB tuner (limited BW)")
    extract_ts = OptBool(True, "Extract MPEG-TS streams from capture")

    _DVB_TOOLS = ["dvbv5-zap", "dvb-fe-tool", "dvbsnoop"]
    _TS_TOOLS = ["ts_scan", "tsduck", "dvbsnoop"]

    def _find_dvb_tool(self) -> str | None:
        for tool in self._DVB_TOOLS:
            if shutil.which(tool):
                return tool
        return None

    def _find_ts_tool(self) -> str | None:
        for tool in self._TS_TOOLS:
            if shutil.which(tool):
                return tool
        return None

    def _check_dvb_adapter(self) -> bool:
        adapter_path = f"/dev/dvb/adapter{int(self.adapter)}"
        return os.path.exists(adapter_path)

    def _tune_dvb(self) -> bool:
        tool = self._find_dvb_tool()
        if not tool:
            return False

        if_freq = self.frequency - self.lnb_lo
        pol = str(self.polarization).upper()

        if tool == "dvbv5-zap":
            chan_file = os.path.join(str(self.output_dir), "channel.conf")
            with open(chan_file, "w") as f:
                f.write("[CAPTURE]\n")
                f.write("\tDELIVERY_SYSTEM = DVBS2\n")
                f.write(f"\tFREQUENCY = {int(self.frequency * 1000)}\n")
                f.write(f"\tSYMBOL_RATE = {int(self.symbol_rate) * 1000}\n")
                f.write(f"\tPOLARIZATION = {'HORIZONTAL' if pol == 'H' else 'VERTICAL'}\n")
                if str(self.modulation) != "auto":
                    f.write(f"\tMODULATION = {self.modulation}\n")

            cmd = [
                tool,
                "-a", str(int(self.adapter)),
                "-c", chan_file,
                "CAPTURE",
            ]
            try:
                proc = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )
                time.sleep(3)
                if proc.poll() is not None:
                    return False
                proc.terminate()
                return True
            except (OSError, FileNotFoundError):
                return False

        elif tool == "dvb-fe-tool":
            cmd = [
                tool,
                "-a", str(int(self.adapter)),
                "--set-frontend",
                f"frequency={int(if_freq * 1000)}",
                f"symbol_rate={int(self.symbol_rate) * 1000}",
                "delivery_system=DVBS2",
            ]
            try:
                result = subprocess.run(cmd, capture_output=True, timeout=10)
                return result.returncode == 0
            except (subprocess.TimeoutExpired, FileNotFoundError):
                return False

        return False

    def _capture_ts(self, output_file: str) -> bool:
        dvr_path = f"/dev/dvb/adapter{int(self.adapter)}/dvr0"
        if not os.path.exists(dvr_path):
            return False

        try:
            with open(dvr_path, "rb") as dvr, open(output_file, "wb") as out:
                end_time = time.time() + self.timeout
                total = 0
                while time.time() < end_time:
                    try:
                        data = dvr.read(188 * 100)
                        if data:
                            out.write(data)
                            total += len(data)
                    except OSError:
                        break
            return total > 0
        except OSError:
            return False

    def _capture_rtlsdr(self, output_file: str) -> bool:
        if not shutil.which("rtl_sdr"):
            return False

        if_freq = self.frequency - self.lnb_lo
        cmd = [
            "rtl_sdr",
            "-f", str(int(if_freq * 1e6)),
            "-s", "2400000",
            "-g", "49",
            "-n", str(int(2400000 * self.timeout)),
            output_file,
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=self.timeout + 10)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def _analyze_ts(self, ts_file: str) -> dict:
        info = {"pids": [], "services": [], "size_bytes": 0}
        try:
            info["size_bytes"] = os.path.getsize(ts_file)
        except OSError:
            return info

        try:
            with open(ts_file, "rb") as f:
                pids_seen = set()
                packets = 0
                while packets < 10000:
                    pkt = f.read(188)
                    if len(pkt) < 188:
                        break
                    if pkt[0] != 0x47:
                        f.read(1)
                        continue
                    pid = ((pkt[1] & 0x1F) << 8) | pkt[2]
                    pids_seen.add(pid)
                    packets += 1
                info["pids"] = sorted(pids_seen)
        except OSError:
            pass

        return info

    @mute
    def check(self) -> bool:
        if self.use_rtlsdr:
            return shutil.which("rtl_sdr") is not None
        return self._check_dvb_adapter()

    def run(self) -> None:
        if self.use_rtlsdr:
            if not shutil.which("rtl_sdr"):
                print_error("rtl_sdr not found")
                return
            print_success("Using RTL-SDR for DVB-S2 capture (limited bandwidth)")
        else:
            if not self._check_dvb_adapter():
                print_error(f"DVB adapter {self.adapter} not found")
                return
            tool = self._find_dvb_tool()
            if not tool:
                print_error("No DVB tool found (install dvb-apps or v4l-utils)")
                return
            print_success(f"DVB adapter {self.adapter} found, tool: {tool}")

        self._exploit()

    def _exploit(self) -> None:
        os.makedirs(str(self.output_dir), exist_ok=True)

        if_freq = self.frequency - self.lnb_lo
        print_status(
            f"Transponder: {self.frequency} MHz, IF: {if_freq:.1f} MHz, "
            f"SR: {self.symbol_rate} ksps, Pol: {self.polarization}"
        )

        if self.use_rtlsdr:
            raw_file = os.path.join(str(self.output_dir), "dvbs2_raw.iq")
            print_status(f"Capturing IQ via RTL-SDR for {self.timeout}s ...")
            if not self._capture_rtlsdr(raw_file):
                print_error("RTL-SDR capture failed")
                return
            print_success(f"IQ capture saved: {raw_file}")
            print_info(
                "Raw IQ captured.  Use leandvb or gr-dvbs2rx to demodulate "
                "DVB-S2 frames from IQ data."
            )
            return

        print_status("Tuning DVB-S2 frontend ...")
        if not self._tune_dvb():
            print_error("Failed to tune DVB-S2 frontend")
            return

        print_success("Frontend locked, capturing transport stream ...")
        ts_file = os.path.join(str(self.output_dir), "capture.ts")
        if not self._capture_ts(ts_file):
            print_error("TS capture failed (no data from DVR)")
            return

        info = self._analyze_ts(ts_file)
        print_success(
            f"Captured {info['size_bytes']} bytes, "
            f"{len(info['pids'])} PIDs detected"
        )

        if info["pids"]:
            pid_str = ", ".join(f"0x{p:04X}" for p in info["pids"][:20])
            print_info(f"PIDs: {pid_str}")

        if self.extract_ts:
            ts_tool = self._find_ts_tool()
            if ts_tool:
                print_info(f"Use '{ts_tool}' to analyze {ts_file}")
            else:
                print_info(f"Install dvbsnoop or tsduck to analyze {ts_file}")
