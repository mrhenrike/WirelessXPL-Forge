# Author: André Henrique (LinkedIn/X: @mrhenrike)
import os
import re
import shutil
import struct
import subprocess
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Iridium Satellite Pager Message Decoding.

    Passively captures and decodes Iridium satellite pager messages
    and short burst data (SBD).  Iridium operates at 1616-1626.5 MHz
    using TDMA/FDMA with QPSK modulation.  The downlink signals can
    be received with an RTL-SDR and a passive patch antenna.

    Uses gr-iridium for burst extraction and iridium-toolkit for
    message reassembly and decoding.  Pager messages (Ring Alert,
    MSG) and some SBD data are transmitted without encryption on
    certain channels.

    Hardware necessario:
      - RTL-SDR V3 (ou RTL-SDR Blog V4) com oscilador TCXO estavel
      - Antena patch para banda L: 1621.35 MHz (centro da banda Iridium)
        ou antena helicoidal RHCP para 1616-1626.5 MHz
      - (Opcional) LNA filtrado para banda L (1525-1660 MHz)
      - (Opcional) RTL-SDR com bias-tee para alimentar LNA ativo
      - Posicionamento: ceu aberto, sem obstrucoes acima de 30 graus

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Iridium Satellite Pager Message Decoding",
        "description": (
            "Passive capture and decoding of Iridium satellite pager "
            "messages and short burst data (SBD).  Iridium operates at "
            "1616-1626.5 MHz.  Uses gr-iridium for burst extraction and "
            "iridium-toolkit for decoding.  Hardware: RTL-SDR V3 com "
            "TCXO + antena patch 1621.35 MHz (banda L Iridium) ou "
            "antena helicoidal RHCP.  Opcional: LNA filtrado banda L."
        ),
        "authors": (
            "Sec-Research/gr-iridium (Schneider & Schink)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://github.com/muccc/gr-iridium",
            "https://github.com/muccc/iridium-toolkit",
            "https://media.ccc.de/v/33c3-7922-iridium_pager",
        ),
        "disclosure_date": "2016-12-28",
        "platform": "linux",
        "arch": "all",
        "privileged": True,
        "targets": (
            "Iridium pager ring alerts (IRA)",
            "Iridium short burst data (SBD)",
            "Iridium voice channel signaling",
            "Iridium simplex downlink data",
        ),
    }

    target = OptIP("", "Not used (passive satellite capture)")
    port = OptPort(1, "Not used (passive satellite capture)")
    timeout = OptFloat(60.0, "Capture duration in seconds")
    center_freq = OptFloat(1626.0e6, "Center frequency in Hz (Iridium band)")
    sample_rate = OptFloat(2.4e6, "SDR sample rate in sps")
    gain = OptFloat(49.6, "SDR gain in dB")
    sdr_device = OptString("rtlsdr", "SDR device: rtlsdr, hackrf, uhd")
    output_dir = OptString("/tmp/iridium_decode", "Output directory")
    bias_tee = OptBool(False, "Enable RTL-SDR bias tee for active antenna/LNA")
    decode_voice = OptBool(False, "Attempt voice channel decoding (experimental)")
    max_bursts = OptInteger(10000, "Maximum bursts to process")

    _IRIDIUM_BAND = (1616.0e6, 1626.5e6)

    def _find_gr_iridium(self) -> str | None:
        if shutil.which("iridium-extractor"):
            return "iridium-extractor"
        return None

    def _find_toolkit(self) -> str | None:
        for path in [
            "/opt/iridium-toolkit/reassembler.py",
            os.path.expanduser("~/iridium-toolkit/reassembler.py"),
            shutil.which("iridium-reassembler") or "",
        ]:
            if path and os.path.exists(path):
                return path
        return None

    def _find_capture_tool(self) -> str | None:
        dev = str(self.sdr_device)
        if dev == "rtlsdr":
            return "rtl_sdr" if shutil.which("rtl_sdr") else None
        elif dev == "hackrf":
            return "hackrf_transfer" if shutil.which("hackrf_transfer") else None
        elif dev == "uhd":
            return "uhd_rx_cfile" if shutil.which("uhd_rx_cfile") else None
        return None

    def _capture_iq(self, output_file: str) -> bool:
        dev = str(self.sdr_device)

        if dev == "rtlsdr":
            cmd = [
                "rtl_sdr",
                "-f", str(int(self.center_freq)),
                "-s", str(int(self.sample_rate)),
                "-g", str(int(self.gain)),
                "-n", str(int(self.sample_rate * self.timeout)),
            ]
            if self.bias_tee:
                cmd.extend(["-T"])
            cmd.append(output_file)
        elif dev == "hackrf":
            cmd = [
                "hackrf_transfer",
                "-r", output_file,
                "-f", str(int(self.center_freq)),
                "-s", str(int(self.sample_rate)),
                "-l", str(int(self.gain)),
                "-a", "1",
                "-n", str(int(self.sample_rate * self.timeout)),
            ]
        else:
            return False

        try:
            result = subprocess.run(cmd, capture_output=True, timeout=self.timeout + 15)
            return result.returncode == 0 and os.path.exists(output_file)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def _extract_bursts(self, iq_file: str, burst_file: str) -> int:
        extractor = self._find_gr_iridium()
        if not extractor:
            return self._simple_burst_detect(iq_file, burst_file)

        cmd = [
            extractor,
            "-D", "4",
            "--multi-frame",
            "-o", burst_file,
            iq_file,
        ]

        try:
            result = subprocess.run(
                cmd, capture_output=True, timeout=self.timeout * 2
            )
            if os.path.exists(burst_file):
                with open(burst_file) as f:
                    return sum(1 for _ in f)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return 0

    def _simple_burst_detect(self, iq_file: str, burst_file: str) -> int:
        try:
            with open(iq_file, "rb") as f:
                data = f.read(min(os.path.getsize(iq_file), 50 * 1024 * 1024))
        except OSError:
            return 0

        window = 512
        threshold = 0.3
        bursts = []
        in_burst = False
        burst_start = 0

        for i in range(0, len(data) - window * 2, window * 2):
            energy = 0.0
            for j in range(window):
                idx = i + j * 2
                if idx + 1 >= len(data):
                    break
                real = (data[idx] - 128) / 128.0
                imag = (data[idx + 1] - 128) / 128.0
                energy += real * real + imag * imag
            energy /= window

            if energy > threshold and not in_burst:
                in_burst = True
                burst_start = i
            elif energy <= threshold and in_burst:
                in_burst = False
                duration_samples = (i - burst_start) // 2
                if 200 < duration_samples < 50000:
                    time_s = burst_start / (2 * self.sample_rate)
                    bursts.append({
                        "offset": burst_start,
                        "duration": duration_samples,
                        "time_s": time_s,
                    })
                    if len(bursts) >= int(self.max_bursts):
                        break

        with open(burst_file, "w") as f:
            for b in bursts:
                f.write(
                    f"RAW: t={b['time_s']:.6f} "
                    f"off={b['offset']} "
                    f"dur={b['duration']}\n"
                )

        return len(bursts)

    def _decode_messages(self, burst_file: str) -> list[dict]:
        toolkit = self._find_toolkit()
        messages = []

        if toolkit:
            msg_file = burst_file + ".msg"
            cmd = ["python3", toolkit, "-i", burst_file, "-m", "msg", "-o", msg_file]
            try:
                subprocess.run(cmd, capture_output=True, timeout=60)
                if os.path.exists(msg_file):
                    with open(msg_file) as f:
                        for line in f:
                            line = line.strip()
                            if line:
                                messages.append({"raw": line, "type": "decoded"})
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
        else:
            try:
                with open(burst_file) as f:
                    for line in f:
                        if "IRA:" in line or "MSG:" in line or "IBC:" in line:
                            messages.append({"raw": line.strip(), "type": "raw"})
            except OSError:
                pass

        return messages[:100]

    @mute
    def check(self) -> bool:
        return self._find_capture_tool() is not None

    def run(self) -> None:
        tool = self._find_capture_tool()
        if not tool:
            print_error(f"SDR capture tool for '{self.sdr_device}' not found")
            return

        if not (self._IRIDIUM_BAND[0] <= self.center_freq <= self._IRIDIUM_BAND[1]):
            print_info(
                f"Center freq {self.center_freq / 1e6:.1f} MHz is outside "
                f"Iridium band (1616-1626.5 MHz)"
            )

        print_success(f"SDR tool: {tool}, freq: {self.center_freq / 1e6:.1f} MHz")
        self._exploit()

    def _exploit(self) -> None:
        os.makedirs(str(self.output_dir), exist_ok=True)

        iq_file = os.path.join(str(self.output_dir), "iridium_capture.raw")
        burst_file = os.path.join(str(self.output_dir), "iridium_bursts.txt")

        print_status(
            f"Capturing at {self.center_freq / 1e6:.2f} MHz for {self.timeout}s ..."
        )
        if not self._capture_iq(iq_file):
            print_error("IQ capture failed")
            return

        size = os.path.getsize(iq_file) if os.path.exists(iq_file) else 0
        print_success(f"Captured {size} bytes")

        print_status("Extracting Iridium bursts ...")
        extractor = self._find_gr_iridium()
        if extractor:
            print_info(f"Using gr-iridium: {extractor}")
        else:
            print_info("gr-iridium not found; using simple energy burst detection")

        burst_count = self._extract_bursts(iq_file, burst_file)
        print_status(f"Detected {burst_count} bursts")

        if burst_count == 0:
            print_error(
                "No bursts detected.  Check antenna pointing, frequency, "
                "and ensure open sky visibility above 30 degrees."
            )
            return

        print_status("Decoding messages ...")
        messages = self._decode_messages(burst_file)

        msg_log = os.path.join(str(self.output_dir), "messages.log")
        with open(msg_log, "w") as f:
            f.write(f"# Iridium messages decoded from {burst_count} bursts\n")
            for m in messages:
                f.write(f"{m['raw']}\n")

        print_success(
            f"Decoded {len(messages)} message(s) from {burst_count} bursts\n"
            f"Burst file: {burst_file}\n"
            f"Message log: {msg_log}"
        )

        if not messages:
            print_info(
                "No decodable messages found.  Install gr-iridium and "
                "iridium-toolkit for full decoding capability, or "
                "increase capture duration."
            )
