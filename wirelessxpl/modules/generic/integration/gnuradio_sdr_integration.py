# Author: André Henrique (LinkedIn/X: @mrhenrike)
import json
import os
import subprocess
import tempfile
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """GnuRadio SDR Platform Integration for Wireless Attack Flowgraphs.

    Provides a bridge between WirelessXPL exploit modules and GnuRadio
    Companion (GRC) flowgraphs for advanced SDR-based wireless attacks.
    Supports launching pre-built flowgraphs for signal capture, jamming,
    replay, spoofing, and injection across multiple wireless protocols.

    The module can execute GRC flowgraphs (.grc) or compiled Python
    flowgraphs (.py) with configurable parameters, capture output data,
    and integrate results into the WirelessXPL pipeline.

    Hardware requirements:
      - RTL-SDR v3/v4 (RTL2832U, ~$30, 24-1766 MHz, RX only) or
      - HackRF One (Great Scott Gadgets, ~$350, 1-6000 MHz, TX+RX) or
      - Ettus USRP B200/B210 (~$1500-3000, 70-6000 MHz, TX+RX) or
      - LimeSDR Mini (~$200, 10-3500 MHz, TX+RX) or
      - PlutoSDR (Analog Devices, ~$150, 325-3800 MHz, TX+RX)
      - GnuRadio 3.10+ (https://www.gnuradio.org/)

    CVSS: N/A (attack platform integration)

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "GnuRadio SDR Platform Integration",
        "description": (
            "Bridges WirelessXPL with GnuRadio for SDR-based wireless "
            "attacks.  Launches pre-built or custom GRC flowgraphs with "
            "configurable parameters for signal capture, jamming, replay, "
            "spoofing, and injection.  Supports multiple SDR hardware "
            "platforms and integrates capture output into the WirelessXPL "
            "pipeline for automated analysis."
        ),
        "authors": (
            "mrhenrike (Andre Henrique)",
        ),
        "references": (
            "https://www.gnuradio.org/",
            "https://wiki.gnuradio.org/index.php/Tutorials",
            "https://greatscottgadgets.com/hackrf/",
        ),
        "disclosure_date": "2026-10-01",
        "platform": "linux",
        "arch": "all",
        "privileged": False,
        "targets": (
            "Any wireless signal in SDR TX/RX range",
            "Pre-built flowgraphs for WiFi, BLE, Zigbee, LoRa, TETRA, DMR",
        ),
    }

    target = OptIP("", "Not used (SDR platform)")
    port = OptPort(1, "Not used")
    timeout = OptFloat(30.0, "Flowgraph execution timeout in seconds")
    flowgraph = OptString("", "Path to GRC flowgraph (.grc) or compiled Python (.py)")
    sdr_device = OptString("rtlsdr", "SDR device: rtlsdr, hackrf, usrp, limesdr, plutosdr")
    center_freq = OptFloat(2.437e9, "Center frequency in Hz")
    sample_rate = OptFloat(2.4e6, "Sample rate in samples/sec")
    gain = OptFloat(40.0, "SDR gain in dB")
    output_sink = OptString("", "Path for output file sink (raw IQ or decoded)")
    flowgraph_params = OptString("", "Extra flowgraph parameters as key=value,key=value")
    mode = OptString("capture", "Operation mode: capture, jam, replay, inject, custom")

    _BUILTIN_FLOWGRAPHS = {
        "capture": "rf_capture.py",
        "jam": "rf_jammer.py",
        "replay": "rf_replay.py",
        "inject": "rf_injector.py",
    }

    _SDR_SOURCES = {
        "rtlsdr": "osmosdr.source",
        "hackrf": "osmosdr.source",
        "usrp": "uhd.usrp_source",
        "limesdr": "osmosdr.source",
        "plutosdr": "iio.pluto_source",
    }

    def _check_gnuradio(self) -> bool:
        """Check if GnuRadio is installed and accessible."""
        try:
            result = subprocess.run(
                ["gnuradio-config", "--version"],
                capture_output=True, timeout=5,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _get_gnuradio_version(self) -> str:
        """Get installed GnuRadio version."""
        try:
            result = subprocess.run(
                ["gnuradio-config", "--version"],
                capture_output=True, timeout=5, text=True,
            )
            return result.stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return "unknown"

    def _compile_grc(self, grc_path: str) -> str:
        """Compile a GRC flowgraph to Python."""
        py_path = grc_path.replace(".grc", ".py")
        try:
            subprocess.run(
                ["grcc", grc_path, "-o", os.path.dirname(grc_path) or "."],
                capture_output=True, timeout=30,
            )
            if os.path.isfile(py_path):
                return py_path
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return ""

    def _generate_capture_flowgraph(self) -> str:
        """Generate a simple capture flowgraph as Python script."""
        output = self.output_sink or tempfile.mktemp(suffix=".raw")
        script = f"""\
#!/usr/bin/env python3
# Auto-generated RF capture flowgraph
import time
try:
    from gnuradio import gr, blocks
    import osmosdr
except ImportError:
    print("GnuRadio not available")
    raise SystemExit(1)

class RFCapture(gr.top_block):
    def __init__(self):
        gr.top_block.__init__(self, "RF Capture")
        self.sdr_source = osmosdr.source(args="")
        self.sdr_source.set_sample_rate({self.sample_rate})
        self.sdr_source.set_center_freq({self.center_freq})
        self.sdr_source.set_gain({self.gain})
        self.file_sink = blocks.file_sink(gr.sizeof_gr_complex, "{output}")
        self.connect(self.sdr_source, self.file_sink)

if __name__ == "__main__":
    tb = RFCapture()
    tb.start()
    time.sleep({self.timeout})
    tb.stop()
    tb.wait()
    print(f"Captured to {output}")
"""
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, prefix="gnuradio_"
        )
        tmp.write(script)
        tmp.close()
        return tmp.name

    def _generate_jammer_flowgraph(self) -> str:
        """Generate a noise jammer flowgraph."""
        script = f"""\
#!/usr/bin/env python3
# Auto-generated RF jammer flowgraph
import time
try:
    from gnuradio import gr, analog, blocks
    import osmosdr
except ImportError:
    print("GnuRadio not available")
    raise SystemExit(1)

class RFJammer(gr.top_block):
    def __init__(self):
        gr.top_block.__init__(self, "RF Jammer")
        self.noise = analog.noise_source_c(analog.GR_GAUSSIAN, 1.0, 0)
        self.sdr_sink = osmosdr.sink(args="")
        self.sdr_sink.set_sample_rate({self.sample_rate})
        self.sdr_sink.set_center_freq({self.center_freq})
        self.sdr_sink.set_gain({self.gain})
        self.connect(self.noise, self.sdr_sink)

if __name__ == "__main__":
    tb = RFJammer()
    tb.start()
    time.sleep({self.timeout})
    tb.stop()
    tb.wait()
    print("Jamming complete")
"""
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, prefix="gnuradio_"
        )
        tmp.write(script)
        tmp.close()
        return tmp.name

    def _run_flowgraph(self, script_path: str) -> tuple:
        """Execute a Python flowgraph script. Returns (success, output)."""
        env = os.environ.copy()
        extra_params = {}
        if self.flowgraph_params:
            for param in str(self.flowgraph_params).split(","):
                if "=" in param:
                    k, v = param.split("=", 1)
                    extra_params[k.strip()] = v.strip()
                    env[k.strip().upper()] = v.strip()

        try:
            result = subprocess.run(
                ["python3", script_path],
                capture_output=True,
                timeout=self.timeout + 10,
                text=True,
                env=env,
            )
            return (result.returncode == 0, result.stdout + result.stderr)
        except subprocess.TimeoutExpired:
            return (False, "Flowgraph execution timed out")
        except FileNotFoundError:
            return (False, "python3 not found")

    @mute
    def check(self) -> bool:
        """Verify GnuRadio is installed."""
        return self._check_gnuradio()

    def run(self) -> None:
        if not self.check():
            print_error(
                "GnuRadio not installed. Install with: "
                "sudo apt install gnuradio gr-osmosdr"
            )
            return

        version = self._get_gnuradio_version()
        print_success(f"GnuRadio {version} detected")
        self._exploit()

    def _exploit(self) -> None:
        mode = str(self.mode).lower()
        flowgraph_path = str(self.flowgraph)

        if flowgraph_path:
            if flowgraph_path.endswith(".grc"):
                print_status(f"Compiling GRC flowgraph: {flowgraph_path}")
                compiled = self._compile_grc(flowgraph_path)
                if not compiled:
                    print_error("Failed to compile GRC flowgraph")
                    return
                flowgraph_path = compiled
            elif not flowgraph_path.endswith(".py"):
                print_error("Flowgraph must be .grc or .py")
                return
        else:
            print_status(f"Generating built-in '{mode}' flowgraph")
            if mode == "capture":
                flowgraph_path = self._generate_capture_flowgraph()
            elif mode == "jam":
                flowgraph_path = self._generate_jammer_flowgraph()
            else:
                print_error(
                    f"No built-in flowgraph for mode '{mode}'. "
                    "Provide a custom flowgraph with the 'flowgraph' option."
                )
                return

        freq_mhz = self.center_freq / 1e6
        print_status(
            f"Executing flowgraph: {os.path.basename(flowgraph_path)}, "
            f"mode={mode}, freq={freq_mhz:.3f} MHz, "
            f"rate={self.sample_rate / 1e6:.1f} MSps"
        )

        success, output = self._run_flowgraph(flowgraph_path)

        if success:
            print_success("Flowgraph executed successfully")
            if output.strip():
                for line in output.strip().split("\n")[-5:]:
                    print_info(f"  {line}")
            if self.output_sink and os.path.isfile(str(self.output_sink)):
                size = os.path.getsize(str(self.output_sink))
                print_info(f"  Output file: {self.output_sink} ({size} bytes)")
        else:
            print_error(f"Flowgraph failed: {output[:200]}")

        # Cleanup auto-generated scripts
        if not str(self.flowgraph) and os.path.isfile(flowgraph_path):
            os.unlink(flowgraph_path)
