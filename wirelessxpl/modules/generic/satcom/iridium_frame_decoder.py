# Author: André Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.exploit.exploit import BaseExploit


class Exploit(BaseExploit):
    """Iridium Satellite Frame Decoding and Eavesdropping.

    Passively captures and decodes Iridium satellite communication
    frames using a software-defined radio (SDR).  Iridium operates
    a constellation of 66 LEO satellites at ~780 km altitude,
    transmitting on L-band (1616-1626.5 MHz) using TDMA/FDMA with
    QPSK modulation at 25 kHz channel spacing.

    This module connects to an SDR daemon, tunes to the Iridium
    downlink band, captures raw IQ samples, and decodes Iridium
    burst frames including: IBC (Iridium Broadcast Channel),
    ring alerts, paging messages, and voice/data frame headers.

    The decoding is passive (receive-only) and does not transmit
    any signal.  Frame content beyond headers may be encrypted
    with the Iridium proprietary cipher.

    Hardware necessario:
      - SDR receptor com cobertura L-band (RTL-SDR, Airspy, USRP)
      - Antena omnidirecional ou patch para 1616-1626.5 MHz
      - LNA para L-band (recomendado para melhorar SNR)
      - Largura de banda minima: 250 kHz (ideal: 1 MHz+)

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Iridium Satellite Frame Decoder and Eavesdropper",
        "description": (
            "Passively captures and decodes Iridium LEO satellite "
            "communication frames via SDR.  Tunes to the Iridium L-band "
            "downlink (1616-1626.5 MHz), captures IQ samples, and decodes "
            "burst frames including IBC, ring alerts, paging, and voice/data "
            "headers.  Receive-only; does not transmit.  Requires SDR "
            "receiver with L-band coverage (RTL-SDR, Airspy, USRP) and "
            "omnidirectional or patch antenna for 1616-1626.5 MHz."
        ),
        "authors": (
            "Andre Henrique (@mrhenrike)",
        ),
        "references": (
            "https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/beurze",
            "https://github.com/muccc/gr-iridium",
            "https://i.blackhat.com/USA-22/Wednesday/US-22-Lopes-SATCOM-Terminals.pdf",
        ),
        "disclosure_date": "2016-08-10",
        "platform": "linux",
        "arch": "all",
        "privileged": False,
        "targets": (
            "Iridium LEO satellite constellation (L-band downlink)",
            "Iridium 9555/9575 handset communications",
            "Iridium GO!/Iridium Certus terminals",
        ),
    }

    target = OptIP("127.0.0.1", "SDR control daemon IP address")
    port = OptPort(5555, "SDR control daemon TCP port")
    timeout = OptFloat(10.0, "Connection timeout in seconds")
    center_freq = OptFloat(1621.25, "Center frequency in MHz (Iridium band)")
    sample_rate = OptFloat(1.0, "SDR sample rate in MHz")
    rx_gain = OptInteger(40, "SDR RX gain in dB")
    capture_duration = OptInteger(60, "Capture duration in seconds")
    output_file = OptString("", "Path to save decoded frames (CSV format)")
    channel_filter = OptString("", "Filter by channel type: IBC, ring, page, voice, data, all")

    # Iridium L-band frequency allocation
    _IRIDIUM_BAND_START = 1616.0    # MHz
    _IRIDIUM_BAND_END = 1626.5      # MHz
    _CHANNEL_SPACING = 0.04167      # ~41.67 kHz per duplex channel
    _NUM_CHANNELS = 240              # Simplex channels in the band

    # Iridium burst types (from frame preamble)
    _BURST_TYPES = {
        0x00: "IBC",        # Iridium Broadcast Channel
        0x01: "RING",       # Ring alert
        0x02: "PAGE",       # Paging channel
        0x03: "ACCH",       # Associated Control Channel
        0x04: "VOICE",      # Voice traffic
        0x05: "DATA",       # Data traffic
        0x06: "SYNC",       # Synchronization burst
        0x07: "UNKNOWN",    # Unclassified
    }

    # Iridium frame structure constants
    _PREAMBLE_LEN = 64       # bits
    _UW_LEN = 16             # Unique word length in bits
    _HEADER_LEN = 32         # Frame header bits
    _FRAME_LEN_BITS = 1320   # Total burst length in bits (normal)

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

    def _decode_burst_type(self, header_byte: int) -> str:
        """Decode the burst type from the frame header."""
        burst_id = (header_byte >> 5) & 0x07
        return self._BURST_TYPES.get(burst_id, "UNKNOWN")

    def _decode_frame_header(self, data: bytes) -> dict | None:
        """Decode an Iridium frame header from raw bytes."""
        if len(data) < 12:
            return None

        # Extract fields from the header
        preamble = struct.unpack(">Q", data[:8])[0]
        header_word = struct.unpack(">I", data[8:12])[0]

        burst_type = self._decode_burst_type((header_word >> 24) & 0xFF)
        channel_id = (header_word >> 12) & 0xFFF
        frame_num = header_word & 0xFFF

        freq_offset = self._IRIDIUM_BAND_START + (channel_id * self._CHANNEL_SPACING)

        return {
            "burst_type": burst_type,
            "channel_id": channel_id,
            "frame_num": frame_num,
            "frequency": round(freq_offset, 4),
            "preamble_valid": (preamble >> 48) == 0xAAAA,
        }

    def _matches_filter(self, burst_type: str) -> bool:
        """Check if a burst type matches the configured channel filter."""
        filt = str(self.channel_filter).strip().upper()
        if not filt or filt == "ALL":
            return True
        return burst_type.upper() == filt

    def _format_frame(self, frame: dict, timestamp: float) -> str:
        """Format a decoded frame as a CSV line."""
        return (
            f"{timestamp:.3f},"
            f"{frame['burst_type']},"
            f"{frame['channel_id']},"
            f"{frame['frame_num']},"
            f"{frame['frequency']:.4f},"
            f"{frame['preamble_valid']}"
        )

    @mute
    def check(self) -> bool:
        freq = float(self.center_freq)
        if not (self._IRIDIUM_BAND_START <= freq <= self._IRIDIUM_BAND_END):
            return False
        sock = self._connect_sdr()
        if sock is None:
            return False
        try:
            resp = self._send_sdr_command(sock, "info")
            return "ERROR" not in resp
        finally:
            sock.close()

    def run(self) -> None:
        freq = float(self.center_freq)
        sr = float(self.sample_rate)

        if not (self._IRIDIUM_BAND_START <= freq <= self._IRIDIUM_BAND_END):
            print_error(
                f"Frequency {freq} MHz is outside the Iridium band "
                f"({self._IRIDIUM_BAND_START}-{self._IRIDIUM_BAND_END} MHz)"
            )
            return

        print_status("Iridium Frame Decoder Configuration:")
        print_info(f"  Center frequency : {freq} MHz")
        print_info(f"  Sample rate      : {sr} MHz")
        print_info(f"  RX gain          : {self.rx_gain} dB")
        print_info(f"  Capture duration : {self.capture_duration} s")
        filt = str(self.channel_filter).strip() or "all"
        print_info(f"  Channel filter   : {filt}")
        print_info("  Mode             : PASSIVE (receive-only)")

        self._exploit()

    def _exploit(self) -> None:
        sock = self._connect_sdr()
        if sock is None:
            print_error("Cannot connect to SDR daemon. Aborting.")
            return

        output_fh = None
        try:
            freq_hz = int(float(self.center_freq) * 1e6)
            sr_hz = int(float(self.sample_rate) * 1e6)

            # Configure SDR for receive
            print_status("Configuring SDR for Iridium L-band reception ...")
            self._send_sdr_command(sock, f"set freq {freq_hz}")
            self._send_sdr_command(sock, f"set sample_rate {sr_hz}")
            self._send_sdr_command(sock, f"set rxgain {self.rx_gain}")
            self._send_sdr_command(sock, f"set bandwidth {sr_hz}")

            # Open output file if specified
            if self.output_file:
                try:
                    output_fh = open(str(self.output_file), "w")
                    output_fh.write(
                        "timestamp,burst_type,channel_id,frame_num,"
                        "frequency_mhz,preamble_valid\n"
                    )
                    print_success(f"Writing decoded frames to: {self.output_file}")
                except OSError as e:
                    print_error(f"Cannot open output file: {e}")
                    return

            # Start capture
            print_status("Starting Iridium frame capture ...")
            self._send_sdr_command(sock, "rx start")

            duration = int(self.capture_duration)
            start = time.time()
            frames_decoded = 0
            frames_by_type: dict[str, int] = {}

            while (time.time() - start) < duration:
                try:
                    raw = sock.recv(8192)
                    if not raw:
                        break
                except (OSError, TimeoutError):
                    break

                # Process received data in frame-sized chunks
                offset = 0
                while offset + 12 <= len(raw):
                    frame = self._decode_frame_header(raw[offset:offset + 12])
                    offset += 12

                    if frame is None:
                        continue
                    if not frame["preamble_valid"]:
                        continue
                    if not self._matches_filter(frame["burst_type"]):
                        continue

                    frames_decoded += 1
                    btype = frame["burst_type"]
                    frames_by_type[btype] = frames_by_type.get(btype, 0) + 1

                    ts = time.time() - start
                    line = self._format_frame(frame, ts)

                    if output_fh:
                        output_fh.write(line + "\n")

                    if frames_decoded <= 50 or frames_decoded % 100 == 0:
                        print_info(
                            f"  [{ts:7.1f}s] {btype:6s} ch={frame['channel_id']:4d} "
                            f"frame={frame['frame_num']:4d} "
                            f"freq={frame['frequency']:.2f} MHz"
                        )

            self._send_sdr_command(sock, "rx stop")
            elapsed = time.time() - start

            # Summary
            print_status(f"Capture complete: {elapsed:.1f}s elapsed")
            print_success(f"Total frames decoded: {frames_decoded}")
            if frames_by_type:
                print_info("Frames by type:")
                for btype, count in sorted(
                    frames_by_type.items(), key=lambda x: x[1], reverse=True
                ):
                    print_info(f"  {btype:8s}: {count}")

            if output_fh:
                print_success(f"Results saved to: {self.output_file}")

        finally:
            if output_fh:
                output_fh.close()
            sock.close()
