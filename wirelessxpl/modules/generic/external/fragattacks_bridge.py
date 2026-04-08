#!/usr/bin/env python3
# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""Bridge subprocess para FragAttacks (BSD) — testes de fragmentação/agregação (Mathy Vanhoef).

Invoca ``research/fragattack.py`` no repositório upstream; não importa código BSD.
Modos: verificação de vulnerabilidade (cliente vs AP), injeção em interface separada,
e cenários alinhados a CVEs via nome de teste e sequência de ações. Análise de PCAP
é feita em paralelo com tcpdump/tshark (o bridge não substitui esses fluxos).
"""
from __future__ import annotations

import logging, os, shutil, subprocess
from pathlib import Path
from typing import List, Optional

from wirelessxpl.core.exploit import *

logger = logging.getLogger(__name__)


class Exploit(Exploit):
    """Ponte subprocess para FragAttacks (BSD) — fragattack.py."""

    __info__ = {
        "name": "FragAttacks Bridge",
        "description": (
            "Executa fragattack.py (BSD, subprocess) para testar clientes e APs contra "
            "falhas de fragmentação/agregação (FragAttacks). Suporta modo AP de teste "
            "(--ap), injeção (--inject), e perfil ping com ações I,E,E ou I,E,F,E (mixed_key). "
            "SSID/PSK efetivos vêm do hostapd/wpa em uso pelo script upstream."
        ),
        "authors": (
            "André Henrique (@mrhenrike) | União Geek",
            "Mathy Vanhoef / FragAttacks (BSD, invoked as subprocess)",
        ),
        "references": (
            "https://github.com/vanhoefm/fragattacks",
            "https://www.fragattacks.com/",
        ),
        "devices": ("wifi",),
    }

    interface = OptString("", "Interface principal (AP de teste ou cliente)")
    test_mode = OptString(
        "client",
        "client = --ap (testa STA contra AP criado pelo tool); ap = supplicant (testa AP)",
    )
    inject = OptString(
        "",
        "Interface de injeção (segundo rádio); repassa --inject <iface>",
    )
    mixed_key = OptBool(
        False,
        "Se verdadeiro, usa sequência de ações com rekey (I,E,F,E) no teste ping",
    )
    ssid = OptString("", "SSID desejado (ajuste hostapd.conf / rede no repositório upstream)")
    psk = OptString("", "PSK desejado (ajuste hostapd.conf / credenciais no repositório upstream)")
    dry_run = OptBool(False, "Somente exibir o comando")

    def _find_fragattack(self) -> Optional[Path]:
        """Localiza ``fragattack.py`` no clone ou PATH."""
        script = shutil.which("fragattack.py")
        if script:
            return Path(script).resolve()

        rel = (
            Path(__file__).resolve().parents[5]
            / "submodules"
            / "IoT"
            / "fragattacks"
            / "research"
            / "fragattack.py"
        )
        if rel.is_file():
            return rel.resolve()

        alt = Path(__file__).resolve().parents[4] / "fragattacks" / "research" / "fragattack.py"
        if alt.is_file():
            return alt.resolve()

        return None

    def _python_for_fragattack(self, script_dir: Path) -> str:
        """Prefere o Python do venv ``research/venv`` se existir."""
        venv_py = script_dir / "venv" / "bin" / "python3"
        if os.name != "nt" and venv_py.is_file():
            return str(venv_py)
        return shutil.which("python3") or "python3"

    def _build_command(self, script: Path) -> List[str]:
        """Monta argv para fragattack.py.

        Returns:
            Lista de argumentos (sem ``sudo``).

        Raises:
            ValueError: Interface ausente ou modo de teste inválido.
        """
        iface = str(self.interface).strip()
        if not iface:
            raise ValueError("Defina interface.")

        mode = str(self.test_mode).strip().lower()
        if mode not in ("client", "ap"):
            raise ValueError("test_mode deve ser 'client' ou 'ap'.")

        testname = "ping"
        actions = "I,E,F,E" if self.mixed_key else "I,E,E"

        py = self._python_for_fragattack(script.parent)
        cmd: List[str] = [py, str(script), iface, testname, actions]

        inj = str(self.inject).strip()
        if inj:
            cmd.extend(["--inject", inj])

        if mode == "client":
            cmd.append("--ap")

        return cmd

    def run(self) -> None:
        """Executa fragattack.py ou imprime o comando (dry_run)."""
        script = self._find_fragattack()
        if not script:
            print_error(
                "fragattack.py não encontrado. Clone vanhoefm/fragattacks, rode "
                "research/build.sh e research/pysetup.sh, ou adicione ao PATH.",
            )
            return

        try:
            cmd = self._build_command(script)
        except ValueError as err:
            print_error(str(err))
            return

        full_cmd = ["sudo"] + cmd
        cmd_str = " ".join(full_cmd)

        ssid = str(self.ssid).strip()
        psk = str(self.psk).strip()
        if ssid or psk:
            print_info(
                "SSID/PSK: o fragattack.py usa hostapd/wpa do diretório research — "
                "alinhe hostapd.conf / wpa_supplicant ao SSID/PSK desejados "
                "(opções do bridge são lembrete operacional).",
            )

        if self.dry_run:
            print_info("DRY RUN — comando:")
            print_status(cmd_str)
            print_info(
                "Dica: correlacione com PCAP via `sudo tcpdump -i <iface> -w captura.pcap` "
                "ou tshark em paralelo.",
            )
            return

        print_status("FragAttacks: {}".format(cmd_str))
        print_info("Execute a partir do ambiente configurado em fragattacks/research (venv).")
        try:
            subprocess.run(full_cmd, cwd=str(script.parent), check=False)
        except KeyboardInterrupt:
            print_info("fragattack interrompido pelo usuário.")
        except Exception as err:
            print_error("Falha ao executar fragattack: {}".format(err))
