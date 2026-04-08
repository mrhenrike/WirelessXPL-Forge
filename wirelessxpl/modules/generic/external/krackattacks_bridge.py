#!/usr/bin/env python3
# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""Bridge subprocess para KRACKattacks-scripts (BSD) — testes de reinstalação de chave.

Invoca ``krack-test-client.py`` (4-way e group handshake) ou ``krack-ft-test.py`` (802.11r FT)
a partir do diretório ``krackattack/`` do repositório upstream. Não são scripts de ataque
em produção; exigem credenciais e hostapd/wpa_supplicant modificados conforme o README oficial.
"""
from __future__ import annotations

import logging, os, shutil, subprocess
import textwrap
from pathlib import Path
from typing import List, Optional

from wirelessxpl.core.exploit import *

logger = logging.getLogger(__name__)

_KRACK_MODES = frozenset(("4way", "group", "ft"))


class Exploit(Exploit):
    """Ponte subprocess para KRACK test scripts (BSD)."""

    __info__ = {
        "name": "KRACKattacks Bridge",
        "description": (
            "Executa krack-test-client.py (teste 4-way e group key) ou krack-ft-test.py "
            "(FT handshake / 802.11r) como subprocesso (BSD). Requer build do hostapd "
            "modificado e venv em krackattacks-scripts/krackattack. "
            "SSID/PSK padrão do upstream costumam ser testnetwork/abcdefgh salvo em hostapd.conf."
        ),
        "authors": (
            "André Henrique (@mrhenrike) | União Geek",
            "Mathy Vanhoef / krackattacks-scripts (BSD, invoked as subprocess)",
        ),
        "references": (
            "https://github.com/vanhoefm/krackattacks-scripts",
            "https://www.krackattacks.com/",
        ),
        "devices": ("wifi",),
    }

    interface = OptString("", "Interface Wi-Fi (-i no cliente KRACK; FT usa -i no wpa_supplicant)")
    mode = OptString("4way", "4way | group | ft")
    ssid = OptString("", "SSID (FT: gera wpa_supplicant.conf em .tmp se preenchido com psk)")
    psk = OptString("", "PSK (FT: junto com ssid gera conf temporário)")
    target_client = OptString(
        "",
        "MAC do cliente alvo (informativo; o script upstream descobre STAs via DHCP/handshake)",
    )
    dry_run = OptBool(False, "Somente exibir o comando")

    def _find_krack_root(self) -> Optional[Path]:
        """Diretório ``krackattack`` com scripts e venv."""
        candidates = [
            Path(__file__).resolve().parents[5]
            / "submodules"
            / "IoT"
            / "krackattacks-scripts"
            / "krackattack",
            Path(__file__).resolve().parents[4]
            / "krackattacks-scripts"
            / "krackattack",
        ]
        for p in candidates:
            if (p / "krack-test-client.py").is_file():
                return p.resolve()
        return None

    def _venv_python(self, krack_root: Path) -> str:
        """Python do venv do projeto KRACK, se existir."""
        if os.name == "nt":
            venv_py = krack_root / "venv" / "Scripts" / "python.exe"
        else:
            venv_py = krack_root / "venv" / "bin" / "python3"
        if venv_py.is_file():
            return str(venv_py)
        return shutil.which("python3") or "python3"

    def _write_ft_wpa_conf(self, tmp_dir: Path) -> Path:
        """Grava wpa_supplicant.conf mínimo para FT-PSK.

        Args:
            tmp_dir: Diretório temporário do submódulo (``.tmp``).

        Returns:
            Caminho do arquivo gerado.

        Raises:
            ValueError: SSID ou PSK ausentes.
        """
        ssid = str(self.ssid).strip()
        psk = str(self.psk).strip()
        if not ssid or not psk:
            raise ValueError("Para mode=ft defina ssid e psk (conf wpa_supplicant).")

        tmp_dir.mkdir(parents=True, exist_ok=True)
        path = tmp_dir / "krack_ft_wpa_supplicant.conf"
        body = textwrap.dedent(
            '''\
            ctrl_interface=/var/run/wpa_supplicant
            network={{
            ssid="{ssid}"
            key_mgmt=FT-PSK
            psk="{psk}"
            }}
            ''',
        ).format(ssid=ssid.replace('"', '\\"'), psk=psk.replace('"', '\\"'))
        path.write_text(body, encoding="utf-8")
        return path

    def _build_command(self, krack_root: Path) -> List[str]:
        """Monta linha de comando para o modo selecionado.

        Returns:
            Argumentos sem ``sudo``.

        Raises:
            ValueError: Combinação inválida de opções.
        """
        mode = str(self.mode).strip().lower()
        if mode not in _KRACK_MODES:
            raise ValueError("mode deve ser: 4way, group ou ft.")

        py = self._venv_python(krack_root)
        iface = str(self.interface).strip()

        if mode == "ft":
            if not iface:
                raise ValueError("Defina interface para FT (wpa_supplicant -i).")
            conf = self._write_ft_wpa_conf(Path(__file__).resolve().parents[4] / ".tmp")
            return [
                py,
                str(krack_root / "krack-ft-test.py"),
                "wpa_supplicant",
                "-D",
                "nl80211",
                "-i",
                iface,
                "-c",
                str(conf),
            ]

        script = krack_root / "krack-test-client.py"
        cmd: List[str] = [py, str(script)]
        if mode == "group":
            cmd.append("--group")
        if iface:
            cmd.extend(["-i", iface])

        return cmd

    def run(self) -> None:
        """Executa o script KRACK apropriado."""
        krack_root = self._find_krack_root()
        if not krack_root:
            print_error(
                "krackattack/ não encontrado. Clone vanhoefm/krackattacks-scripts, "
                "execute krackattack/build.sh e krackattack/pysetup.sh.",
            )
            return

        tc = str(self.target_client).strip()
        if tc:
            print_info(
                "target_client={} — o krack-test-client.py identifica clientes via DHCP/handshake; "
                "use o hostapd modificado para isolar o STA se necessário.".format(tc),
            )

        mode = str(self.mode).strip().lower()
        if mode in ("4way", "group"):
            ssid = str(self.ssid).strip()
            psk = str(self.psk).strip()
            if ssid or psk:
                print_info(
                    "Para 4way/group edite hostapd/hostapd.conf no repositório KRACK "
                    "(SSID/PSK padrão testnetwork/abcdefgh).",
                )

        try:
            cmd = self._build_command(krack_root)
        except ValueError as err:
            print_error(str(err))
            return

        full_cmd = ["sudo"] + cmd
        cmd_str = " ".join(full_cmd)

        if self.dry_run:
            print_info("DRY RUN — comando:")
            print_status(cmd_str)
            print_info("cwd sugerido: {}".format(krack_root))
            return

        print_status("KRACK: {}".format(cmd_str))
        print_info("cwd: {}".format(krack_root))
        print_info("Desative NetworkManager/rfkill conforme README upstream antes de rodar.")
        try:
            subprocess.run(full_cmd, cwd=str(krack_root), check=False)
        except KeyboardInterrupt:
            print_info("KRACK interrompido pelo usuário.")
        except Exception as err:
            print_error("Falha ao executar script KRACK: {}".format(err))
