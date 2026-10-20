#!/usr/bin/env python3
# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""Orquestrador de wordlists para laboratório Wi‑Fi / WPA (pontes subprocess).

Unifica listas estáticas do superprojeto (SecLists, BRWordList, 1wordlist) e
dispara geradores externos (cupp, elpscrk, cewler, CeWL, wfh, pnwgen, crunch,
BruteForge, 0day‑Xfinity) quando disponíveis. Ferramentas interativas (cupp -i/-w,
elpscrk) geram sementes a partir de ``target_profile_json`` e registram o comando
sugerido para execução manual.

Version: 1.0.0
"""


import hashlib
import json
import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from collections.abc import Iterable

from wirelessxpl.core.exploit import *

logger = logging.getLogger(__name__)

_MODES = frozenset({"static", "osint", "pattern", "isp", "combined", "auto"})
_COUNTRIES = frozenset({"br", "us", "generic"})
_STATIC_TEXT_GLOBS = ("*.txt", "*.lst", "*.log")


class Exploit(Exploit):
    """Orquestra wordlists estáticas e subprocessos de geradores do superprojeto."""

    __info__ = {
        "name": "Wordlist orchestrator (Wi‑Fi / WPA lab)",
        "description": (
            "Modos static | osint | pattern | isp | combined | auto: localiza wordlists "
            "em submodules/Wordlists, invoca cewler/CeWL/wfh/pnwgen/crunch/BruteForge/"
            "Xfinity via subprocess, faz merge opcional com deduplicação e filtros de "
            "comprimento (WPA ≥ 8)."
        ),
        "authors": ("André Henrique (@mrhenrike) | União Geek",),
        "references": (
            "https://github.com/danielmiessler/SecLists",
            "https://github.com/digininja/CeWL",
            "https://github.com/roys/cewler",
        ),
        "devices": ("wifi", "wpa_lab"),
    }

    mode = OptString(
        "auto",
        "Modo: static | osint | pattern | isp | combined | auto",
    )
    target_ssid = OptString("", "SSID alvo (OSINT / padrões / semente)")
    target_url = OptString("", "URL para CeWL/cewler")
    target_profile_json = OptString(
        "",
        "JSON com chaves tipo name, birthdate, pet, keywords (lista) para sementes OSINT",
    )
    country = OptString(
        "generic",
        "País: br | us | generic (telefonia / ISP)",
    )
    output_file = OptString(
        "",
        "Arquivo de saída da wordlist combinada",
    )
    max_words = OptInteger(
        0,
        "Máximo de linhas na saída (0 = ilimitado)",
    )
    min_length = OptInteger(8, "Comprimento mínimo da senha (WPA: 8+)")
    max_length = OptInteger(63, "Comprimento máximo da senha")
    include_defaults = OptBool(
        True,
        "Incluir SecLists Default-Credentials (modo static/combined/auto)",
    )
    include_phone = OptBool(
        False,
        "Incluir geradores de telefone (wfh phone / pnwgen) em pattern/combined/auto",
    )
    merge_dedup = OptBool(True, "Mesclar fontes com deduplicação")
    dry_run = OptBool(False, "Somente planejar / exibir comandos, sem escrever nem executar")
    crunch_charset = OptString(
        "abcdefghijklmnopqrstuvwxyz0123456789",
        "Charset para crunch (quando pattern ativo)",
    )
    crunch_extra = OptString(
        "",
        "Argumentos extras para crunch (ex.: -t @@@@%%%%)",
        advanced=True,
    )
    wfh_pattern = OptString(
        "",
        "Se preenchido, chama wfh pattern -t \"...\" (vars em wfh_pattern_vars_json)",
        advanced=True,
    )
    wfh_pattern_vars_json = OptString(
        "",
        "JSON de variáveis para wfh pattern (ex.: {\"cod\":\"1200-1300\"})",
        advanced=True,
    )
    bruteforge_charset = OptString(
        "lowercase",
        "BruteForge: digits | lowercase | uppercase | special | all",
        advanced=True,
    )
    include_bruteforge = OptBool(
        False,
        "Incluir BruteForge (charset+tamanho; keyspace pode ser enorme)",
        advanced=True,
    )
    run_xfinity_keyspace = OptBool(
        False,
        "Executar xfinity-keyspace.py (pode gerar dezenas de GB; use com cautela)",
        advanced=True,
    )
    tmp_dir = OptString(
        "",
        "Diretório temporário (vazio = WirelessXPL-Forge/.tmp/wordlist_orchestrator)",
        advanced=True,
    )

    def _wxf_root(self) -> Path:
        """Raiz do repositório WirelessXPL-Forge."""

        return Path(__file__).resolve().parents[4]

    def _submodules_root(self) -> Path:
        """Diretório ``submodules`` (irmão de IoT)."""

        return self._wxf_root().parents[2]

    def _wordlists_root(self) -> Path | None:
        """Caminho ``submodules/Wordlists`` se existir."""

        cand = self._submodules_root() / "Wordlists"
        return cand if cand.is_dir() else None

    def _ensure_tmp(self) -> Path:
        """Garante pasta temporária dentro do submódulo (política do superprojeto)."""

        raw = str(self.tmp_dir).strip()
        if raw:
            base = Path(raw)
        else:
            base = self._wxf_root() / ".tmp" / "wordlist_orchestrator"
        base.mkdir(parents=True, exist_ok=True)
        return base

    def _python_exe(self) -> str:
        """Interpretador Python para subprocessos."""

        for name in ("python3", "python", sys.executable):
            if name == sys.executable:
                return sys.executable
            w = shutil.which(name)
            if w:
                return w
        return sys.executable

    def _parse_profile(self) -> dict[str, object]:
        """Converte ``target_profile_json`` em dicionário."""

        raw = str(self.target_profile_json).strip()
        if not raw:
            return {}
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            print_error(f"target_profile_json inválido: {exc}")
            return {}
        return data if isinstance(data, dict) else {}

    def _profile_seed_lines(self, profile: dict[str, object], ssid: str) -> list[str]:
        """Extrai linhas de semente a partir do perfil e do SSID."""

        out: list[str] = []

        def _add(val: object) -> None:
            if val is None:
                return
            if isinstance(val, (list, tuple, set)):
                for x in val:
                    _add(x)
                return
            s = str(val).strip()
            if s:
                out.append(s)

        for _k, v in profile.items():
            _add(v)

        s = ssid.strip()
        if s:
            out.extend(
                [
                    s,
                    s.lower(),
                    s.upper(),
                    s.replace(" ", ""),
                    s.replace("_", ""),
                    hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()[:16],
                ]
            )

        seen: set[str] = set()
        uniq: list[str] = []
        for line in out:
            if line not in seen:
                seen.add(line)
                uniq.append(line)
        return uniq

    def _write_seed_file(self, tmp: Path, profile: dict[str, object], ssid: str) -> Path:
        """Grava arquivo de sementes para merge e referência manual (cupp/elpscrk)."""

        path = tmp / "profile_seed.txt"
        lines = self._profile_seed_lines(profile, ssid)
        if bool(self.dry_run):
            print_status(f"[dry_run] sementes ({len(lines)} linhas) → {path}")
            return path
        path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8", errors="replace")
        return path

    def _collect_text_files(self, root: Path, recursive: bool) -> list[Path]:
        """Lista arquivos de texto comuns sob ``root``."""

        found: list[Path] = []
        if not root.is_dir():
            return found
        it: Iterable[Path]
        if recursive:
            for pat in _STATIC_TEXT_GLOBS:
                found.extend(root.rglob(pat))
        else:
            for pat in _STATIC_TEXT_GLOBS:
                found.extend(root.glob(pat))
        # Ignorar metadados de git e binários óbvios
        skip_parts = {".git", "__pycache__", ".venv", "node_modules"}
        return sorted(
            p
            for p in found
            if p.is_file()
            and not any(part in skip_parts for part in p.parts)
            and p.stat().st_size < 200 * 1024 * 1024
        )

    def _find_static_wordlists(self) -> list[Path]:
        """Localiza wordlists estáticas disponíveis no superprojeto.

        Returns:
            Lista de caminhos para arquivos .txt/.lst relevantes.
        """

        wl = self._wordlists_root()
        if not wl:
            print_error("submodules/Wordlists não encontrado.")
            return []

        paths: list[Path] = []

        wifi_wpa = wl / "SecLists" / "Passwords" / "WiFi-WPA"
        if wifi_wpa.is_dir():
            paths.extend(sorted(wifi_wpa.glob("probable-v2-wpa-top*.txt")))

        if bool(self.include_defaults):
            dc = wl / "SecLists" / "Passwords" / "Default-Credentials"
            if dc.is_dir():
                paths.extend(self._collect_text_files(dc, recursive=True))

        br = wl / "BRWordList"
        if br.is_dir():
            paths.extend(self._collect_text_files(br, recursive=True))

        ow = wl / "1wordlist"
        if ow.is_dir():
            paths.extend(self._collect_text_files(ow, recursive=False))

        uniq = sorted({p.resolve() for p in paths if p.is_file()})
        print_status(f"Wordlists estáticas localizadas: {len(uniq)}")
        return uniq

    def _run_cmd(
        self,
        argv: list[str],
        cwd: Path | None = None,
        env: dict | None = None,
    ) -> int:
        """Executa subprocesso ou registra comando em dry_run.

        Args:
            argv: Argumentos do processo (incluindo binário).
            cwd: Diretório de trabalho.
            env: Variáveis de ambiente adicionais.

        Returns:
            Código de saída (0 se dry_run).
        """

        print_status("CMD: {}".format(" ".join(argv)))
        if cwd:
            print_status(f"CWD: {cwd}")
        if bool(self.dry_run):
            print_status("dry_run — subprocesso não executado.")
            return 0
        merged = {**os.environ, **(env or {})}
        try:
            proc = subprocess.run(
                argv,
                cwd=str(cwd) if cwd else None,
                env=merged,
                check=False,
            )
            return int(proc.returncode)
        except OSError as exc:
            print_error(f"Falha ao iniciar processo: {exc}")
            return 127

    def _generate_osint_wordlist(self, tmp: Path) -> list[Path]:
        """Dispara cewler/CeWL e materializa sementes de perfil.

        cupp (``-i`` / ``-w``) e elpscrk são predominantemente interativos; este
        método grava ``profile_seed.txt`` e imprime os caminhos sugeridos para
        execução manual.

        Args:
            tmp: Diretório temporário do módulo.

        Returns:
            Caminhos de arquivos gerados ou existentes para merge posterior.
        """

        wl = self._wordlists_root()
        generated: list[Path] = []
        profile = self._parse_profile()
        ssid = str(self.target_ssid).strip()
        seed = self._write_seed_file(tmp, profile, ssid)
        if seed.exists() and seed.stat().st_size > 0:
            generated.append(seed)

        url = str(self.target_url).strip()
        if not url:
            print_info("target_url vazio — pulando cewler/CeWL.")

        # cewler (Python / Scrapy)
        if wl and url:
            cewler_src = wl / "cewler" / "src"
            out_cewler = tmp / "cewler_out.txt"
            if cewler_src.is_dir():
                py = self._python_exe()
                env = {**os.environ, "PYTHONPATH": str(cewler_src)}
                argv = [
                    py,
                    "-m",
                    "cewler.cewler",
                    url,
