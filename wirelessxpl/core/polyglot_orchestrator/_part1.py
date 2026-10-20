#!/usr/bin/env python3
# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""Polyglot Orchestrator — executa exploits e ferramentas em qualquer linguagem.

Compila e executa código em C, C++, Rust, Go, Ruby, Java, Perl, Lua e outros runtimes
que não podem ser incorporados diretamente em Python. Fornece:

  - Detecção automática de compiladores/interpretadores no PATH
  - Compilação on-demand com cache (recompila apenas se o fonte mudou)
  - Execução com timeout, captura de saída e tratamento de erros
  - Suporte a argumentos dinâmicos, variáveis de ambiente e stdin
  - Relatório de pré-requisitos ausentes para guiar o usuário

Uso típico dentro de um módulo:

    from wirelessxpl.core.polyglot_orchestrator import PolyglotOrchestrator, Lang

    orch = PolyglotOrchestrator()
    result = orch.run(Lang.C, "/path/to/exploit.c", args=["target_mac"])

Version: 1.0.0
"""


import hashlib
import logging
import os
import platform
import shutil
import subprocess
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path

logger = logging.getLogger(__name__)


class Lang(Enum):
    """Linguagens suportadas pelo orquestrador."""

    C = auto()
    CPP = auto()
    RUST = auto()
    GO = auto()
    RUBY = auto()
    JAVA = auto()
    PERL = auto()
    LUA = auto()
    BASH = auto()
    POWERSHELL = auto()
    NODE = auto()
    PHP = auto()
    PYTHON2 = auto()
    KOTLIN = auto()
    SWIFT = auto()


@dataclass
class LangConfig:
    """Configuração de compilação/interpretação para uma linguagem."""

    lang: Lang
    # Candidatos de binário a procurar no PATH (ordem de preferência)
    compiler_candidates: list[str] = field(default_factory=list)
    # Se True, precisa compilar antes de executar
    needs_compile: bool = False
    # Flags de compilação base
    compile_flags: list[str] = field(default_factory=list)
    # Extensão do binário compilado (vazio = sem extensão)
    binary_ext: str = ""
    # Extensão padrão do arquivo fonte
    source_ext: str = ""
    # Flags de execução (para interpreters)
    run_flags: list[str] = field(default_factory=list)


_LANG_CONFIGS: dict[Lang, LangConfig] = {
    Lang.C: LangConfig(
        lang=Lang.C,
        compiler_candidates=["gcc", "cc", "clang", "x86_64-linux-gnu-gcc"],
        needs_compile=True,
        compile_flags=["-O2", "-Wall", "-lpthread", "-lm"],
        binary_ext="" if platform.system() != "Windows" else ".exe",
        source_ext=".c",
    ),
    Lang.CPP: LangConfig(
        lang=Lang.CPP,
        compiler_candidates=["g++", "c++", "clang++"],
        needs_compile=True,
        compile_flags=["-O2", "-std=c++17", "-lpthread", "-lm"],
        binary_ext="" if platform.system() != "Windows" else ".exe",
        source_ext=".cpp",
    ),
    Lang.RUST: LangConfig(
        lang=Lang.RUST,
        compiler_candidates=["rustc"],
        needs_compile=True,
        compile_flags=["--edition", "2021"],
        binary_ext="" if platform.system() != "Windows" else ".exe",
        source_ext=".rs",
    ),
    Lang.GO: LangConfig(
        lang=Lang.GO,
        compiler_candidates=["go"],
        needs_compile=True,
        compile_flags=["build", "-o"],
        source_ext=".go",
    ),
    Lang.RUBY: LangConfig(
        lang=Lang.RUBY,
        compiler_candidates=["ruby", "ruby3", "ruby2.7"],
        needs_compile=False,
        source_ext=".rb",
    ),
    Lang.JAVA: LangConfig(
        lang=Lang.JAVA,
        compiler_candidates=["java"],
        needs_compile=True,
        compile_flags=[],
        source_ext=".java",
    ),
    Lang.PERL: LangConfig(
        lang=Lang.PERL,
        compiler_candidates=["perl"],
        needs_compile=False,
        source_ext=".pl",
    ),
    Lang.LUA: LangConfig(
        lang=Lang.LUA,
        compiler_candidates=["lua", "lua5.4", "lua5.3", "lua5.1"],
        needs_compile=False,
        source_ext=".lua",
    ),
    Lang.BASH: LangConfig(
        lang=Lang.BASH,
        compiler_candidates=["bash", "sh"],
        needs_compile=False,
        source_ext=".sh",
    ),
    Lang.POWERSHELL: LangConfig(
        lang=Lang.POWERSHELL,
        compiler_candidates=["pwsh", "powershell"],
        needs_compile=False,
        run_flags=["-ExecutionPolicy", "Bypass", "-File"],
        source_ext=".ps1",
    ),
    Lang.NODE: LangConfig(
        lang=Lang.NODE,
        compiler_candidates=["node", "nodejs"],
        needs_compile=False,
        source_ext=".js",
    ),
    Lang.PHP: LangConfig(
        lang=Lang.PHP,
        compiler_candidates=["php", "php8", "php7"],
        needs_compile=False,
        source_ext=".php",
    ),
    Lang.PYTHON2: LangConfig(
        lang=Lang.PYTHON2,
        compiler_candidates=["python2", "python2.7"],
        needs_compile=False,
        source_ext=".py",
    ),
    Lang.KOTLIN: LangConfig(
        lang=Lang.KOTLIN,
        compiler_candidates=["kotlinc"],
        needs_compile=True,
        source_ext=".kt",
    ),
    Lang.SWIFT: LangConfig(
        lang=Lang.SWIFT,
        compiler_candidates=["swift", "swiftc"],
        needs_compile=False,
        source_ext=".swift",
    ),
}


@dataclass
class RunResult:
    """Resultado de execução de um exploit externo."""

    returncode: int = 0
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    binary_path: Path | None = None

    @property
    def success(self) -> bool:
        """True se retornou código 0 e não houve timeout."""
        return self.returncode == 0 and not self.timed_out

    def print_output(self) -> None:
        """Imprime stdout/stderr formatados."""
        if self.stdout:
            for line in self.stdout.strip().splitlines():
                print(f"  [>] {line}")
        if self.stderr:
            for line in self.stderr.strip().splitlines():
                print(f"  [!] {line}")


