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

from __future__ import annotations

import hashlib
import logging
import os
import platform
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple, Union

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
    compiler_candidates: List[str] = field(default_factory=list)
    # Se True, precisa compilar antes de executar
    needs_compile: bool = False
    # Flags de compilação base
    compile_flags: List[str] = field(default_factory=list)
    # Extensão do binário compilado (vazio = sem extensão)
    binary_ext: str = ""
    # Extensão padrão do arquivo fonte
    source_ext: str = ""
    # Flags de execução (para interpreters)
    run_flags: List[str] = field(default_factory=list)


_LANG_CONFIGS: Dict[Lang, LangConfig] = {
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
    binary_path: Optional[Path] = None

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


class PolyglotOrchestrator:
    """Compila e executa exploits/ferramentas em qualquer linguagem suportada.

    Args:
        cache_dir: Diretório para binários compilados (padrão: temp do sistema).
        default_timeout: Timeout padrão em segundos para execução.
        dry_run: Se True, apenas exibe o comando sem executar.
    """

    def __init__(
        self,
        cache_dir: Optional[Union[str, Path]] = None,
        default_timeout: int = 120,
        dry_run: bool = False,
    ) -> None:
        if cache_dir:
            self._cache_dir = Path(cache_dir)
            self._cache_dir.mkdir(parents=True, exist_ok=True)
        else:
            self._cache_dir = Path(tempfile.gettempdir()) / "wxf_polyglot_cache"
            self._cache_dir.mkdir(exist_ok=True)

        self.default_timeout = default_timeout
        self.dry_run = dry_run
        self._compiler_cache: Dict[Lang, Optional[str]] = {}

    # ------------------------------------------------------------------ #
    # Detecção de compiladores/interpretadores
    # ------------------------------------------------------------------ #

    def find_compiler(self, lang: Lang) -> Optional[str]:
        """Retorna o caminho do compilador/interpretador para a linguagem.

        Args:
            lang: Linguagem alvo.

        Returns:
            Caminho completo do binário ou None se não encontrado.
        """
        if lang in self._compiler_cache:
            return self._compiler_cache[lang]

        cfg = _LANG_CONFIGS.get(lang)
        if not cfg:
            self._compiler_cache[lang] = None
            return None

        for candidate in cfg.compiler_candidates:
            path = shutil.which(candidate)
            if path:
                logger.debug("Compiler found for %s: %s", lang.name, path)
                self._compiler_cache[lang] = path
                return path

        self._compiler_cache[lang] = None
        return None

    def check_lang_available(self, lang: Lang) -> bool:
        """Verifica se a linguagem está disponível no sistema.

        Args:
            lang: Linguagem a verificar.

        Returns:
            True se o compilador/interpretador estiver no PATH.
        """
        return self.find_compiler(lang) is not None

    def runtime_report(self) -> Dict[str, bool]:
        """Retorna um relatório de disponibilidade de todos os runtimes.

        Returns:
            Dicionário {nome_linguagem: disponível}.
        """
        return {lang.name: self.check_lang_available(lang) for lang in Lang}

    def print_runtime_report(self) -> None:
        """Imprime o relatório de runtimes no console."""
        report = self.runtime_report()
        print("  PolyglotOrchestrator — Status de Runtimes:")
        for lang_name, available in sorted(report.items()):
            status = "[+]" if available else "[-]"
            print(f"    {status} {lang_name}")

    # ------------------------------------------------------------------ #
    # Compilação
    # ------------------------------------------------------------------ #

    def _source_hash(self, source_path: Path) -> str:
        """SHA-256 dos primeiros 128KB do arquivo fonte (para cache)."""
        h = hashlib.sha256()
        try:
            with open(source_path, "rb") as f:
                h.update(f.read(131072))
        except OSError:
            pass
        return h.hexdigest()[:16]

    def _cached_binary(self, source_path: Path, lang: Lang) -> Path:
        """Caminho esperado do binário em cache para o fonte dado."""
        cfg = _LANG_CONFIGS[lang]
        stem = source_path.stem
        src_hash = self._source_hash(source_path)
        name = f"{stem}_{src_hash}{cfg.binary_ext}"
        return self._cache_dir / name

    def compile(
        self,
        lang: Lang,
        source_path: Union[str, Path],
        extra_flags: Optional[List[str]] = None,
        force: bool = False,
    ) -> Tuple[bool, Path, str]:
        """Compila um arquivo fonte.

        Args:
            lang: Linguagem do fonte.
            source_path: Caminho para o arquivo fonte.
            extra_flags: Flags adicionais de compilação.
            force: Se True, recompila mesmo se binário em cache existir.

        Returns:
            Tupla (sucesso, caminho_binario, mensagem_de_erro).
        """
        source_path = Path(source_path).resolve()
        cfg = _LANG_CONFIGS.get(lang)

        if not cfg:
            return False, Path(), f"Linguagem não suportada: {lang}"

        if not cfg.needs_compile:
            return True, source_path, ""

        compiler = self.find_compiler(lang)
        if not compiler:
            candidates = ", ".join(cfg.compiler_candidates)
            return (
                False, Path(),
                f"Compilador não encontrado para {lang.name}. "
                f"Instale um dos seguintes: {candidates}",
            )

        binary_path = self._cached_binary(source_path, lang)

        if binary_path.exists() and not force:
            logger.debug("Cache hit: %s", binary_path)
            return True, binary_path, ""

        # Monta comando de compilação
        if lang == Lang.GO:
            cmd = [compiler] + cfg.compile_flags + [str(binary_path), str(source_path)]
        elif lang == Lang.JAVA:
            # javac compila para .class; execução usa 'java ClassName'
            cmd = ["javac", str(source_path)]
            binary_path = source_path.parent / (source_path.stem + ".class")
        elif lang == Lang.KOTLIN:
            jar_path = self._cache_dir / (source_path.stem + ".jar")
            cmd = [compiler, str(source_path), "-include-runtime", "-d", str(jar_path)]
            binary_path = jar_path
        elif lang == Lang.RUST:
            cmd = [compiler, str(source_path)] + cfg.compile_flags + ["-o", str(binary_path)]
        else:
            cmd = (
                [compiler]
                + cfg.compile_flags
                + (extra_flags or [])
                + [str(source_path), "-o", str(binary_path)]
            )

        if extra_flags and lang not in (Lang.GO, Lang.JAVA, Lang.KOTLIN):
            cmd += extra_flags

        logger.debug("Compilando: %s", " ".join(cmd))

        if self.dry_run:
            print(f"  [dry-run] compile: {' '.join(cmd)}")
            return True, binary_path, ""

        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=300,
            )
            if result.returncode != 0:
                err = result.stderr.decode("utf-8", errors="replace")
                return False, Path(), f"Erro de compilação ({lang.name}):\n{err}"
            return True, binary_path, ""
        except FileNotFoundError:
            return False, Path(), f"Compilador não encontrado: {cmd[0]}"
        except subprocess.TimeoutExpired:
            return False, Path(), "Timeout ao compilar."
        except Exception as exc:
            return False, Path(), f"Erro inesperado ao compilar: {exc}"

    # ------------------------------------------------------------------ #
    # Execução
    # ------------------------------------------------------------------ #

    def run(
        self,
        lang: Lang,
        source_path: Union[str, Path],
        args: Optional[Sequence[str]] = None,
        env: Optional[Dict[str, str]] = None,
        cwd: Optional[Union[str, Path]] = None,
        timeout: Optional[int] = None,
        stdin_data: Optional[str] = None,
        extra_compile_flags: Optional[List[str]] = None,
        force_recompile: bool = False,
        capture_output: bool = True,
    ) -> RunResult:
        """Compila (se necessário) e executa um exploit/ferramenta.

        Args:
            lang: Linguagem do exploit.
            source_path: Caminho para o arquivo fonte.
            args: Argumentos passados ao processo filho.
            env: Variáveis de ambiente extras (mescladas com os do processo atual).
            cwd: Diretório de trabalho para execução.
            timeout: Timeout em segundos (usa default_timeout se None).
            stdin_data: Dados para enviar via stdin.
            extra_compile_flags: Flags extras de compilação (apenas para linguagens compiladas).
            force_recompile: Força recompilação mesmo com cache válido.
            capture_output: Se False, permite saída direta ao terminal.

        Returns:
            RunResult com código de retorno, stdout, stderr, e flags de erro.
        """
        source_path = Path(source_path).resolve()
        cfg = _LANG_CONFIGS.get(lang)
        if not cfg:
            return RunResult(returncode=-1, stderr=f"Linguagem não suportada: {lang}")

        timeout = timeout if timeout is not None else self.default_timeout
        args = list(args) if args else []

        # Etapa 1: compilação (se necessário)
        if cfg.needs_compile:
            ok, binary_path, err_msg = self.compile(
                lang, source_path,
                extra_flags=extra_compile_flags,
                force=force_recompile,
            )
            if not ok:
                return RunResult(returncode=-2, stderr=err_msg)
        else:
            binary_path = source_path

        # Etapa 2: monta comando de execução
        compiler = self.find_compiler(lang)
        if not compiler and not cfg.needs_compile:
            candidates = ", ".join(cfg.compiler_candidates)
            return RunResult(
                returncode=-3,
                stderr=(
                    f"Runtime não encontrado para {lang.name}. "
                    f"Instale um dos seguintes: {candidates}"
                ),
            )

        if cfg.needs_compile:
            if lang == Lang.JAVA:
                cmd = [shutil.which("java") or "java", str(binary_path.stem)]
                cwd = cwd or binary_path.parent
            elif lang == Lang.KOTLIN:
                cmd = [shutil.which("java") or "java", "-jar", str(binary_path)]
            else:
                cmd = [str(binary_path)]
        else:
            run_flags = cfg.run_flags or []
            cmd = [compiler] + run_flags + [str(binary_path)]

        cmd += args

        run_env = dict(os.environ)
        if env:
            run_env.update(env)

        if self.dry_run:
            print(f"  [dry-run] exec: {' '.join(cmd)}")
            return RunResult(returncode=0)

        logger.debug("Executando: %s", " ".join(cmd))

        try:
            stdin_bytes = stdin_data.encode() if stdin_data else None
            if capture_output:
                proc = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    input=stdin_bytes,
                    timeout=timeout,
                    env=run_env,
                    cwd=str(cwd) if cwd else None,
                )
                return RunResult(
                    returncode=proc.returncode,
                    stdout=proc.stdout.decode("utf-8", errors="replace"),
                    stderr=proc.stderr.decode("utf-8", errors="replace"),
                    binary_path=binary_path if cfg.needs_compile else None,
                )
            else:
                proc = subprocess.run(
                    cmd,
                    input=stdin_bytes,
                    timeout=timeout,
                    env=run_env,
                    cwd=str(cwd) if cwd else None,
                )
                return RunResult(
                    returncode=proc.returncode,
                    binary_path=binary_path if cfg.needs_compile else None,
                )
        except subprocess.TimeoutExpired:
            return RunResult(returncode=-4, timed_out=True, stderr=f"Timeout após {timeout}s.")
        except FileNotFoundError as exc:
            return RunResult(returncode=-5, stderr=f"Binário não encontrado: {exc}")
        except Exception as exc:
            return RunResult(returncode=-6, stderr=f"Erro inesperado na execução: {exc}")

    # ------------------------------------------------------------------ #
    # Execução de script inline (código como string)
    # ------------------------------------------------------------------ #

    def run_inline(
        self,
        lang: Lang,
        code: str,
        args: Optional[Sequence[str]] = None,
        timeout: Optional[int] = None,
    ) -> RunResult:
        """Executa código-fonte fornecido como string.

        Salva em arquivo temporário e chama ``run()``.

        Args:
            lang: Linguagem do código.
            code: Código-fonte completo.
            args: Argumentos passados ao processo.
            timeout: Timeout em segundos.

        Returns:
            RunResult com resultado da execução.
        """
        cfg = _LANG_CONFIGS.get(lang)
        ext = cfg.source_ext if cfg else ".tmp"

        with tempfile.NamedTemporaryFile(
            suffix=ext, mode="w", delete=False, encoding="utf-8"
        ) as f:
            f.write(code)
            tmp_path = f.name

        try:
            return self.run(lang, tmp_path, args=args, timeout=timeout)
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


# Instância global de conveniência
_default_orchestrator: Optional[PolyglotOrchestrator] = None


def get_orchestrator(
    cache_dir: Optional[Union[str, Path]] = None,
    dry_run: bool = False,
) -> PolyglotOrchestrator:
    """Retorna (ou cria) a instância global do orquestrador.

    Args:
        cache_dir: Diretório de cache (usado apenas na primeira chamada).
        dry_run: Modo dry-run (usado apenas na primeira chamada).

    Returns:
        Instância global de PolyglotOrchestrator.
    """
    global _default_orchestrator
    if _default_orchestrator is None:
        _default_orchestrator = PolyglotOrchestrator(
            cache_dir=cache_dir, dry_run=dry_run
        )
    return _default_orchestrator
