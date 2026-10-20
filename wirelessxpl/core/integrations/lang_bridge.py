"""Generic compiler/interpreter bridge for non-Python code integration.

Detects available compilers, compiles source when needed, executes
the resulting binary and captures output. Each language has its own
runner module; this file provides the shared registry and dispatch.

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""


import logging
import shutil
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

_RUNNERS: dict[str, "LanguageRunner"] = {}


@dataclass
class CompilerInfo:
    language: str
    compiler_path: str
    version: str
    supports_flags: list[str] = field(default_factory=list)


@dataclass
class CompileResult:
    success: bool
    binary_path: str | None = None
    stdout: str = ""
    stderr: str = ""
    returncode: int = -1


@dataclass
class RunResult:
    success: bool
    stdout: str = ""
    stderr: str = ""
    returncode: int = -1
    duration_ms: float = 0.0


class LanguageRunner:
    """Base class for language-specific runners."""

    language: str = ""
    extensions: tuple[str, ...] = ()
    compiler_names: tuple[str, ...] = ()

    def detect_compiler(self) -> CompilerInfo | None:
        for name in self.compiler_names:
            path = shutil.which(name)
            if path:
                version = self._get_version(path)
                return CompilerInfo(
                    language=self.language,
                    compiler_path=path,
                    version=version,
                )
        return None

    def _get_version(self, path: str) -> str:
        try:
            proc = subprocess.run(
                [path, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            first_line = (proc.stdout or proc.stderr).strip().split("\n")[0]
            return first_line
        except Exception:
            return "unknown"

    def compile(
        self,
        source: Path,
        output: Path,
        flags: Sequence[str] | None = None,
    ) -> CompileResult:
        raise NotImplementedError

    def run(
        self,
        binary: Path,
        args: Sequence[str] | None = None,
        timeout: int = 120,
        env: dict[str, str] | None = None,
    ) -> RunResult:
        raise NotImplementedError


def register_runner(runner: LanguageRunner) -> None:
    _RUNNERS[runner.language] = runner
    for ext in runner.extensions:
        _RUNNERS[ext] = runner


def get_runner(language_or_ext: str) -> LanguageRunner | None:
    return _RUNNERS.get(language_or_ext)


def list_available_compilers() -> list[CompilerInfo]:
    seen = set()
    result = []
    for runner in _RUNNERS.values():
        if runner.language in seen:
            continue
        seen.add(runner.language)
        info = runner.detect_compiler()
        if info:
            result.append(info)
    return result


def compile_and_run(
    source: Path,
    args: Sequence[str] | None = None,
    output_dir: Path | None = None,
    timeout: int = 120,
    extra_flags: Sequence[str] | None = None,
    env: dict[str, str] | None = None,
) -> RunResult:
    ext = source.suffix.lstrip(".")
    runner = get_runner(ext)
    if not runner:
        return RunResult(
            success=False,
            stderr=f"No runner registered for extension .{ext}",
        )

    compiler = runner.detect_compiler()
    if not compiler:
        return RunResult(
            success=False,
            stderr=f"No {runner.language} compiler found in PATH "
            f"(tried: {', '.join(runner.compiler_names)})",
        )

    if output_dir is None:
        output_dir = source.parent
    output_bin = output_dir / source.stem

    cr = runner.compile(source, output_bin, flags=extra_flags)
    if not cr.success:
        return RunResult(
            success=False,
            stdout=cr.stdout,
            stderr=cr.stderr,
            returncode=cr.returncode,
        )

    return runner.run((cr.binary_path and Path(cr.binary_path)) or output_bin, args=args, timeout=timeout, env=env)
