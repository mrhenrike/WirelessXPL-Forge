"""Rust compiler runner for the lang_bridge framework.

Compiles .rs sources via rustc (single file) or cargo (project dir),
then executes the resulting binary. Used for integrating Rust-based
wireless tools (e.g. airgorah components) into WirelessXPL.

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""

from __future__ import annotations

import subprocess
import time
from pathlib import Path
from typing import Dict, Optional, Sequence

from wirelessxpl.core.integrations.lang_bridge import (
    CompileResult,
    LanguageRunner,
    RunResult,
    register_runner,
)


class RustRunner(LanguageRunner):
    language = "rust"
    extensions = ("rs",)
    compiler_names = ("rustc", "cargo")

    def compile(
        self,
        source: Path,
        output: Path,
        flags: Optional[Sequence[str]] = None,
    ) -> CompileResult:
        if (source.parent / "Cargo.toml").exists():
            return self._cargo_build(source.parent, flags)
        return self._rustc_build(source, output, flags)

    def _rustc_build(
        self,
        source: Path,
        output: Path,
        flags: Optional[Sequence[str]] = None,
    ) -> CompileResult:
        cmd = ["rustc", str(source), "-o", str(output)]
        if flags:
            cmd.extend(flags)

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )
            return CompileResult(
                success=proc.returncode == 0,
                binary_path=str(output) if proc.returncode == 0 else None,
                stdout=proc.stdout,
                stderr=proc.stderr,
                returncode=proc.returncode,
            )
        except subprocess.TimeoutExpired:
            return CompileResult(
                success=False,
                stderr="Rust compilation timed out (300s)",
            )
        except FileNotFoundError:
            return CompileResult(
                success=False,
                stderr="rustc not found in PATH",
            )

    def _cargo_build(
        self,
        project_dir: Path,
        flags: Optional[Sequence[str]] = None,
    ) -> CompileResult:
        cmd = ["cargo", "build", "--release"]
        if flags:
            cmd.extend(flags)

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,
                cwd=str(project_dir),
            )
            binary = None
            if proc.returncode == 0:
                target_dir = project_dir / "target" / "release"
                for f in target_dir.iterdir():
                    if f.is_file() and not f.suffix and f.stat().st_mode & 0o111:
                        binary = str(f)
                        break

            return CompileResult(
                success=proc.returncode == 0,
                binary_path=binary,
                stdout=proc.stdout,
                stderr=proc.stderr,
                returncode=proc.returncode,
            )
        except subprocess.TimeoutExpired:
            return CompileResult(
                success=False,
                stderr="cargo build timed out (600s)",
            )
        except FileNotFoundError:
            return CompileResult(
                success=False,
                stderr="cargo not found in PATH",
            )

    def run(
        self,
        binary: Path,
        args: Optional[Sequence[str]] = None,
        timeout: int = 120,
        env: Optional[Dict[str, str]] = None,
    ) -> RunResult:
        cmd = [str(binary)]
        if args:
            cmd.extend(args)

        start = time.monotonic()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
            )
            elapsed = (time.monotonic() - start) * 1000
            return RunResult(
                success=proc.returncode == 0,
                stdout=proc.stdout,
                stderr=proc.stderr,
                returncode=proc.returncode,
                duration_ms=elapsed,
            )
        except subprocess.TimeoutExpired:
            elapsed = (time.monotonic() - start) * 1000
            return RunResult(
                success=False,
                stderr=f"Execution timed out ({timeout}s)",
                duration_ms=elapsed,
            )
        except FileNotFoundError:
            return RunResult(
                success=False,
                stderr=f"Binary not found: {binary}",
            )


class CRunner(LanguageRunner):
    language = "c"
    extensions = ("c", "h")
    compiler_names = ("gcc", "cc", "clang")

    def compile(
        self,
        source: Path,
        output: Path,
        flags: Optional[Sequence[str]] = None,
    ) -> CompileResult:
        compiler = self.detect_compiler()
        if not compiler:
            return CompileResult(success=False, stderr="No C compiler found")

        cmd = [compiler.compiler_path, str(source), "-o", str(output)]
        if flags:
            cmd.extend(flags)
        else:
            cmd.extend(["-Wall", "-O2"])

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )
            return CompileResult(
                success=proc.returncode == 0,
                binary_path=str(output) if proc.returncode == 0 else None,
                stdout=proc.stdout,
                stderr=proc.stderr,
                returncode=proc.returncode,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            return CompileResult(success=False, stderr=str(exc))

    def run(
        self,
        binary: Path,
        args: Optional[Sequence[str]] = None,
        timeout: int = 120,
        env: Optional[Dict[str, str]] = None,
    ) -> RunResult:
        cmd = [str(binary)]
        if args:
            cmd.extend(args)

        start = time.monotonic()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
            )
            elapsed = (time.monotonic() - start) * 1000
            return RunResult(
                success=proc.returncode == 0,
                stdout=proc.stdout,
                stderr=proc.stderr,
                returncode=proc.returncode,
                duration_ms=elapsed,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            elapsed = (time.monotonic() - start) * 1000
            return RunResult(success=False, stderr=str(exc), duration_ms=elapsed)


register_runner(RustRunner())
register_runner(CRunner())
