class PolyglotOrchestrator:
    """Compila e executa exploits/ferramentas em qualquer linguagem suportada.

    Args:
        cache_dir: Diretório para binários compilados (padrão: temp do sistema).
        default_timeout: Timeout padrão em segundos para execução.
        dry_run: Se True, apenas exibe o comando sem executar.
    """

    def __init__(
        self,
        cache_dir: str | Path | None = None,
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
        self._compiler_cache: dict[Lang, str | None] = {}

    # ------------------------------------------------------------------ #
    # Detecção de compiladores/interpretadores
    # ------------------------------------------------------------------ #

    def find_compiler(self, lang: Lang) -> str | None:
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

    def runtime_report(self) -> dict[str, bool]:
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
        source_path: str | Path,
        extra_flags: list[str] | None = None,
        force: bool = False,
    ) -> tuple[bool, Path, str]:
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
                capture_output=True,
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
        source_path: str | Path,
        args: Sequence[str] | None = None,
        env: dict[str, str] | None = None,
        cwd: str | Path | None = None,
        timeout: int | None = None,
        stdin_data: str | None = None,
        extra_compile_flags: list[str] | None = None,
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
                    capture_output=True,
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
        args: Sequence[str] | None = None,
        timeout: int | None = None,
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
_default_orchestrator: PolyglotOrchestrator | None = None


def get_orchestrator(
    cache_dir: str | Path | None = None,
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
