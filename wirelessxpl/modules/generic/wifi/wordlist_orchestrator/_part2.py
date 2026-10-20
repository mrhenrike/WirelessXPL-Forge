                    "-o",
                    str(out_cewler),
                    "--min-word-length",
                    str(int(self.min_length)),
                ]
                rc = self._run_cmd(argv, cwd=str(wl / "cewler"), env=env)
                if rc == 0 and out_cewler.is_file() and out_cewler.stat().st_size > 0:
                    generated.append(out_cewler)
            else:
                print_info("cewler não encontrado em Wordlists/cewler.")

        # CeWL (Ruby)
        if wl and url:
            cewl_rb = wl / "CeWL" / "cewl.rb"
            out_cewl = tmp / "cewl_out.txt"
            if cewl_rb.is_file():
                ruby = shutil.which("ruby")
                if not ruby:
                    print_info("ruby não está no PATH — CeWL omitido.")
                else:
                    argv = [
                        ruby,
                        str(cewl_rb),
                        "-w",
                        str(out_cewl),
                        "-m",
                        str(int(self.min_length)),
                        url,
                    ]
                    rc = self._run_cmd(argv, cwd=str(cewl_rb.parent))
                    if rc == 0 and out_cewl.is_file():
                        generated.append(out_cewl)
            else:
                print_info("cewl.rb não encontrado.")

        # cupp / elpscrk — somente orientação (modos interativos)
        if wl:
            cupp_py = wl / "cupp" / "cupp.py"
            if cupp_py.is_file():
                print_status(
                    f"cupp (interativo): {self._python_exe()} {cupp_py} -i   ou   {self._python_exe()} {cupp_py} -w {seed}"
                )
            elp = wl / "elpscrk" / "elpscrk.py"
            if elp.is_file():
                print_status(
                    f"elpscrk (interativo): {self._python_exe()} {elp}"
                )

        return generated

    def _generate_pattern_wordlist(self, tmp: Path) -> list[Path]:
        """Executa wfh, pnwgen, crunch e BruteForge quando configurados.

        Args:
            tmp: Diretório temporário.

        Returns:
            Lista de arquivos gerados.
        """

        wl = self._wordlists_root()
        out_paths: list[Path] = []
        if not wl:
            return out_paths

        py = self._python_exe()
        mn = max(1, int(self.min_length))
        mx = max(mn, int(self.max_length))
        cap = int(self.max_words)
        wfh_prefix: list[str] = []
        if cap > 0:
            wfh_prefix = ["--limit", str(cap)]

        # WordListsForHacking / wfh
        wfh_py = wl / "WordListsForHacking" / "wfh.py"
        if wfh_py.is_file():
            pattern = str(self.wfh_pattern).strip()
            if pattern:
                vars_json = str(self.wfh_pattern_vars_json).strip()
                argv = [py, str(wfh_py)] + wfh_prefix + ["pattern", "-t", pattern]
                if vars_json:
                    try:
                        vdict = json.loads(vars_json)
                        if isinstance(vdict, dict):
                            for k, val in vdict.items():
                                argv.extend(["--vars", f"{k}={val}"])
                    except json.JSONDecodeError:
                        print_error("wfh_pattern_vars_json inválido.")
                out_wfh = tmp / "wfh_pattern.txt"
                argv.extend(["-o", str(out_wfh)])
                self._run_cmd(argv, cwd=str(wfh_py.parent))
                if out_wfh.is_file():
                    out_paths.append(out_wfh)
            else:
                cs = str(self.crunch_charset).strip() or "abc"
                out_wfh = tmp / "wfh_charset.txt"
                argv = (
                    [py, str(wfh_py)]
                    + wfh_prefix
                    + ["charset", str(mn), str(mx), cs, "-o", str(out_wfh)]
                )
                self._run_cmd(argv, cwd=str(wfh_py.parent))
                if out_wfh.is_file():
                    out_paths.append(out_wfh)

            if bool(self.include_phone):
                out_phone = tmp / "wfh_phone.txt"
                country = str(self.country).strip().lower()
                phone_argv = [py, str(wfh_py)] + wfh_prefix + ["phone", "-o", str(out_phone)]
                if country == "br":
                    phone_argv.extend(["--country", "brazil"])
                self._run_cmd(phone_argv, cwd=str(wfh_py.parent))
                if out_phone.is_file():
                    out_paths.append(out_phone)

        # pnwgen (prefixo/sufixo + comprimento; cópia em tmp para não sujar o submódulo)
        pnw = wl / "pnwgen" / "pnwgen.py"
        if bool(self.include_phone) and pnw.is_file():
            prefix = ""
            suffix = str(self.target_ssid).strip()
            length = 8 if str(self.country).strip().lower() == "br" else 7
            pn_dir = tmp / "pnwgen_run"
            if not bool(self.dry_run):
                pn_dir.mkdir(parents=True, exist_ok=True)
                shutil.copy2(pnw, pn_dir / "pnwgen.py")
                doc = pnw.parent / "doc"
                if doc.is_dir():
                    shutil.copytree(doc, pn_dir / "doc", dirs_exist_ok=True)
            argv = [py, str(pn_dir / "pnwgen.py"), prefix, suffix, str(length)]
            rc = self._run_cmd(argv, cwd=str(pn_dir))
            built = pn_dir / "wordlist.txt"
            if not bool(self.dry_run) and rc == 0 and built.is_file():
                out_pn = tmp / "pnwgen_wordlist.txt"
                shutil.copy2(built, out_pn)
                out_paths.append(out_pn)

        # crunch (binário no PATH ou build local futuro)
        crunch_bin = shutil.which("crunch")
        out_crunch = tmp / "crunch_out.txt"
        if crunch_bin:
            extra = str(self.crunch_extra).strip().split() if str(self.crunch_extra).strip() else []
            argv = [crunch_bin, str(mn), str(mx), str(self.crunch_charset), "-o", str(out_crunch)]
            argv.extend(extra)
            self._run_cmd(argv)
            if out_crunch.is_file():
                out_paths.append(out_crunch)
        else:
            print_info("crunch não encontrado no PATH — use pacote do sistema ou compile Windows-Crunch.")

        # BruteForge (charset + comprimento; opcional — keyspace explode rápido)
        bf = self._submodules_root() / "Hacking" / "BruteForge" / "bruteforge.py"
        out_bf = tmp / "bruteforge_out.txt"
        if bool(self.include_bruteforge) and bf.is_file():
            charset = str(self.bruteforge_charset).strip()
            if charset not in {"digits", "lowercase", "uppercase", "special", "all"}:
                charset = "lowercase"
            argv = [
                py,
                str(bf),
                "-m",
                str(mn),
                "-M",
                str(mx),
                "-c",
                charset,
                "-o",
                str(out_bf),
            ]
            self._run_cmd(argv, cwd=str(bf.parent))
            if out_bf.is_file():
                out_paths.append(out_bf)

        return out_paths

    def _generate_isp_wordlist(self, tmp: Path) -> list[Path]:
        """Comcast/Xfinity: listas estáticas leves ou gerador completo opcional.

        Args:
            tmp: Diretório temporário.

        Returns:
            Arquivos para merge.
        """

        wl = self._wordlists_root()
        paths: list[Path] = []
        if not wl:
            return paths

        xdir = wl / "0day-Xfinity-Wordlist-Generator"
        if not xdir.is_dir():
            print_info("0day-Xfinity-Wordlist-Generator não encontrado.")
            return paths

        wl_sub = xdir / "wordlists"
        if wl_sub.is_dir():
            paths.extend(p for p in self._collect_text_files(wl_sub, recursive=False) if p.stat().st_size < 50 * 1024 * 1024)

        keyspace_py = xdir / "xfinity-keyspace.py"
        if bool(self.run_xfinity_keyspace) and keyspace_py.is_file():
            print_error(
                "xfinity-keyspace.py pode gerar dezenas/centenas de GB. Confirme espaço em disco."
            )
            self._run_cmd([self._python_exe(), str(keyspace_py)], cwd=str(xdir))
            ksp = xdir / "keyspace.txt"
            if ksp.is_file():
                paths.append(ksp)

        return paths

    def _merge_wordlists(self, sources: list[Path], output: Path) -> tuple[int, int]:
        """Combina fontes, filtra comprimento e deduplica opcionalmente.

        Args:
            sources: Arquivos de entrada (texto linha a linha).
            output: Arquivo de saída.

        Returns:
            Tupla (linhas escritas, linhas lidas aproximadas).
        """

        cap = int(self.max_words)
        unlimited = cap <= 0
        mn = int(self.min_length)
        mx = int(self.max_length)
        dedup = bool(self.merge_dedup)

        seen: set[str] = set()
        written = 0
        read_lines = 0

        if bool(self.dry_run):
            print_status(
                "[dry_run] merge de {} arquivos → {} (dedup={}, cap={})".format(
                    len(sources), output, dedup, cap if not unlimited else "∞"
                )
            )
            return (0, 0)

        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("w", encoding="utf-8", errors="replace", newline="\n") as fout:
            for src in sources:
                if not src.is_file():
                    continue
                try:
                    with src.open("r", encoding="utf-8", errors="replace") as fin:
                        for line in fin:
                            read_lines += 1
                            word = line.strip()
                            if not word or len(word) < mn or len(word) > mx:
                                continue
                            if dedup and word in seen:
                                continue
                            if dedup:
                                seen.add(word)
                            fout.write(word + "\n")
                            written += 1
                            if not unlimited and written >= cap:
                                return (written, read_lines)
                except OSError as exc:
                    print_error(f"Erro ao ler {src}: {exc}")

        return (written, read_lines)


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
        """Orquestra coleta/geração conforme ``mode`` e grava ``output_file``."""

        mode = str(self.mode).strip().lower()
        if mode not in _MODES:
            print_error("mode inválido: {}. Use: {}".format(mode, ", ".join(sorted(_MODES))))
            return

        country = str(self.country).strip().lower()
        if country not in _COUNTRIES:
            print_error("country deve ser br, us ou generic.")
            return

        out = Path(str(self.output_file).strip()) if str(self.output_file).strip() else Path()
        if not str(self.output_file).strip():
            print_error("Defina output_file.")
            return

        tmp = self._ensure_tmp()
        sources: list[Path] = []

        def _want_static() -> bool:
            return mode in {"static", "combined", "auto"}

        def _want_osint() -> bool:
            if mode in {"osint", "combined"}:
                return True
            if mode == "auto":
                return bool(str(self.target_url).strip() or str(self.target_profile_json).strip())
            return False

        def _want_pattern() -> bool:
            if mode in {"pattern", "combined"}:
                return True
            if mode == "auto":
                return bool(self.include_phone)
            return False

        def _want_isp() -> bool:
            if mode in {"isp", "combined"}:
                return True
            if mode == "auto" and country == "us":
                return True
            return False

        if _want_static():
            sources.extend(self._find_static_wordlists())

        if _want_osint():
            sources.extend(self._generate_osint_wordlist(tmp))

        if _want_pattern():
            sources.extend(self._generate_pattern_wordlist(tmp))

        if _want_isp():
            sources.extend(self._generate_isp_wordlist(tmp))

        # Ordem estável e sem duplicar path
        uniq_sources: list[Path] = []
        seen_p: set[str] = set()
        for p in sources:
            key = str(p.resolve())
            if key not in seen_p:
                seen_p.add(key)
                uniq_sources.append(p)

        print_status(f"Fontes para merge: {len(uniq_sources)}")
        written, read_lines = self._merge_wordlists(uniq_sources, out)
        print_success(
            f"Concluído: {written} linhas gravadas (≈{read_lines} linhas lidas) em {out}"
        )
