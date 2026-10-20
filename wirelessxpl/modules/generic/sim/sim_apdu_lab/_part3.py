                with open(log_path, "w", encoding="utf-8") as fh:
                    for fid_str in found:
                        fh.write(f"{fid_str}\n")
                print_info(f"Lista salva em: {log_path}")
            except OSError as exc:
                print_error(f"Falha ao gravar log: {exc}")

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------


    def check(self) -> str:
        """Verify SIM card reader and related tools are present."""
        import shutil
        tools = ["pySIM-shell", "pcsc_scan", "openssl"]
        found = [t for t in tools if shutil.which(t)]
        pysim = shutil.which("pySIM-shell") or shutil.which("pysim-shell")
        if pysim:
            return f"pySIM tools found at {pysim} - insert SIM card to proceed"
        if found:
            return f"Partial tools found: {', '.join(found)} - pySIM-shell missing"
        return "SIM tools not found - install pysim, pcscd, pcsc-tools"

    def run(self) -> None:
        """Execute APDU lab in the specified mode."""
        mode = str(self.mode).strip().lower()
        if mode not in self._VALID_MODES:
            print_error(
                "mode invalido. Opcoes: {}".format(", ".join(sorted(self._VALID_MODES)))
            )
            return

        if mode == "info":
            self._mode_info()
            return

        require_authorised_lab()
        require_sim_ownership()

        if not bool(self.i_know_scope):
            print_error(
                "Defina i_know_scope=true para confirmar laboratorio "
                "autorizado e posse do SIM."
            )
            return

        if not HAS_PYSCARD:
            print_error(
                "pyscard e necessario. Instale com: pip install pyscard"
            )
            return

        if bool(self.dry_run):
            print_info(f"[dry-run] Modo: {mode}")
            print_info("[dry-run] Nenhuma operacao real sera executada.")
            return

        conn = self._get_connection()
        if conn is None:
            return

        try:
            dispatch = {
                "send": lambda: self._mode_send(conn),
                "script": lambda: self._mode_script(conn),
                "select": lambda: self._mode_select(conn),
                "read_binary": lambda: self._mode_read_binary(conn),
                "read_record": lambda: self._mode_read_record(conn),
                "update_binary": lambda: self._mode_update_binary(conn),
                "verify_pin": lambda: self._mode_verify_pin(conn),
                "get_response": lambda: self._mode_get_response(conn),
                "status": lambda: self._mode_status(conn),
                "enumerate_files": lambda: self._mode_enumerate_files(conn),
            }
            handler = dispatch.get(mode)
            if handler:
                handler()
        finally:
            try:
                conn.disconnect()
            except Exception:
                pass
