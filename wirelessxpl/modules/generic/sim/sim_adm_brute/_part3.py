                    "{}: {} SW={:02X}{:02X}\n".format(
                        "OK" if success else "FAIL", pin_str, sw1, sw2,
                    )
                )

            if success:
                print_success(f"ADM PIN ENCONTRADO: {pin_str}")
                if log_fh:
                    log_fh.write(f"FOUND: {pin_str}\n")
                    log_fh.close()
                return

            if delay_sec > 0:
                time.sleep(delay_sec)

        if log_fh:
            log_fh.close()

        final = self._check_retry_counter(conn)
        print_info(f"Nenhum PIN encontrado no range. {tested} testados.")
        if final is not None and final >= 0:
            print_info(f"Tentativas restantes: {final}")

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
        """Execute ADM brute-force in the specified mode."""
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
            if mode == "brute_common":
                print_info("[dry-run] PINs que seriam testados:")
                for label, pin_bytes in COMMON_ADM_PINS:
                    print_info(f"  {_hex(pin_bytes)} ({label})")
            return

        conn = self._get_connection()
        if conn is None:
            return

        try:
            dispatch = {
                "check_remaining": lambda: self._mode_check_remaining(conn),
                "verify_single": lambda: self._mode_verify_single(conn),
                "brute_common": lambda: self._mode_brute_common(conn),
                "brute_wordlist": lambda: self._mode_brute_wordlist(conn),
                "brute_sequential": lambda: self._mode_brute_sequential(conn),
            }
            handler = dispatch.get(mode)
            if handler:
                handler()
        finally:
            try:
                conn.disconnect()
            except Exception:
                pass
