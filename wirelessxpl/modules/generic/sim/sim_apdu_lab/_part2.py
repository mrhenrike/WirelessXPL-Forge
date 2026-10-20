class Exploit(Exploit):
    """Interactive APDU command laboratory for SIM/USIM cards."""

    __info__ = {
        "name": "SIM APDU Lab",
        "description": (
            "Interactive APDU command laboratory for SIM/USIM cards. "
            "Send arbitrary commands, execute scripts, enumerate files, "
            "and perform PIN verification for security research. "
            "Requires PC/SC reader and pyscard library."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "ISO/IEC 7816-4 (Interindustry commands for interchange)",
            "3GPP TS 11.11 (SIM specification)",
            "3GPP TS 31.102 (USIM application)",
            "ETSI TS 102.221 (UICC-Terminal interface)",
        ),
        "devices": ("SIM", "USIM", "ISIM", "UICC"),
    }

    mode = OptString(
        "info",
        "Modo: info | send | script | select | read_binary | read_record | "
        "update_binary | verify_pin | get_response | status | enumerate_files",
    )
    apdu_hex = OptString("", "Comando APDU em hex (ex.: 00A40000022FE2)")
    file_id = OptString("", "File ID em hex para SELECT (ex.: 2FE2, 7F20)")
    record_number = OptInteger(1, "Numero do registro para READ/UPDATE RECORD")
    pin_type = OptString("PIN1", "Tipo de PIN: PIN1, PIN2, ADM")
    pin_value = OptString("", "Valor do PIN/ADM (digitos ou hex para ADM)")
    script_file = OptString("", "Caminho do arquivo de script APDU")
    reader_index = OptInteger(0, "Indice do leitor PC/SC (padrao: 0)")
    output_dir = OptString(".tmp", "Diretorio de saida para logs")
    dry_run = OptBool(False, "Exibir operacoes sem executar")
    i_know_scope = OptBool(False, "Confirm authorized lab environment and SIM ownership")

    _VALID_MODES = frozenset({
        "info", "send", "script", "select", "read_binary", "read_record",
        "update_binary", "verify_pin", "get_response", "status",
        "enumerate_files",
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
        """Transmit APDU and return (data, sw1, sw2)."""
        data, sw1, sw2 = conn.transmit(apdu)
        return data, sw1, sw2

    def _send_and_display(self, conn: Any, apdu: list[int], label: str = "") -> tuple[list[int], int, int]:
        """Send APDU, display command/response, and return result."""
        prefix = f"[{label}] " if label else ""
        print_info(f"{prefix}>> {_hex(apdu)}")

        data, sw1, sw2 = self._send_apdu(conn, apdu)

        sw_meaning = _interpret_sw(sw1, sw2)
        if data:
            print_info(f"{prefix}<< Data: {_hex(data)}")
        print_info(f"{prefix}<< SW: {sw1:02X} {sw2:02X} ({sw_meaning})")

        if sw1 == 0x61 and sw2 > 0:
            print_status(f"{prefix}Recuperando {sw2} bytes via GET RESPONSE...")
            get_resp = [0x00, 0xC0, 0x00, 0x00, sw2]
            data2, sw1_2, sw2_2 = self._send_apdu(conn, get_resp)
            if data2:
                print_info(f"{prefix}<< GET RESPONSE Data: {_hex(data2)}")
            print_info(
                f"{prefix}<< GET RESPONSE SW: {sw1_2:02X} {sw2_2:02X} ({_interpret_sw(sw1_2, sw2_2)})"
            )
            return data2, sw1_2, sw2_2

        return data, sw1, sw2

    # ------------------------------------------------------------------
    # Mode: info
    # ------------------------------------------------------------------

    def _mode_info(self) -> None:
        print_info("SIM APDU Lab - Referencia de Comandos")
        print_info("=" * 50)
        print_info("")
        print_info("Estrutura APDU (ISO 7816-4):")
        print_info("  CLA INS P1 P2 [Lc Data] [Le]")
        print_info("  CLA  = Classe (00 para SIM/USIM)")
        print_info("  INS  = Instrucao")
        print_info("  P1   = Parametro 1")
        print_info("  P2   = Parametro 2")
        print_info("  Lc   = Tamanho dos dados de entrada")
        print_info("  Le   = Tamanho esperado da resposta")
        print_info("")
        print_info("Comandos comuns:")
        print_info("  SELECT (A4):")
        print_info("    00 A4 00 00 02 [FID]         - SELECT por FID")
        print_info("    00 A4 04 00 [Lc] [AID]       - SELECT por AID")
        print_info("  READ BINARY (B0):")
        print_info("    00 B0 [offset_hi] [offset_lo] [Le]")
        print_info("  READ RECORD (B2):")
        print_info("    00 B2 [rec_num] 04 [Le]      - Modo absoluto")
        print_info("  UPDATE BINARY (D6):")
        print_info("    00 D6 [offset_hi] [offset_lo] [Lc] [data]")
        print_info("  VERIFY (20):")
        print_info("    00 20 00 01 08 [PIN1 padded]  - Verificar PIN1")
        print_info("    00 20 00 81 08 [PIN2 padded]  - Verificar PIN2")
        print_info("    00 20 00 0A 08 [ADM1]         - Verificar ADM1")
        print_info("  GET RESPONSE (C0):")
        print_info("    00 C0 00 00 [Le]")
        print_info("  STATUS (F2):")
        print_info("    80 F2 00 00 00")
        print_info("")
        print_info("EFs comuns:")
        print_info("  2FE2 - ICCID          6F07 - IMSI")
        print_info("  6F40 - MSISDN          6F3C - SMS")
        print_info("  6F3A - ADN (agenda)    6F38 - SST")
        print_info("  6F46 - SPN             6F42 - SMSP")
        print_info("  6F30 - PLMN selector")
        print_info("")
        print_info("DFs comuns:")
        print_info("  3F00 - MF (raiz)       7F20 - DF_GSM")
        print_info("  7F10 - DF_TELECOM      7FFF - ADF_USIM")
        print_info("")
        print_info("Status Words (SW1 SW2):")
        for sw_code, meaning in sorted(SW_TABLE.items()):
            print_info(f"  {sw_code:04X} - {meaning}")
        print_info("  61xx - xx bytes disponiveis (GET RESPONSE)")
        print_info("  6Cxx - Le incorreto, correto = xx")
        print_info("  63Cx - Verificacao falhou, x tentativas restantes")
        print_info("")
        print_info("Dependencias:")
        print_info("  pyscard: {}".format("SIM" if HAS_PYSCARD else "NAO - pip install pyscard"))

        if HAS_PYSCARD:
            try:
                available = list_readers()
                if available:
                    print_info("Leitores PC/SC detectados:")
                    for i, r in enumerate(available):
                        print_info(f"  [{i}] {r}")
                else:
                    print_info("Nenhum leitor PC/SC detectado.")
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Mode: send
    # ------------------------------------------------------------------

    def _mode_send(self, conn: Any) -> None:
        hex_str = str(self.apdu_hex).strip()
        if not hex_str:
            print_error("Defina apdu_hex com o comando APDU em hexadecimal.")
            return

        apdu = _parse_hex_string(hex_str)
        if apdu is None:
            print_error("APDU invalido. Use formato hexadecimal (ex.: 00A40000022FE2).")
            return

        if len(apdu) < 4:
            print_error("APDU muito curto. Minimo: 4 bytes (CLA INS P1 P2).")
            return

        if len(apdu) > MAX_APDU_LEN:
            print_error(
                f"APDU excede tamanho maximo ({len(apdu)} > {MAX_APDU_LEN} bytes)."
            )
            return

        self._send_and_display(conn, apdu, "SEND")

    # ------------------------------------------------------------------
    # Mode: script
    # ------------------------------------------------------------------

    def _mode_script(self, conn: Any) -> None:
        script_path = str(self.script_file).strip()
        if not script_path:
            print_error("Defina script_file com o caminho do arquivo de comandos.")
            return

        if not os.path.isfile(script_path):
            print_error(f"Arquivo nao encontrado: {script_path}")
            return

        try:
            with open(script_path, encoding="utf-8") as fh:
                lines = fh.readlines()
        except OSError as exc:
            print_error(f"Falha ao ler arquivo: {exc}")
            return

        line_count = 0
        ok_count = 0
        err_count = 0

        out_dir = self._ensure_output_dir()
        log_file = None
        if out_dir:
            log_path = os.path.join(out_dir, "apdu_script_log.txt")
            try:
                log_file = open(log_path, "w", encoding="utf-8")
            except OSError:
                pass

        for line_num, raw_line in enumerate(lines, 1):
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue

            apdu = _parse_hex_string(line)
            if apdu is None:
                print_error(f"Linha {line_num}: APDU invalido: {line}")
                err_count += 1
                continue

            if len(apdu) < 4:
                print_error(f"Linha {line_num}: APDU muito curto.")
                err_count += 1
                continue

            if len(apdu) > MAX_APDU_LEN:
                print_error(f"Linha {line_num}: APDU excede limite.")
                err_count += 1
                continue

            label = f"L{line_num}"
            data, sw1, sw2 = self._send_and_display(conn, apdu, label)
            line_count += 1

            if (sw1, sw2) == (0x90, 0x00) or sw1 == 0x61:
                ok_count += 1
            else:
                err_count += 1

            if log_file:
                log_file.write(
                    "L{}: >> {} | << SW={:02X}{:02X} data={}\n".format(
                        line_num, _hex(apdu), sw1, sw2,
                        _hex(data) if data else "(vazio)",
                    )
                )

        if log_file:
            log_file.close()
            print_info(f"Log salvo em: {log_path}")

        print_info(
            f"Script concluido: {line_count} comandos, {ok_count} OK, {err_count} erros"
        )

    # ------------------------------------------------------------------
    # Mode: select
    # ------------------------------------------------------------------

    def _mode_select(self, conn: Any) -> None:
        fid_str = str(self.file_id).strip()
        if not fid_str:
            print_error("Defina file_id com o FID em hex (ex.: 2FE2, 7F20).")
            return

        fid_bytes = _parse_hex_string(fid_str)
        if fid_bytes is None or len(fid_bytes) < 2:
            print_error("file_id invalido. Use 2 ou mais bytes hex (ex.: 2FE2).")
            return

        apdu = [0x00, 0xA4, 0x00, 0x00, len(fid_bytes)] + fid_bytes
        self._send_and_display(conn, apdu, "SELECT")

    # ------------------------------------------------------------------
    # Mode: read_binary
    # ------------------------------------------------------------------

    def _mode_read_binary(self, conn: Any) -> None:
        apdu = [0x00, 0xB0, 0x00, 0x00, 0x00]
        data, sw1, sw2 = self._send_and_display(conn, apdu, "READ BINARY")
        if sw1 == 0x6C and sw2 > 0:
            print_status(f"Reenviando com Le=0x{sw2:02X}...")
            apdu[4] = sw2
            self._send_and_display(conn, apdu, "READ BINARY (retry)")

    # ------------------------------------------------------------------
    # Mode: read_record
    # ------------------------------------------------------------------

    def _mode_read_record(self, conn: Any) -> None:
        rec_num = int(self.record_number)
        if rec_num < 1 or rec_num > 254:
            print_error("record_number deve estar entre 1 e 254.")
            return

        apdu = [0x00, 0xB2, rec_num, 0x04, 0x00]
        data, sw1, sw2 = self._send_and_display(conn, apdu, "READ RECORD")
        if sw1 == 0x6C and sw2 > 0:
            print_status(f"Reenviando com Le=0x{sw2:02X}...")
            apdu[4] = sw2
            self._send_and_display(conn, apdu, "READ RECORD (retry)")

    # ------------------------------------------------------------------
    # Mode: update_binary
    # ------------------------------------------------------------------

    def _mode_update_binary(self, conn: Any) -> None:
        hex_str = str(self.apdu_hex).strip()
        if not hex_str:
            print_error(
                "Defina apdu_hex com os dados para UPDATE BINARY (hex). "
                "Antes, faca SELECT do arquivo e VERIFY do PIN/ADM."
            )
            return

        update_data = _parse_hex_string(hex_str)
        if update_data is None:
            print_error("Dados invalidos em apdu_hex.")
            return

        if len(update_data) > 255:
            print_error("Dados excedem 255 bytes para UPDATE BINARY.")
            return

        apdu = [0x00, 0xD6, 0x00, 0x00, len(update_data)] + update_data
        print_status(f"Enviando UPDATE BINARY ({len(update_data)} bytes)...")
        self._send_and_display(conn, apdu, "UPDATE BINARY")

    # ------------------------------------------------------------------
    # Mode: verify_pin
    # ------------------------------------------------------------------

    def _mode_verify_pin(self, conn: Any) -> None:
        pin_val = str(self.pin_value).strip()
        if not pin_val:
            print_error("Defina pin_value com o valor do PIN/ADM.")
            return

        pin_type_str = str(self.pin_type).strip().upper()
        p2_map = {"PIN1": 0x01, "PIN2": 0x81, "ADM": 0x0A}
        p2 = p2_map.get(pin_type_str)
        if p2 is None:
            print_error("pin_type invalido. Use: PIN1, PIN2, ADM")
            return

        if pin_type_str == "ADM":
            pin_bytes = _parse_hex_string(pin_val)
            if pin_bytes is None:
                print_error("ADM PIN invalido. Use hexadecimal (16 chars = 8 bytes).")
                return
            if len(pin_bytes) != 8:
                print_error("ADM PIN deve ter exatamente 8 bytes (16 caracteres hex).")
                return
        else:
            if not pin_val.isdigit():
                print_error("PIN deve conter apenas digitos.")
                return
            if len(pin_val) < 4 or len(pin_val) > 8:
                print_error("PIN deve ter entre 4 e 8 digitos.")
                return
            pin_bytes = [ord(c) for c in pin_val]
            while len(pin_bytes) < 8:
                pin_bytes.append(0xFF)

        # Check remaining attempts first
        check_apdu = [0x00, 0x20, 0x00, p2, 0x00]
        _, chk_sw1, chk_sw2 = self._send_apdu(conn, check_apdu)
        if chk_sw1 == 0x63 and (chk_sw2 & 0xF0) == 0xC0:
            remaining = chk_sw2 & 0x0F
            print_info(f"Tentativas restantes antes da verificacao: {remaining}")
            if remaining == 0:
                print_error("PIN bloqueado. Nenhuma tentativa restante.")
                return
            if remaining <= 2:
                print_error(
                    f"ATENCAO: apenas {remaining} tentativas restantes. "
                    "Erro ira bloquear o cartao."
                )

        apdu = [0x00, 0x20, 0x00, p2, 0x08] + pin_bytes
        # Mask PIN in display for security
        masked_apdu = [0x00, 0x20, 0x00, p2, 0x08] + [0x00] * 8
        print_info(f">> {_hex(masked_apdu)} (PIN mascarado)")

        _, sw1, sw2 = self._send_apdu(conn, apdu)
        sw_meaning = _interpret_sw(sw1, sw2)
        print_info(f"<< SW: {sw1:02X} {sw2:02X} ({sw_meaning})")

        if (sw1, sw2) == (0x90, 0x00):
            print_success(f"{pin_type_str} verificado com sucesso.")
        elif sw1 == 0x63:
            remaining = sw2 & 0x0F
            print_error(
                f"{pin_type_str} incorreto. Tentativas restantes: {remaining}"
            )

    # ------------------------------------------------------------------
    # Mode: get_response
    # ------------------------------------------------------------------

    def _mode_get_response(self, conn: Any) -> None:
        apdu = [0x00, 0xC0, 0x00, 0x00, 0x00]
        data, sw1, sw2 = self._send_and_display(conn, apdu, "GET RESPONSE")
        if sw1 == 0x6C and sw2 > 0:
            apdu[4] = sw2
            self._send_and_display(conn, apdu, "GET RESPONSE (retry)")

    # ------------------------------------------------------------------
    # Mode: status
    # ------------------------------------------------------------------

    def _mode_status(self, conn: Any) -> None:
        apdu = [0x80, 0xF2, 0x00, 0x00, 0x00]
        data, sw1, sw2 = self._send_and_display(conn, apdu, "STATUS")
        if sw1 == 0x6C and sw2 > 0:
            apdu[4] = sw2
            self._send_and_display(conn, apdu, "STATUS (retry)")

    # ------------------------------------------------------------------
    # Mode: enumerate_files
    # ------------------------------------------------------------------

    def _mode_enumerate_files(self, conn: Any) -> None:
        print_status("Enumerando EFs acessiveis sob o DF atual...")
        print_info(
            "Isso pode demorar. Testando FIDs de 0x0000 a 0xFFFF "
            "com SELECT por FID."
        )
        out_dir = self._ensure_output_dir()
        found: list[str] = []
        total = 0

        for fid_hi in range(0x00, 0x100):
            for fid_lo in range(0x00, 0x100):
                fid = [fid_hi, fid_lo]
                apdu = [0x00, 0xA4, 0x00, 0x00, 0x02, fid_hi, fid_lo]
                try:
                    data, sw1, sw2 = self._send_apdu(conn, apdu)
                except Exception:
                    continue

                total += 1
                if (sw1, sw2) == (0x90, 0x00) or sw1 == 0x61 or sw1 == 0x9F:
                    fid_str = f"{fid_hi:02X}{fid_lo:02X}"
                    found.append(fid_str)
                    print_success(f"  Encontrado: {fid_str} (SW={sw1:02X}{sw2:02X})")

                if total % 4096 == 0:
                    print_status(
                        f"  Progresso: {total}/65536 testados, {len(found)} encontrados"
                    )

        print_info("")
        print_success(f"Enumeracao concluida: {len(found)} EFs encontrados de {total} testados.")
        for fid_str in found:
            print_info(f"  {fid_str}")

        if out_dir and found:
            log_path = os.path.join(out_dir, "enumerated_files.txt")
            try:
