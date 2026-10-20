        if not ok:
            return ""
        ok, data = self._read_record(conn, 1)
        if not ok or not data:
            return ""
        if len(data) < 14:
            return ""
        num_len_pos = len(data) - 14
        num_len = data[num_len_pos]
        if num_len == 0xFF or num_len < 1:
            return ""
        ton_npi = data[num_len_pos + 1]
        prefix = "+" if (ton_npi & 0x70) == 0x10 else ""
        number_bcd = data[num_len_pos + 2: num_len_pos + 2 + num_len - 1]
        return prefix + _decode_dialing_number(number_bcd)

    def _read_spn(self, conn: Any) -> str:
        ok, _ = self._select_file(conn, DF_GSM)
        if not ok:
            return ""
        ok, _ = self._select_file(conn, EF_SPN)
        if not ok:
            return ""
        ok, data = self._read_binary(conn, 17)
        if not ok or not data:
            return ""
        return _decode_alpha_id(data[1:])

    def _read_sst(self, conn: Any) -> list[int]:
        ok, _ = self._select_file(conn, DF_GSM)
        if not ok:
            return []
        ok, _ = self._select_file(conn, EF_SST)
        if not ok:
            return []
        ok, data = self._read_binary(conn, 0)
        if not ok:
            return []
        return data

    def _read_sms_records(self, conn: Any) -> list[dict[str, Any]]:
        ok, _ = self._select_file(conn, DF_TELECOM)
        if not ok:
            ok, _ = self._select_file(conn, DF_GSM)
        ok, _ = self._select_file(conn, EF_SMS)
        if not ok:
            print_error("EF_SMS nao encontrado.")
            return []

        messages = []
        max_rec = int(self.max_records)
        for rec_num in range(1, max_rec + 1):
            ok, data = self._read_record(conn, rec_num)
            if not ok:
                break
            if not data or data[0] == 0xFF or data[0] == 0x00:
                continue

            status_map = {0x01: "received_read", 0x03: "received_unread",
                         0x05: "sent", 0x07: "sent_unsent"}
            status = status_map.get(data[0], f"unknown(0x{data[0]:02X})")
            messages.append({
                "record": rec_num,
                "status": status,
                "raw_hex": _hex(data[:32]),
            })
        return messages

    def _read_phonebook(self, conn: Any) -> list[dict[str, str]]:
        ok, _ = self._select_file(conn, DF_TELECOM)
        if not ok:
            ok, _ = self._select_file(conn, DF_GSM)
        ok, _ = self._select_file(conn, EF_ADN)
        if not ok:
            print_error("EF_ADN nao encontrado.")
            return []

        entries = []
        max_rec = int(self.max_records)
        for rec_num in range(1, max_rec + 1):
            ok, data = self._read_record(conn, rec_num)
            if not ok:
                break
            if not data or all(b == 0xFF for b in data):
                continue
            if len(data) < 14:
                continue

            alpha_len = len(data) - 14
            alpha = _decode_alpha_id(data[:alpha_len]) if alpha_len > 0 else ""
            num_len = data[alpha_len]
            if num_len == 0xFF or num_len < 1:
                continue
            ton_npi = data[alpha_len + 1]
            prefix = "+" if (ton_npi & 0x70) == 0x10 else ""
            number_bcd = data[alpha_len + 2: alpha_len + 2 + num_len - 1]
            number = prefix + _decode_dialing_number(number_bcd)

            if alpha or number:
                entries.append({"name": alpha, "number": number, "record": str(rec_num)})
        return entries

    # ------------------------------------------------------------------
    # Mode handlers
    # ------------------------------------------------------------------

    def _mode_info(self) -> None:
        print_info("pySim SIM Card Reader / Decoder")
        print_info("=" * 45)
        print_info("")
        print_info("Capacidades:")
        print_info("  Leitura de IMSI, ICCID, MSISDN, SPN, SST")
        print_info("  Leitura de SMS armazenados (EF_SMS)")
        print_info("  Leitura de agenda telefonica (EF_ADN)")
        print_info("  Decodificacao de ATR (Answer To Reset)")
        print_info("  Exportacao completa para JSON")
        print_info("  Analise de tabelas de servico (SST/UST)")
        print_info("  Informacoes eUICC/eSIM (se suportado)")
        print_info("")
        print_info("Dependencias:")
        print_info("  pyscard: {}".format("SIM" if HAS_PYSCARD else "NAO - pip install pyscard"))
        print_info("  pySim:   {}".format("SIM" if HAS_PYSIM else "NAO - pip install pySim"))
        print_info("")

        if HAS_PYSCARD:
            try:
                available = list_readers()
                if available:
                    print_info("Leitores PC/SC detectados:")
                    for i, r in enumerate(available):
                        print_info(f"  [{i}] {r}")
                else:
                    print_info("Nenhum leitor PC/SC detectado.")
            except Exception as exc:
                print_error(f"Erro ao listar leitores: {exc}")
        print_info("")
        print_info("Modos disponiveis:")
        for m in sorted(self._VALID_MODES):
            print_info(f"  {m}")

    def _mode_read_all(self, conn: Any) -> dict[str, Any]:
        result: dict[str, Any] = {}
        print_status("Lendo ICCID...")
        iccid = self._read_iccid(conn)
        if iccid:
            print_success(f"ICCID: {iccid}")
            result["iccid"] = iccid
        else:
            print_info("ICCID nao disponivel.")

        print_status("Lendo IMSI...")
        imsi = self._read_imsi(conn)
        if imsi:
            print_success(f"IMSI: {imsi}")
            result["imsi"] = imsi
        else:
            print_info("IMSI nao disponivel (pode necessitar PIN).")

        print_status("Lendo MSISDN...")
        msisdn = self._read_msisdn(conn)
        if msisdn:
            print_success(f"MSISDN: {msisdn}")
            result["msisdn"] = msisdn
        else:
            print_info("MSISDN nao disponivel.")

        print_status("Lendo SPN...")
        spn = self._read_spn(conn)
        if spn:
            print_success(f"SPN: {spn}")
            result["spn"] = spn

        print_status("Lendo SST...")
        sst = self._read_sst(conn)
        if sst:
            result["sst_raw"] = _hex(sst)
            print_info(f"SST: {_hex(sst)}")

        print_status("Lendo SMS...")
        sms = self._read_sms_records(conn)
        if sms:
            result["sms_count"] = len(sms)
            result["sms"] = sms
            print_info(f"SMS encontrados: {len(sms)}")

        print_status("Lendo agenda telefonica (ADN)...")
        phonebook = self._read_phonebook(conn)
        if phonebook:
            result["phonebook_count"] = len(phonebook)
            result["phonebook"] = phonebook
            print_info(f"Contatos encontrados: {len(phonebook)}")

        return result

    def _mode_read_imsi(self, conn: Any) -> None:
        imsi = self._read_imsi(conn)
        if imsi:
            print_success(f"IMSI: {imsi}")
            if len(imsi) >= 6:
                print_info(f"MCC: {imsi[:3]}")
                print_info(f"MNC: {imsi[3:5] if len(imsi) > 5 else imsi[3:]}")
                print_info("MSIN: {}".format(imsi[5:] if len(imsi) > 5 else ""))
        else:
            print_error("Falha ao ler IMSI. Verifique se o PIN foi informado.")

    def _mode_read_iccid(self, conn: Any) -> None:
        iccid = self._read_iccid(conn)
        if iccid:
            print_success(f"ICCID: {iccid}")
            if len(iccid) >= 7:
                print_info(f"Issuer: {iccid[:7]}")
        else:
            print_error("Falha ao ler ICCID.")

    def _mode_read_sms(self, conn: Any) -> None:
        sms = self._read_sms_records(conn)
        if not sms:
            print_info("Nenhum SMS encontrado no cartao.")
            return
        print_success(f"{len(sms)} SMS encontrados:")
        for msg in sms:
            print_info(
                "  Registro {}: status={}, dados={}".format(
                    msg["record"], msg["status"], msg["raw_hex"],
                )
            )

    def _mode_read_phonebook(self, conn: Any) -> None:
        entries = self._read_phonebook(conn)
        if not entries:
            print_info("Nenhum contato encontrado na agenda.")
            return
        print_success(f"{len(entries)} contatos encontrados:")
        for entry in entries:
            print_info(
                "  [{}] {} - {}".format(entry["record"], entry["name"], entry["number"])
            )

    def _mode_decode_atr(self, conn: Any) -> None:
        try:
            atr = conn.getATR()
        except Exception as exc:
            print_error(f"Falha ao obter ATR: {exc}")
            return

        if not atr:
            print_error("ATR vazio.")
            return

        print_success(f"ATR: {_hex(atr)}")
        parsed = _decode_atr_bytes(atr)
        print_info("  Convencao: {}".format(parsed["ts"]))
        print_info("  T0: {}".format(parsed["t0"]))
        if parsed["protocols"]:
            proto_names = [f"T={p}" for p in parsed["protocols"]]
            print_info("  Protocolos: {}".format(", ".join(proto_names)))
        if parsed.get("historical_bytes"):
            print_info("  Historical Bytes: {}".format(parsed["historical_bytes"]))
        if parsed.get("historical_ascii"):
            print_info("  Historical (ASCII): {}".format(parsed["historical_ascii"]))

    def _mode_export_json(self, conn: Any) -> None:
        out_dir = self._ensure_output_dir()
        if not out_dir:
            return

        print_status("Coletando dados do cartao para exportacao...")
        card_data = self._mode_read_all(conn)

        try:
            atr = conn.getATR()
            if atr:
                card_data["atr"] = _decode_atr_bytes(atr)
        except Exception:
            pass

        out_file = str(self.output_file).strip()
        if not out_file:
            iccid = card_data.get("iccid", "unknown")
            out_file = os.path.join(out_dir, f"sim_dump_{iccid}.json")
        elif not os.path.isabs(out_file):
            out_file = os.path.join(out_dir, out_file)

        try:
            with open(out_file, "w", encoding="utf-8") as fh:
                json.dump(card_data, fh, indent=2, ensure_ascii=False)
            print_success(f"Dados exportados para: {out_file}")
        except OSError as exc:
            print_error(f"Falha ao gravar arquivo: {exc}")

    def _mode_check_services(self, conn: Any) -> None:
        sst_data = self._read_sst(conn)
        if not sst_data:
            print_error("Falha ao ler tabela de servicos (SST/UST).")
            return

        print_success(f"Tabela de servicos (raw): {_hex(sst_data)}")

        sst_services = {
            1: "CHV1 disable", 2: "Abbreviated Dialling Numbers (ADN)",
            3: "Fixed Dialling Numbers (FDN)", 4: "Short Message Storage (SMS)",
            5: "Advice of Charge (AoC)", 6: "Capability Configuration Parameters (CCP2)",
            7: "PLMN selector", 8: "RFU",
            9: "MSISDN", 10: "Extension 1",
            11: "Extension 2", 12: "SMS Parameters (SMSP)",
            13: "Last Number Dialled (LND)", 14: "Cell Broadcast Message Identifier",
            15: "Group Identifier Level 1", 16: "Group Identifier Level 2",
            17: "Service Provider Name (SPN)", 18: "Service Dialling Numbers (SDN)",
        }

        print_info("Servicos habilitados:")
        for byte_idx, byte_val in enumerate(sst_data):
            for bit_pos in range(4):
                svc_num = byte_idx * 4 + bit_pos + 1
                allocated = (byte_val >> (bit_pos * 2)) & 0x01
                activated = (byte_val >> (bit_pos * 2 + 1)) & 0x01
                if allocated:
                    svc_name = sst_services.get(svc_num, f"Service {svc_num}")
                    status = "ativo" if activated else "alocado"
                    print_info(f"  [{svc_num:02d}] {svc_name} ({status})")

    def _mode_esim_info(self, conn: Any) -> None:
        print_status("Tentando acessar informacoes eUICC/eSIM...")

        # ISD-R AID (GSMA SGP.02)
        isd_r_aid = [0xA0, 0x00, 0x00, 0x05, 0x59, 0x10, 0x10, 0xFF,
                     0xFF, 0xFF, 0xFF, 0x89, 0x00, 0x00, 0x01, 0x00]
        select_apdu = [0x00, 0xA4, 0x04, 0x00, len(isd_r_aid)] + isd_r_aid
        data, sw1, sw2 = self._send_apdu(conn, select_apdu)

        if (sw1, sw2) == SW_OK or sw1 == 0x61:
            print_success("eUICC ISD-R detectado.")
            if data:
                print_info(f"Resposta: {_hex(data)}")

            # EID retrieval via GET DATA
            get_eid = [0x80, 0xCA, 0xBF, 0x3E, 0x00]
            data2, sw1_2, sw2_2 = self._send_apdu(conn, get_eid)
            if (sw1_2, sw2_2) == SW_OK and data2:
                print_info(f"EID data: {_hex(data2)}")
            elif sw1_2 == 0x6C and sw2_2 > 0:
                get_eid[4] = sw2_2
                data2, sw1_2, sw2_2 = self._send_apdu(conn, get_eid)
                if (sw1_2, sw2_2) == SW_OK and data2:
                    print_info(f"EID data: {_hex(data2)}")
        else:
            print_info(
                f"ISD-R nao encontrado (SW={sw1:02X}{sw2:02X}). "
                "O cartao pode nao ser eUICC."
            )

        # ECASD AID
        ecasd_aid = [0xA0, 0x00, 0x00, 0x05, 0x59, 0x10, 0x10, 0xFF,
                     0xFF, 0xFF, 0xFF, 0x89, 0x00, 0x00, 0x02, 0x00]
        select_ecasd = [0x00, 0xA4, 0x04, 0x00, len(ecasd_aid)] + ecasd_aid
        data3, sw1_3, sw2_3 = self._send_apdu(conn, select_ecasd)
        if (sw1_3, sw2_3) == SW_OK or sw1_3 == 0x61:
            print_info("ECASD detectado.")
            if data3:
                print_info(f"ECASD resposta: {_hex(data3)}")

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
        """Execute SIM card reader in the specified mode."""
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
                "pyscard e necessario para interagir com o cartao. "
                "Instale com: pip install pyscard"
            )
            return

        if bool(self.dry_run):
            print_info(f"[dry-run] Modo: {mode}")
            print_info(f"[dry-run] Leitor: {int(self.reader_index)}")
            print_info("[dry-run] Nenhuma operacao real sera executada.")
            return

        conn = self._get_connection()
        if conn is None:
            return

        try:
            if not self._verify_pin(conn):
                return

            dispatch = {
                "read_all": lambda: self._mode_read_all(conn),
                "read_imsi": lambda: self._mode_read_imsi(conn),
                "read_iccid": lambda: self._mode_read_iccid(conn),
                "read_sms": lambda: self._mode_read_sms(conn),
                "read_phonebook": lambda: self._mode_read_phonebook(conn),
                "decode_atr": lambda: self._mode_decode_atr(conn),
                "export_json": lambda: self._mode_export_json(conn),
                "check_services": lambda: self._mode_check_services(conn),
                "esim_info": lambda: self._mode_esim_info(conn),
            }
            handler = dispatch.get(mode)
            if handler:
                handler()
        finally:
            try:
                conn.disconnect()
            except Exception:
                pass
