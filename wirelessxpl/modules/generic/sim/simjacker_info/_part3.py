        print_info("  2. S@T Browser Removal")
        print_info("     - OTA update to remove/disable S@T Browser applet")
        print_info("     - Replace SIM cards with S@T-free versions")
        print_info("     - Disable unused OTA services in subscriber profile")
        print_info("")
        print_info("  3. OTA Security Hardening")
        print_info("     - Enforce minimum SPI security level (CC + Encryption)")
        print_info("     - Use AES-128/256 for KIC/KID (not DES/3DES)")
        print_info("     - Enable counter-based replay protection")
        print_info("     - Restrict OTA access to authorized platforms only")
        print_info("")
        print_info("  4. SIM Profile Audit")
        print_info("     - Inventory all deployed SIM applets")
        print_info("     - Remove unused/legacy applets (S@T, WIB, etc.)")
        print_info("     - Regular security assessment of SIM platform")
        print_info("")
        print_info("USER-SIDE MITIGATIONS:")
        print_info("  1. SnoopSnitch (Android)")
        print_info("     - Open-source app that detects binary SMS attacks")
        print_info("     - Requires rooted device with Qualcomm baseband")
        print_info("     - GitHub: https://github.com/SRLabs/SnoopSnitch")
        print_info("")
        print_info("  2. SIM Tester (SRLabs)")
        print_info("     - PC/SC-based SIM vulnerability scanner")
        print_info("     - Tests for S@T, WIB, OTA security levels")
        print_info("     - GitHub: https://opensource.srlabs.de/projects/simtester")
        print_info("")
        print_info("  3. SIM Replacement")
        print_info("     - Request new SIM from operator")
        print_info("     - Ask operator to confirm S@T/WIB status")
        print_info("     - Prefer eSIM where available (newer security)")
        print_info("")
        print_info("  4. General Awareness")
        print_info("     - Monitor for unexpected SMS activity")
        print_info("     - Watch for unknown STK menu items")
        print_info("     - Report suspicious behavior to operator")


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
        op = str(self.mode).strip().lower()

        # Info-only modes (no SIM interaction)
        info_modes = {
            "info": self._info,
            "simjacker_detail": self._simjacker_detail,
            "wibattack_detail": self._wibattack_detail,
            "stk_attacks": self._stk_attacks,
            "ota_sms_analysis": self._ota_sms_analysis,
            "cve_database": self._cve_database,
            "mitigation": self._mitigation,
        }
        handler = info_modes.get(op)
        if handler:
            handler()
            return

        # Interactive modes require scope confirmation
        if not bool(self.i_know_scope):
            print_error(
                "Set i_know_scope = true to confirm authorized lab and SIM ownership."
            )
            return

        require_authorised_lab()
        require_sim_ownership()

        active_modes = {
            "detect_vulnerable": self._detect_vulnerable,
            "scan_stk_apps": self._scan_stk_apps,
        }
        handler = active_modes.get(op)
        if handler:
            handler()
        else:
            print_error(
                f"Unknown mode: {op}. Valid: info, simjacker_detail, wibattack_detail, "
                "stk_attacks, ota_sms_analysis, detect_vulnerable, scan_stk_apps, "
                "cve_database, mitigation"
            )
