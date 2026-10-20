        _validator = HWValidator()
        _gw = PhaseGateway("SS7/SigPloit Bridge")
        _gw.phase(
            "SigPloit / SS7 toolset",
            lambda: _validator.require(Requirement.SS7_SIGPLOIT, silent=True),
            fix_hint="git clone https://github.com/SigPloiter/SigPloit",
        )
        if not _gw.run():
            return

        if not self.i_know_scope:
            print_error(
                "Set i_know_scope=True to confirm authorized lab and "
                "operator authorization for signaling access."
            )
            return
        require_authorised_lab()

        if mode not in self._VALID_MODES:
            print_error(
                "Invalid mode '{}'. Valid: {}".format(
                    mode, ", ".join(sorted(self._VALID_MODES))
                )
            )
            return

        self._exploit()

    def _exploit(self) -> None:
        """E2E SS7/Diameter/GTP attack: dispatch the selected signaling
        attack (location tracking, SMS intercept, call redirect, DoS,
        IMSI enum, GTP tunnel hijack) via SigPloit toolset."""
        mode = str(self.mode).strip().lower()
        dispatch = {
            "ss7_location": self._ss7_location,
            "ss7_intercept_sms": self._ss7_intercept_sms,
            "ss7_call_redirect": self._ss7_call_redirect,
            "ss7_dos": self._ss7_dos,
            "ss7_imsi_enum": self._ss7_imsi_enum,
            "diameter_location": self._diameter_location,
            "diameter_dos": self._diameter_dos,
            "gtp_tunnel_hijack": self._gtp_tunnel_hijack,
            "gtp_dos": self._gtp_dos,
            "scan_exposure": self._scan_exposure,
        }
        dispatch[mode]()
