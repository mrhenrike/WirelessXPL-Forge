            "profile_info": self._profile_info,
            "check_ts48": self._check_ts48,
            "euicc_info": self._euicc_info,
            "certificate_check": self._certificate_check,
            "smdpp_test": self._smdpp_test,
        }
        handler = dispatch.get(op)
        if handler:
            handler()
        else:
            print_error(
                f"Unknown mode: {op}. Valid: info, read_eid, list_profiles, "
                "profile_info, check_ts48, euicc_info, certificate_check, smdpp_test"
            )
