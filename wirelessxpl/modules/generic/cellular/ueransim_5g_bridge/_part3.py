            "suci_analysis": self._suci_analysis,
            "nas_security": self._nas_security,
            "rrc_analysis": self._rrc_analysis,
        }
        dispatch[mode]()
