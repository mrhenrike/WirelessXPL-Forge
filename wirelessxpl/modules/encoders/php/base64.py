from base64 import b64encode
from wirelessxpl.core.exploit.encoders import BaseEncoder
from wirelessxpl.core.exploit.payloads import Architectures


class Encoder(BaseEncoder):
    __info__ = {
        "name": "PHP Base64 Encoder",
        "description": "Module encodes PHP payload to Base64 format.",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>",  # wirelessxpl module
        ),
    }

    architecture = Architectures.PHP

    def encode(self, payload):
        encoded_payload = str(b64encode(bytes(payload, "utf-8")), "utf-8")
        return "eval(base64_decode('{}'));".format(encoded_payload)
