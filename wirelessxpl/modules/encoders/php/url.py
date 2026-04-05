from urllib.parse import quote

from wirelessxpl.core.exploit.encoders import BaseEncoder
from wirelessxpl.core.exploit.payloads import Architectures


class Encoder(BaseEncoder):
    __info__ = {
        "name": "PHP URL Encoder",
        "description": "Module encodes PHP payload to URL-encoded format.",
        "authors": (
            "André Henrique (@mrhenrike) | União Geek",  # WirelessXPL-Forge encoder
        ),
    }

    architecture = Architectures.PHP

    def encode(self, payload):
        encoded_payload = quote(payload, safe="")
        return "eval(urldecode('{}'));".format(encoded_payload)
