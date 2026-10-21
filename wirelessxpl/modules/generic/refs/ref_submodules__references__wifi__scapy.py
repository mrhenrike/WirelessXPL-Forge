"""Reference index — verbatim vendor from `submodules/references/wifi/scapy`."""
from pathlib import Path


__info__ = {
    "name": "Reference index — verbatim vendor from `submodules/references/wifi/scapy`",
    "description": (
        "Reference index — verbatim vendor from `submodules/references/wifi/scapy`"
    ),
    "authors": ("Andre Henrique (@mrhenrike)",),
    "devices": ("wireless",),
}

VENDOR_ROOT = Path(__file__).resolve().parents[2] / "wirelessxpl/resources/vendor/submodules__references__wifi__scapy"
SOURCE_REPO = "submodules/references/wifi/scapy"


def run(**kwargs) -> None:
    """Execute the module (standalone entry point)."""
    print(f"[*] {__info__['name']} starting...")
    print("[*] Module execution: implement target-specific logic.")
