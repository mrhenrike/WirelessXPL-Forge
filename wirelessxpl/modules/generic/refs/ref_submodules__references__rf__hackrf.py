"""Reference index — verbatim vendor from `submodules/references/rf/HackRF`."""
from pathlib import Path


__info__ = {
    "name": "Reference index — verbatim vendor from `submodules/references/rf/HackRF`",
    "description": (
        "Reference index — verbatim vendor from `submodules/references/rf/HackRF`"
    ),
    "authors": ("Andre Henrique (@mrhenrike)",),
    "devices": ("wireless",),
}

VENDOR_ROOT = Path(__file__).resolve().parents[2] / "wirelessxpl/resources/vendor/submodules__references__rf__hackrf"
SOURCE_REPO = "submodules/references/rf/HackRF"


def run(**kwargs) -> None:
    """Execute the module (standalone entry point)."""
    print(f"[*] {__info__['name']} starting...")
    print("[*] Module execution: implement target-specific logic.")
