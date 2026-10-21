"""Reference index — verbatim vendor from `submodules/references/rf/gps-sdr-sim`."""
from pathlib import Path


__info__ = {
    "name": "Reference index — verbatim vendor from `submodules/references/rf/gps-sdr-sim`",
    "description": (
        "Reference index — verbatim vendor from `submodules/references/rf/gps-sdr-sim`"
    ),
    "authors": ("Andre Henrique (@mrhenrike)",),
    "devices": ("wireless",),
}

VENDOR_ROOT = Path(__file__).resolve().parents[2] / "wirelessxpl/resources/vendor/submodules__references__rf__gps-sdr-sim"
SOURCE_REPO = "submodules/references/rf/gps-sdr-sim"


def run(**kwargs) -> None:
    """Execute the module (standalone entry point)."""
    print(f"[*] {__info__['name']} starting...")
    print("[*] Module execution: implement target-specific logic.")
