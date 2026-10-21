"""Reference index — verbatim vendor from `submodules/references/rf/rtl-sdr`."""
from pathlib import Path


__info__ = {
    "name": "Reference index — verbatim vendor from `submodules/references/rf/rtl-sdr`",
    "description": (
        "Reference index — verbatim vendor from `submodules/references/rf/rtl-sdr`"
    ),
    "authors": ("Andre Henrique (@mrhenrike)",),
    "devices": ("wireless",),
}

VENDOR_ROOT = Path(__file__).resolve().parents[2] / "wirelessxpl/resources/vendor/submodules__references__rf__rtl-sdr"
SOURCE_REPO = "submodules/references/rf/rtl-sdr"


def run(**kwargs) -> None:
    """Execute the module (standalone entry point)."""
    print(f"[*] {__info__['name']} starting...")
    print("[*] Module execution: implement target-specific logic.")
