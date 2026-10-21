"""Reference index — verbatim vendor from `submodules/references/rf/flipperzero-firmware`."""
from pathlib import Path


__info__ = {
    "name": "Reference index — verbatim vendor from `submodules/references/rf/flipperzero-firmware`",
    "description": (
        "Reference index — verbatim vendor from `submodules/references/rf/flipperzero-firmware`"
    ),
    "authors": ("Andre Henrique (@mrhenrike)",),
    "devices": ("wireless",),
}

VENDOR_ROOT = Path(__file__).resolve().parents[2] / "wirelessxpl/resources/vendor/submodules__references__rf__flipperzero-firmware"
SOURCE_REPO = "submodules/references/rf/flipperzero-firmware"


def run(**kwargs) -> None:
    """Execute the module (standalone entry point)."""
    print(f"[*] {__info__['name']} starting...")
    print("[*] Module execution: implement target-specific logic.")
