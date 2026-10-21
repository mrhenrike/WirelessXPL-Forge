"""Reference index — verbatim vendor from `submodules/references/wifi/bettercap`."""
from pathlib import Path


__info__ = {
    "name": "Reference index — verbatim vendor from `submodules/references/wifi/bettercap`",
    "description": (
        "Reference index — verbatim vendor from `submodules/references/wifi/bettercap`"
    ),
    "authors": ("Andre Henrique (@mrhenrike)",),
    "devices": ("wireless",),
}

VENDOR_ROOT = Path(__file__).resolve().parents[2] / "wirelessxpl/resources/vendor/submodules__references__wifi__bettercap"
SOURCE_REPO = "submodules/references/wifi/bettercap"


def run(**kwargs) -> None:
    """Execute the module (standalone entry point)."""
    print(f"[*] {__info__['name']} starting...")
    print("[*] Module execution: implement target-specific logic.")
