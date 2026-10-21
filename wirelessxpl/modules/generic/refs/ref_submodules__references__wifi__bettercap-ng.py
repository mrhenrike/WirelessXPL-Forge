"""Reference index — verbatim vendor from `submodules/references/wifi/bettercap-ng`."""
from pathlib import Path


__info__ = {
    "name": "Reference index — verbatim vendor from `submodules/references/wifi/bettercap-ng`",
    "description": (
        "Reference index — verbatim vendor from `submodules/references/wifi/bettercap-ng`"
    ),
    "authors": ("Andre Henrique (@mrhenrike)",),
    "devices": ("wireless",),
}

VENDOR_ROOT = Path(__file__).resolve().parents[2] / "wirelessxpl/resources/vendor/submodules__references__wifi__bettercap-ng"
SOURCE_REPO = "submodules/references/wifi/bettercap-ng"


def run(**kwargs) -> None:
    """Execute the module (standalone entry point)."""
    print(f"[*] {__info__['name']} starting...")
    print("[*] Module execution: implement target-specific logic.")
