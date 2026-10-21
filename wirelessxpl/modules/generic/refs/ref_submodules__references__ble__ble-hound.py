"""Reference index — verbatim vendor from `submodules/references/ble/BLE-Hound`."""
from pathlib import Path


__info__ = {
    "name": "Reference index — verbatim vendor from `submodules/references/ble/BLE-Hound`",
    "description": (
        "Reference index — verbatim vendor from `submodules/references/ble/BLE-Hound`"
    ),
    "authors": ("Andre Henrique (@mrhenrike)",),
    "devices": ("wireless",),
}

VENDOR_ROOT = Path(__file__).resolve().parents[2] / "wirelessxpl/resources/vendor/submodules__references__ble__ble-hound"
SOURCE_REPO = "submodules/references/ble/BLE-Hound"


def run(**kwargs) -> None:
    """Execute the module (standalone entry point)."""
    print(f"[*] {__info__['name']} starting...")
    print("[*] Module execution: implement target-specific logic.")
