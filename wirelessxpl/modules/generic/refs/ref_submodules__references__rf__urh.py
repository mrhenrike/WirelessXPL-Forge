"""Reference index — verbatim vendor from `submodules/references/rf/urh`."""
from pathlib import Path


__info__ = {
    "name": "Reference index — verbatim vendor from `submodules/references/rf/urh`",
    "description": (
        "Reference index — verbatim vendor from `submodules/references/rf/urh`"
    ),
    "authors": ("Andre Henrique (@mrhenrike)",),
    "devices": ("wireless",),
}

VENDOR_ROOT = Path(__file__).resolve().parents[2] / "wirelessxpl/resources/vendor/submodules__references__rf__urh"
SOURCE_REPO = "submodules/references/rf/urh"


def run(**kwargs) -> None:
    """Execute the module (standalone entry point)."""
    print(f"[*] {__info__['name']} starting...")
    print("[*] Module execution: implement target-specific logic.")
