"""Reference index — verbatim vendor from `submodules/references/rf/gr-ieee802-11`."""
from pathlib import Path


__info__ = {
    "name": "Reference index — verbatim vendor from `submodules/references/rf/gr-ieee802-11`",
    "description": (
        "Reference index — verbatim vendor from `submodules/references/rf/gr-ieee802-11`"
    ),
    "authors": ("Andre Henrique (@mrhenrike)",),
    "devices": ("wireless",),
}

VENDOR_ROOT = Path(__file__).resolve().parents[2] / "wirelessxpl/resources/vendor/submodules__references__rf__gr-ieee802-11"
SOURCE_REPO = "submodules/references/rf/gr-ieee802-11"


def run(**kwargs) -> None:
    """Execute the module (standalone entry point)."""
    print(f"[*] {__info__['name']} starting...")
    print("[*] Module execution: implement target-specific logic.")
