"""Reference index — verbatim vendor from `submodules/references/cellular/gr-gsm`."""
from pathlib import Path


__info__ = {
    "name": "Reference index — verbatim vendor from `submodules/references/cellular/gr-gsm`",
    "description": (
        "Reference index — verbatim vendor from `submodules/references/cellular/gr-gsm`"
    ),
    "authors": ("Andre Henrique (@mrhenrike)",),
    "devices": ("wireless",),
}

VENDOR_ROOT = Path(__file__).resolve().parents[2] / "wirelessxpl/resources/vendor/submodules__references__cellular__gr-gsm"
SOURCE_REPO = "submodules/references/cellular/gr-gsm"


def run(**kwargs) -> None:
    """Execute the module (standalone entry point)."""
    print(f"[*] {__info__['name']} starting...")
    print("[*] Module execution: implement target-specific logic.")
