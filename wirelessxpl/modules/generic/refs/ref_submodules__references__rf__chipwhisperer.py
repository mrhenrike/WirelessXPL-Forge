"""Reference index — verbatim vendor from `submodules/references/rf/chipwhisperer`."""
from pathlib import Path


__info__ = {
    "name": "Reference index — verbatim vendor from `submodules/references/rf/chipwhisperer`",
    "description": (
        "Reference index — verbatim vendor from `submodules/references/rf/chipwhisperer`"
    ),
    "authors": ("Andre Henrique (@mrhenrike)",),
    "devices": ("wireless",),
}

VENDOR_ROOT = Path(__file__).resolve().parents[2] / "wirelessxpl/resources/vendor/submodules__references__rf__chipwhisperer"
SOURCE_REPO = "submodules/references/rf/chipwhisperer"


def run(**kwargs) -> None:
    """Execute the module (standalone entry point)."""
    print(f"[*] {__info__['name']} starting...")
    print("[*] Module execution: implement target-specific logic.")
