"""Reference index — verbatim vendor from `submodules/references/cellular/srsLTE`."""
from pathlib import Path


__info__ = {
    "name": "Reference index — verbatim vendor from `submodules/references/cellular/srsLTE`",
    "description": (
        "Reference index — verbatim vendor from `submodules/references/cellular/srsLTE`"
    ),
    "authors": ("Andre Henrique (@mrhenrike)",),
    "devices": ("wireless",),
}

VENDOR_ROOT = Path(__file__).resolve().parents[2] / "wirelessxpl/resources/vendor/submodules__references__cellular__srslte"
SOURCE_REPO = "submodules/references/cellular/srsLTE"


def run(**kwargs) -> None:
    """Execute the module (standalone entry point)."""
    print(f"[*] {__info__['name']} starting...")
    print("[*] Module execution: implement target-specific logic.")
