"""Reference index — verbatim vendor from `submodules/references/drone/pymavlink`."""
from pathlib import Path


__info__ = {
    "name": "Reference index — verbatim vendor from `submodules/references/drone/pymavlink`",
    "description": (
        "Reference index — verbatim vendor from `submodules/references/drone/pymavlink`"
    ),
    "authors": ("Andre Henrique (@mrhenrike)",),
    "devices": ("wireless",),
}

VENDOR_ROOT = Path(__file__).resolve().parents[2] / "wirelessxpl/resources/vendor/submodules__references__drone__pymavlink"
SOURCE_REPO = "submodules/references/drone/pymavlink"


def run(**kwargs) -> None:
    """Execute the module (standalone entry point)."""
    print(f"[*] {__info__['name']} starting...")
    print("[*] Module execution: implement target-specific logic.")
