"""Reference index — verbatim vendor from `submodules/references/drone/dronekit-python`."""
from pathlib import Path


__info__ = {
    "name": "Reference index — verbatim vendor from `submodules/references/drone/dronekit-python`",
    "description": (
        "Reference index — verbatim vendor from `submodules/references/drone/dronekit-python`"
    ),
    "authors": ("Andre Henrique (@mrhenrike)",),
    "devices": ("wireless",),
}

VENDOR_ROOT = Path(__file__).resolve().parents[2] / "wirelessxpl/resources/vendor/submodules__references__drone__dronekit-python"
SOURCE_REPO = "submodules/references/drone/dronekit-python"


def run(**kwargs) -> None:
    """Execute the module (standalone entry point)."""
    print(f"[*] {__info__['name']} starting...")
    print("[*] Module execution: implement target-specific logic.")
