"""Reference index — verbatim vendor from `submodules/references/cellular/srsRAN-4G`."""
from pathlib import Path


__info__ = {
    "name": "Reference index — verbatim vendor from `submodules/references/cellular/srsRAN-4G`",
    "description": (
        "Reference index — verbatim vendor from `submodules/references/cellular/srsRAN-4G`"
    ),
    "authors": ("Andre Henrique (@mrhenrike)",),
    "devices": ("wireless",),
}

VENDOR_ROOT = Path(__file__).resolve().parents[2] / "wirelessxpl/resources/vendor/submodules__references__cellular__srsran-4g"
SOURCE_REPO = "submodules/references/cellular/srsRAN-4G"


def run(**kwargs) -> None:
    """Execute the module (standalone entry point)."""
    print(f"[*] {__info__['name']} starting...")
    print("[*] Module execution: implement target-specific logic.")
