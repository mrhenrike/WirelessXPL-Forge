"""Reference index — verbatim vendor from `submodules/references/rf/gnuradio`."""
from pathlib import Path


__info__ = {
    "name": "Reference index — verbatim vendor from `submodules/references/rf/gnuradio`",
    "description": (
        "Reference index — verbatim vendor from `submodules/references/rf/gnuradio`"
    ),
    "authors": ("Andre Henrique (@mrhenrike)",),
    "devices": ("wireless",),
}

VENDOR_ROOT = Path(__file__).resolve().parents[2] / "wirelessxpl/resources/vendor/submodules__references__rf__gnuradio"
SOURCE_REPO = "submodules/references/rf/gnuradio"


def run(**kwargs) -> None:
    """Execute the module (standalone entry point)."""
    print(f"[*] {__info__['name']} starting...")
    print("[*] Module execution: implement target-specific logic.")
