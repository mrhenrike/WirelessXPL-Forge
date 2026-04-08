# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""WirelessXPL-Forge entry point for `python -m wirelessxpl` and `wxf` CLI."""

from __future__ import annotations

import sys


def main() -> None:
    """Launch the WXF interactive shell."""
    from wirelessxpl.interpreter import WirelessXPLInterpreter  # type: ignore[import]

    interpreter = WirelessXPLInterpreter()
    interpreter.start()


if __name__ == "__main__":
    sys.exit(main())
