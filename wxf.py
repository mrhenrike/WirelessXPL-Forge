#!/usr/bin/env python3

import logging.handlers
import platform
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from tools.venv_bootstrap import ensure_runtime

ensure_runtime(__file__)

if sys.version_info < (3, 8):
    print("WirelessXPL requires Python 3.8+ (detected: {}).".format(platform.python_version()))
    exit(1)

import os

if os.name == "posix" and os.geteuid() != 0:
    print("\033[93m[!] Not running as root — RF/monitor/BLE modules may be unavailable.\033[0m")
    print("\033[93m    Recommended: sudo python3 wxf.py\033[0m\n")

log_handler = logging.handlers.RotatingFileHandler(filename="wirelessxpl.log", maxBytes=500000)
log_formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s       %(message)s")
log_handler.setFormatter(log_formatter)
LOGGER = logging.getLogger()
LOGGER.setLevel(logging.DEBUG)
LOGGER.addHandler(log_handler)


def _load_global_config() -> None:
    try:
        from wirelessxpl.core.config import WXFConfig
        from wirelessxpl.core.exploit.printer import PrinterThread, printer_queue
        PrinterThread().start()
        cfg = WXFConfig.get()
        cfg.print_banner()
        printer_queue.join()
    except Exception as exc:
        print(f"\033[93m[!] Config init warning: {exc}\033[0m")


def _launcher(argv):
    _load_global_config()
    try:
        from wirelessxpl.interpreter import WirelessXPLInterpreter
    except ModuleNotFoundError as err:
        print("WirelessXPL bootstrap error: missing Python dependency: {}".format(err))
        print("Run: pip install -r requirements.txt")
        print("Check: wxf --doctor")
        raise SystemExit(1)

    wxf = WirelessXPLInterpreter()
    if len(argv[1:]):
        wxf.nonInteractive(argv)
    else:
        wxf.start()


def wirelessxpl(argv):
    from tools.xpl_cli import ProductInfo, bootstrap

    try:
        import tomllib
        _ver = tomllib.loads((_ROOT / "pyproject.toml").read_text())["project"]["version"]
    except Exception:
        _ver = "2.0.4"

    product = ProductInfo(
        name="WirelessXPL-Forge",
        slug="wirelessxpl-forge",
        version=_ver,
        cli_name="wxf",
        min_python=(3, 8),
        pip_package="wirelessxpl-forge",
        setup_hint="pip install -r requirements.txt",
    )
    bootstrap(argv, product, _launcher)


if __name__ == "__main__":
    try:
        wirelessxpl(sys.argv)
    except (KeyboardInterrupt, SystemExit):
        pass
