#!/usr/bin/env python3

import logging.handlers
import platform
import sys
if sys.version_info.major < 3:
    print("WirelessXPL supports only Python3. Rerun application in Python3 environment.")
    exit(1)
if sys.version_info < (3, 8):
    print("WirelessXPL requires Python 3.8+ (detected: {}).".format(platform.python_version()))
    exit(1)

log_handler = logging.handlers.RotatingFileHandler(filename="wirelessxpl.log", maxBytes=500000)
log_formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s       %(message)s")
log_handler.setFormatter(log_formatter)
LOGGER = logging.getLogger()
LOGGER.setLevel(logging.DEBUG)
LOGGER.addHandler(log_handler)


def wirelessxpl(argv):
    try:
        from wirelessxpl.interpreter import WirelessXPLInterpreter
    except ModuleNotFoundError as err:
        print("WirelessXPL bootstrap error: missing Python dependency: {}".format(err))
        print("Run: python -m pip install -r requirements.txt")
        print("Optional diagnostics: python tools/env_doctor.py")
        raise SystemExit(1)

    rxf = WirelessXPLInterpreter()
    if len(argv[1:]):
        rxf.nonInteractive(argv)
    else:
        rxf.start()

if __name__ == "__main__":
    try:
        wirelessxpl(sys.argv)
    except (KeyboardInterrupt, SystemExit):
        pass
