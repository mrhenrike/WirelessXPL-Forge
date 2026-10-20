#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
"""SIMJacker and WIBattack information, detection, and analysis module.

Comprehensive reference for SIM-based OTA attacks including SIMJacker
(CVE-2019-16256/57), WIBattack, and SIM Toolkit exploitation vectors.
Provides detection guidance, SIM vulnerability scanning for S@T Browser
and WIB applets, STK app enumeration, OTA SMS structure analysis, CVE
database, and mitigation recommendations.

Requires: pyscard (for detect/scan modes), PC/SC reader.

Version: 1.0.0
"""


import json
import logging
import os
from typing import Any, List, Optional, Tuple

from wirelessxpl.core.exploit import *
from wirelessxpl.modules.generic.sim._disclaimer import (
    require_authorised_lab,
    require_sim_ownership,
)

logger = logging.getLogger(__name__)

HAS_PYSCARD = False
try:
    from smartcard.System import readers as sc_readers
    from smartcard.util import toHexString
    HAS_PYSCARD = True
except ImportError:
    pass

# Known applet AIDs for vulnerability detection
SAT_BROWSER_AIDS = [
    "A0000000090001",
    "A0000000090002",
    "A0000000090003",
]

WIB_BROWSER_AIDS = [
    "A0000000871001",
    "A0000000871002",
]

# EF_SST (SIM Service Table) - indicates available services
EF_SST_PATH = [0x3F, 0x00, 0x7F, 0xFF, 0x6F, 0x38]

# EF_DIR - application directory
EF_DIR_PATH = [0x3F, 0x00, 0x2F, 0x00]

# GET STATUS command for card application enumeration
CMD_GET_STATUS = [0x80, 0xF2, 0x40, 0x00, 0x02, 0x4F, 0x00]

# SELECT by AID
CMD_SELECT_AID = [0x00, 0xA4, 0x04, 0x00]

# SELECT by file path
CMD_SELECT_FILE = [0x00, 0xA4, 0x08, 0x04]

# READ BINARY
CMD_READ_BINARY = [0x00, 0xB0, 0x00, 0x00]

# STK proactive command types (for reference)
STK_COMMANDS = {
    0x10: "SETUP CALL",
    0x13: "SEND SMS",
    0x14: "SEND SS",
    0x15: "SEND USSD",
    0x20: "SETUP EVENT LIST",
    0x21: "SETUP IDLE MODE TEXT",
    0x26: "PROVIDE LOCAL INFO",
    0x35: "OPEN CHANNEL",
    0x36: "CLOSE CHANNEL",
    0x37: "RECEIVE DATA",
    0x38: "SEND DATA",
    0x40: "SETUP MENU",
    0x41: "SELECT ITEM",
    0x43: "DISPLAY TEXT",
    0x44: "GET INKEY",
    0x45: "GET INPUT",
}

# CVE database entries
CVE_DATABASE = [
    {
        "id": "CVE-2019-16256",
        "name": "SIMJacker - S@T Browser Exploitation",
        "severity": "Critical",
        "cvss": "9.8",
        "year": 2019,
        "description": (
            "The S@T Browser (SIMalliance Toolbox Browser) technology on SIM cards "
            "allows remote attackers to send binary SMS messages that instruct the "
            "SIM to execute STK commands without user awareness. Exploited in the "
            "wild for targeted surveillance; can exfiltrate device location (Cell-ID) "
            "and IMEI via silent SMS responses."
        ),
        "attack_vector": "Binary SMS (OTA)",
        "impact": "Location tracking, IMEI theft, call interception setup",
        "references": [
            "https://simjacker.com/",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-16256",
        ],
    },
    {
        "id": "CVE-2019-16257",
        "name": "SIMJacker - Response Handling",
        "severity": "High",
        "cvss": "7.5",
        "year": 2019,
        "description": (
            "The S@T Browser on SIM cards does not properly validate response "
            "handling for proactive commands, allowing additional data exfiltration "
            "and command chaining beyond the initial SIMJacker attack."
        ),
        "attack_vector": "Binary SMS (OTA)",
        "impact": "Extended data exfiltration, command chaining",
        "references": [
            "https://simjacker.com/",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-16257",
        ],
    },
    {
        "id": "GSMA-CVD-2019-0026",
        "name": "WIBattack - WIB Browser Exploitation",
        "severity": "Critical",
        "cvss": "N/A (GSMA CVD)",
        "year": 2019,
        "description": (
            "The Wireless Internet Browser (WIB) on SIM cards from various vendors "
            "is vulnerable to the same class of OTA SMS attacks as SIMJacker. "
            "Allows remote execution of STK commands via crafted binary SMS targeting "
            "the WIB applet TAR (Toolkit Application Reference)."
        ),
        "attack_vector": "Binary SMS (OTA)",
        "impact": "Location tracking, call/SMS interception, USSD execution",
        "references": [
            "https://ginnoslab.org/wibattack/",
        ],
    },
    {
        "id": "CVE-2020-15802",
        "name": "BLURtooth - Cross-Transport Key Derivation",
        "severity": "Medium",
        "cvss": "5.9",
        "year": 2020,
        "description": (
            "Bluetooth BR/EDR and BLE implementations using CTKD allow an attacker "
            "to overwrite the BR/EDR encryption key via BLE pairing. Related to SIM "
            "security research as Bluetooth-connected SIM access devices may be "
            "affected."
        ),
        "attack_vector": "Bluetooth proximity",
        "impact": "Key overwrite, MITM on Bluetooth connections",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2020-15802",
            "https://francozappa.github.io/about-bias/",
        ],
    },
    {
        "id": "GSMA-TS48-2025",
        "name": "TS.48 Generic Test Profile - eUICC Rogue Applet",
        "severity": "High",
        "cvss": "N/A",
        "year": 2025,
        "description": (
            "GSMA TS.48 specification (versions <= 6.0) defines a Generic Test "
            "Profile with known test keys. Production eUICCs that accept this "
            "profile allow installation of rogue Java Card applets, enabling "
            "cross-profile data access and persistent eUICC compromise. "
            "Kigen eUICC research demonstrated practical exploitation."
        ),
        "attack_vector": "eSIM profile installation (SM-DP+)",
        "impact": "Rogue applet install, cross-profile access, eUICC compromise",
        "references": [
            "https://www.gsma.com/esim/ts-48/",
        ],
    },
    {
        "id": "JavaCard-Sandbox-2019",
        "name": "Java Card Platform Sandbox Escape",
        "severity": "High",
        "cvss": "N/A",
        "year": 2019,
        "description": (
            "Multiple Java Card platform implementations contain vulnerabilities "
            "allowing sandbox escape and unauthorized memory access. Applets can "
            "break type safety to read/write arbitrary card memory, accessing "
            "cryptographic keys and other applet data."
        ),
        "attack_vector": "Malicious Java Card applet",
        "impact": "Key extraction, sandbox escape, full card compromise",
        "references": [
            "https://www.oracle.com/java/java-card/",
        ],
    },
    {
        "id": "SS7-MAP-Protocol",
        "name": "SS7/MAP Protocol Abuse",
        "severity": "Critical",
        "cvss": "N/A (protocol-level)",
        "year": 2014,
        "description": (
            "SS7 Signaling System 7 and MAP (Mobile Application Part) protocols "
            "lack authentication, allowing any SS7-connected entity to query "
            "subscriber location, intercept calls/SMS, redirect communications, "
            "and retrieve authentication vectors. Directly related to SIM security "
            "as Ki extraction via SS7 has been demonstrated."
        ),
        "attack_vector": "SS7 network access",
        "impact": "Location tracking, call/SMS interception, Ki retrieval",
        "references": [
            "https://berlin.ccc.de/~tobias/31c3-ss7-locate-track-manipulate.pdf",
        ],
    },
]


def _ensure_tmp(base: str) -> str:
    tmp = os.path.join(base, ".tmp")
    os.makedirs(tmp, exist_ok=True)
    return tmp


