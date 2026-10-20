"""Gate-2 coverage tests for WirelessXPL-Forge core modules."""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


# ---------------------------------------------------------------------------
# wirelessxpl.core.exploit.exceptions
# ---------------------------------------------------------------------------

def test_exception_hierarchy() -> None:
    from wirelessxpl.core.exploit.exceptions import (
        OptionValidationError,
        StopThreadPoolExecutor,
        WirelessXPLException,
    )
    assert issubclass(OptionValidationError, WirelessXPLException)
    assert issubclass(StopThreadPoolExecutor, WirelessXPLException)


def test_exception_message() -> None:
    from wirelessxpl.core.exploit.exceptions import WirelessXPLException
    e = WirelessXPLException("test msg")
    assert str(e) == "test msg"


# ---------------------------------------------------------------------------
# wirelessxpl.core.exploit.option — Option descriptors
# ---------------------------------------------------------------------------

def test_option_base() -> None:
    from wirelessxpl.core.exploit.option import OptString
    opt = OptString("val", "desc")
    assert opt.description == "desc"
    assert opt.value == "val"
    assert opt.display_value == "val"


def test_option_advanced() -> None:
    from wirelessxpl.core.exploit.option import Option
    opt = Option("", "desc", advanced=True)
    assert opt.advanced is True


def test_optip_valid_ipv4() -> None:
    from wirelessxpl.core.exploit.option import OptIP
    opt = OptIP("", "target")
    opt.__set__("", "192.168.1.1")
    assert opt.value == "192.168.1.1"


def test_optip_empty() -> None:
    from wirelessxpl.core.exploit.option import OptIP
    opt = OptIP("", "target")
    opt.__set__("", "")
    assert opt.value == ""


def test_optip_invalid() -> None:
    from wirelessxpl.core.exploit.exceptions import OptionValidationError
    from wirelessxpl.core.exploit.option import OptIP
    opt = OptIP("", "target")
    with pytest.raises(OptionValidationError):
        opt.__set__("", "invalid.address.here")


def test_optport_valid() -> None:
    from wirelessxpl.core.exploit.option import OptPort
    opt = OptPort(80, "port")
    assert opt.value == 80
    opt.__set__("", 443)
    assert opt.value == 443


def test_optport_invalid_range() -> None:
    from wirelessxpl.core.exploit.exceptions import OptionValidationError
    from wirelessxpl.core.exploit.option import OptPort
    opt = OptPort(80, "port")
    with pytest.raises(OptionValidationError):
        opt.__set__("", 0)
    with pytest.raises(OptionValidationError):
        opt.__set__("", 70000)


def test_optbool_true_values() -> None:
    from wirelessxpl.core.exploit.option import OptBool
    opt = OptBool(False, "flag")
    for v in (True, "true", "yes", "1", "on"):
        opt.__set__("", v)
        assert opt.value is True


def test_optbool_false_values() -> None:
    from wirelessxpl.core.exploit.option import OptBool
    opt = OptBool(True, "flag")
    for v in (False, "false", "no", "0", "off"):
        opt.__set__("", v)
        assert opt.value is False


def test_optbool_invalid() -> None:
    from wirelessxpl.core.exploit.exceptions import OptionValidationError
    from wirelessxpl.core.exploit.option import OptBool
    opt = OptBool(False, "flag")
    with pytest.raises(OptionValidationError):
        opt.__set__("", "maybe")


def test_optinteger_valid() -> None:
    from wirelessxpl.core.exploit.option import OptInteger
    opt = OptInteger(0, "num")
    opt.__set__("", 42)
    assert opt.value == 42


def test_optfloat_valid() -> None:
    from wirelessxpl.core.exploit.option import OptFloat
    opt = OptFloat(0.0, "timeout")
    opt.__set__("", "3.14")
    assert opt.value == pytest.approx(3.14)


def test_optstring_coercion() -> None:
    from wirelessxpl.core.exploit.option import OptString
    opt = OptString("", "data")
    opt.__set__("", 12345)
    assert opt.value == "12345"


def test_optmac_valid() -> None:
    from wirelessxpl.core.exploit.option import OptMAC
    opt = OptMAC("", "mac")
    opt.__set__("", "aa:bb:cc:dd:ee:ff")
    assert opt.value == "aa:bb:cc:dd:ee:ff"


def test_optmac_invalid() -> None:
    from wirelessxpl.core.exploit.exceptions import OptionValidationError
    from wirelessxpl.core.exploit.option import OptMAC
    opt = OptMAC("", "mac")
    with pytest.raises(OptionValidationError):
        opt.__set__("", "not-a-mac")


# ---------------------------------------------------------------------------
# wirelessxpl.core.exploit.utils — helper functions
# ---------------------------------------------------------------------------

def test_is_ipv4() -> None:
    from wirelessxpl.core.exploit.utils import is_ipv4
    assert is_ipv4("192.168.1.1") is True
    assert is_ipv4("10.0.0.1") is True
    assert is_ipv4("256.0.0.1") is False
    assert is_ipv4("abc") is False


def test_is_ipv6() -> None:
    from wirelessxpl.core.exploit.utils import is_ipv6
    assert is_ipv6("::1%lo") is True
    assert is_ipv6("abc") is False


def test_random_text_length() -> None:
    from wirelessxpl.core.exploit.utils import random_text
    txt = random_text(16)
    assert len(txt) == 16
    assert all(c.isalnum() for c in txt)


def test_random_text_custom_alphabet() -> None:
    from wirelessxpl.core.exploit.utils import random_text
    txt = random_text(10, alph="AB")
    assert all(c in "AB" for c in txt)


def test_convert_ip() -> None:
    from wirelessxpl.core.exploit.utils import convert_ip
    assert convert_ip("192.168.1.1") == bytes([192, 168, 1, 1])


def test_convert_port() -> None:
    from wirelessxpl.core.exploit.utils import convert_port
    assert convert_port(80) == b"\x00\x50"
    assert convert_port(443) == b"\x01\xbb"


def test_pythonize_path() -> None:
    from wirelessxpl.core.exploit.utils import pythonize_path
    assert pythonize_path("exploits/wifi/deauth") == "exploits.wifi.deauth"


def test_humanize_path() -> None:
    from wirelessxpl.core.exploit.utils import humanize_path
    assert humanize_path("exploits.wifi.deauth") == "exploits/wifi/deauth"


def test_detect_file_content_passwd() -> None:
    from wirelessxpl.core.exploit.utils import detect_file_content
    assert detect_file_content("root:x:0:0:root:/root:/bin/bash") is True
    assert detect_file_content("nothing here") is False


def test_version_comparison() -> None:
    from wirelessxpl.core.exploit.utils import Version
    v1 = Version("1.2.3")
    v2 = Version("1.2.4")
    v3 = Version("1.2.3")
    assert v1 < v2
    assert v2 > v1
    assert v1 == v3
    assert v1 != v2
    assert v1 <= v3
    assert v2 >= v1


def test_module_path_disabled() -> None:
    from wirelessxpl.core.exploit.utils import _module_path_disabled
    assert _module_path_disabled("cameras.hikvision.exploit") is True
    assert _module_path_disabled("wifi.deauth.exploit") is False


# ---------------------------------------------------------------------------
# wirelessxpl.core.config — timing parser
# ---------------------------------------------------------------------------

def test_parse_timing_by_number() -> None:
    from wirelessxpl.core.config import parse_timing
    p = parse_timing("3")
    assert p["name"] == "normal"
    assert p["level"] == 3


def test_parse_timing_by_name() -> None:
    from wirelessxpl.core.config import parse_timing
    p = parse_timing("aggressive")
    assert p["level"] == 4


def test_parse_timing_t_prefix() -> None:
    from wirelessxpl.core.config import parse_timing
    p = parse_timing("T5")
    assert p["name"] == "insane"


def test_parse_timing_invalid_defaults_normal() -> None:
    from wirelessxpl.core.config import parse_timing
    p = parse_timing("xyz")
    assert p["level"] == 3


def test_timing_profiles_complete() -> None:
    from wirelessxpl.core.config import TIMING_PROFILES
    assert len(TIMING_PROFILES) == 6
    for k in ("0", "1", "2", "3", "4", "5"):
        assert k in TIMING_PROFILES


def test_timing_by_name_map() -> None:
    from wirelessxpl.core.config import TIMING_BY_NAME
    assert "paranoid" in TIMING_BY_NAME
    assert "insane" in TIMING_BY_NAME


# ---------------------------------------------------------------------------
# wirelessxpl.core.config — IfaceInfo + WXFConfig (minimal)
# ---------------------------------------------------------------------------

def test_iface_info_dataclass() -> None:
    from wirelessxpl.core.config import IfaceInfo
    info = IfaceInfo(
        name="wlx001122334455",
        index=1,
        usb=True,
        monitor_cap=True,
        current_mode="managed",
        internet=False,
    )
    assert info.name == "wlx001122334455"
    assert info.usb is True


def test_is_internal_pattern() -> None:
    from wirelessxpl.core.config import _is_internal
    assert _is_internal("wlp2s0") is True
    assert _is_internal("wl0") is True
    assert _is_internal("wlx001122334455") is False


# ---------------------------------------------------------------------------
# wirelessxpl.core.glossary — search and format
# ---------------------------------------------------------------------------

def test_glossary_has_entries() -> None:
    from wirelessxpl.core.glossary import GLOSSARY
    assert len(GLOSSARY) > 50


def test_search_term_exact() -> None:
    from wirelessxpl.core.glossary import search_term
    results = search_term("ssid")
    assert len(results) >= 1
    assert results[0][0] == "ssid"


def test_search_term_partial() -> None:
    from wirelessxpl.core.glossary import search_term
    results = search_term("wpa")
    assert len(results) >= 3


def test_format_entry() -> None:
    from wirelessxpl.core.glossary import GLOSSARY, format_entry
    key = "ssid"
    entry = GLOSSARY[key]
    text = format_entry(key, entry)
    assert "SSID" in text
    assert "wifi" in text.lower() or "Categoria" in text


def test_format_compact_list() -> None:
    from wirelessxpl.core.glossary import format_compact_list
    text = format_compact_list()
    assert "TERMO" in text
    assert "termos" in text


def test_format_compact_list_filter() -> None:
    from wirelessxpl.core.glossary import format_compact_list
    text = format_compact_list(filter_category="attack")
    assert "termos" in text


def test_glossary_help() -> None:
    from wirelessxpl.core.glossary import glossary_help
    h = glossary_help()
    assert "glossary" in h
    assert "Total" in h


def test_normalize_term() -> None:
    from wirelessxpl.core.glossary import _normalize
    assert _normalize("WPA-2") == "wpa_2"
    assert _normalize(" Hello World ") == "hello_world"


# ---------------------------------------------------------------------------
# wirelessxpl.core.bt_crypto — Bluetooth SAFER+ cryptographic primitives
# ---------------------------------------------------------------------------

def test_exp45_log45_inverse() -> None:
    from wirelessxpl.core.bt_crypto import EXP_45, LOG_45
    assert len(EXP_45) == 256
    assert len(LOG_45) == 256
    for i in range(256):
        assert LOG_45[EXP_45[i]] == i


def test_add_one_xor_positions() -> None:
    from wirelessxpl.core.bt_crypto import _XOR_INDICES, _add_one
    a = bytearray(range(16))
    b = bytearray([1] * 16)
    result = _add_one(a, b)
    for i in range(16):
        if i in _XOR_INDICES:
            assert result[i] == a[i] ^ b[i]
        else:
            assert result[i] == (a[i] + b[i]) % 256


def test_add_two_complement() -> None:
    from wirelessxpl.core.bt_crypto import _XOR_INDICES, _add_two
    a = bytearray(range(16))
    b = bytearray([1] * 16)
    result = _add_two(a, b)
    for i in range(16):
        if i in _XOR_INDICES:
            assert result[i] == (a[i] + b[i]) % 256
        else:
            assert result[i] == a[i] ^ b[i]


def test_pht() -> None:
    from wirelessxpl.core.bt_crypto import _pht
    a, b = _pht(10, 20)
    assert a == (2 * 10 + 20) % 256
    assert b == (10 + 20) % 256


def test_permute_length() -> None:
    from wirelessxpl.core.bt_crypto import _permute
    inp = bytearray(range(16))
    out = _permute(inp)
    assert len(out) == 16


def test_rotate_key() -> None:
    from wirelessxpl.core.bt_crypto import _rotate_key
    k = bytearray([0b10000000])
    r = _rotate_key(k)
    assert r[0] == 0b00000100


def test_e1_sres_aco_lengths() -> None:
    from wirelessxpl.core.bt_crypto import e1
    key = bytearray(range(16))
    rand = bytearray(range(16, 32))
    btadd = bytearray([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
    sres, aco = e1(key, rand, btadd)
    assert len(sres) == 4
    assert len(aco) == 12


def test_e3_output_length() -> None:
    from wirelessxpl.core.bt_crypto import e3
    key = bytearray(range(16))
    rand = bytearray(range(16, 32))
    cof = bytearray(range(12))
    kc = e3(key, rand, cof)
    assert len(kc) == 16


def test_kc_to_kc_prime_full_entropy() -> None:
    from wirelessxpl.core.bt_crypto import Kc_to_Kc_prime
    kc = bytearray(range(16))
    result = Kc_to_Kc_prime(kc, 16)
    assert result == kc


def test_kc_to_kc_prime_reduced() -> None:
    from wirelessxpl.core.bt_crypto import Kc_to_Kc_prime
    kc = bytearray(range(16))
    result = Kc_to_Kc_prime(kc, 1)
    assert len(result) == 16
    assert result != kc


def test_kdf_full_chain() -> None:
    from wirelessxpl.core.bt_crypto import kdf
    link_key = bytearray(range(16))
    au_rand = bytearray(range(16, 32))
    en_rand = bytearray(range(32, 48))
    btadd = bytearray([0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
    kc_prime = kdf(link_key, au_rand, en_rand, btadd, entropy=7)
    assert len(kc_prime) == 16


# ---------------------------------------------------------------------------
# wirelessxpl.core.pool — importability
# ---------------------------------------------------------------------------

def test_pool_importable() -> None:
    import wirelessxpl.core.pool as pool
    assert hasattr(pool, "__file__")
