#!/usr/bin/env python3
"""WXF Module Validator — tests all wifi_lab modules load correctly.
Author: André Henrique (@mrhenrike) | União Geek
"""
import sys
import os

sys.path.insert(0, "/mnt/d/Projetos-SafeLabs/submodules/Uniao-Geek/WirelessXPL-Forge")
os.chdir("/mnt/d/Projetos-SafeLabs/submodules/Uniao-Geek/WirelessXPL-Forge")

MODULES = [
    ("handshake_snooper", "wirelessxpl.modules.generic.wifi_lab.handshake_snooper"),
    ("krack_attack", "wirelessxpl.modules.generic.wifi_lab.krack_attack"),
    ("fragattacks", "wirelessxpl.modules.generic.wifi_lab.fragattacks"),
    ("deauth_csa_suite", "wirelessxpl.modules.generic.wifi_lab.deauth_csa_suite"),
    ("ssid_confusion", "wirelessxpl.modules.generic.wifi_lab.ssid_confusion"),
    ("kr00k_attack", "wirelessxpl.modules.generic.wifi_lab.kr00k_attack"),
    ("wifi_sniffer", "wirelessxpl.modules.generic.wifi_lab.wifi_sniffer"),
    ("auth_flood", "wirelessxpl.modules.generic.wifi_lab.auth_flood"),
    ("deauth_multimode", "wirelessxpl.modules.generic.wifi_lab.deauth_multimode"),
    ("wpa3_attack_suite", "wirelessxpl.modules.generic.wifi_lab.wpa3_attack_suite"),
    ("beacon_flood_advanced", "wirelessxpl.modules.generic.wifi_lab.beacon_flood_advanced"),
    ("selective_jammer", "wirelessxpl.modules.generic.wifi_lab.selective_jammer"),
    ("replay_attack", "wirelessxpl.modules.generic.wifi_lab.replay_attack"),
    ("evil_twin_advanced", "wirelessxpl.modules.generic.wifi_lab.evil_twin_advanced"),
    ("wps_multimode", "wirelessxpl.modules.generic.wifi_lab.wps_multimode"),
    ("mfa_phishing_portal", "wirelessxpl.modules.generic.wifi_lab.mfa_phishing_portal"),
    ("karma_mana_attack", "wirelessxpl.modules.generic.wifi_lab.karma_mana_attack"),
    ("mitm_wifi_bridge", "wirelessxpl.modules.generic.wifi_lab.mitm_wifi_bridge"),
    ("transparent_proxy", "wirelessxpl.modules.generic.wifi_lab.transparent_proxy"),
    ("connectivity_portal", "wirelessxpl.modules.generic.wifi_lab.connectivity_portal"),
    ("dualband_evil_twin", "wirelessxpl.modules.generic.wifi_lab.dualband_evil_twin"),
    ("evil_qr_attack", "wirelessxpl.modules.generic.wifi_lab.evil_qr_attack"),
    ("wordlist_orchestrator", "wirelessxpl.modules.generic.wifi_lab.wordlist_orchestrator"),
    ("hashcat_gpu_orchestrator", "wirelessxpl.modules.generic.wifi_lab.hashcat_gpu_orchestrator"),
    ("pcap_wpa_handshake_validate", "wirelessxpl.modules.generic.wifi_lab.pcap_wpa_handshake_validate"),
    ("responder_wifi", "wirelessxpl.modules.generic.wifi_lab.responder_wifi"),
    ("aireplay_deauth_barrage", "wirelessxpl.modules.generic.wifi_lab.aireplay_deauth_barrage"),
]

BRIDGES = [
    ("mdk4_bridge", "wirelessxpl.modules.generic.external.mdk4_bridge"),
    ("hcx_toolchain_bridge", "wirelessxpl.modules.generic.external.hcx_toolchain_bridge"),
    ("eaphammer_bridge", "wirelessxpl.modules.generic.external.eaphammer_bridge"),
    ("reaver_bridge", "wirelessxpl.modules.generic.external.reaver_bridge"),
    ("wifite2_bridge", "wirelessxpl.modules.generic.external.wifite2_bridge"),
    ("bettercap_bridge", "wirelessxpl.modules.generic.external.bettercap_bridge"),
]

ok_count = 0
fail_count = 0

print("=" * 90)
print("  WXF MODULE VALIDATION — Wi-Fi Lab + Bridges")
print("=" * 90)

for section_name, module_list in [("NATIVE MODULES", MODULES), ("BRIDGE MODULES", BRIDGES)]:
    print(f"\n--- {section_name} ---")
    for short_name, modpath in module_list:
        try:
            mod = __import__(modpath, fromlist=["Exploit"])
            E = mod.Exploit
            info = getattr(E, "__info__", {})
            name = info.get("name", "?")
            opts = [a for a in dir(E) if hasattr(getattr(E, a, None), "description")]
            print(f"  [OK] {short_name:.<40s} {name} ({len(opts)} opts)")
            ok_count += 1
        except Exception as ex:
            err = str(ex).split("\n")[0][:60]
            print(f"  [!!] {short_name:.<40s} FAIL: {err}")
            fail_count += 1

print(f"\n{'=' * 90}")
print(f"  RESULT: {ok_count} OK / {fail_count} FAIL / {ok_count + fail_count} TOTAL")
print(f"{'=' * 90}")
