# Changelog

All notable changes to WirelessXPL-Forge are documented in this file.

---

## [1.7.0] - 2026-06-19

### Novos modulos nativos (Python/Scapy - sem bridges externos)

- `wps_engine_native.py`: WPS EAP-WSC M1-M8 state machine, Pixie Dust (CVE-2014-9527), PIN brute-force (Luhn/Zhao/OUI/sequencial), NULL PIN, WPS lock detection. Substitui: reaver, bully, pixiewps
- `flood_engine_native.py`: 8 modos mdk4 em Scapy: beacon flood, auth flood, deauth/disassoc flood, probe flood, Michael MIC shutdown, WPA downgrade, EAPOL flood, WIDS confusion. Exporta `send_deauth()` reutilizavel. Substitui: mdk3, mdk4
- `phishing_engine.py`: Evil twin + captive portal com 23 templates i18n. AP clone via hostapd config dinamico. DNS/DHCP nativos. Verificacao de handshake (estilo Fluxion). Credential store com SHA-256. Substitui: wifiphisher, fluxion
- `dns_dhcp_server.py`: Servidor DNS via dnslib (modo captive: redireciona tudo; modo spoof: dominios seletivos). Servidor DHCP via Scapy BOOTP. Substitui: dnsmasq
- `monitor_mode_manager.py`: Monitor mode via iw/iwconfig. Mata processos conflitantes. Channel hopping em thread. Context manager. Substitui: airmon-ng
- `dragonblood_suite.py` v2.0.0: DragonTimingAttack (CVE-2019-9494), DragonForce (downgrade WPA2), DragonDrain (CVE-2019-9495 DoS), DragonSlayer (CVE-2019-9499 EAP-pwd). Python nativo sem subprocess
- `core/os_guard.py`: Decorator `@requires_os(OSRequirement.LINUX_ONLY|LINUX_MAC|CROSS_PLATFORM)`. 17 testes unitarios passando

### Politica de dependencias atualizada

- Adicionadas ao core: `scapy`, `dnslib>=0.9.24`, `cryptography>=41.0`
- ACEITAS: aircrack-ng suite completa, hcxdumptool, hcxtools, hashcat, hostapd, wash
- REMOVIDAS (substituidas por codigo nativo): reaver, bully, pixiewps, mdk3, mdk4, wifiphisher, fluxion, dnsmasq, cowpatty, pyrit

### Bridges obsoletos removidos

- `airgeddon_bridge.py`, `wirespy_bridge.py`, `pwnagotchi_bridge.py`, `sniffair_passive_recon.py`
- `hashcatch_bridge.py`, `pmk_precompute.py`, `mdk3_bridge.py`, `mdk4_bridge.py`
- `wifiphisher_bridge.py`, `fluxion_bridge.py`, `reaver_bridge.py`, `bully_bridge.py`
- `pyrit_gpu_bridge.py`, `momo_integrated_attack.py`, `evilginx_prereq_pointer.py`

### OS Guard

- Modulos LINUX_ONLY: todos wifi/* (raw sockets, monitor mode, nl80211)
- Modulos LINUX_MAC: bluetooth/* (BlueZ/CoreBluetooth)
- Modulos CROSS_PLATFORM: pcap/*, sim/*, exportadores offline

---
