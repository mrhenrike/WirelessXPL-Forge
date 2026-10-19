# Changelog

All notable changes to WirelessXPL-Forge are documented in this file.

---

## [2.2.0] - 2026-10-19

### Added
- **xpl-core integration:** shells shim (`wirelessxpl/core/shells/`) re-exporting from xpl-core canonical package
- **IoT shell mixin:** `shell_mixin.py` with wireless/embedded-specific payloads (busybox_nc, mkfifo, socat, telnet_reverse)
- **PEP 561:** `py.typed` marker for downstream type checking
- **mypy config:** `check_untyped_defs`, `ignore_missing_imports` for 20 external modules (scapy, bleak, dbus, etc.)
- **ruff linting:** target-version py39, line-length 120; select E/W/F/I/B/SIM/RUF; per-file-ignores for exploit modules
- **Test suite expansion:** 86 to 199 tests covering config, pool, phase_gateway, hw_profiler, bt_crypto, shells shim
- **CI/CD:** GitHub Actions `ci.yml` (ruff, mypy, pytest matrix py3.9-3.14), `publish.yml` (trusted publisher PyPI)
- `.github/workflows/` tracked in git (removed .gitignore exclusion)

### Changed
- Auto-fixed 897 ruff issues across 444 files (import sorting, f-strings, unused imports)
- Fixed duplicate glossary key (`pixie_dust` renamed to `pixie_dust_wps`)
- Removed unused `BleakError` import in `btle_device.py`
- Hardened `.gitignore` with sensitive-file patterns

### Dependencies
- `xpl-core>=0.1.0` (new: provides shared shell infrastructure)

---

## [2.1.2] - 2026-10-06

### Changed
- Release alignment: sync package version with GitHub tag + PyPI ship (HEAD beyond v2.1.1).

## [minor-sync-2026-09-26] - 2026-09-26

### Changed
- EmbedXPL v5.0.0 sync: search engine + autopwn modules deployed
- Domain contracts updated (DOMAIN-CONTRACTS.md)

## [2.0.4] - 2026-06-25

### Added
- Global CLI flags via `tools/xpl_cli.py`: `-h`/`--help`, `-V`/`--version`, `-i`/`--interactive`, `--doctor`/`--check`
- Colorized help banner on `wxf --help`

---

## [1.8.1] - 2026-06-19

### Fixed
- **wps_engine_native**: Added 802.11 Auth+AssocReq+EAPOL-Start sequence before the EAP-WSC sniff loop. Without this sequence the AP never sent EAP-Request/Identity and the WPS attack timed out indefinitely. Confirmed in field tests with WPS v1.0 APs.
- **core/exploit.OptBool**: Now accepts native Python `bool` values in addition to strings "true"/"false". Previously calling `run(i_know_scope=True)` raised `OptionValidationError`.
- **pmkid_autopwn**: Added explicit early check for `hcxdumptool` and `hcxpcapngtool` at the start of `run()`, with clear installation instructions, instead of silent or confusing failure.
- **wps_engine_native**, **monitor_mode_manager**: Added channel drift warning to module docstrings (some APs advertise ch3 but operate on ch4 - try adjacent channels and use `iw dev <iface> scan` to confirm).

### Notes
- Field tests confirmed in lab environment with 44 APs detected, 33 with WPS enabled.
- Known limitation: USB Wi-Fi adapters in VirtualBox EHCI passthrough may have TX injection restrictions depending on chipset.

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
