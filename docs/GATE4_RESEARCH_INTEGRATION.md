# WirelessXPL-Forge: Gate 4 Research Integration Report

## Sources Studied

| SRC | Repository | License | Integration | Status |
|-----|-----------|---------|-------------|--------|
| SRC-1005 | martin-olivier/airgorah | MIT | Recode native | integrated-native |
| SRC-1006 | airgorah crate (crates.io) | MIT | Reference | studied-no-action |
| SRC-149 | derv82/wifit3 | GPL-2.0 | Recode (ref only) | reference-only |
| SRC-150 | derv82/wifite2 | GPL-2.0 | Recode (ref only) | reference-only |
| SRC-679 | yslxotwod/wifisting | GPL-3.0 | Recode (ref only) | reference-only |
| SRC-681 | ainfosec/FISSURE | GPL-3.0 | Recode (ref only) | reference-only |
| SRC-144 | BigNerd95/QCSuper | GPL-3.0 | Recode native | integrated-native |
| SRC-164 | tc4dy/CVE-2026-0073-PoC | MIT | Recode native | integrated-native |
| SRC-352 | D4Vinci/WifiPass | GPL-3.0 | N/A | studied-no-action |
| SRC-533 | D4Vinci/AirCracker | GPL-3.0 | N/A | studied-no-action |
| SRC-454 | iphelix/airoscapy | MIT | N/A | studied-future |
| SRC-095 | VE3NEA/OmniRig | MIT | Reference | studied-future |
| SRC-096 | Hamlib/Hamlib | LGPL-2.1 | Reference | studied-future |
| SRC-146 | BigNerd95/AtherosFreedom | N/A | Reference | studied-no-action |
| SRC-834-847 | Koenkk/zigbee-* | Various | Reference | studied-future |
| SRC-680 | cn0xroot/RFSec-ToolKit | N/A | Reference | studied-no-action |

## New Modules Created

### Core modules

| Module | Source Ref | Description |
|--------|-----------|-------------|
| `core/integrations/lang_bridge.py` | Regra Magna 6 | Generic compiler bridge registry |
| `core/integrations/rust_runner.py` | Regra Magna 6 | Rust + C runner implementations |
| `core/pcap/crackable_detector.py` | airgorah (MIT) | EAPOL/PMKID crackable material detector |
| `core/oui_resolver.py` | airgorah (MIT) | MAC OUI vendor lookup with cache |
| `core/wifi/target_selector.py` | wifite2 (ref) | WiFi target filter, rank and attack suggestion |
| `core/wifi/channel_hopper.py` | airgorah (MIT) | Channel hopping with park-on-channel |

### Exploit modules

| Module | Source Ref | Description |
|--------|-----------|-------------|
| `modules/exploits/wifi_wps/__init__.py` | New | WPS attack module package |
| `modules/exploits/wifi_wps/pixie_dust.py` | wifit3 (ref) | Offline WPS PixieDust PIN recovery |
| `modules/exploits/wifi_wps/lockout_detector.py` | wifit3 (ref) | WPS lockout detection + backoff |

### Generic modules

| Module | Source Ref | Description |
|--------|-----------|-------------|
| `modules/generic/cellular/qualcomm_diag_capture.py` | QCSuper (ref) | Qualcomm Diag 2G/3G/4G/5G capture |
| `modules/generic/cellular/adb_wireless_debug_scanner.py` | CVE-2026-0073 (MIT) | ADB wireless TLS bypass scanner |
| `modules/generic/wifi/hidden_ssid_decloak.py` | wifit3 (ref) | Hidden SSID passive decloaking |

## Issues/PRs Applied Preventively

From airgorah:
- #197: Monitor mode cleanup on scan exit
- #244: Lock protection in channel hopper
- PR #226: Park-on-channel during deauth
- PR #229: PMKID detection + solicitation

From wifite2:
- #547: `iw` fallback (sysfs approach in channel_hopper.py)
- #249: SSID sanitization in target_selector.py

From wifit3:
- #112: Enterprise exclusion in target_selector.py
- PR #103: CPU performance (threaded hopper with dwell_time)

From FISSURE:
- PR #97: Monitor mode preservation during WiFi scan
- Issue #100: Document `iw` dependency

From QCSuper:
- PR #171/#172/#173: NR RRC v17/v26 headers, SDX75 padding

## Future Integration Roadmap

| Feature | Source | Priority | Notes |
|---------|--------|----------|-------|
| MITM ARP/DNS/SSL complete | wifisting 07 | HIGH | Recode needed (GPL) |
| 802.1x Enterprise relay | wifisting 13 | HIGH | Recode needed (GPL) |
| PMF Bypass | wifisting 34 | HIGH | Recode needed (GPL) |
| ML Signal Classifier | FISSURE | HIGH | Recode needed (GPL) |
| PMKID active solicitation | airgorah pmkid.rs | HIGH | Recode (MIT ok) |
| Attack chaining WiFi | wifite2 all.py | HIGH | autopwn/wifi.py |
| WPA PSK verify offline | wifit3 wpa_psk.py | HIGH | Recode (ref) |
| Capture vault/resume | wifit3 vault.py | MEDIUM | Session mgmt |
| WPS PIN database | wifit3 known_pins.py | MEDIUM | OUI-based PINs |
| Remote sensor nodes | wifisting 31 + FISSURE | MEDIUM | Architecture |
| Wireless M-Bus | wifisting 59 | LOW | Smart meters |
| GnuRadio flow graph library | FISSURE | LOW | SDR integration |
| Zigbee ecosystem | Koenkk repos | LOW | z2m converters |
