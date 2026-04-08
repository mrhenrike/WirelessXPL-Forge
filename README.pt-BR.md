# WirelessXPL-Forge

> **Framework modular de pesquisa em segurança wireless** para 802.11 (WPA2/WPA3/WPE/EAPOL), Bluetooth Classic, BLE, Zigbee, RFID e workflows de laboratório ESP32 — projetado para testes de invasão autorizados, pesquisa e educação.

**Versão:** 1.1.0 | **Licença:** BSD-3-Clause | **Python:** 3.8 – 3.13

**Idioma:** **English (en-US):** [README.md](README.md) · **Português (pt-BR)** — padrão desta página

[![Python 3.8–3.13](https://img.shields.io/badge/Python-3.8--3.13-blue.svg)](https://www.python.org/downloads/)
[![CI](https://github.com/mrhenrike/WirelessXPL-Forge/actions/workflows/compat-matrix.yml/badge.svg)](https://github.com/mrhenrike/WirelessXPL-Forge/actions/workflows/compat-matrix.yml)
[![Release](https://github.com/mrhenrike/WirelessXPL-Forge/actions/workflows/publish-pypi.yml/badge.svg)](https://github.com/mrhenrike/WirelessXPL-Forge/actions/workflows/publish-pypi.yml)
[![PyPI](https://img.shields.io/pypi/v/wirelessxpl.svg)](https://pypi.org/project/wirelessxpl/)
[![Licença](https://img.shields.io/badge/Licença-BSD%203--Clause-blue.svg)](LICENSE)

---

## Sobre o Projeto

O **WirelessXPL-Forge (WXF)** é um shell interativo e framework de módulos para pesquisa em segurança wireless. Ele oferece:

- Uma **CLI estilo Metasploit** (`use`, `set`, `run`, `search device=wifi`) para workflows de ataque e análise wireless
- Módulos Python nativos para **FragAttacks**, **KRACK**, **WPA3/Dragonblood**, **ataques BLE pairing**, **Braktooth**, **BlueBorne**, **AWDL**, **Zigbee/KillerBee**, e muito mais
- **Módulos bridge** para ferramentas externas: `aircrack-ng`, `hcxdumptool`, `mdk4`, `wifiphisher`, `eaphammer`, `airgeddon`, `bettercap`, `btlejack`, `opendrop`
- **Orquestração serial** para **firmware Bruce** (ESP32 Marauder) com perfis de fluxo semiautônomos
- **Catálogos upstream** rastreando a incorporação de issues/PRs da comunidade em 15+ repositórios de pesquisa de segurança
- **Pipelines de análise PCAP**: EAPOL 4-way, PMKID, TKIP, Dragonblood, WPE, BLE, workspace SQL para PCAPs

**Projetos irmãos:** [RouterXPL-Forge](https://github.com/mrhenrike/RouterXPL-Forge) (roteadores/switches) · [FirewallXPL-Forge](https://github.com/mrhenrike/FirewallXPL-Forge) (NGFW/UTM, privado)

**Linhagem:** [threat9/routersploit](https://github.com/threat9/routersploit) → RouterXPL-Forge → fork wireless

**Mantenedor:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) | [União Geek](https://github.com/Uniao-Geek)

---

## Pré-requisitos do sistema (não inclusos)

| Ferramenta | Função |
|------------|--------|
| **aircrack-ng suite** | `aircrack-ng`, `airodump-ng`, `aireplay-ng` — usado por módulos PCAP e wifi_lab |
| **hcxtools / hcxdumptool** | Captura PMKID e conversão de hash para hashcat |
| **hashcat** | Cracking offline WPA2/WPA3 (modos 22000/22001) |
| **tshark** *(opcional)* | Dissecção BLE / 802.11 quando camadas Scapy são insuficientes |
| **mdk4 / mdk3** *(opcional)* | Tempestades de deauth, beacon floods, mesh flooding |
| **hostapd + dnsmasq** *(opcional)* | Rogue AP / evil-twin + DHCP/DNS para portais cativos |
| **wifiphisher** *(opcional)* | Campanhas de phishing via módulo bridge |
| **eaphammer** *(opcional)* | Captura de credenciais EAP/PEAP |
| **airgeddon** *(opcional)* | Menu de múltiplos ataques (bridge disponível) |
| **btlejack** *(opcional)* | BLE sniff/jam/hijack |
| **opendrop / owl** *(opcional)* | Workflows de laboratório AWDL/AirDrop |
| **Bruce ESP32 firmware** *(opcional)* | [BruceDevices/firmware](https://github.com/BruceDevices/firmware) — wardriving portátil; exporte PCAP para `generic/pcap/*` |
| **pyserial** *(opcional)* | Bridge serial para firmware Bruce (`pip install wirelessxpl[serial]`) |

Execute `use generic/external/wireless_tool_prereq_audit` após a instalação para verificar seu PATH.

---

## Instalação Rápida

### Via PyPI

```bash
pip install wirelessxpl
# com suporte serial para Bruce/ESP32:
pip install "wirelessxpl[serial]"
# com classificação ML de sinal:
pip install "wirelessxpl[ml-lite]"
```

### Via código fonte

```bash
git clone https://github.com/mrhenrike/WirelessXPL-Forge.git
cd WirelessXPL-Forge
pip install -r requirements.txt
python wxf.py
# ou
python -m wirelessxpl
# ou (após pip install -e .)
wxf
```

### WSL2 / Kali (recomendado para ferramentas de captura)

```bash
sudo apt install aircrack-ng hcxtools hcxdumptool mdk4 hostapd dnsmasq tshark
pip install wirelessxpl
```

---

## Uso Rápido

```
$ python wxf.py
wxf > help
wxf > show modules
wxf > search device=wifi
wxf > search device=bluetooth
wxf > use generic/wifi_lab/handshake_snooper
wxf (HandshakeSnooper) > show options
wxf (HandshakeSnooper) > set interface wlan0mon
wxf (HandshakeSnooper) > set target_bssid AA:BB:CC:DD:EE:FF
wxf (HandshakeSnooper) > run
```

### Modo não-interativo (scripts)

```bash
python wxf.py -m generic/wifi_lab/handshake_snooper \
  interface=wlan0mon target_bssid=AA:BB:CC:DD:EE:FF
```

---

## Referência de Módulos

### Wi-Fi / 802.11 (generic/wifi_lab)

| Módulo | Descrição |
|--------|-----------|
| `fragattacks` | FragAttacks (CVE-2020-26140+) — injeção de frames + detecção 802.11ax |
| `handshake_snooper` | Pipeline PMKID-first + captura de handshake por deauth |
| `wpa3_attack_suite` | Dragonblood SAE flood, CSA+harvest, Double SSID, downgrade |
| `auth_flood` | Auth/EAPOL flood, amok mode, mesh flood (backend mdk4) |
| `evil_twin_workflow` | Evil-twin completo com verificação pós-captura (aircrack-ng) |
| `captive_portal_modern_lab` | Portal cativo moderno com coletor de credenciais HTML/JS |
| `mitm_wifi_bridge` | ARP/DNS spoofing + Ghost combo (bettercap) |
| `adaptive_harvest` | Harvesting adaptativo de canais/PMKID guiado por score |
| `wardriving_deauth_loop` | Ciclos automatizados de scan/deauth/captura (wardriving) |
| `wireless_ids` | IDS leve: baseline de BSSID + detecção de rogue AP |
| `awdl_attack` | AWDL/AirDrop (opendrop + owl) — discover, send, DoS |
| `momo_integrated_attack` | Orquestração KARMA + PMKID-first + downgrade |

### Bluetooth / BLE (generic/bluetooth)

| Módulo | Descrição |
|--------|-----------|
| `bt_hid_injection` | Injeção de teclado HID Bluetooth (fallback Broadcom) |
| `bt_baseband_attack` | BrakTooth / SweynTooth via serial ESP32 |
| `bt_session_attack` | Ataques de sessão KNOB, BIAS, BLUFFS |
| `blueborne_attack` | BlueBorne L2CAP overflow (perfis de offset de kernel) |
| `ble_btlejack` | BTLEJack BLE sniff/jam/hijack |

### Bridge ESP32 / Bruce (generic/external)

| Módulo | Descrição |
|--------|-----------|
| `bruce_serial_bridge` | Engine de fluxo serial para firmware Bruce ESP32 (15+ perfis) |
| `bruce_upstream_tracker` | Visualizador de catálogo de issues/PRs do firmware Bruce |
| `airgeddon_bridge` | Bridge multi-modo para Airgeddon |
| `wifiphisher_bridge` | Bridge Wifiphisher com sniffer embutido |
| `eaphammer_bridge` | Bridge EAPHammer (PEAP Win11 + coerção HTTP) |

---

## Integração Bruce / ESP32 Marauder

O WXF inclui um engine completo de fluxo serial para o [BruceDevices/firmware](https://github.com/BruceDevices/firmware):

```
wxf > use generic/external/bruce_serial_bridge
wxf (BruceSerialBridge) > set serial_port /dev/ttyACM0
wxf (BruceSerialBridge) > set flow_profile capture_handshake_flow
wxf (BruceSerialBridge) > run

# Perfis de fluxo disponíveis:
#   baseline_status_flow            capture_handshake_flow
#   wifi_menu_navigation_flow       deauth_clone_verify_flow
#   sniffer_capture_flow            evil_portal_karma_flow
#   wifi_attack_lab_flow            raw_sniffer_probe_flow
#   wifi_bruteforce_recon_flow      navigation_recovery_flow
#   captive_portal_endpoint_config_flow
#   repeater_wisp_setup_flow        external_adapter_probe_flow
#   webui_password_flow             target_attack_stability_flow
#   ble_recon_spam_flow             ble_badble_recovery_flow
#   rf_spectrum_scan_flow           rf_jammer_stability_flow
```

---

## Documentação e Wiki

- **[docs/wiki/en-US/](docs/wiki/en-US/)** — Inglês (padrão)
- **[docs/wiki/pt-BR/](docs/wiki/pt-BR/)** — Português
- **[docs/FULL_CATALOG.md](docs/FULL_CATALOG.md)** — catálogo completo de módulos
- **[docs/COVERAGE_MATRIX.md](docs/COVERAGE_MATRIX.md)** — matriz de cobertura de dispositivos

---

## Contribuindo

Veja [CONTRIBUTING.pt-BR.md](CONTRIBUTING.pt-BR.md) e [CONTRIBUTORS.pt-BR.md](CONTRIBUTORS.pt-BR.md).  
Leia nosso [Código de Conduta](CODE_OF_CONDUCT.pt-BR.md) e a [Política de Segurança](SECURITY.pt-BR.md).

---

## Licença

BSD 3-Clause License — veja [LICENSE](LICENSE) para detalhes.

**O WirelessXPL-Forge é destinado exclusivamente para pesquisa de segurança e educação autorizadas.**  
O uso contra sistemas que você não possui ou não tem permissão escrita explícita para testar é ilegal.

---

**Autor:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) | [União Geek](https://github.com/Uniao-Geek)  
**Linhagem:** [threat9/routersploit](https://github.com/threat9/routersploit) → RouterXPL-Forge → WirelessXPL-Forge
