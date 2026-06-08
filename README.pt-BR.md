# WirelessXPL-Forge

> **Framework modular de pesquisa em segurança wireless** para 802.11 (WPA2/WPA3/WPE/EAPOL), Bluetooth Classic, BLE, Zigbee, RFID e workflows de laboratorio ESP32 - projetado para testes de invasao autorizados, pesquisa e educacao.

**Versao:** 1.8.0 | **Licenca:** BSD-3-Clause | **Python:** 3.8 - 3.13

**Idioma:** **English (en-US):** [README.md](README.md) · **Portugues (pt-BR)** - padrao desta pagina

[![Python 3.8-3.13](https://img.shields.io/badge/Python-3.8--3.13-blue.svg)](https://www.python.org/downloads/)
[![CI](https://github.com/mrhenrike/WirelessXPL-Forge/actions/workflows/compat-matrix.yml/badge.svg)](https://github.com/mrhenrike/WirelessXPL-Forge/actions/workflows/compat-matrix.yml)
[![Release](https://github.com/mrhenrike/WirelessXPL-Forge/actions/workflows/publish-pypi.yml/badge.svg)](https://github.com/mrhenrike/WirelessXPL-Forge/actions/workflows/publish-pypi.yml)
[![PyPI](https://img.shields.io/pypi/v/wirelessxpl.svg)](https://pypi.org/project/wirelessxpl/)
[![Licenca](https://img.shields.io/badge/Licenca-BSD%203--Clause-blue.svg)](LICENSE)

---

## Sobre o Projeto

O **WirelessXPL-Forge (WXF)** e um shell interativo e framework de modulos para pesquisa em seguranca wireless. Ele oferece:

- Uma **CLI estilo Metasploit** (`use`, `set`, `run`, `search device=wifi`) para workflows de ataque e analise wireless
- Modulos Python nativos para **FragAttacks**, **KRACK**, **SweynTooth**, **WPA3/Dragonblood**, **ataques BLE pairing**, **Braktooth**, **BlueBorne**, **AWDL**, **Zigbee/KillerBee**, **Sub-GHz**, **Drones/MAVLink** e mais
- **Modulos bridge** para ferramentas externas: `aircrack-ng`, `hcxdumptool`, `mdk4`, `wifiphisher`, `eaphammer`, `airgeddon`, `bettercap`, `btlejack`, `opendrop`
- **Orquestracao serial** para **firmware Bruce** (ESP32 Marauder) com perfis de fluxo semiautonomos
- **Catalogos upstream** rastreando a incorporacao de issues/PRs da comunidade em 15+ repositorios de pesquisa de seguranca
- **Pipelines de analise PCAP**: EAPOL 4-way, PMKID, TKIP, Dragonblood, WPE, BLE, workspace SQL para PCAPs

**Projetos irmaos:** [RouterXPL-Forge](https://github.com/mrhenrike/RouterXPL-Forge) (roteadores/switches) · [FirewallXPL-Forge](https://github.com/mrhenrike/FirewallXPL-Forge) (NGFW/UTM, privado)

**Linhagem:** [threat9/routersploit](https://github.com/threat9/routersploit) → RouterXPL-Forge → fork wireless

**Mantenedor:** Andre Henrique ([@mrhenrike](https://github.com/mrhenrike)) | [Uniao Geek](https://github.com/Uniao-Geek)

---

## Pre-requisitos do sistema (fora do wheel PyPI)

O `pip install wirelessxpl` traz **apenas** o pacote Python e dependencias declaradas. A tabela abaixo lista **ferramentas no host** (apt, brew, instaladores) que nao fazem parte do `.whl`. Os **modulos bridge** continuam **integrados** ao WXF (`use` - `run`); sao **orquestracao via subprocess**, nao "ferramenta solta". Nao incorporamos projetos inteiros (ex.: wifiphisher GPL) neste repositorio - ver **[docs/INTEGRATION_MODEL.md](docs/INTEGRATION_MODEL.md)**.

| Ferramenta | Funcao |
|------------|--------|
| **aircrack-ng suite** | `aircrack-ng`, `airodump-ng`, `aireplay-ng` - PCAP / wifi_lab |
| **hcxtools / hcxdumptool** | PMKID e conversao de hash para hashcat |
| **hashcat** | Cracking offline WPA2/WPA3 (modos 22000/22001) |
| **tshark** *(opcional)* | Disseccao BLE / 802.11 |
| **mdk4 / mdk3** *(opcional)* | Deauth, beacon floods, mesh flooding |
| **hostapd + dnsmasq** *(opcional)* | Rogue AP / evil-twin + DHCP/DNS |
| **wifiphisher** *(opcional)* | Phishing via **bridge** |
| **eaphammer** *(opcional)* | EAP/PEAP via **bridge** |
| **airgeddon** *(opcional)* | Ataques via **bridge** |
| **btlejack** *(opcional)* | BLE via **bridge** |
| **opendrop / owl** *(opcional)* | AWDL/AirDrop via **bridge** |
| **Firmware Bruce ESP32** *(opcional)* | [BruceDevices/firmware](https://github.com/BruceDevices/firmware) - imagem de dispositivo |
| **pyserial** *(opcional)* | Serial Bruce (`pip install wirelessxpl[serial]`) |

Execute `use generic/external/wireless_tool_prereq_audit` apos instalar para validar o PATH.

---

## Instalacao Rapida

### Via PyPI

```bash
pip install wirelessxpl
# com suporte serial para Bruce/ESP32:
pip install "wirelessxpl[serial]"
# com classificacao ML de sinal:
pip install "wirelessxpl[ml-lite]"
```

### Via codigo fonte

```bash
git clone https://github.com/mrhenrike/WirelessXPL-Forge.git
cd WirelessXPL-Forge
pip install -r requirements.txt
python wxf.py
# ou
python -m wirelessxpl
# ou (apos pip install -e .)
wxf
```

### WSL2 / Kali (recomendado para ferramentas de captura)

```bash
sudo apt install aircrack-ng hcxtools hcxdumptool mdk4 hostapd dnsmasq tshark
pip install wirelessxpl
```

---

## Uso Rapido

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

### Modo nao-interativo (scripts)

```bash
python wxf.py -m generic/wifi_lab/handshake_snooper \
  interface=wlan0mon target_bssid=AA:BB:CC:DD:EE:FF
```

---

## Referencia de Modulos

### Wi-Fi / 802.11 (generic/wifi_lab)

| Modulo | Descricao |
|--------|-----------|
| `fragattacks` | FragAttacks (CVE-2020-26140+) - injecao de frames + deteccao 802.11ax |
| `handshake_snooper` | Pipeline PMKID-first + captura de handshake por deauth |
| `wpa3_attack_suite` | Dragonblood SAE flood, CSA+harvest, Double SSID, downgrade |
| `auth_flood` | Auth/EAPOL flood, amok mode, mesh flood (backend mdk4) |
| `evil_twin_workflow` | Evil-twin completo com verificacao pos-captura (aircrack-ng) |
| `captive_portal_modern_lab` | Portal cativo moderno com coletor de credenciais HTML/JS |
| `mitm_wifi_bridge` | ARP/DNS spoofing + Ghost combo (bettercap) |
| `adaptive_harvest` | Harvesting adaptativo de canais/PMKID guiado por score |
| `wardriving_deauth_loop` | Ciclos automatizados de scan/deauth/captura (wardriving) |
| `wireless_ids` | IDS leve: baseline de BSSID + deteccao de rogue AP |
| `awdl_attack` | AWDL/AirDrop (opendrop + owl) - discover, send, DoS |
| `momo_integrated_attack` | Orquestracao KARMA + PMKID-first + downgrade |

### Wi-Fi Lab - SweynTooth BLE (generic/bluetooth/sweyntooth) - NOVO v1.8.0

| Modulo | Descricao |
|--------|-----------|
| `sweyntooth_scanner` | Scanner BLE passivo detectando assinaturas de firmware vulneraveis ao SweynTooth |
| `sweyntooth_cve_2019_16336` | CVE-2019-16336 - BLE Link Layer length overflow (Texas Instruments) |
| `sweyntooth_cve_2019_17517` | CVE-2019-17517 - BLE data channel PDU overflow (Microchip) |
| `sweyntooth_cve_2019_17519` | CVE-2019-17519 - BLE slave connection reject bypass (Dialog Semiconductor) |
| `sweyntooth_cve_2019_17520` | CVE-2019-17520 - BLE public key crash no pairing (Telink) |

### Wi-Fi Lab - FragAttacks (generic/wifi_lab/fragattacks) - NOVO v1.8.0

| Modulo | Descricao |
|--------|-----------|
| `fragattacks_scanner` | Scanner passivo detectando APs vulneraveis ao FragAttacks por beacon flags |
| `fragattacks_cve_2020_26140` | CVE-2020-26140 - Injecao de dados em texto plano em APs WPA2 nao-estritos |
| `fragattacks_cve_2020_26141` | CVE-2020-26141 - Abuso de cache de fragmentos / injecao de fragmentos nao contiguos |
| `fragattacks_cve_2020_26143` | CVE-2020-26143 - Aceitacao de fragmentos mistos plaintext/cifrado |

### Wi-Fi Lab - KRACK (generic/wifi_lab/krack) - NOVO v1.8.0

| Modulo | Descricao |
|--------|-----------|
| `krack_scanner` | Scanner passivo de indicadores de reutilizacao de nonce KRACK (CVE-2017-13077..13088) |
| `krack_4way_retransmit` | CVE-2017-13077 - Reinstalacao PTK via retransmissao Msg3 |
| `krack_group_key_retransmit` | CVE-2017-13080 - Reinstalacao GTK via replay do group key handshake |

### Bluetooth / BLE / Zigbee (generic/bluetooth)

| Modulo | Descricao |
|--------|-----------|
| `bt_hid_keyboard_inject` | Injecao de teclado HID Bluetooth (Broadcom/BlueZ) |
| `bt_baseband_attack` | BrakTooth / SweynTooth via serial ESP32 |
| `bt_session_attack` | Ataques de sessao KNOB, BIAS, BLUFFS |
| `blueborne_attack` | BlueBorne L2CAP overflow (perfis de offset de kernel) |
| `ble_btlejack` | BTLEJack BLE sniff/jam/hijack |
| `ble_crackle` | Recuperacao de chave BLE Legacy Pairing |
| `knob_native_cve_2019_9506` | **CVE-2019-9506** - Downgrade de entropia de chave BT BR/EDR para 1 byte |
| `zigbee_touchlink_factory_reset` | Zigbee ZLL Touchlink Factory Reset sem autenticacao (Hue, TRADFRI) |
| `zigbee_network_key_extract` | Extracao de Network Key Zigbee via decrypt de Transport Key |
| `zigbee_rejoin_hijack` | Zigbee Rejoin Hijack: beacon spoof - desassociacao - captura Transport Key |
| `ble_gatt_enum_unauth` | BLE GATT enumeration sem autenticacao (servicos, caracteristicas, writable handles) |
| `ble_spoofing_impersonation` | BLE device cloning via advertising data replay |

---

### Suite de Ataque Sub-GHz (generic/subghz) - NOVO v1.8.0

> **AVISO LEGAL:** Transmitir em faixas Sub-GHz licenciadas sem autorizacao e
> ilegal na maioria das jurisdicoes. Use apenas em equipamentos proprios,
> dentro de gaiolas de Faraday/blindagem RF, ou em engagements de red team
> devidamente autorizados. Clonar/abrir portoes/garagens sem consentimento do
> proprietario do imovel configura crime.

#### Protocolos Suportados

| Protocolo | Bits | Frequencia | Seguranca | Modulo | HW Necessario |
|-----------|------|------------|-----------|--------|---------------|
| EV1527 | 24 | 433 MHz | Nenhuma | `subghz/static_code_replay` | HackRF / CC1101 |
| Princeton/PT2262 | 24 | 315/433 MHz | Nenhuma | `subghz/static_code_replay` | HackRF / CC1101 |
| CAME | 12 | 303-868 MHz | Nenhuma | `subghz/debruijn_bruteforce` | HackRF |
| NICE Flo | 12 | 433/868 MHz | Nenhuma | `subghz/debruijn_bruteforce` | HackRF |
| KeeLoq | 64 | 433/868 MHz | Rolling code | `subghz/keeloq_*` | HackRF |
| TPMS | var | 315/433 MHz | CRC only | `subghz/tpms/*` | RTL-SDR |

#### Referencia de Modulos

| Modulo | Descricao |
|--------|-----------|
| `static_code_replay` | Replay de codigo estatico EV1527/Princeton/CAME/NICE/Holtek/Chamberlain |
| `debruijn_bruteforce` | Bruteforce por sequencia DeBruijn para protocolos de portao de 12 bits |
| `keeloq_decoder` | Decodificador e analisador de rolling code KeeLoq |
| `keeloq_replay` | Replay de rolling code KeeLoq dentro da janela de contador |
| `ev1527_vehicle_cve_2025_70994` | CVE-2025-70994 - Replay de chave remota veicular EV1527 |
| `subghz_jammer` | Jammer seletivo Sub-GHz (apenas em testes autorizados) |
| `br_gate_scanner` | Scanner e gravador de protocolos de portao/garagem brasileiros |
| `tpms/tpms_decoder` | Decodificador passivo de sensores TPMS |
| `tpms/tpms_spoof` | Injecao de alerta de pressao TPMS falsificado |
| `tools/ook_analyzer` | Analisador de sinal OOK: preambulo, timing de bit, identificacao de protocolo |

#### Exemplo de Uso - Bruteforce DeBruijn (portoes CAME)

```
wxf > use generic/subghz/debruijn_bruteforce
wxf (DeBruijn) > set protocol CAME
wxf (DeBruijn) > set frequency 433.92
wxf (DeBruijn) > set output_sub /tmp/came_brute.sub
wxf (DeBruijn) > run

[*] Gerando sequencia DeBruijn para CAME 12 bits em 433.92 MHz
[*] Total de codigos a testar: 4096
[*] Tempo estimado a 287ms/codigo: ~4.8 minutos
[+] Gerado: /tmp/came_brute.sub (compativel com Flipper Zero)
[*] Carregar no Flipper: Sub-GHz -> Saved -> came_brute.sub -> Send
```

#### Exemplo de Uso - Replay EV1527

```
wxf > use generic/subghz/static_code_replay
wxf (StaticCodeReplay) > set protocol EV1527
wxf (StaticCodeReplay) > set code 0xA3F21B
wxf (StaticCodeReplay) > set frequency 433.92
wxf (StaticCodeReplay) > set interface hackrf
wxf (StaticCodeReplay) > set simulate true
wxf (StaticCodeReplay) > run

[SIMULADO] Transmitiria codigo EV1527 0xA3F21B em 433.92 MHz
[SIMULADO] Sequencia OOK: 24 bits, 350us/bit
[!] Defina simulate=false e interface=hackrf para transmitir ao vivo
```

---

### Seguranca de Drones/UAV (generic/drones) - NOVO v1.8.0

> **AVISO LEGAL:** Interferencia nao autorizada em drones (deauth, desarme forcado,
> spoofing de GPS, injecao de comandos) viola a legislacao aeronautica em todas as
> jurisdicoes. Em muitos paises constitui crime federal com penas graves.
> Use APENAS em drones proprios, em ambientes blindados, ou sob autorizacao
> escrita explicitica do proprietario do drone e da autoridade aeronautica competente.

| Modulo | Descricao |
|--------|-----------|
| `drone_scanner` | Descoberta de drones por fingerprint de SSID WiFi (DJI, Parrot, Holy Stone, FPV) |
| `mavlink/mavlink_scanner` | Scanner de dispositivos MAVLink em UDP 14550 / TCP 5760 |
| `mavlink/mavlink_force_disarm` | Comando de desarme forcado via MAV_CMD_COMPONENT_ARM_DISARM |
| `mavlink/mavlink_gps_spoof` | Injeta NMEA GPS falsificado para estacao terrestre / GCS |
| `mavlink/mavlink_waypoint_inject` | Sobrescreve waypoints da missao ativa |
| `mavlink/mavlink_geofence_disable` | Desabilita parametros de geofence via PARAM_SET |
| `mavlink/mavlink_param_dump` | Dump de todos os parametros do autopiloto (auditoria read-only) |
| `mavlink/mavlink_flood_dos` | Flood de mensagens MAVLink (DoS) |
| `dji/dji_wifi_scan` | Scanner de SSID DJI e extrator de versao |
| `dji/dji_deauth` | Deautenticacao WiFi DJI (interrupcao de pouso) |
| `dji/dji_quicktransfer_exfil_cve_2023_6951` | CVE-2023-6951 - Exfiltracao de arquivos DJI QuickTransfer sem autenticacao |
| `parrot/parrot_anafi_deauth_cve_2019_3944` | CVE-2019-3944 - Deauth WiFi Parrot ANAFI |
| `parrot/parrot_anafi_webcrash_cve_2019_3945` | CVE-2019-3945 - Crash de API REST Parrot ANAFI |
| `parrot/parrot_anafi_udp_cmd_inject` | Injecao de comandos UDP Parrot ANAFI |
| `parrot/parrot_bebop_dhcp_exhaust_cve_2022_46416` | CVE-2022-46416 - Esgotamento de pool DHCP Parrot Bebop |
| `holystone/hsrid01_ble_dos_cve_2024_52876` | CVE-2024-52876 - DoS BLE Holy Stone HSRID01 |
| `fpv/eachine_e52_tcp_takeover` | Takeover por replay TCP Eachine E52 |

#### Exemplo de Uso - MAVLink Force Disarm

```
wxf > use generic/drones/mavlink/mavlink_force_disarm
wxf (MAVForceDisarm) > set rhost 192.168.1.100
wxf (MAVForceDisarm) > set rport 14550
wxf (MAVForceDisarm) > set simulate true
wxf (MAVForceDisarm) > run

[SIMULADO] Enviaria MAV_CMD_COMPONENT_ARM_DISARM (param1=0, param2=21196)
[SIMULADO] Para: udp://192.168.1.100:14550 sysid=1 compid=1
[!] Defina simulate=false para enviar comando ao vivo
[!] PRE-REQUISITO: Acesso de rede ao drone na porta UDP 14550
[!] ATENCAO: Desarme forcado em drone airborne causa queda
```

#### Exemplo de Uso - Exfiltracao DJI QuickTransfer (CVE-2023-6951)

```
wxf > use generic/drones/dji/dji_quicktransfer_exfil_cve_2023_6951
wxf (DJIQuickTransferExfil) > set rhost 192.168.2.1
wxf (DJIQuickTransferExfil) > set output_dir /tmp/dji_exfil
wxf (DJIQuickTransferExfil) > set simulate true
wxf (DJIQuickTransferExfil) > run

[SIMULADO] CVE-2023-6951: Acesso nao autenticado a arquivos DJI QuickTransfer
[SIMULADO] Alvo: http://192.168.2.1:80
[SIMULADO] Enumeraria /DCIM/ e baixaria arquivos de midia
[!] Defina simulate=false para exfiltracao ao vivo - requer associacao WiFi ao drone
```

---

### Seguranca Maritima (generic/maritime) - NOVO v1.8.0

> **AVISO LEGAL:** Spoofing de AIS e NMEA em alto mar e ilegal pela SOLAS e
> legislacao maritima em todas as jurisdicoes. Cria riscos de seguranca
> a navegacao. Use apenas em ambientes de laboratorio autorizados
> ou camaras RF fechadas.

| Modulo | Descricao |
|--------|-----------|
| `nmea_spoof` | Injecao de sentencas NMEA 0183 GPS/navegacao (multiplexador TCP) |
| `ais_spoof` | Spoofing de relatorio de posicao AIS com codificacao de bits Tipo 1 |

#### Exemplo de Uso - Spoof de Embarcacao AIS

```
wxf > use generic/maritime/ais_spoof
wxf (AISSpoofAttack) > set target_host 192.168.1.100
wxf (AISSpoofAttack) > set target_port 10110
wxf (AISSpoofAttack) > set simulate true
wxf (AISSpoofAttack) > run

[SIMULADO] Sentenca AIS Tipo 1 para MMSI 123456789 (PHANTOM)
[SIMULADO] Posicao: 1.264N / 103.826E a 12.0 nos COG 90
[SIMULADO] Sentenca: !AIVDM,1,1,,A,15NN...
[!] Defina simulate=false + acesso de rede ao multiplexador AIS (TCP 10110) para injetar
[!] ATENCAO: Spoofing de AIS e crime maritimo
```

---

### Radar Veicular (generic/vehicular_radar) - NOVO v1.8.0

> **AVISO LEGAL:** Jamming ou spoofing ativo de radar e ilegal na maioria das
> jurisdicoes e cria riscos de seguranca nas estradas. Use APENAS em camaras
> anecoicas blindadas ou pistas de teste autorizadas com acesso controlado.

| Modulo | Descricao |
|--------|-----------|
| `traffic_enforcement_scanner` | Scanner de fingerprint Kapsch RSU / Motorola Vigilant / Selea ANPR |
| `fmcw_radar_attack` | Calculadora de parametros de ataque FMCW (MadRadar/mmSpoof - referencia) |

#### Exemplo de Uso - Scanner de Equipamentos de Fiscalizacao

```
wxf > use generic/vehicular_radar/traffic_enforcement_scanner
wxf (TrafficEnforcementScanner) > set target_cidr 10.0.1.0/24
wxf (TrafficEnforcementScanner) > run

[*] Escaneando 10.0.1.0/24 por dispositivos de fiscalizacao de trafego...
[+] 10.0.1.42: Kapsch TrafficCom RSU | portas: 443,8443
     CVEs: CVE-2025-25734, CVE-2025-25735, CVE-2025-25736
[+] 10.0.1.67: Motorola Vigilant LPR | portas: 80,443
     CVEs: CVE-2024-51023, CVE-2024-51024
[*] Scan concluido: 2 dispositivos encontrados
```

---

### Arsenal WiFi - Evidencias, Wardrive, WIDS, Sessao (v1.8.0)

| Modulo | Descricao |
|--------|-----------|
| `evidence_vault/evidence_vault` | Ledger de auditoria com hash chain e prova de custodia (ISO/IEC 27037) |
| `wardrive/wardrive_logger` | Logger de descoberta WiFi com tag GPS e exportacao CSV/JSON/KML |
| `wids/wifi_ids` | WIDS Python nativo: deteccao de flood deauth, evil twin, rogue AP, beacon flood |
| `session_manager/session_manager` | Gerenciador de sessao de pentest com SQLite e exportacao JSON |
| `bluetooth/bt_hid_keyboard_inject` | Injecao de teclado HID Bluetooth (Broadcom/BlueZ) |

#### Exemplo de Uso - Evidence Vault

```
wxf > use generic/evidence_vault/evidence_vault
wxf (EvidenceVault) > set session_id pentest_escritorio_2026
wxf (EvidenceVault) > set vault_dir /evidencias
wxf (EvidenceVault) > run scan --ssid "WiFiEscritorio" --bssid AA:BB:CC:DD:EE:FF --channel 6 --rssi -65 --security WPA2

[+] Evidencia registrada: #0001 tipo=scan sha256=abc123...
[+] Cabeca da cadeia: abc123...

wxf (EvidenceVault) > verify
[+] Cadeia VALIDA (3 registros)
[+] Cadeia de custodia ISO/IEC 27037 mantida
```

#### Exemplo de Uso - WIDS

```
wxf > use generic/wids/wifi_ids
wxf (WirelessIDS) > set interface wlan0mon
wxf (WirelessIDS) > set simulate true
wxf (WirelessIDS) > run

[SIMULADO] Cenario WIDS: DEAUTH_FLOOD detectado
  BSSID: AA:BB:CC:DD:EE:FF | cliente: 11:22:33:44:55:66 | frames: 45/10s
  Alerta: DEAUTH_FLOOD severidade=ALTA
[SIMULADO] EVIL_TWIN detectado - SSID 'WiFiEscritorio' em novo BSSID
[*] Para iniciar monitoramento ao vivo: set simulate false
```

---

### Protocolos IoT (generic/iot_proto)

| Modulo | Descricao |
|--------|-----------|
| `mqtt_broker_enum_inject` | MQTT - acesso anonimo, enumeracao de topicos e injecao de payload |
| `mqtt_lateral_pivot` | MQTT - pivot via broker para dispositivos IoT internos |
| `mqtt_broker_dos` | **CVE-2017-7651** DoS por CONNECT/DISCONNECT cycling com LWT oversized |
| `mqtt_sys_acl_bypass_cve_2020_13849` | **CVE-2020-13849** Mosquitto ACL bypass via subscricao $SYS/# |
| `coap_resource_enum` | CoAP - discovery `.well-known/core` + fator de amplificacao UDP |
| `coap_block_overflow` | **CVE-2019-9750** CoAP Block2 option heap overflow em stacks embarcados |
| `upnp_ssdp_attack` | UPnP/SSDP - descoberta + **CVE-2020-12695** CallStranger SSRF |
| `upnp_ssdp_rce_inject` | **CVE-2013-0229** SOAP action injection + AddPortMapping sem auth |
| `upnp_ssdp_amplification` | SSDP amplification/reflection 20-50x via M-SEARCH spoofado |
| `mdns_poisoning` | mDNS - enumeracao passiva de servicos + envenenamento de respostas |
| `mdns_amplification` | mDNS amplification 5-30x via QTYPE=ANY (Bonjour/Avahi) |
| `dds_rtps_attack` | DDS/RTPS - enumeracao de participantes ROS2/automotivo (sem auth) |
| `tftp_firmware_attack` | TFTP - download/upload de firmware sem autenticacao em dispositivos embarcados |

### LoRaWAN (generic/lorawan)

| Modulo | Descricao |
|--------|-----------|
| `lorawan_adr_bitflip_cve_2022_39274` | **CVE-2022-39274** - ADR bit-flip para degradacao de sinal/DoS |
| `lorawan_join_replay` | Join Accept Replay - session hijack por falta de protecao anti-replay (LoRaWAN 1.0.x) |

### Automotivo / CAN bus (generic/automotive)

| Modulo | Descricao |
|--------|-----------|
| `can_bus_attack` | CAN bus - enumeracao ECU via OBD-II, fuzzing de IDs, UDS ECU reset, frame replay |
| `mercedes_mbux_bt_rce_cve_2023_37462` | **CVE-2023-37462** Mercedes MBUX NTG6 Bluetooth RCE (scan, info, probe) |

### Z-Wave (generic/zwave)

| Modulo | Descricao |
|--------|-----------|
| `zwave_s0_key_extract` | Z-Wave S0 pairing sniff: temp key all-zeros - extracao de network key |
| `zwave_replay_attack` | Replay de comandos Z-Wave sem S2 (desbloqueio de porta, switch, termostato) |

### Bridge ESP32 / Bruce (generic/external)

| Modulo | Descricao |
|--------|-----------|
| `bruce_serial_bridge` | Engine de fluxo serial para firmware Bruce ESP32 (15+ perfis) |
| `bruce_upstream_tracker` | Visualizador de catalogo de issues/PRs do firmware Bruce |
| `airgeddon_bridge` | Bridge multi-modo para Airgeddon |
| `wifiphisher_bridge` | Bridge Wifiphisher com sniffer embutido |
| `eaphammer_bridge` | Bridge EAPHammer (PEAP Win11 + coercao HTTP) |

---

## Integracao Bruce / ESP32 Marauder

O WXF inclui um engine completo de fluxo serial para o [BruceDevices/firmware](https://github.com/BruceDevices/firmware):

```
wxf > use generic/external/bruce_serial_bridge
wxf (BruceSerialBridge) > set serial_port /dev/ttyACM0
wxf (BruceSerialBridge) > set flow_profile capture_handshake_flow
wxf (BruceSerialBridge) > run

# Perfis de fluxo disponiveis:
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

## Documentacao e Wiki

- **[docs/wiki/en-US/](docs/wiki/en-US/)** - Ingles (padrao)
- **[docs/wiki/pt-BR/](docs/wiki/pt-BR/)** - Portugues
- **[docs/FULL_CATALOG.md](docs/FULL_CATALOG.md)** - catalogo completo de modulos
- **[docs/COVERAGE_MATRIX.md](docs/COVERAGE_MATRIX.md)** - matriz de cobertura de dispositivos

---

## Contribuindo

Veja [CONTRIBUTING.pt-BR.md](CONTRIBUTING.pt-BR.md) e [CONTRIBUTORS.pt-BR.md](CONTRIBUTORS.pt-BR.md).
Leia nosso [Codigo de Conduta](CODE_OF_CONDUCT.pt-BR.md) e a [Politica de Seguranca](SECURITY.pt-BR.md).

---

## Licenca

BSD 3-Clause License - veja [LICENSE](LICENSE) para detalhes.

**O WirelessXPL-Forge e destinado exclusivamente para pesquisa de seguranca e educacao autorizadas.**
O uso contra sistemas que voce nao possui ou nao tem permissao escrita explicita para testar e ilegal.

---

**Autor:** Andre Henrique ([@mrhenrike](https://github.com/mrhenrike)) | [Uniao Geek](https://github.com/Uniao-Geek)
**Linhagem:** [threat9/routersploit](https://github.com/threat9/routersploit) → RouterXPL-Forge → WirelessXPL-Forge
