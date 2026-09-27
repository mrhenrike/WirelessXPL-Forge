
---

## Novos Módulos — Requisitos de Hardware e Software (mai/2026)

### Core (todos os novos módulos)

| Componente | Instalação |
|---|---|
| `wirelessxpl/core/phase_gateway.py` | nativo — sem dependências externas |
| `wirelessxpl/core/hw_validator.py` | nativo — sem dependências externas |
| `wirelessxpl/core/polyglot_orchestrator.py` | gcc, rustc, go, ruby, node no PATH |

### Z-Wave (`zwave/zwave_attack_suite.py`)

| Requisito | Tipo | Instalação |
|---|---|---|
| Dongle Z-Wave USB (UZB7, Aeotec Z-Stick) | Hardware | Comprar: Aeotec Z-Stick Gen5+ |
| `pyserial` | Python | `pip install pyserial` |
| `pyzwave` | Python | `pip install pyzwave` |
| `gcc` | Sistema | `apt install build-essential` |

### Matter / Thread (`matter/matter_thread_bridge.py`)

| Requisito | Tipo | Instalação |
|---|---|---|
| `python-matter-server` | Python | `pip install python-matter-server` |
| `zeroconf` | Python | `pip install zeroconf` |
| `chip-tool` | Sistema | Build: github.com/project-chip/connectedhomeip |
| `avahi-browse` | Sistema | `apt install avahi-utils` |

### V2X / DSRC (`v2x/v2x_dsrc_attack.py`)

| Requisito | Tipo | Instalação |
|---|---|---|
| USRP B200/B210 ou HackRF One | Hardware | SDR com antena 5.9 GHz |
| `gnuradio` | Sistema | `apt install gnuradio` |
| `hackrf_transfer` | Sistema | `apt install hackrf` |
| `scapy` | Python | `pip install scapy` |

### TPMS (`tpms/tpms_spoof_replay.py`)

| Requisito | Tipo | Instalação |
|---|---|---|
| RTL-SDR (RX) | Hardware | RTL-SDR v3 |
| HackRF One (TX para spoof) | Hardware | HackRF One |
| `rtl_433` | Sistema | `apt install rtl-433` |
| `hackrf_transfer` | Sistema | `apt install hackrf` |

### UWB (`uwb/uwb_relay_attack.py`)

| Requisito | Tipo | Instalação |
|---|---|---|
| Decawave DWM1001 ou Qorvo DW3120 | Hardware | Kit de desenvolvimento UWB |
| `pyserial` | Python | `pip install pyserial` |
| `pyusb` | Python | `pip install pyusb` |

### DECT (`dect/dect_eavesdrop_bridge.py`)

| Requisito | Tipo | Instalação |
|---|---|---|
| RTL-SDR (RX @ 1.88-1.90 GHz) | Hardware | RTL-SDR v3 |
| HackRF One (TX para clone) | Hardware | HackRF One |
| `dect-scanner` | Sistema | `git clone https://github.com/znuh/dect-scanner && make` |

### NFC (`nfc/nfc_relay_ndef_bridge.py`)

| Requisito | Tipo | Instalação |
|---|---|---|
| ACR122U ou PN532 | Hardware | Leitor NFC USB |
| Proxmark3 (para clone Mifare) | Hardware | Proxmark3 RDV4 |
| `nfcpy` | Python | `pip install nfcpy` |
| `pyscard` | Python | `pip install pyscard` |
| `mfoc` + `nfc-mfclassic` | Sistema | `apt install mfoc libnfc-bin` |

### CVE-2025-13834 BT RFCOMM OOB

| Requisito | Tipo | Instalação |
|---|---|---|
| Adaptador BT BR/EDR | Hardware | Qualquer dongle BT classe 1/2 |
| `socket` + `struct` | Python | stdlib |

### CVE-2021-27289 Zigbee Replay

| Requisito | Tipo | Instalação |
|---|---|---|
| ApiMote ou CC2531 com firmware KillerBee | Hardware | Kit KillerBee |
| `killerbee` | Python | `pip install killerbee` |
| `scapy` | Python | `pip install scapy` |

### CVE-2024-30078 Windows WiFi Driver RCE

| Requisito | Tipo | Instalação |
|---|---|---|
| Adaptador WiFi com packet injection | Hardware | Alfa AWUS036ACS |
| `libpcap` + `gcc` | Sistema | `apt install libpcap-dev build-essential` |
| `scapy` | Python | `pip install scapy` |

### CVE-2024-45569 Qualcomm WLAN ML IE

| Requisito | Tipo | Instalação |
|---|---|---|
| Adaptador WiFi com beacon injection | Hardware | Alfa AWUS036ACS |
| `libpcap` + `gcc` | Sistema | `apt install libpcap-dev build-essential` |
| `scapy` | Python | `pip install scapy` |

### AirSnitch Client Isolation Bypass

| Requisito | Tipo | Instalação |
|---|---|---|
| 2x adaptadores WiFi monitor mode | Hardware | — |
| `airsnitch` | Python | `git clone https://github.com/vanhoefm/airsnitch /opt/airsnitch` |

### WIFIAIR-C2 Beacon C2 Channel

| Requisito | Tipo | Instalação |
|---|---|---|
| Adaptador WiFi com beacon injection | Hardware | Alfa AWUS036ACS |
| `scapy` | Python | `pip install scapy` |
| `pycryptodome` | Python | `pip install pycryptodome` |
