# Guia de Instalacao / Installation Guide

**Author:** Andre Henrique ([@mrhenrike](https://github.com/mrhenrike)) | **Uniao Geek**

**WirelessXPL-Forge v1.8.0** | BSD-3-Clause

---

## Indice / Table of Contents

- [PT-BR: Guia de Instalacao](#pt-br-guia-de-instalacao)
- [EN: Installation Guide](#en-installation-guide)

---

## PT-BR: Guia de Instalacao

### Requisitos minimos de sistema

| Requisito | Minimo | Recomendado |
|---|---|---|
| Python | 3.9+ | 3.11 ou 3.12 |
| Sistema operacional | Linux (ataques nativos) | Kali Linux 2024+ / Ubuntu 22.04+ |
| RAM | 512 MB | 2 GB+ |
| Disco | 200 MB | 2 GB+ (com ferramentas externas) |

> **Nota:** Modulos de modo `info` funcionam no Windows e macOS. Modulos de ataque ativo (captura, injecao, monitor mode) requerem Linux com driver WiFi compativel ou WSL2.

---

### Instalacao basica (core)

```bash
pip install wirelessxpl
```

O pacote core inclui suporte nativo a WiFi via Scapy e DNS via dnslib, sem dependencias extras de hardware.

---

### Instalacao por caso de uso

#### Quero fazer auditoria WiFi completa (WPA2/WPA3/WPS/PMKID/Evil Twin)

```bash
pip install "wirelessxpl[wifi]"
```

Inclui: `scapy`, `dnslib`, `cryptography`, `netaddr`

Ferramentas externas necessarias:
```bash
sudo apt install aircrack-ng hcxtools hcxdumptool hostapd
```

---

#### Quero pesquisa BLE/Bluetooth (KNOB, BLESA, GATT, BlueBorne)

```bash
pip install "wirelessxpl[bt]"
```

Inclui: `bleak`, `pybluez` (Linux), `dbus-python` (Linux)

Ferramentas externas necessarias:
```bash
sudo apt install bluez bluetooth
```

---

#### Quero analise de SIM card / Celular / LTE / 5G (IMSI, SS7, SIMjacker)

```bash
pip install "wirelessxpl[cellular]"
```

Inclui: `pyscard`, `pytlv`, `pyserial`

Ferramentas externas / hardware necessario:
- Leitor de smart card (PC/SC compativel)
- SDR hardware para SS7/LTE (ex: BladeRF, USRP)
- srsRAN ou OpenBTS para lab LTE/5G

---

#### Quero SDR / RF / SubGHz (RTL-SDR, replay, jam, 433 MHz, 915 MHz)

```bash
pip install "wirelessxpl[rf]"
```

Inclui: `pyrtlsdr` (Linux/macOS), `pyserial`, `pyusb`, `numpy`

Hardware necessario:
- RTL-SDR, HackRF One, YARD Stick One, ou similar

---

#### Quero analise de Drones / UAV / MAVLink (skyjack, spoof, deauth)

```bash
pip install "wirelessxpl[drone]"
```

Inclui: `pymavlink`, `dronekit`

---

#### Quero analise GPS / Wardriving (GPSD, exportar GPX)

```bash
pip install "wirelessxpl[gps]"
```

Inclui: `gpsd-py3`, `gpxpy`

Hardware necessario:
- Receptor GPS USB ou GPSD configurado no sistema

---

#### Quero pesquisa IoT / Zigbee / RFID (Killerbee, Zigator, NFC)

```bash
pip install "wirelessxpl[iot]"
```

Inclui: `pyserial`, `pyusb`

Hardware necessario:
- Sniffer Zigbee (ex: ATUSB, ApiMote) para Killerbee
- Leitor RFID USB (ex: ACR122U, Proxmark3)

---

#### Quero infrared / IR (blaster, replay)

```bash
pip install "wirelessxpl[ir]"
```

Inclui: `pyserial`, `pyusb`

Hardware necessario:
- Blaster IR USB (ex: IRTOY, LIRC-compativel)

---

#### Quero tudo instalado

```bash
pip install "wirelessxpl[all]"
```

Instala todos os pacotes Python opcionais (~135 MB estimado).

---

#### Combinacoes personalizadas

```bash
# WiFi + Bluetooth + Celular
pip install "wirelessxpl[wifi,bt,cellular]"

# WiFi + GPS para wardriving completo
pip install "wirelessxpl[wifi,gps]"

# RF + Drone para pesquisa UAV
pip install "wirelessxpl[rf,drone]"
```

---

### Tabela de extras

| Extra | Tecnologia | Pacotes pip | Tamanho estimado |
|---|---|---|---|
| (nenhum) | Core WiFi nativo via Scapy | scapy, dnslib, cryptography | ~45 MB |
| `[wifi]` | WiFi 802.11 completo | scapy, dnslib, cryptography, netaddr | +0 MB |
| `[bt]` | Bluetooth BLE + Classic | bleak, pybluez, dbus-python | +8 MB |
| `[cellular]` | Celular/SIM/LTE/5G | pyscard, pytlv, pyserial | +5 MB |
| `[rf]` | RF/SDR/SubGHz | pyrtlsdr, pyserial, pyusb, numpy | +50 MB |
| `[drone]` | Drones/UAV/MAVLink | pymavlink, dronekit | +20 MB |
| `[ir]` | Infrared | pyserial, pyusb | +3 MB |
| `[gps]` | GPS/Wardriving | gpsd-py3, gpxpy | +3 MB |
| `[iot]` | IoT/Zigbee/RFID | pyserial, pyusb | +3 MB |
| `[all]` | Tudo acima | (todos os pacotes acima) | ~135 MB |

---

### Verificar o que esta instalado

```bash
python -m wirelessxpl --list-modules
```

Ou dentro do shell interativo:

```
wxf > show modules
wxf > search device=wifi
wxf > search device=bluetooth
```

---

### Ferramentas externas por categoria

| Ferramenta | Categoria | Instalacao (Debian/Kali) |
|---|---|---|
| aircrack-ng | WiFi | `sudo apt install aircrack-ng` |
| hcxdumptool | WiFi (PMKID) | `sudo apt install hcxdumptool` |
| hcxtools | WiFi (conversao) | `sudo apt install hcxtools` |
| hashcat | Cracking WPA/WPA2/WPA3 | `sudo apt install hashcat` |
| hostapd | Rogue AP / Evil Twin | `sudo apt install hostapd` |
| mdk4 | Deauth/flood | `sudo apt install mdk4` |
| wash | WPS scan | `sudo apt install reaver` |
| bluez | Bluetooth | `sudo apt install bluez bluetooth` |
| gpsd | GPS daemon | `sudo apt install gpsd gpsd-clients` |
| tshark | Disseccao de pacotes | `sudo apt install tshark` |

---

## EN: Installation Guide

### Minimum system requirements

| Requirement | Minimum | Recommended |
|---|---|---|
| Python | 3.9+ | 3.11 or 3.12 |
| Operating system | Linux (active attacks) | Kali Linux 2024+ / Ubuntu 22.04+ |
| RAM | 512 MB | 2 GB+ |
| Disk | 200 MB | 2 GB+ (with external tools) |

> **Note:** `info` mode modules work on Windows and macOS. Active attack modules (capture, injection, monitor mode) require Linux with a compatible WiFi driver or WSL2.

---

### Basic install (core)

```bash
pip install wirelessxpl
```

The core package includes native WiFi support via Scapy and DNS via dnslib, without extra hardware dependencies.

---

### Install by use case

#### I want full WiFi auditing (WPA2/WPA3/WPS/PMKID/Evil Twin)

```bash
pip install "wirelessxpl[wifi]"
```

Includes: `scapy`, `dnslib`, `cryptography`, `netaddr`

Required external tools:
```bash
sudo apt install aircrack-ng hcxtools hcxdumptool hostapd
```

---

#### I want BLE/Bluetooth research (KNOB, BLESA, GATT, BlueBorne)

```bash
pip install "wirelessxpl[bt]"
```

Includes: `bleak`, `pybluez` (Linux), `dbus-python` (Linux)

Required external tools:
```bash
sudo apt install bluez bluetooth
```

---

#### I want SIM card / Cellular / LTE / 5G analysis (IMSI, SS7, SIMjacker)

```bash
pip install "wirelessxpl[cellular]"
```

Includes: `pyscard`, `pytlv`, `pyserial`

Required external hardware/tools:
- PC/SC compatible smart card reader
- SDR hardware for SS7/LTE (e.g. BladeRF, USRP)
- srsRAN or OpenBTS for LTE/5G lab

---

#### I want SDR / RF / SubGHz (RTL-SDR, replay, jam, 433 MHz, 915 MHz)

```bash
pip install "wirelessxpl[rf]"
```

Includes: `pyrtlsdr` (Linux/macOS), `pyserial`, `pyusb`, `numpy`

Required hardware:
- RTL-SDR, HackRF One, YARD Stick One, or similar

---

#### I want Drone / UAV / MAVLink analysis (skyjack, spoof, deauth)

```bash
pip install "wirelessxpl[drone]"
```

Includes: `pymavlink`, `dronekit`

---

#### I want GPS / Wardriving (GPSD, GPX export)

```bash
pip install "wirelessxpl[gps]"
```

Includes: `gpsd-py3`, `gpxpy`

Required hardware:
- USB GPS receiver or GPSD configured on the system

---

#### I want IoT / Zigbee / RFID research (Killerbee, Zigator, NFC)

```bash
pip install "wirelessxpl[iot]"
```

Includes: `pyserial`, `pyusb`

Required hardware:
- Zigbee sniffer (e.g. ATUSB, ApiMote) for Killerbee
- RFID USB reader (e.g. ACR122U, Proxmark3)

---

#### I want everything installed

```bash
pip install "wirelessxpl[all]"
```

Installs all optional Python packages (~135 MB estimated).

---

#### Custom combinations

```bash
# WiFi + Bluetooth + Cellular
pip install "wirelessxpl[wifi,bt,cellular]"

# WiFi + GPS for full wardriving
pip install "wirelessxpl[wifi,gps]"

# RF + Drone for UAV research
pip install "wirelessxpl[rf,drone]"
```

---

### Extras table

| Extra | Technology | pip packages | Estimated size |
|---|---|---|---|
| (none) | Core WiFi via Scapy | scapy, dnslib, cryptography | ~45 MB |
| `[wifi]` | Full WiFi 802.11 | scapy, dnslib, cryptography, netaddr | +0 MB |
| `[bt]` | Bluetooth BLE + Classic | bleak, pybluez, dbus-python | +8 MB |
| `[cellular]` | Cellular/SIM/LTE/5G | pyscard, pytlv, pyserial | +5 MB |
| `[rf]` | RF/SDR/SubGHz | pyrtlsdr, pyserial, pyusb, numpy | +50 MB |
| `[drone]` | Drones/UAV/MAVLink | pymavlink, dronekit | +20 MB |
| `[ir]` | Infrared | pyserial, pyusb | +3 MB |
| `[gps]` | GPS/Wardriving | gpsd-py3, gpxpy | +3 MB |
| `[iot]` | IoT/Zigbee/RFID | pyserial, pyusb | +3 MB |
| `[all]` | All above | (all packages above) | ~135 MB |

---

### Check what is installed

```bash
python -m wirelessxpl --list-modules
```

Or inside the interactive shell:

```
wxf > show modules
wxf > search device=wifi
wxf > search device=bluetooth
```

---

### External tools by category

| Tool | Category | Install (Debian/Kali) |
|---|---|---|
| aircrack-ng | WiFi | `sudo apt install aircrack-ng` |
| hcxdumptool | WiFi (PMKID) | `sudo apt install hcxdumptool` |
| hcxtools | WiFi (conversion) | `sudo apt install hcxtools` |
| hashcat | WPA/WPA2/WPA3 cracking | `sudo apt install hashcat` |
| hostapd | Rogue AP / Evil Twin | `sudo apt install hostapd` |
| mdk4 | Deauth/flood | `sudo apt install mdk4` |
| wash | WPS scan | `sudo apt install reaver` |
| bluez | Bluetooth | `sudo apt install bluez bluetooth` |
| gpsd | GPS daemon | `sudo apt install gpsd gpsd-clients` |
| tshark | Packet dissection | `sudo apt install tshark` |

---

*For complete hardware requirements per module, see [PREREQUISITES.md](PREREQUISITES.md).*
