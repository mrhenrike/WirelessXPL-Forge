#!/usr/bin/env bash
# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
# WXF Lab — Enable monitor mode on USB Wi-Fi adapter
# Run: sudo bash 02_monitor_mode.sh
set -euo pipefail

IFACE=""
LOG="/tmp/wxf_monitor.log"
echo "[$(date)] === Monitor Mode Setup ===" | tee "$LOG"

echo "[*] Detecting wireless interfaces..." | tee -a "$LOG"
iw dev 2>&1 | tee -a "$LOG"

WIFI_IFACES=$(iw dev 2>/dev/null | awk '/Interface/{print $2}')
if [ -z "$WIFI_IFACES" ]; then
    echo "[!] No wireless interfaces found." | tee -a "$LOG"
    echo "[*] Checking USB devices..." | tee -a "$LOG"
    lsusb 2>&1 | tee -a "$LOG"
    echo ""
    echo "[!] USB Wi-Fi adapter may need a driver." | tee -a "$LOG"
    echo "[*] Checking dmesg for USB Wi-Fi..." | tee -a "$LOG"
    dmesg | grep -iE 'wifi|wlan|rtl|realtek|8852|wireless|802\.11' | tail -20 | tee -a "$LOG"
    echo ""
    echo "[>>] If the adapter uses RTL8852BU chipset:" | tee -a "$LOG"
    echo "     Run: sudo bash 02a_rtl8852bu_driver.sh" | tee -a "$LOG"
    exit 1
fi

echo "[*] Available wireless interfaces: $WIFI_IFACES" | tee -a "$LOG"

for iface in $WIFI_IFACES; do
    echo "" | tee -a "$LOG"
    echo "[*] Interface: $iface" | tee -a "$LOG"
    iw "$iface" info 2>&1 | tee -a "$LOG"
    echo "[*] Supported modes:" | tee -a "$LOG"
    iw phy "$(iw "$iface" info | awk '/wiphy/{print "phy"$2}')" info 2>/dev/null | grep -A 10 "Supported interface modes" | tee -a "$LOG"
    IFACE="$iface"
done

if [ -z "$IFACE" ]; then
    echo "[!] No suitable interface found" | tee -a "$LOG"
    exit 1
fi

echo "" | tee -a "$LOG"
echo "[*] Killing interfering processes..." | tee -a "$LOG"
airmon-ng check kill 2>&1 | tee -a "$LOG"

echo "[*] Setting $IFACE to monitor mode..." | tee -a "$LOG"
ip link set "$IFACE" down 2>&1 | tee -a "$LOG"
iw "$IFACE" set monitor control 2>&1 | tee -a "$LOG" || {
    echo "[*] Fallback: using airmon-ng..." | tee -a "$LOG"
    airmon-ng start "$IFACE" 2>&1 | tee -a "$LOG"
    IFACE="${IFACE}mon"
}
ip link set "$IFACE" up 2>&1 | tee -a "$LOG"

echo "[*] Verifying monitor mode..." | tee -a "$LOG"
iw "$IFACE" info 2>&1 | tee -a "$LOG"

MODE=$(iw "$IFACE" info 2>/dev/null | awk '/type/{print $2}')
if [ "$MODE" = "monitor" ]; then
    echo "" | tee -a "$LOG"
    echo "[OK] $IFACE is in monitor mode!" | tee -a "$LOG"
    echo "[>>] Ready for scanning. Run:" | tee -a "$LOG"
    echo "     sudo bash 03_recon_scan.sh $IFACE" | tee -a "$LOG"
else
    echo "[!] Monitor mode failed. Current mode: $MODE" | tee -a "$LOG"
fi
