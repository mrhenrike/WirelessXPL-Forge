#!/usr/bin/env bash
# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
# WXF Lab — Install RTL8852BU driver for USB Wi-Fi adapter
# Run: sudo bash 02a_rtl8852bu_driver.sh
set -euo pipefail

LOG="/tmp/wxf_driver.log"
DRIVER_DIR="/opt/rtl8852bu"
echo "[$(date)] === RTL8852BU Driver Install ===" | tee "$LOG"

echo "[*] USB devices:" | tee -a "$LOG"
lsusb | tee -a "$LOG"

echo "[*] Kernel: $(uname -r)" | tee -a "$LOG"

if [ -d "$DRIVER_DIR" ]; then
    echo "[*] Removing old driver source..." | tee -a "$LOG"
    rm -rf "$DRIVER_DIR"
fi

echo "[*] Cloning RTL8852BU driver (morrownr)..." | tee -a "$LOG"
git clone --depth 1 https://github.com/morrownr/rtl8852bu.git "$DRIVER_DIR" 2>&1 | tee -a "$LOG"

cd "$DRIVER_DIR"

echo "[*] Building driver..." | tee -a "$LOG"
make -j"$(nproc)" 2>&1 | tee -a "$LOG"

echo "[*] Installing driver..." | tee -a "$LOG"
make install 2>&1 | tee -a "$LOG"

echo "[*] Loading module..." | tee -a "$LOG"
modprobe 8852bu 2>&1 | tee -a "$LOG" || insmod 8852bu.ko 2>&1 | tee -a "$LOG"

sleep 2
echo "[*] Checking interfaces..." | tee -a "$LOG"
ip link show | tee -a "$LOG"
iw dev 2>&1 | tee -a "$LOG"

echo ""
echo "[OK] Driver installed. Run: sudo bash 02_monitor_mode.sh" | tee -a "$LOG"
