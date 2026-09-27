#!/usr/bin/env bash
# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
# WXF Lab — WSL Wireless Setup (run once with: sudo bash 01_wsl_setup.sh)
set -euo pipefail

LOG="/tmp/wxf_setup.log"
echo "[$(date)] === WXF WSL Setup ===" | tee "$LOG"

echo "[*] Updating package lists..." | tee -a "$LOG"
apt-get update 2>&1 | tee -a "$LOG"

echo "[*] Installing wireless tools..." | tee -a "$LOG"
apt-get install -y \
    aircrack-ng \
    mdk4 \
    reaver \
    hcxdumptool \
    hcxtools \
    wireless-tools \
    iw \
    net-tools \
    usbutils \
    pciutils \
    python3 \
    python3-pip \
    python3-venv \
    hashcat \
    tshark \
    tcpdump \
    macchanger \
    build-essential \
    dkms \
    linux-headers-$(uname -r) \
    git \
    bc \
    2>&1 | tee -a "$LOG"

echo "[*] Installing Python deps for WXF..." | tee -a "$LOG"
pip3 install --break-system-packages scapy pycryptodome 2>&1 | tee -a "$LOG" || \
    pip3 install scapy pycryptodome 2>&1 | tee -a "$LOG"

echo "[*] Configuring passwordless sudo for wireless tools..." | tee -a "$LOG"
SUDOERS_WXF="/etc/sudoers.d/wxf-wireless"
cat > "$SUDOERS_WXF" <<'SUDOEOF'
# WXF wireless tools — passwordless execution
%sudo ALL=(ALL) NOPASSWD: /usr/sbin/airmon-ng
%sudo ALL=(ALL) NOPASSWD: /usr/sbin/airodump-ng
%sudo ALL=(ALL) NOPASSWD: /usr/sbin/aireplay-ng
%sudo ALL=(ALL) NOPASSWD: /usr/sbin/aircrack-ng
%sudo ALL=(ALL) NOPASSWD: /usr/bin/mdk4
%sudo ALL=(ALL) NOPASSWD: /usr/bin/reaver
%sudo ALL=(ALL) NOPASSWD: /usr/bin/hcxdumptool
%sudo ALL=(ALL) NOPASSWD: /usr/bin/hcxpcapngtool
%sudo ALL=(ALL) NOPASSWD: /usr/bin/hcxhashtool
%sudo ALL=(ALL) NOPASSWD: /sbin/iw
%sudo ALL=(ALL) NOPASSWD: /sbin/iwconfig
%sudo ALL=(ALL) NOPASSWD: /sbin/ifconfig
%sudo ALL=(ALL) NOPASSWD: /sbin/ip
%sudo ALL=(ALL) NOPASSWD: /usr/bin/macchanger
%sudo ALL=(ALL) NOPASSWD: /usr/bin/tcpdump
%sudo ALL=(ALL) NOPASSWD: /usr/bin/tshark
SUDOEOF
chmod 0440 "$SUDOERS_WXF"

echo "[*] Verifying installations..." | tee -a "$LOG"
for tool in airmon-ng airodump-ng aireplay-ng aircrack-ng mdk4 reaver hcxdumptool hcxpcapngtool iw iwconfig hashcat tshark tcpdump python3; do
    if command -v "$tool" &>/dev/null; then
        echo "  [OK] $tool: $(command -v $tool)" | tee -a "$LOG"
    else
        echo "  [!!] $tool: NOT FOUND" | tee -a "$LOG"
    fi
done

echo ""
echo "[*] Checking kernel wireless support..." | tee -a "$LOG"
if [ -d /sys/class/net ]; then
    echo "  Net interfaces:" | tee -a "$LOG"
    ls /sys/class/net/ | tee -a "$LOG"
fi

echo ""
echo "[OK] Setup complete. Log saved to $LOG" | tee -a "$LOG"
echo "[>>] Next: From Windows PowerShell (admin), run:" | tee -a "$LOG"
echo "     usbipd bind --busid 1-11 --force" | tee -a "$LOG"
echo "     usbipd attach --wsl --busid 1-11" | tee -a "$LOG"
echo "[>>] Then in WSL:" | tee -a "$LOG"
echo "     sudo bash 02_monitor_mode.sh" | tee -a "$LOG"
