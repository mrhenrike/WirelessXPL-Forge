# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
# WXF Lab — Attach USB Wi-Fi adapter to WSL via usbipd
# Run: PowerShell (Admin) > .\00_win_usb_attach.ps1

$ErrorActionPreference = "Stop"

Write-Host "[*] WXF Lab — USB Wi-Fi Passthrough to WSL" -ForegroundColor Cyan
Write-Host ""

# Refresh PATH to pick up usbipd
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

Write-Host "[*] Listing USB devices..." -ForegroundColor Yellow
usbipd list

Write-Host ""
Write-Host "[*] Binding USB Wi-Fi adapter (busid 1-11, VID:A69C PID:8D81)..." -ForegroundColor Yellow
usbipd bind --busid 1-11 --force 2>&1
Write-Host "[OK] Bound successfully." -ForegroundColor Green

Write-Host ""
Write-Host "[*] Attaching to WSL..." -ForegroundColor Yellow
usbipd attach --wsl --busid 1-11 2>&1
Write-Host "[OK] Attached to WSL!" -ForegroundColor Green

Write-Host ""
Write-Host "[*] Verifying in WSL..." -ForegroundColor Yellow
wsl -d Ubuntu -- bash -c "lsusb 2>/dev/null; echo '---'; ip link show 2>/dev/null; echo '---'; iw dev 2>/dev/null"

Write-Host ""
Write-Host "[>>] USB Wi-Fi adapter is now available in WSL." -ForegroundColor Cyan
Write-Host "[>>] In WSL, run: sudo bash /mnt/d/Projetos-SafeLabs/laboratory/wifi-recon/scripts/02_monitor_mode.sh" -ForegroundColor White
