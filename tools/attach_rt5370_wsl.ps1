# attach_rt5370_wsl.ps1 — Detecta e conecta RT5370 ao WSL2 automaticamente
# Execute no PowerShell (sem precisar de admin) toda vez que reconectar o adapter
#
# Uso: .\attach_rt5370_wsl.ps1
#      .\attach_rt5370_wsl.ps1 -watch   (monitora continuamente)

param([switch]$watch)

function Attach-RT5370 {
    Write-Host "[*] Verificando RT5370 (148f:5370)..." -ForegroundColor Cyan
    $list = usbipd list 2>&1
    $rt5370 = $list | Where-Object { $_ -match "148f:5370" }

    if (-not $rt5370) {
        Write-Host "[-] RT5370 nao detectado. Conecte o adaptador USB." -ForegroundColor Yellow
        return $false
    }

    $busid = ($rt5370 | Select-Object -First 1).Trim().Split(" ")[0]
    $state = if ($rt5370 -match "Shared") { "Shared" } elseif ($rt5370 -match "Not shared") { "Not shared" } else { "?" }

    Write-Host "[+] RT5370 detectado: BUSID=$busid STATE=$state" -ForegroundColor Green

    if ($state -ne "Shared") {
        Write-Host "[*] Bindando dispositivo ao usbipd..." -ForegroundColor Cyan
        usbipd bind --busid $busid 2>&1 | Write-Host
        Start-Sleep -Seconds 1
    }

    Write-Host "[*] Conectando RT5370 ao WSL2..." -ForegroundColor Cyan
    usbipd attach --wsl --busid $busid 2>&1 | Write-Host
    Start-Sleep -Seconds 2

    Write-Host "[*] Carregando driver rt2800usb no WSL..." -ForegroundColor Cyan
    wsl -e bash -c "sudo modprobe rt2800usb && echo '[+] rt2800usb carregado' || echo '[!] Falha ao carregar rt2800usb'"

    Write-Host "[*] Verificando interface wireless..." -ForegroundColor Cyan
    $wlan = wsl -e bash -c "iw dev 2>/dev/null | grep Interface | head -3"
    if ($wlan) {
        Write-Host "[+] Interface(s) wireless detectadas:" -ForegroundColor Green
        Write-Host "    $wlan"
        Write-Host ""
        Write-Host "[+] RT5370 pronto no WSL! Execute:" -ForegroundColor Green
        Write-Host "    wsl -e bash -c 'sudo airmon-ng start wlan0'" -ForegroundColor White
        Write-Host "    wsl -e bash -c 'sudo airodump-ng wlan0mon'" -ForegroundColor White
    } else {
        Write-Host "[!] Nenhuma interface wlan detectada. Verifique: wsl -e bash -c 'dmesg | grep rt2800'" -ForegroundColor Yellow
    }
    return $true
}

if ($watch) {
    Write-Host "[*] Modo watch — aguardando RT5370 ser conectado..." -ForegroundColor Cyan
    while ($true) {
        $list = usbipd list 2>&1
        if ($list -match "148f:5370") {
            Attach-RT5370
            Write-Host "[*] Aguardando proxima reconexao..." -ForegroundColor Gray
        }
        Start-Sleep -Seconds 3
    }
} else {
    Attach-RT5370
}
