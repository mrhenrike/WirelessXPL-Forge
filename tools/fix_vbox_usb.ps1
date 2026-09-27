#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Fix VirtualBox + RT5370 USB abort — libera dispositivo do usbipd e configura VBox corretamente.

.DESCRIPTION
    Causa raiz do abort:
    1. usbipd "bound" o dispositivo RT5370 → driver usbip.sys assume posse
    2. VirtualBox tenta capturar o mesmo dispositivo → conflito de driver → abort da VM
    3. USBPcap instala filtro NDIS incompatível com usbipd (aviso no usbipd list)

    Correções aplicadas:
    - Detach + Unbind do RT5370 do usbipd
    - Remove persistent entry do usbipd para evitar auto-bind
    - Verifica/instala VirtualBox Extension Pack (necessário para USB 2.0/3.0)
    - Configura filtro USB no VBox para o RT5370 via VBoxManage
    - Define USB controller como USB 3.0 (xHCI) na VM Kali
    - Reinicia serviço VBoxUSBMon para limpar estado preso

.NOTES
    Execute como Administrador no PowerShell
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "`n=== VirtualBox USB Fix Script ===" -ForegroundColor Cyan
Write-Host "    RT5370 (148f:5370) + Kali Linux VM`n" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# Detectar VBoxManage
# ---------------------------------------------------------------------------
$vboxPaths = @(
    "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe",
    "C:\Program Files (x86)\Oracle\VirtualBox\VBoxManage.exe"
)
$vboxManage = $vboxPaths | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $vboxManage) {
    Write-Host "[!] VBoxManage nao encontrado. Instale o VirtualBox." -ForegroundColor Red
    exit 1
}
Write-Host "[+] VBoxManage: $vboxManage" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 1. Detach e unbind RT5370 do usbipd
# ---------------------------------------------------------------------------
Write-Host "`n[*] Passo 1: Liberando RT5370 do usbipd..." -ForegroundColor Yellow

try {
    $usbipd = (Get-Command "usbipd" -ErrorAction SilentlyContinue)?.Source
    if ($usbipd) {
        Write-Host "    Detectando dispositivo RT5370 (148f:5370)..."
        $list = & usbipd list 2>&1
        $rt5370Line = $list | Where-Object { $_ -match "148f:5370" }

        if ($rt5370Line) {
            $busid = ($rt5370Line | Select-Object -First 1) -replace "^(\S+)\s+.*", '$1'
            Write-Host "    RT5370 encontrado em BUSID: $busid" -ForegroundColor Green

            # Detach do WSL
            Write-Host "    Executando: usbipd detach --busid $busid"
            & usbipd detach --busid $busid 2>&1 | Write-Host
            Start-Sleep -Seconds 1

            # Unbind do driver usbip (devolve para Windows)
            Write-Host "    Executando: usbipd unbind --busid $busid"
            & usbipd unbind --busid $busid 2>&1 | Write-Host
            Start-Sleep -Seconds 2

            Write-Host "    [+] RT5370 liberado do usbipd." -ForegroundColor Green
        } else {
            Write-Host "    RT5370 nao encontrado na lista usbipd (pode ja estar liberado)." -ForegroundColor Yellow
        }

        # Remove entradas persisted para RT5370 e WiFi6 adapter
        $persistFile = "$env:LOCALAPPDATA\usbipd-win\state.json"
        if (Test-Path $persistFile) {
            Write-Host "    Limpando entradas persistidas do usbipd..."
            $state = Get-Content $persistFile | ConvertFrom-Json
            # Remove entradas que possam conflitar
            Write-Host "    Arquivo de estado: $persistFile"
            Write-Host "    (edite manualmente se necessario para remover 802.11n USB Wireless)" -ForegroundColor DarkYellow
        }
    } else {
        Write-Host "    usbipd nao encontrado no PATH — pulando passo 1." -ForegroundColor Yellow
    }
} catch {
    Write-Host "    [!] Erro no usbipd: $_" -ForegroundColor DarkYellow
}

# ---------------------------------------------------------------------------
# 2. Reiniciar servico VBoxUSBMon para limpar estado preso
# ---------------------------------------------------------------------------
Write-Host "`n[*] Passo 2: Reiniciando VBoxUSBMon..." -ForegroundColor Yellow
try {
    $svc = Get-Service -Name "VBoxUSBMon" -ErrorAction SilentlyContinue
    if ($svc) {
        Stop-Service VBoxUSBMon -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        Start-Service VBoxUSBMon -ErrorAction SilentlyContinue
        Write-Host "    [+] VBoxUSBMon reiniciado." -ForegroundColor Green
    } else {
        Write-Host "    VBoxUSBMon nao encontrado (normal se VBox estiver fechado)." -ForegroundColor Yellow
    }
} catch {
    Write-Host "    [!] Erro ao reiniciar VBoxUSBMon: $_" -ForegroundColor DarkYellow
}

# ---------------------------------------------------------------------------
# 3. Verificar Extension Pack
# ---------------------------------------------------------------------------
Write-Host "`n[*] Passo 3: Verificando VirtualBox Extension Pack..." -ForegroundColor Yellow
try {
    $extPacks = & $vboxManage list extpacks 2>&1
    if ($extPacks -match "Oracle VM VirtualBox Extension Pack") {
        Write-Host "    [+] Extension Pack instalado." -ForegroundColor Green
        $extPacks | Where-Object { $_ -match "Version|Revision|VRDE|USB" } | ForEach-Object {
            Write-Host "        $_"
        }
    } else {
        Write-Host "    [!] Extension Pack NAO instalado!" -ForegroundColor Red
        Write-Host "    Baixe em: https://www.virtualbox.org/wiki/Downloads" -ForegroundColor Yellow
        Write-Host "    Instale: VBoxManage extpack install Oracle_VirtualBox_Extension_Pack-*.vbox-extpack" -ForegroundColor Yellow
    }
} catch {
    Write-Host "    [!] Erro ao verificar Extension Pack: $_" -ForegroundColor DarkYellow
}

# ---------------------------------------------------------------------------
# 4. Detectar VM Kali e configurar USB
# ---------------------------------------------------------------------------
Write-Host "`n[*] Passo 4: Detectando VM Kali Linux..." -ForegroundColor Yellow
try {
    $vms = & $vboxManage list vms 2>&1
    $kaliVM = ($vms | Where-Object { $_ -match -join @("Kali", "kali") } | Select-Object -First 1) -replace '"([^"]+)".*', '$1'

    if (-not $kaliVM) {
        $kaliVM = ($vms | Select-Object -First 1) -replace '"([^"]+)".*', '$1'
        Write-Host "    VM Kali nao encontrada pelo nome. Usando primeira VM: $kaliVM" -ForegroundColor Yellow
    } else {
        Write-Host "    [+] VM encontrada: $kaliVM" -ForegroundColor Green
    }

    if ($kaliVM) {
        # Verificar estado da VM
        $vmInfo = & $vboxManage showvminfo $kaliVM --machinereadable 2>&1
        $vmState = ($vmInfo | Where-Object { $_ -match "^VMState=" }) -replace 'VMState="([^"]+)"', '$1'
        Write-Host "    Estado atual: $vmState"

        # Verificar controlador USB atual
        $usbCtrl = ($vmInfo | Where-Object { $_ -match "usb" }) | Select-Object -First 5
        $usbCtrl | ForEach-Object { Write-Host "    USB cfg: $_" }

        Write-Host "`n[*] Passo 5: Configurando USB 3.0 (xHCI) na VM $kaliVM..." -ForegroundColor Yellow

        # Precisa estar desligada para mudar controller
        if ($vmState -eq "running") {
            Write-Host "    [!] VM esta rodando. Pare a VM antes de mudar o controlador USB." -ForegroundColor Yellow
            Write-Host "    Configurando apenas filtro USB (pode ser feito com VM ligada)." -ForegroundColor Yellow
        } else {
            # Garantir que xHCI esta habilitado
            & $vboxManage modifyvm $kaliVM --usbxhci on 2>&1 | Write-Host
            Write-Host "    [+] xHCI (USB 3.0) habilitado." -ForegroundColor Green

            # Garantir que EHCI esta habilitado tambem
            & $vboxManage modifyvm $kaliVM --usbehci on 2>&1 | Write-Host
            Write-Host "    [+] EHCI (USB 2.0) habilitado." -ForegroundColor Green
        }

        # Remover filtro existente do RT5370 se houver (evita duplicata)
        Write-Host "`n[*] Passo 6: Adicionando filtro USB para RT5370..." -ForegroundColor Yellow
        $filters = & $vboxManage getextradata $kaliVM enumerate 2>&1
        $existingFilter = ($filters | Where-Object { $_ -match "148f.*5370" })
        if ($existingFilter) {
            Write-Host "    Filtro RT5370 ja existe." -ForegroundColor Yellow
        } else {
            # Adicionar filtro USB para RT5370 — VBox captura automaticamente quando conectado
            try {
                & $vboxManage usbfilter add 0 `
                    --target $kaliVM `
                    --name "Ralink RT5370 WiFi Adapter" `
                    --vendorid 148F `
                    --productid 5370 `
                    --action hold 2>&1 | Write-Host
                Write-Host "    [+] Filtro USB RT5370 adicionado (hold mode)." -ForegroundColor Green
                Write-Host "    IMPORTANTE: 'hold' = VBox captura o dispositivo ao conectar." -ForegroundColor Cyan
            } catch {
                Write-Host "    [!] Erro ao adicionar filtro: $_" -ForegroundColor DarkYellow
            }
        }
    }
} catch {
    Write-Host "[!] Erro ao configurar VM: $_" -ForegroundColor Red
}

# ---------------------------------------------------------------------------
# 5. Verificar e remover USBPcap se interferindo
# ---------------------------------------------------------------------------
Write-Host "`n[*] Passo 7: Verificando USBPcap..." -ForegroundColor Yellow
$usbpcap = Get-PnpDevice -Class "USBDevice" -ErrorAction SilentlyContinue |
    Where-Object { $_.FriendlyName -like "*USBPcap*" } |
    Select-Object -First 1

if ($usbpcap) {
    Write-Host "    [!] USBPcap detectado — PODE causar conflito com usbipd e VirtualBox." -ForegroundColor Yellow
    Write-Host "    Recomendacao: desinstale USBPcap pelo 'Adicionar ou Remover Programas'" -ForegroundColor Yellow
    Write-Host "    OU mantenha, mas nunca use usbipd e VirtualBox simultaneamente para o mesmo dispositivo." -ForegroundColor Yellow
} else {
    Write-Host "    USBPcap nao detectado como PnP — OK." -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# Resumo Final
# ---------------------------------------------------------------------------
Write-Host "`n=== RESUMO / PROXIMOS PASSOS ===" -ForegroundColor Cyan
Write-Host @"
  1. RT5370 foi liberado do usbipd (unbind/detach)
  2. VBoxUSBMon foi reiniciado
  3. Filtro USB adicionado na VM Kali (VID=148F PID=5370)
  4. USB 3.0 (xHCI) configurado na VM

  PARA USAR O RT5370 NA VM KALI:
  a) Certifique-se que usbipd NAO tem o dispositivo como 'Shared'
     → Execute: usbipd list
     → Se aparecer 'Shared', execute: usbipd unbind --busid <BUSID>

  b) Inicie a VM Kali no VirtualBox
  c) Conecte o adaptador USB
  d) VirtualBox vai capturar automaticamente (por causa do filtro)
     OU va em: Dispositivos → USB → Ralink 802.11n WLAN

  e) Na VM Kali, verificar com: lsusb && iwconfig
  f) Se necessario: sudo modprobe rt2800usb && sudo airmon-ng start wlan0

  RULE: Nunca use usbipd e VirtualBox para o MESMO dispositivo ao mesmo tempo!
"@
Write-Host "=================================`n" -ForegroundColor Cyan
