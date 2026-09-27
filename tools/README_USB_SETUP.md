# RT5370 USB WiFi — Guia Completo de Setup (VirtualBox + WSL2)

## Causa Raiz do VERR_READ_ERROR — Diagnóstico Completo

### O que estava causando o abort/VERR_READ_ERROR

A cadeia de causas (todas identificadas e corrigidas):

1. **USBPcap** instalado como `UpperFilter` na classe USB Hub (`{36FC9E60}`)
   — interceptava o read do device descriptor causando `VERR_READ_ERROR (-111)`

2. **`IsForced: true`** no usbipd para o RT5370  
   — capturava o dispositivo via `usbip.sys` antes do VirtualBox poder reivindicá-lo

3. **`vwifibus`** como UpperFilter no dispositivo RT5370 especificamente  
   — Windows Virtual WiFi Bus impedindo captura limpa pelo VBoxUSBMon

4. **USB filter com `action=hold`** no VirtualBox  
   — causava captura automática agressiva que conflitava com drivers existentes

### O que foi corrigido

| Problema | Correção | Status |
|---|---|---|
| USBPcap UpperFilter no USB Hub | Removido do registro | OK |
| USBPcap como instalação | Desinstalado completamente | OK |
| USBPcap service | Desabilitado (Start=4) | OK (requer reboot) |
| RT5370 IsForced no usbipd | `usbipd unbind --hardware-id 148F:5370` | OK |
| vwifibus no dispositivo RT5370 | Removido do UpperFilters | OK |
| VBox filter action=hold | Removido | OK |
| EHCI (USB 2.0) ausente no VBox | Habilitado | OK |

---

## PRÓXIMO PASSO OBRIGATÓRIO: Reinicialização

**O USBPcap está desinstalado e desabilitado, mas o driver de kernel ainda está**  
**carregado na memória (NOT_STOPPABLE). Um reboot limpa completamente.**

Após o reboot, a stack do RT5370 será:
```
Antes:  netr28ux → USBPcap → ACPI → USBHUB3  ← VERR_READ_ERROR
Depois: netr28ux → ACPI → USBHUB3             ← VBox funciona
```

---

## Pós-Reboot: Usando o RT5370 no VirtualBox

### 1. Conecte o RT5370 (cabo USB)

### 2. Inicie a VM Kali no VirtualBox

### 3. Conecte manualmente (Devices > USB)
No menu da VM: `Dispositivos → USB → Ralink 802.11 n WLAN [0101]`

Não há mais filtro automático (foi removido para evitar captura precoce).  
Você pode adicionar um filtro novamente DEPOIS de confirmar que o attach funciona.

### 4. Na VM Kali (terminal root)
```bash
lsusb | grep 148f                    # deve aparecer Ralink 148f:5370
sudo airmon-ng check kill
sudo airmon-ng start wlan0
sudo airodump-ng wlan0mon             # scan de APs
```

### 5. Executar setup completo
```bash
bash /path/to/kali_setup_rt5370.sh
```

---

## Re-adicionar filtro VBox (opcional, após confirmar que funciona)

```powershell
$vbox = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
& $vbox usbfilter add 0 --target "Kali-Linux-2025.1c" `
    --name "Ralink RT5370 WiFi" `
    --vendorid 148F --productid 5370
```

---

## Regra: Nunca use usbipd e VirtualBox para o mesmo dispositivo

```
usbipd list → se RT5370 aparecer como "Shared", execute:
usbipd unbind --hardware-id 148F:5370
```

---

## Opção 2: WSL2 (kernel customizado — sem reboot necessário)

O WSL2 já está configurado com o kernel `+` que tem `rt2800usb`:

```powershell
# Conectar RT5370 ao WSL
.\tools\attach_rt5370_wsl.ps1
```

```bash
# No WSL2
sudo modprobe rt2800usb
iw dev  # deve aparecer wlan0
```

---

## Troubleshooting Avançado

### Verificar se USBPcap foi removido (após reboot)
```powershell
Get-Service USBPcap -ErrorAction SilentlyContinue  # deve retornar vazio
pnputil /enum-devices /deviceid "USB\VID_148F&PID_5370" /stack
# stack deve ser: netr28ux → ACPI → USBHUB3 (sem USBPcap)
```

### Verificar filtros USB do registro
```powershell
(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{36FC9E60-C465-11CF-8056-444553540000}").UpperFilters
# deve retornar vazio ou $null
```

### Logs VirtualBox
```
D:\VMs\Daryus Labs\Kali-Linux-2025.1c\Logs\VBox.log
```
