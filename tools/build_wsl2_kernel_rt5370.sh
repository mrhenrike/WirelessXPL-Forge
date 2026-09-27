#!/usr/bin/env bash
# build_wsl2_kernel_rt5370.sh — Compila kernel WSL2 com suporte rt2800usb
#
# Execute DENTRO do WSL2 (Ubuntu) como usuário normal (não root)
# O script usa sudo apenas quando necessário
#
# Tempo estimado de compilação: 20-40 minutos (dependendo do hardware)
# Requisito de espaço: ~5 GB em disco
#
# Após compilação:
#   - Kernel novo em ~/wsl2-kernel/arch/x86/boot/bzImage
#   - .wslconfig atualizado automaticamente
#   - WSL reiniciado com o novo kernel

set -euo pipefail

RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
CYN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYN}[*]${NC} $*"; }
ok()    { echo -e "${GRN}[+]${NC} $*"; }
warn()  { echo -e "${YLW}[!]${NC} $*"; }
fail()  { echo -e "${RED}[X]${NC} $*"; exit 1; }

# ---------------------------------------------------------------------------
# Configurações
# ---------------------------------------------------------------------------
KERNEL_VERSION="$(uname -r | sed 's/-microsoft-standard-WSL2.*//')"
WSL2_KERNEL_TAG="linux-msft-wsl-${KERNEL_VERSION}"
REPO_URL="https://github.com/microsoft/WSL2-Linux-Kernel.git"
BUILD_DIR="$HOME/wsl2-kernel"
KERNEL_OUTPUT="$BUILD_DIR/arch/x86/boot/bzImage"
WSLCONFIG_PATH="/mnt/c/Users/$(cmd.exe /c echo %USERNAME% 2>/dev/null | tr -d '\r\n')/.wslconfig"
JOBS=$(nproc)

echo ""
echo "================================================================"
echo "  WSL2 Custom Kernel Build — rt2800usb (Ralink RT5370)"
echo "  Kernel base: $KERNEL_VERSION"
echo "  Build dir:   $BUILD_DIR"
echo "  CPUs:        $JOBS"
echo "================================================================"
echo ""

# ---------------------------------------------------------------------------
# 1. Instalar dependências de build
# ---------------------------------------------------------------------------
info "Instalando dependências de compilação..."
sudo apt-get update -qq
sudo apt-get install -y --no-install-recommends \
    build-essential \
    flex \
    bison \
    libssl-dev \
    libelf-dev \
    bc \
    dwarves \
    git \
    cpio \
    libncurses-dev \
    pahole \
    pkg-config \
    python3-minimal \
    dkms 2>&1 | tail -5
ok "Dependências instaladas."

# ---------------------------------------------------------------------------
# 2. Clonar kernel WSL2
# ---------------------------------------------------------------------------
if [[ -d "$BUILD_DIR" ]]; then
    info "Diretório de build já existe: $BUILD_DIR"
    info "Usando fonte existente. Para rebuild limpo: rm -rf $BUILD_DIR"
else
    info "Clonando WSL2 kernel source (pode demorar)..."
    # Tenta o tag exato, senão usa main
    if git ls-remote --tags "$REPO_URL" | grep -q "$WSL2_KERNEL_TAG"; then
        git clone --depth 1 --branch "$WSL2_KERNEL_TAG" "$REPO_URL" "$BUILD_DIR"
    else
        warn "Tag '$WSL2_KERNEL_TAG' nao encontrado. Usando branch 'linux-msft-wsl-6.6.y'..."
        git clone --depth 1 --branch "linux-msft-wsl-6.6.y" "$REPO_URL" "$BUILD_DIR"
    fi
    ok "Kernel clonado em $BUILD_DIR"
fi

cd "$BUILD_DIR"

# ---------------------------------------------------------------------------
# 3. Configuração base do kernel
# ---------------------------------------------------------------------------
info "Preparando configuração do kernel..."

# Usar config do kernel WSL2 atual como base
if [[ -f "/proc/config.gz" ]]; then
    zcat /proc/config.gz > .config
    ok "Config base carregada de /proc/config.gz"
elif [[ -f "/boot/config-$(uname -r)" ]]; then
    cp "/boot/config-$(uname -r)" .config
    ok "Config base carregada de /boot/config-$(uname -r)"
elif [[ -f "Microsoft/config-wsl" ]]; then
    cp Microsoft/config-wsl .config
    ok "Config base: Microsoft/config-wsl"
else
    make defconfig
    warn "Usando defconfig (menos otimizado para WSL2)."
fi

# ---------------------------------------------------------------------------
# 4. Habilitar módulos wireless (RT2800USB e dependências)
# ---------------------------------------------------------------------------
info "Habilitando módulos wireless no .config..."

enable_module() {
    local opt="$1"
    if grep -q "^# ${opt} is not set" .config; then
        sed -i "s/^# ${opt} is not set/${opt}=m/" .config
        ok "  Habilitado: ${opt}=m"
    elif grep -q "^${opt}=n" .config; then
        sed -i "s/^${opt}=n/${opt}=m/" .config
        ok "  Alterado para: ${opt}=m"
    elif ! grep -q "^${opt}=" .config; then
        echo "${opt}=m" >> .config
        ok "  Adicionado: ${opt}=m"
    else
        ok "  Já configurado: $(grep "^${opt}=" .config)"
    fi
}

# Dependências de base wireless
enable_module "CONFIG_NET"
enable_module "CONFIG_WIRELESS"
enable_module "CONFIG_CFG80211"
enable_module "CONFIG_MAC80211"
enable_module "CONFIG_RFKILL"
enable_module "CONFIG_USB"
enable_module "CONFIG_USB_SUPPORT"
enable_module "CONFIG_USB_OHCI_HCD"
enable_module "CONFIG_USB_EHCI_HCD"
enable_module "CONFIG_USB_XHCI_HCD"

# Ralink/RT2800USB stack completo
enable_module "CONFIG_RT2X00"
enable_module "CONFIG_RT2X00LIB"
enable_module "CONFIG_RT2X00USB"
enable_module "CONFIG_RT2800LIB"
enable_module "CONFIG_RT2800USB"
enable_module "CONFIG_RT2800USB_RT53XX"   # RT5370 specifico
enable_module "CONFIG_RT2800USB_RT55XX"
enable_module "CONFIG_RT2800USB_UNKNOWN"

# MAC80211 features úteis
enable_module "CONFIG_MAC80211_MESH"
enable_module "CONFIG_MAC80211_MONITOR"

# NFC opcional
enable_module "CONFIG_NFC"
enable_module "CONFIG_NFC_NCI"

ok "Módulos habilitados."

# Resolver dependências automaticamente
info "Resolvendo dependências de configuração (olddefconfig)..."
make olddefconfig 2>&1 | grep -E "NEW|value" | head -20 || true

# ---------------------------------------------------------------------------
# 5. Verificar configuração final
# ---------------------------------------------------------------------------
info "Verificando configuração RT2800USB..."
for cfg in CONFIG_CFG80211 CONFIG_MAC80211 CONFIG_RT2X00 CONFIG_RT2X00LIB \
           CONFIG_RT2X00USB CONFIG_RT2800LIB CONFIG_RT2800USB CONFIG_RT2800USB_RT53XX; do
    val=$(grep "^${cfg}" .config 2>/dev/null | head -1 || echo "AUSENTE")
    if [[ "$val" == *"=m"* || "$val" == *"=y"* ]]; then
        ok "  $val"
    else
        warn "  $cfg: $val"
    fi
done

# ---------------------------------------------------------------------------
# 6. Compilar
# ---------------------------------------------------------------------------
info "Compilando kernel com $JOBS threads (isso demora ~20-40 min)..."
info "Acompanhe o progresso: tail -f /tmp/kernel_build.log"

make -j"$JOBS" LOCALVERSION="-wxf-rt5370" 2>&1 | tee /tmp/kernel_build.log | \
    grep -E "CC|LD|HOSTCC|error:|warning:|Error" | \
    grep -v "^make\[" | \
    while IFS= read -r line; do
        if echo "$line" | grep -q "error:"; then
            echo -e "${RED}$line${NC}"
        else
            echo "$line"
        fi
    done

[[ -f "$KERNEL_OUTPUT" ]] || fail "Compilação falhou! Verifique /tmp/kernel_build.log"
ok "Kernel compilado: $KERNEL_OUTPUT ($(du -sh "$KERNEL_OUTPUT" | cut -f1))"

# ---------------------------------------------------------------------------
# 7. Instalar módulos
# ---------------------------------------------------------------------------
info "Instalando módulos do kernel..."
sudo make modules_install INSTALL_MOD_PATH="$BUILD_DIR/modules_install" 2>&1 | tail -5
ok "Módulos instalados em $BUILD_DIR/modules_install/"

# ---------------------------------------------------------------------------
# 8. Copiar kernel para Windows e atualizar .wslconfig
# ---------------------------------------------------------------------------
KERNEL_WIN_PATH="/mnt/c/wsl2-kernels/bzImage-rt5370"
info "Copiando kernel para Windows: $KERNEL_WIN_PATH"
mkdir -p "$(dirname "$KERNEL_WIN_PATH")"
cp "$KERNEL_OUTPUT" "$KERNEL_WIN_PATH"
ok "Kernel copiado: $(du -sh "$KERNEL_WIN_PATH" | cut -f1)"

# Detectar usuário Windows
WIN_USER=$(cmd.exe /c echo %USERNAME% 2>/dev/null | tr -d '\r\n' | tr -d '[:space:]')
[[ -n "$WIN_USER" ]] || WIN_USER="mrhen"
WSLCONFIG_PATH="/mnt/c/Users/${WIN_USER}/.wslconfig"

info "Atualizando .wslconfig: $WSLCONFIG_PATH"

if [[ -f "$WSLCONFIG_PATH" ]]; then
    # Backup
    cp "$WSLCONFIG_PATH" "${WSLCONFIG_PATH}.bak"
    ok "Backup: ${WSLCONFIG_PATH}.bak"

    # Remover kernel line existente se houver
    sed -i '/^kernel=/d' "$WSLCONFIG_PATH"
else
    # Criar .wslconfig básico
    cat > "$WSLCONFIG_PATH" << 'WSLCFG'
[wsl2]
WSLCFG
fi

# Adicionar linha do kernel (path Windows com backslashes)
WIN_KERNEL_PATH=$(echo "$KERNEL_WIN_PATH" | sed 's|/mnt/c|C:|' | sed 's|/|\\\\|g')
# Append kernel= na seção [wsl2]
python3 -c "
import re, sys
path = r'C:\\\\wsl2-kernels\\\\bzImage-rt5370'
content = open('$WSLCONFIG_PATH').read()
if '[wsl2]' in content:
    content = re.sub(r'(\[wsl2\])', r'\1\nkernel=' + path, content, count=1)
else:
    content = '[wsl2]\nkernel=' + path + '\n' + content
open('$WSLCONFIG_PATH', 'w').write(content)
print('OK: kernel=' + path + ' adicionado ao .wslconfig')
"

ok ".wslconfig atualizado:"
cat "$WSLCONFIG_PATH"

# ---------------------------------------------------------------------------
# 9. Resumo e instruções finais
# ---------------------------------------------------------------------------
echo ""
echo "================================================================"
echo "  COMPILACAO CONCLUIDA!"
echo "================================================================"
echo "  Kernel: $KERNEL_OUTPUT"
echo "  Win:    C:\\wsl2-kernels\\bzImage-rt5370"
echo "  Config: $WSLCONFIG_PATH"
echo ""
echo "  PROXIMOS PASSOS:"
echo ""
echo "  1. Feche o WSL2:"
echo "     (no PowerShell): wsl --shutdown"
echo ""
echo "  2. Abra o WSL2 novamente — ele vai usar o novo kernel:"
echo "     uname -r"
echo "     # deve mostrar: 6.6.x-wxf-rt5370"
echo ""
echo "  3. Conecte o RT5370 e verifique:"
echo "     (Windows) usbipd attach --wsl --busid <BUSID>"
echo "     (WSL) lsusb && sudo modprobe rt2800usb && iwconfig"
echo ""
echo "  4. Execute os ataques via WirelessXPL-Forge:"
echo "     sudo airmon-ng start wlan0"
echo "     python3 /mnt/d/Projetos-SafeLabs/.../wirelessxpl.py"
echo "================================================================"
echo ""
