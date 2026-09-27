# Integration model — native code vs. external tools

**Author:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) \| **União Geek** — [https://github.com/Uniao-Geek](https://github.com/Uniao-Geek)

**Languages:** English (en-US). **Português (pt-BR):** see section [Em português](#em-português-resumo) below.

## What `pip install wirelessxpl` ships

The **PyPI wheel** contains **only** the `wirelessxpl` Python package: framework core, modules under `wirelessxpl/modules/`, resources, and declared Python dependencies (`requirements.txt` / `pyproject.toml`). It does **not** embed:

- C/Capture binaries (aircrack-ng, hashcat, mdk4, …)
- GPL-licensed third-party **codebases** (wifiphisher, eaphammer, …) — those stay **separate installs** on the host, invoked via **bridge modules** when you choose to use them.

## Why “not bundled” is not “not integrated”

| Layer | Meaning |
|-------|---------|
| **Integrated in WXF** | The module appears in `use`, `set`, `run`, logging, options — same UX as native code. |
| **Bridge** | Implementation calls `subprocess` to a **host binary** you installed (e.g. `wifiphisher`, `eaphammer`). No GPL source is **imported** into our BSD-3-Clause tree; see bridge docstrings (e.g. `eaphammer_bridge.py`). |
| **Native** | Logic is pure Python (and our deps) inside this repo — e.g. many `generic/wifi_lab/*`, BLE/Zigbee flows, PCAP parsers. |

So: **bridges are real integration** (CLI + orchestration), not a loose “run this manually” note — but they still **require** the external tool on `PATH` because we do not vendor that upstream project.

## Tools we intentionally keep as host dependencies

These are **large**, **often GPL**, **driver-heavy**, or **frequently updated upstream** — shipping them inside `wirelessxpl` would bloat the wheel, complicate licensing, and duplicate package managers (apt vs pip):

- **aircrack-ng**, **hcxdumptool** / **hcxtools**, **hashcat**, **mdk3/mdk4**, **tshark**
- **Bruce / ESP32 firmware** (device image, not a Python lib)

You install them with your OS package manager or upstream installers; then `wireless_tool_prereq_audit` and bridge modules can find them.

## Can we “embed all code” for wifiphisher, bettercap, etc.?

**Not as a single PyPI monolith**, for practical and legal reasons:

1. **License**: Many tools are **GPL**. Bundling their source or importing their modules into our BSD project creates **derivative-work** obligations we avoid by **subprocess-only** bridges (documented in each bridge).
2. **Size & maintenance**: Millions of lines, kernel/drivers, rolling upstream — not sustainable inside WirelessXPL-Forge.
3. **What we *do* instead**: Grow **native** Python coverage in `wirelessxpl/modules` (wifi_lab, bluetooth, zigbee, pcap, …) where it fits the BSD stack; keep bridges for full-featured external suites.

If you need a **fully offline** lab, prebuild a **distro image** (e.g. Kali + apt install) or a **Dockerfile** that installs WXF + tools — that’s deployment, not vendoring into the wheel.

## Em português (resumo)

- O que vem no **`pip install wirelessxpl`** é **só** o pacote Python e dependências declaradas — **não** inclui binários do aircrack, hashcat, wifiphisher, etc.
- **“Não bundled”** aqui significa: **não vai dentro do wheel**; **não** significa “desintegrado”. Os **módulos bridge** integram essas ferramentas ao fluxo do WXF (`use`/`run`), chamando o executável no sistema se ele existir.
- **Incorporar o código-fonte inteiro** de wifiphisher/eaphammer/bettercap dentro deste repositório **não é o modelo** (licença GPL + manutenção + tamanho). O modelo suportado é **código nativo** em Python no próprio projeto + **bridges** para ferramentas pesadas instaladas no host.
- Ferramentas que você citou como **“core” para continuar externas** (aircrack, hashcat, tshark, mdk*, hcx*, firmware Bruce) seguem **fora do wheel** por natureza (binários / firmware).

---

> **Author:** André Henrique ([@mrhenrike](https://github.com/mrhenrique)) \| **União Geek** — [https://github.com/Uniao-Geek](https://github.com/Uniao-Geek)
