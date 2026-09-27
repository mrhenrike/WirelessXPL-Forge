# Architecture diagrams — WirelessXPL-Forge

**Author:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) \| **União Geek** — [https://github.com/Uniao-Geek](https://github.com/Uniao-Geek)

**Languages:** Diagram labels are **English (en-US)** by default (aligned with tool output). **Português (pt-BR):** [README.pt-BR.md](README.pt-BR.md).

Diagrams follow the same visual language as **MikrotikAPI-BF** (`mikrotik_full_attack_surface.png`): central core, **access vectors** as spokes, **✓ / ✗ / ◐** for coverage, optional CVE callouts. **Colours:** green = mandatory core, orange = vectors, yellow = optional, blue = targets (see `07-wirelessxpl-full-attack-surface.mmd`).

## Files

| File | Category |
|------|----------|
| [07-wirelessxpl-full-attack-surface.mmd](07-wirelessxpl-full-attack-surface.mmd) | **WXF full map** — Wi‑Fi, BLE, Zigbee, PCAP, bridges, targets |
| [01-router-soho.mmd](01-router-soho.mmd) | SOHO / home gateway (Linux / RTOS firmware) |
| [02-switch-l2-l3.mmd](02-switch-l2-l3.mmd) | Managed L2/L3 switch |
| [03-ngfw-utm.mmd](03-ngfw-utm.mmd) | NGFW / UTM / enterprise firewall appliance |
| [04-isp-cpe.mmd](04-isp-cpe.mmd) | ISP CPE / residential gateway |
| [05-edge-mixed.mmd](05-edge-mixed.mmd) | Mixed small-office edge (router + UTM-lite) |
| [06-network-tap.mmd](06-network-tap.mmd) | Network TAP / passive broker (mgmt-only vectors) |

## Rendered PNGs

| PNG | Source |
|-----|--------|
| [../../img/architecture/rxf_arch_wirelessxpl_full_attack_surface.png](../../img/architecture/rxf_arch_wirelessxpl_full_attack_surface.png) | **WirelessXPL full attack surface** |
| [../../img/architecture/rxf_arch_router_soho.png](../../img/architecture/rxf_arch_router_soho.png) | SOHO router |
| [../../img/architecture/rxf_arch_switch_l2l3.png](../../img/architecture/rxf_arch_switch_l2l3.png) | Switch |
| [../../img/architecture/rxf_arch_ngfw_utm.png](../../img/architecture/rxf_arch_ngfw_utm.png) | NGFW / UTM |
| [../../img/architecture/rxf_arch_isp_cpe.png](../../img/architecture/rxf_arch_isp_cpe.png) | ISP CPE |
| [../../img/architecture/rxf_arch_edge_mixed.png](../../img/architecture/rxf_arch_edge_mixed.png) | Mixed edge |
| [../../img/architecture/rxf_arch_network_tap.png](../../img/architecture/rxf_arch_network_tap.png) | Network TAP |

### Gallery (embedded)

| WirelessXPL — full attack surface |
|:---:|
| ![WirelessXPL full attack surface](../../img/architecture/rxf_arch_wirelessxpl_full_attack_surface.png) |

| SOHO router | Switch |
|:---:|:---:|
| ![SOHO router](../../img/architecture/rxf_arch_router_soho.png) | ![Switch](../../img/architecture/rxf_arch_switch_l2l3.png) |

| NGFW / UTM | ISP CPE |
|:---:|:---:|
| ![NGFW / UTM](../../img/architecture/rxf_arch_ngfw_utm.png) | ![ISP CPE](../../img/architecture/rxf_arch_isp_cpe.png) |

| Mixed edge | Network TAP |
|:---:|:---:|
| ![Mixed edge](../../img/architecture/rxf_arch_edge_mixed.png) | ![Network TAP](../../img/architecture/rxf_arch_network_tap.png) |

## Render locally (optional)

With [Mermaid CLI](https://github.com/mermaid-js/mermaid-cli):

```bash
npx @mermaid-js/mermaid-cli -i docs/diagrams/architecture/07-wirelessxpl-full-attack-surface.mmd -o docs/img/architecture/rxf_arch_wirelessxpl_full_attack_surface.png -b white -w 1600
```

## Português (pt-BR)

- **✓ Coberto:** módulos existentes em `wirelessxpl/modules/` para aquele vetor (ex.: `creds`, `exploits`, `generic` PCAP/CVE).
- **✗ Parcial / não focado:** depende de modelo; usar `generic/cve/cve_lookup`, `scanners/autopwn` e pesquisa por *vendor*.

---

> **Author:** André Henrique ([@mrhenrike](https://github.com/mrhenrique)) \| **União Geek** — [https://github.com/Uniao-Geek](https://github.com/Uniao-Geek)
