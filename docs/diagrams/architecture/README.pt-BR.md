# Diagramas de arquitetura — WirelessXPL-Forge

**Autor:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) \| **União Geek** — [https://github.com/Uniao-Geek](https://github.com/Uniao-Geek)

**Idiomas:** rótulos dos diagramas em **inglês (en-US)** por padrão (alinhado à saída da ferramenta). **English:** [README.md](README.md).

O estilo replica o hub-and-spoke do **MikrotikAPI-BF** (`mikrotik_full_attack_surface.png`): núcleo, vetores de acesso, legenda de cobertura (**✓ / ✗ / ◐**). O mapa **07** consolida Wi‑Fi, BLE, Zigbee, PCAP, bridges e alvos.

## Arquivos

| Arquivo | Categoria |
|---------|-----------|
| [07-wirelessxpl-full-attack-surface.mmd](07-wirelessxpl-full-attack-surface.mmd) | **Mapa WXF completo** |
| [01-router-soho.mmd](01-router-soho.mmd) | Router SOHO |
| [02-switch-l2-l3.mmd](02-switch-l2-l3.mmd) | Switch L2/L3 |
| [03-ngfw-utm.mmd](03-ngfw-utm.mmd) | NGFW / UTM |
| [04-isp-cpe.mmd](04-isp-cpe.mmd) | CPE ISP |
| [05-edge-mixed.mmd](05-edge-mixed.mmd) | Edge misto |
| [06-network-tap.mmd](06-network-tap.mmd) | TAP / broker passivo |

## PNGs gerados

| PNG | Fonte |
|-----|-------|
| [../../img/architecture/rxf_arch_wirelessxpl_full_attack_surface.png](../../img/architecture/rxf_arch_wirelessxpl_full_attack_surface.png) | **Superfície de ataque WXF** |
| [../../img/architecture/rxf_arch_router_soho.png](../../img/architecture/rxf_arch_router_soho.png) | SOHO |
| [../../img/architecture/rxf_arch_switch_l2l3.png](../../img/architecture/rxf_arch_switch_l2l3.png) | Switch |
| [../../img/architecture/rxf_arch_ngfw_utm.png](../../img/architecture/rxf_arch_ngfw_utm.png) | NGFW |
| [../../img/architecture/rxf_arch_isp_cpe.png](../../img/architecture/rxf_arch_isp_cpe.png) | CPE |
| [../../img/architecture/rxf_arch_edge_mixed.png](../../img/architecture/rxf_arch_edge_mixed.png) | Edge misto |
| [../../img/architecture/rxf_arch_network_tap.png](../../img/architecture/rxf_arch_network_tap.png) | TAP |

### Galeria

| Mapa completo WirelessXPL |
|:---:|
| ![WXF](../../img/architecture/rxf_arch_wirelessxpl_full_attack_surface.png) |

| SOHO | Switch |
|:---:|:---:|
| ![SOHO](../../img/architecture/rxf_arch_router_soho.png) | ![Switch](../../img/architecture/rxf_arch_switch_l2l3.png) |

| NGFW | CPE |
|:---:|:---:|
| ![NGFW](../../img/architecture/rxf_arch_ngfw_utm.png) | ![CPE](../../img/architecture/rxf_arch_isp_cpe.png) |

| Edge misto | TAP |
|:---:|:---:|
| ![Edge](../../img/architecture/rxf_arch_edge_mixed.png) | ![TAP](../../img/architecture/rxf_arch_network_tap.png) |

## Renderizar localmente

```bash
npx @mermaid-js/mermaid-cli -i docs/diagrams/architecture/07-wirelessxpl-full-attack-surface.mmd -o docs/img/architecture/rxf_arch_wirelessxpl_full_attack_surface.png -b white -w 1600
```

---

> **Autor:** André Henrique ([@mrhenrike](https://github.com/mrhenrique)) \| **União Geek** — [https://github.com/Uniao-Geek](https://github.com/Uniao-Geek)
