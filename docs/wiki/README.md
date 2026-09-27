# WirelessXPL-Forge — documentation wiki (bilingual)

**Author:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) \| **União Geek** — [https://github.com/Uniao-Geek](https://github.com/Uniao-Geek)

## Languages / Idiomas

| Locale | Hub |
|--------|-----|
| **English (en-US)** — default | [en-US/README.md](en-US/README.md) |
| **Português (pt-BR)** | [pt-BR/README.md](pt-BR/README.md) |

## Architecture diagrams / Diagramas de arquitetura

**en-US** labels on PNGs. **Sources / Fontes:** [diagrams/architecture/README.md](../diagrams/architecture/README.md). **PyPI:** `pip install wirelessxpl`.

| WirelessXPL — full attack surface |
|:---:|
| ![WXF full map](../img/architecture/rxf_arch_wirelessxpl_full_attack_surface.png) |

| SOHO router | L2–L3 switch |
|:---:|:---:|
| ![SOHO router](../img/architecture/rxf_arch_router_soho.png) | ![Switch](../img/architecture/rxf_arch_switch_l2l3.png) |

| NGFW / UTM | ISP CPE |
|:---:|:---:|
| ![NGFW UTM](../img/architecture/rxf_arch_ngfw_utm.png) | ![ISP CPE](../img/architecture/rxf_arch_isp_cpe.png) |

| Mixed edge | Network TAP |
|:---:|:---:|
| ![Mixed edge](../img/architecture/rxf_arch_edge_mixed.png) | ![Network TAP](../img/architecture/rxf_arch_network_tap.png) |

## Shared asset / Recurso partilhado

- **Module path index (language-neutral):** [ANEXO-INDICE-MODULOS.md](ANEXO-INDICE-MODULOS.md) — regenerate with `python tools/gen_wiki_module_index.py`

## Related products / Produtos relacionados

| Repository | Role |
|------------|------|
| [RouterXPL-Forge](https://github.com/mrhenrike/RouterXPL-Forge) | Routers, switches, TAPs, SOHO edge |
| [FirewallXPL-Forge](https://github.com/mrhenrike/FirewallXPL-Forge) | NGFW / UTM / perimeter lab |

## Governance & CI / Governança e CI

| Topic | Links |
|-------|--------|
| License | [LICENSE](../../LICENSE) (BSD; upstream Threat9 notice retained) |
| Code of Conduct | [CODE_OF_CONDUCT.md](../../CODE_OF_CONDUCT.md) · [CODE_OF_CONDUCT.pt-BR.md](../../CODE_OF_CONDUCT.pt-BR.md) |
| Security | [SECURITY.md](../../SECURITY.md) · [SECURITY.pt-BR.md](../../SECURITY.pt-BR.md) |
| Contributing | [CONTRIBUTING.md](../../CONTRIBUTING.md) · [CONTRIBUTING.pt-BR.md](../../CONTRIBUTING.pt-BR.md) |
| Contributors | [CONTRIBUTORS.md](../../CONTRIBUTORS.md) · [CONTRIBUTORS.pt-BR.md](../../CONTRIBUTORS.pt-BR.md) |
| GitHub Actions | [compat-matrix.yml](../../.github/workflows/compat-matrix.yml) |

## Wireless intel catalogs / Catálogos de intel 802.11

Structured WPA3 / Wi‑Fi 6–7 threat vectors (JSON, lab alignment): see the **Intel catalogs** row in [docs/README.md](../README.md) · [docs/README.pt-BR.md](../README.pt-BR.md).

## Repository root / Raiz do repositório

- [README.md](../../README.md) (en-US) · [README.pt-BR.md](../../README.pt-BR.md)
- [CONTRIBUTING.md](../../CONTRIBUTING.md) · [CONTRIBUTING.pt-BR.md](../../CONTRIBUTING.pt-BR.md)
- [docs/README.md](../README.md) · [docs/README.pt-BR.md](../README.pt-BR.md) — `docs/` folder hub

---

> **Author:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) \| **União Geek** — [https://github.com/Uniao-Geek](https://github.com/Uniao-Geek)
