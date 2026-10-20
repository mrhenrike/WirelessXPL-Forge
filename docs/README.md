# Documentation folder  - `docs/`

**Author:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) \| **União Geek**  - [https://github.com/Uniao-Geek](https://github.com/Uniao-Geek)

**Language:** Files below are in **English (en-US)**.

## Contents / Conteúdo

| File | Language | Description |
|------|----------|-------------|
| [COVERAGE_MATRIX.md](COVERAGE_MATRIX.md) | en-US | Coverage matrix, external intel tables |
| [FULL_CATALOG.md](FULL_CATALOG.md) | en-US | Full module catalog snapshot |
| [wiki/README.md](wiki/README.md) | en-US | Wiki index |
| [diagrams/architecture/README.md](diagrams/architecture/README.md) | en-US | **Attack-surface architecture** (MikrotikAPI-BF style) |
| [INTEGRATION_MODEL.md](INTEGRATION_MODEL.md) | en-US + pt summary | **Native vs bridges vs host tools** (what pip ships) |
| [img/architecture/](img/architecture/) | en-US labels on PNG | Exported architecture PNGs |
| Intel catalogs | JSON (bilingual summaries) | [wifi6_80211ax_threat_vectors.json](../wirelessxpl/resources/catalogs/wifi6_80211ax_threat_vectors.json) (802.11ax) · [wifi7_80211be_threat_vectors.json](../wirelessxpl/resources/catalogs/wifi7_80211be_threat_vectors.json) (802.11be / MLO)  - WPA3-aligned threat vectors for lab |

## Attack-surface architecture (PNGs)

Same visual language as MikrotikAPI-BF hub-and-spoke diagrams. **Mermaid:** [diagrams/architecture/](diagrams/architecture/). **Install** the framework: `pip install wirelessxpl` (see root [README.md](../README.md)). **Gallery:**

| WirelessXPL  - full attack surface |
|:---:|
| ![WirelessXPL full attack surface](img/architecture/rxf_arch_wirelessxpl_full_attack_surface.png) |

| SOHO router | Switch |
|:---:|:---:|
| ![SOHO router](img/architecture/rxf_arch_router_soho.png) | ![Switch](img/architecture/rxf_arch_switch_l2l3.png) |

| NGFW / UTM | ISP CPE |
|:---:|:---:|
| ![NGFW](img/architecture/rxf_arch_ngfw_utm.png) | ![ISP CPE](img/architecture/rxf_arch_isp_cpe.png) |

| Mixed edge | Network TAP |
|:---:|:---:|
| ![Mixed edge](img/architecture/rxf_arch_edge_mixed.png) | ![Network TAP](img/architecture/rxf_arch_network_tap.png) |

## Wiki locales

- **English (default):** [wiki/en-US/README.md](wiki/en-US/README.md)


## Regeneration hints

```bash
python tools/generate_coverage_matrix.py
python tools/generate_full_catalog.py
python tools/refresh_cve_extended_catalog.py
python tools/gen_wiki_module_index.py
```

---

> **Author:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) \| **União Geek**  - [https://github.com/Uniao-Geek](https://github.com/Uniao-Geek)
