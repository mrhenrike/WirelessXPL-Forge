# Sobre o WirelessXPL-Forge

O **WirelessXPL-Forge (WXF)** é um framework modular de pesquisa em segurança wireless construído para testes de invasão autorizados, pesquisa de segurança e educação em redes wireless e dispositivos IoT/embarcados.

---

## Identidade do Projeto

| Atributo | Valor |
|----------|-------|
| **Nome** | WirelessXPL-Forge |
| **Nome curto** | WXF |
| **Versão** | 2.0.2 |
| **Licença** | BSD-3-Clause |
| **Python** | 3.8 – 3.13 |
| **Plataforma** | Linux (preferido), macOS, WSL2 |
| **PyPI** | `pip install wirelessxpl` |
| **Repositório** | https://github.com/mrhenrike/WirelessXPL-Forge |
| **Wiki** | https://github.com/mrhenrike/WirelessXPL-Forge/wiki |

---

## Taglines

- *"Um shell. Todos os vetores wireless."*
- *"De 802.11ax ao BLE — pesquisa autorizada, a um módulo de distância."*
- *"Segurança wireless, modular por design."*
- *"WPA, WPA3, BLE, Zigbee, ESP32 — em um framework."*

---

## Origem e Linhagem

O WXF é um fork especializado do [threat9/routersploit](https://github.com/threat9/routersploit), extraído do [RouterXPL-Forge](https://github.com/mrhenrike/RouterXPL-Forge) para se especializar exclusivamente em **protocolos wireless**: 802.11, Bluetooth Classic, BLE, Zigbee, RFID, AWDL e dispositivos embarcados baseados em ESP32.

```
threat9/routersploit
  └─ RouterXPL-Forge (mrhenrike)
       └─ WirelessXPL-Forge (mrhenrike) ← este projeto
       └─ FirewallXPL-Forge (mrhenrike, privado)
```

---

## Filosofia de Design

- **Módulo em primeiro lugar**: cada ataque, análise ou bridge é uma classe Python auto-contida seguindo o contrato `BaseExploit` (`__info__`, opções, `run()`, `check()`)
- **Sem lock-in**: os bridges invocam ferramentas do sistema (`aircrack-ng`, `mdk4`, `hcxdumptool`) como subprocessos — WXF orquestra, não substitui
- **Consciente do upstream**: todos os issues e PRs incorporados da comunidade são rastreados em `wirelessxpl/resources/catalogs/upstream_issues_prs.json` e no mapa upstream Bruce
- **Nível de pesquisa**: os módulos incluem referências de CVE, detalhes de protocolo e notas de laboratório — não apenas "execute e torça"
- **ESP32 nativo**: o engine de fluxo serial Bruce/Marauder torna o wardriving portátil e a automação de menus cidadãos de primeira classe

---

## Visão Geral da Arquitetura

```
WirelessXPL-Forge/
├── wirelessxpl/
│   ├── core/           # interpreter, exploit base, CVE DB, exceptions
│   ├── modules/
│   │   ├── generic/
│   │   │   ├── wifi_lab/      # módulos de ataque Wi-Fi (Python nativo)
│   │   │   ├── bluetooth/     # módulos BT Classic + BLE
│   │   │   ├── pcap/          # pipelines de análise PCAP
│   │   │   ├── cve/           # módulos de exploit CVE (Zigbee, KRACK…)
│   │   │   └── external/      # bridges para ferramentas externas + engine serial Bruce
│   │   ├── exploits/          # exploits específicos de dispositivos
│   │   ├── scanners/          # scanners de rede
│   │   └── creds/             # módulos de credenciais
│   ├── resources/
│   │   └── catalogs/          # JSONs de rastreamento upstream, catálogo CVE
│   └── libs/                  # utilitários compartilhados
├── tools/                     # ferramentas de desenvolvimento e CI
├── docs/                      # documentação, wiki, matriz de cobertura
└── .github/workflows/         # CI/CD (compat-matrix + release + publicação PyPI)
```

---

## Destaque da Matriz de Cobertura

| Dispositivo/Protocolo | Módulos |
|-----------------------|---------|
| Wi-Fi 802.11 (WPA2/WPA3) | fragattacks, wpa3_attack_suite, handshake_snooper, evil_twin_workflow, auth_flood, beacon_flood, captive_portal_modern_lab, adaptive_harvest, wardriving_deauth_loop, wireless_ids, momo_integrated_attack |
| BLE / Bluetooth Classic | ble_btlejack, ble_crackle, bt_hid_injection, bt_baseband_attack (BrakTooth), bt_session_attack (KNOB/BIAS/BLUFFS), blueborne_attack |
| Zigbee / IEEE 802.15.4 | zigbee_attack (KillerBee) |
| AWDL / AirDrop | awdl_attack (opendrop + owl) |
| ESP32 / firmware Bruce | bruce_serial_bridge (15+ perfis de fluxo), bruce_upstream_tracker |
| Análise PCAP | pcap_handshake_extractor, pcap_eapol_survey, pcap_pmkid_extractor, pcap_dragonblood, pcap_sql_workspace |
| MITM / Bridging | mitm_wifi_bridge (ghost_combo), wifipumpkin3_bridge, eaphammer_bridge, wifiphisher_bridge |

---

## Mantenedor

**André Henrique** ([@mrhenrike](https://github.com/mrhenrike))  
[União Geek](https://github.com/Uniao-Geek) — https://github.com/Uniao-Geek  
**Suporte:** [suporte@uniaogeek.com.br](mailto:suporte@uniaogeek.com.br)

---

## Reporte de Vulnerabilidades

Veja [SECURITY.pt-BR.md](../../SECURITY.pt-BR.md) para diretrizes de divulgação responsável.

---

## Aviso Legal

O WirelessXPL-Forge é destinado exclusivamente para **pesquisa de segurança e educação autorizadas**.  
O uso contra sistemas que você não possui ou não tem permissão escrita explícita para testar é ilegal e antiético.  
Os autores não assumem responsabilidade pelo uso indevido deste software.
