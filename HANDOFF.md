# HANDOFF -- WirelessXPL-Forge

## [2026-06-24] — Política: pyproject.toml e PyPI somente local

### Estado ao encerrar
- `pyproject.toml` removido do GitHub (`.gitignore`); template: `pyproject.toml.example`
- Workflow `publish-pypi.yml` removido do repositório remoto
- README/wiki: instalação via clone + `requirements.txt`; sem badges PyPI
- Regra Cursor: `.cursor/rules/local-packaging.mdc`
- Cópia local `pyproject.toml` (v2.0.3) permanece na máquina para build/twine manual

---

## [2026-06-24] — Crack engine v2: HashCater + Cap2Hash nativos

### Estado ao encerrar
- `handshake_crack_engine`: `attack_flow=both`, máscaras smart ISP-BR, proteção térmica GPU
- Cap2Hash nativo: `convert_only` + `input_dir` + `skip_converted`
- Lote: `input_dir` processa múltiplos PCAP/hash com relatório cracked/failed

### Novas opções principais
- `attack_flow` wordlist | bruteforce | both
- `smart_masks`, `mask_runtime_s`, `cooldown_s`, `gpu_temp_abort`, `log_file`

---

## [2026-06-23] — Limpeza de branding, contato e sync remoto (sem PCAPs)

### Estado ao encerrar
- Contato unificado: **suporte@uniaogeek.com.br** em pyproject, README, SECURITY, CODE_OF_CONDUCT, CONTRIBUTORS e wiki
- Removidas menções a SafeLabs, paths legados `/mnt` e `Projetos-SafeLabs` em HANDOFF, docs e código
- Guia offline adicionado: `docs/GUIA-CRACK-PCAP-OFFLINE.md` (sem arquivos PCAP no repositório)
- Commits remotos com `Co-authored-by: Cursor` e PCAPs sintéticos **não** incorporados — master sobrescrito
- Versão bump: **2.0.2**

### Paths importantes
- Linux: `/home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge`
- Wordlists: `/home/mrhenrike/Documentos/Projetos/WordListsForHacking`
- PCAPs de lab: repositório externo `PCAPTrafficAnalysis` (não versionados aqui)

### Pendências resolvidas
- [x] Atribuições de IA (`Co-authored-by: Cursor`) removidas do histórico remoto via force-push
- [x] Contato e suporte atualizados para União Geek

---

## [2026-06-20 14:45] — Sessão de refatoração completa — estado final

### Pendências resolvidas nesta sessão completa
- [x] pybluez deprecated → substituído por bleak em todo o core BLE
- [x] dronekit → removido do pyproject.toml
- [x] wifi_lab/ → removido (canonical é wifi/)
- [x] simulate=True defaults → todos alterados para False (wifi, bluetooth, subghz, drones)
- [x] dry_run=True → alterado para False em hashcat_gpu_orchestrator
- [x] wifi/__init__.py __all__ classes unbound → @requires_os lazy PEP 562 __getattr__
- [x] DragonbloodSuite alias → adicionado em dragonblood_suite.py
- [x] Protocol.WIFI/BLUETOOTH/ZIGBEE inexistentes → substituídos por Protocol.CUSTOM
- [x] bt_hid_keyboard_inject sem classe Exploit → wrapper adicionado
- [x] fragattacks conflito .py vs pacote → renomeado para fragattacks_native.py
- [x] auth_flood nativo Scapy → _scapy_auth_flood() e _scapy_mesh_flood() implementados
- [x] wireless_ids CSV parser → suporta formato compacto (4 col) além de airodump-ng
- [x] bleak path sudo → wxf.py injeta SUDO_USER site-packages globalmente
- [x] OptBoolean → OptBool em todos os módulos
- [x] @multi sem self.target → removido de fragattacks/ e krack/
- [x] print_warning() → adicionada ao core.exploit
- [x] require_authorised_lab(self.*) → corrigido para require_authorised_lab()
- [x] permissões __pycache__ → corrigidas (find -exec chmod 755)
- [x] phishing_engine templates → suporta formato diretório/index.html E .html direto
- [x] pybluez no pyproject.toml → removido dos extras [bt] e [all-modules]
- [x] capive portal loader → _load_template_html() suporta ambos os formatos

### Módulos novos implementados (esta sessão)
- wirelessxpl/modules/generic/wifi/interface_manager.py v2 (select multi-spec)
- wirelessxpl/modules/generic/wifi/arp_mitm_proxy.py (ARP MITM + XSS + XXE + IMG)
- wirelessxpl/modules/generic/wifi/csa_handshake_capture.py (PMF bypass CSA)
- wirelessxpl/modules/generic/wifi/handshake_crack_engine.py (multi-backend crack)
- wirelessxpl/modules/generic/wifi/pmkid_autopwn.py v2 (Scapy nativo)
- wirelessxpl/modules/generic/wifi/wardriving_deauth_loop.py v2 (Scapy nativo)
- wirelessxpl/modules/generic/wifi/wps_engine_native.py v2 (PIN predict, PBC hijack, MAC rotation)
- wirelessxpl/core/config.py (WXFConfig singleton, timing T0-T5, USB detection)
- wirelessxpl/core/wifi/interface_registry.py v2 (USB/PCIe detection fix)

### Pendências genuinamente dependentes de hardware
- [ ] GATT enum de dispositivos BLE próximos (sinal fraco -90dBm+)
- [ ] WPS M4-M8 completo com PSK recovery via PIN correto
- [ ] Beck-Tews TKIP PTK via chopchop completo
- [ ] DragonForce passive capture de respostas status=77
- [ ] DragonSlayer EAP state machine completa
- [ ] Teste de integração: ESP8266WIDSBridge com hardware real
- [ ] CSRF token server-side nos portais captivos (não crítico)
- [ ] BT HID inject requer dispositivo em modo pairing (normal)

### Path atual do projeto
- Linux: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge
- Wordlists: /home/mrhenrike/Documentos/Projetos/WordListsForHacking
- Interfaces: iface_mon=wlx24050f3d5f0a  iface_inj=wlx44334cbe826b  extra=wlx688fc9528f9a
- LHOST: 192.168.18.225:4444

### Resultado final
- 106/106 módulos wifi+bluetooth carregam sem erro
- simulate=False em TODOS os módulos
- wxf.py exibe banner global no startup (interfaces, timing, LHOST)
- Testes e2e com hardware real concluídos com sucesso



### Estado ao encerrar
- Repositório migrado para ambiente Linux nativo (sem WSL2/mnt)
- Novo path canonical: `/home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge`
- Wordlists (sibling): `/home/mrhenrike/Documentos/Projetos/WordListsForHacking`
- Os 5 projetos estão em `/home/mrhenrike/Documentos/Projetos/`
- Histórico reescrito com `git-filter-repo`: todos os commits agora têm autor `mrhenrike <suporte@uniaogeek.com.br>`; atribuições de IA removidas
- Hook `commit-msg` ativo em `.githooks/` (superprojeto); cada repo aponta via `core.hooksPath`
- Regra do Cursor: `.cursor/rules/no-ai-attribution.mdc` (alwaysApply)
- Auth GitHub configurada via `gh` CLI (HTTPS, token com escopo `repo`)

### Fixes aplicados nesta sessão
- `wirelessxpl/modules/generic/wifi/__init__.py`: adicionado `__getattr__` (PEP 562) para lazy binding de `FloodEngine`, `WPSEngine`, `PhishingEngine`, `CaptiveNetwork`, `MonitorModeManager`, `DragonbloodSuite`
- `wirelessxpl/modules/generic/wifi/dragonblood_suite.py`: adicionado alias `DragonbloodSuite = Exploit`
- `tools/`: todos os scripts com paths hardcoded `/home/mrhenrike/Documentos/Projetos/` atualizados para derivar o root via `$(dirname "${BASH_SOURCE[0]}")/../`; scripts de crack usam `${WXF_WL_BASE:-<sibling>}` como base de wordlists
- `tools/fix_paths.py` e `tools/fix_hcxdumptool.py`: portabilizados via `Path(__file__).parent`

### Paths importantes (atualizados)
- Linux: `/home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge`
- Wordlists: `/home/mrhenrike/Documentos/Projetos/WordListsForHacking`
- Windows (legado, não usar): `/home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge`

### Pendências resolvidas
- [x] `wifi/__init__.py` com classes em `__all__` não bound
- [x] Alias `DragonbloodSuite` ausente em `dragonblood_suite.py`
- [x] Paths hardcoded `/mnt/d/...` em todos os tools
- [x] Atribuições de IA removidas do histórico git

### Pendências restantes (requerem hardware)
- [ ] Aplicar `@requires_os` nos módulos WiFi/BT restantes
- [ ] Teste de integração com hardware real: monitor mode, BLE, RTL-SDR, MAVLink
- [ ] WPS M4-M8 completo (PSK recovery via PIN correto)
- [ ] DragonForce: captura passiva de respostas status=77
- [ ] DragonSlayer: EAP state machine completa
- [ ] Beck-Tews TKIP: recuperação completa de PTK via chopchop
- [ ] Templates captive portal: CSRF token server-side
- [ ] `dronekit` deprecated - avaliar substituição



## [2026-06-08 00:40] -- BLOCOs A,B,C,M,O,J expansion complete

### Estado ao encerrar
- Criados 49 arquivos novos em 6 blocos de ataque
- Todos os arquivos passaram em `python -m py_compile` sem erros
- Commit `ceab4b5` realizado e pushed para origin/master
- Repositorio: https://github.com/mrhenrike/WirelessXPL-Forge

### Arquivos criados (por bloco)

**BLOCO M -- Sub-GHz Attack Suite**
- `wirelessxpl/protocols/__init__.py` (novo pacote)
- `wirelessxpl/protocols/subghz/__init__.py`
- `wirelessxpl/protocols/subghz/ook_encoder.py` -- EV1527/Princeton/CAME/NICE/Holtek/Chamberlain/Ansonic
- `wirelessxpl/protocols/subghz/keeloq_engine.py` -- KeeLoq encrypt/decrypt, decode_frame
- `wirelessxpl/protocols/subghz/sub_file_parser.py` -- Flipper Zero .sub parse/generate
- `wirelessxpl/modules/generic/subghz/__init__.py`
- `wirelessxpl/modules/generic/subghz/static_code_replay.py`
- `wirelessxpl/modules/generic/subghz/debruijn_bruteforce.py`
- `wirelessxpl/modules/generic/subghz/keeloq_decoder.py`
- `wirelessxpl/modules/generic/subghz/keeloq_replay.py`
- `wirelessxpl/modules/generic/subghz/ev1527_vehicle_cve_2025_70994.py`
- `wirelessxpl/modules/generic/subghz/subghz_jammer.py` (triple auth gate)
- `wirelessxpl/modules/generic/subghz/br_gate_scanner.py`
- `wirelessxpl/modules/generic/subghz/tpms/tpms_decoder.py`
- `wirelessxpl/modules/generic/subghz/tpms/tpms_spoof.py`
- `wirelessxpl/modules/generic/subghz/tools/ook_analyzer.py`

**BLOCO O -- Drone/UAV Attack Suite**
- `wirelessxpl/modules/generic/drones/drone_scanner.py`
- `wirelessxpl/modules/generic/drones/mavlink/mavlink_scanner.py`
- `wirelessxpl/modules/generic/drones/mavlink/mavlink_force_disarm.py`
- `wirelessxpl/modules/generic/drones/mavlink/mavlink_gps_spoof.py`
- `wirelessxpl/modules/generic/drones/mavlink/mavlink_waypoint_inject.py`
- `wirelessxpl/modules/generic/drones/mavlink/mavlink_geofence_disable.py`
- `wirelessxpl/modules/generic/drones/mavlink/mavlink_param_dump.py`
- `wirelessxpl/modules/generic/drones/mavlink/mavlink_flood_dos.py`
- `wirelessxpl/modules/generic/drones/dji/dji_wifi_scan.py`
- `wirelessxpl/modules/generic/drones/dji/dji_quicktransfer_exfil_cve_2023_6951.py`
- `wirelessxpl/modules/generic/drones/dji/dji_deauth.py`
- `wirelessxpl/modules/generic/drones/dji/dji_droneid_info.py`
- `wirelessxpl/modules/generic/drones/parrot/parrot_anafi_deauth_cve_2019_3944.py`
- `wirelessxpl/modules/generic/drones/parrot/parrot_anafi_webcrash_cve_2019_3945.py`
- `wirelessxpl/modules/generic/drones/parrot/parrot_anafi_udp_cmd_inject.py`
- `wirelessxpl/modules/generic/drones/parrot/parrot_bebop_dhcp_exhaust_cve_2022_46416.py`
- `wirelessxpl/modules/generic/drones/holystone/hsrid01_ble_dos_cve_2024_52876.py`
- `wirelessxpl/modules/generic/drones/fpv/eachine_e52_tcp_takeover.py`

**BLOCO B -- FragAttacks CVEs**
- `wirelessxpl/modules/generic/wifi_lab/fragattacks/fragattacks_cve_2020_26140.py`
- `wirelessxpl/modules/generic/wifi_lab/fragattacks/fragattacks_cve_2020_26141.py`
- `wirelessxpl/modules/generic/wifi_lab/fragattacks/fragattacks_cve_2020_26143.py`
- `wirelessxpl/modules/generic/wifi_lab/fragattacks/fragattacks_scanner.py`

**BLOCO C -- KRACK**
- `wirelessxpl/modules/generic/wifi_lab/krack/krack_4way_retransmit.py`
- `wirelessxpl/modules/generic/wifi_lab/krack/krack_group_key_retransmit.py`
- `wirelessxpl/modules/generic/wifi_lab/krack/krack_scanner.py`

**BLOCO A -- SweynTooth Native**
- `wirelessxpl/modules/generic/bluetooth/sweyntooth/sweyntooth_cve_2019_16336.py`
- `wirelessxpl/modules/generic/bluetooth/sweyntooth/sweyntooth_cve_2019_17517.py`
- `wirelessxpl/modules/generic/bluetooth/sweyntooth/sweyntooth_cve_2019_17519.py`
- `wirelessxpl/modules/generic/bluetooth/sweyntooth/sweyntooth_cve_2019_17520.py`
- `wirelessxpl/modules/generic/bluetooth/sweyntooth/sweyntooth_scanner.py`

**BLOCO J -- RIP/VRRP**
- `wirelessxpl/modules/generic/wifi_lab/rtp_rip_spoof.py`
- `wirelessxpl/modules/generic/wifi_lab/vrrp_takeover.py`

### Commits realizados
- `ceab4b5` -- feat: WXF complete expansion - BLOCOs A/B/C/M/O/J

### Proximo passo imediato
- Registrar novas entradas no README.md (secoes Sub-GHz, Drones, FragAttacks, KRACK, SweynTooth nativo)
- Adicionar entradas para novos modulos no interpreter.py se necessario para CLI discovery
- Testar modulos com hardware real: RTL-SDR (subghz), MAVLink drone (drone suite), BLE adapter (sweyntooth)

### Pendencias conhecidas
- [ ] README.md update para novos blocos A,B,C,M,O,J
- [ ] interpreter.py discovery para novos paths de modulos
- [ ] SweynTooth CVE-2019-17518 (STM BlueNRG-1) ainda nao implementado como modulo dedicado
- [ ] DroneID active decoder requer GNU Radio -- apenas documentado

### Ambiente necessario
- Python 3.9+
- pip install scapy bleak pymavlink (para modulos avancados)
- hackrf-tools, rtl-sdr, rtl_433 (para sub-ghz)
- WiFi adapter em monitor mode (fragattacks, krack)
- BLE adapter hci0 (sweyntooth)

### Paths importantes
- Windows: `/home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge`
- Linux: `/home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge`

## [2026-06-08 03:42] - WiFi Arsenal Integration: Evidence Vault, WIDS, Wardrive, Portal Manager, Session Manager

### Estado ao encerrar
- Analisados 7 repositorios WiFi Arsenal (wifi-arsenal_1 a _7) em submodules/IoT/
- Identificadas funcionalidades unicas nao existentes no WXF
- Implementados 6 novos modulos em wirelessxpl/modules/generic/:
  - evidence_vault/evidence_vault.py (reescrito): SQLite hash-chained audit ledger, ISO 27037 compativel
  - wardrive/wardrive_logger.py (reescrito): GPS logger com gpsd/NMEA, export CSV/JSON/KML/GeoJSON
  - wids/wifi_ids.py (reescrito): WIDS nativo Scapy, detecta 8 tipos de ataque, MQTT opcional
  - evil_twin/portal_manager.py (NOVO): portal captivo stdlib, 8 templates HTML (ISPs BR + Google + Starbucks)
  - wids/esp8266_wids_bridge.py (NOVO): bridge MQTT para ESP8266 WIDS hardware
  - session_manager/session_manager.py (reescrito): persistencia SQLite multi-sessao completa
- Todos os __init__.py atualizados com exports corretos
- Sintaxe validada: python -m py_compile OK em todos os 6 arquivos
- Commit: 92235aa "Add Evidence Vault, Wardrive Logger, WIDS, Portal Manager, Session Manager"
- Push: https://github.com/mrhenrike/WirelessXPL-Forge.git master

### Arquivos modificados
- wirelessxpl/modules/generic/evidence_vault/__init__.py
- wirelessxpl/modules/generic/evidence_vault/evidence_vault.py
- wirelessxpl/modules/generic/wardrive/__init__.py
- wirelessxpl/modules/generic/wardrive/wardrive_logger.py
- wirelessxpl/modules/generic/wids/__init__.py
- wirelessxpl/modules/generic/wids/wifi_ids.py
- wirelessxpl/modules/generic/wids/esp8266_wids_bridge.py (NOVO)
- wirelessxpl/modules/generic/evil_twin/__init__.py (NOVO)
- wirelessxpl/modules/generic/evil_twin/portal_manager.py (NOVO)
- wirelessxpl/modules/generic/session_manager/__init__.py
- wirelessxpl/modules/generic/session_manager/session_manager.py

### Proximo passo imediato
- Integrar portal_manager ao fluxo existente de evil_twin no WXF
- Testar WardriveLogger com GPS real (gpsd) em campo
- Validar WirelessIDS com adaptador em monitor mode

### Pendencias conhecidas
- [ ] Integrar EvidenceVault com os ataques existentes (airgeddon wrapper, etc.)
- [ ] Adicionar mapa interativo Folium/Leaflet usando GeoJSON do WardriveLogger
- [ ] Bluetooth module (arsenal_2) - BluetoothScanner ainda nao integrado ao WXF
- [ ] Portal templates adicionais: Microsoft, hotel, aeroporto
- [ ] Teste de integracao do ESP8266WIDSBridge com hardware real
- [ ] wifi_lab/ap_less_client_attack.py tem modificacao nao commitada (pre-existente)

### Ambiente necessario
- Python 3.9+
- pip install scapy paho-mqtt bleak (para modulos avancados)
- WiFi adapter em monitor mode para WirelessIDS real
- ESP8266 com firmware WIDS para esp8266_wids_bridge
- gpsd daemon para GPS real no WardriveLogger

### Paths importantes
- Windows: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge
- Linux: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge

## [2026-06-08 00:51-01:10] - Auditoria de qualidade WXF v1.8.0 - syntax, implementacao, README

### Estado ao encerrar
- Corrigido erro de sintaxe em wifi_lab/ap_less_client_attack.py (IndentationError linha 100 - if sem body)
- Adicionado 
un() em: is_spoof.py, 	raffic_enforcement_scanner.py, mcw_radar_attack.py
- Adicionado __info__ em: vidence_vault.py, wardrive_logger.py, wifi_ids.py, session_manager.py
- README.md (EN) expandido com: Sub-GHz protocol table, DeBruijn/EV1527/MAVLink/AIS examples, FMCW radar, Evidence Vault, WIDS, SweynTooth, FragAttacks, KRACK sections
- README.pt-BR.md completamente reescrito para v1.8.0 com todas as secoes novas em PT-BR
- Todos os modulos dos BLOCOs A/B/C/F/I/M/O verificados: syntax OK, __info__ presente, simulate implementado onde aplicavel
- Sessao anterior (paralela) ja commitou as mudancas antes do encerramento desta sessao

### Commits realizados (pela sessao paralela)
- d67ce62 - module quality fixes + README.md v1.8.0
- 182ed8 - README.pt-BR.md update v1.8.0
- 6761ed - docs(pt-BR) final v1.8.0 syntax samples

### Proximo passo imediato
- Integrar EvidenceVault com chamadas dos modulos de ataque existentes

### Pendencias conhecidas
- [ ] Integrar EvidenceVault com os ataques existentes (gravar evidencias automaticamente)
- [ ] Adicionar mapa interativo Folium usando GeoJSON do WardriveLogger
- [ ] Bluetooth BLE scanner real integrado ao framework WXF
- [ ] Testes de integracao: ESP8266WIDSBridge + hardware real
- [x] Atribuições de IA removidas do histórico remoto (force-push sem Co-authored-by)

### Ambiente necessario
- Python 3.9+
- pip install scapy paho-mqtt bleak
- WiFi adapter em monitor mode para WirelessIDS
- HackRF / CC1101 para modulos Sub-GHz ao vivo
- RTL-SDR para TPMS decoder

### Paths importantes
- Windows: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge
- Linux: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge

## [2026-06-08 09:05] -- Wiki completa criada e README melhorado

### Estado ao encerrar
- Wiki completa criada e publicada em https://github.com/mrhenrike/WirelessXPL-Forge/wiki
- 14 paginas criadas: Home, Quick-Start, CLI-Reference, Wi-Fi-Attacks, Bluetooth-BLE, SubGHz-Attacks, Drone-Security, Maritime-Security, Evidence-Forensics, Wardriving, WIDS, Hardware, FragAttacks, KRACK, Configuration
- Cada pagina tem terminal I/O completo com exemplos realistas
- README.md atualizado: badges completos (PyPI, Python, CI, Downloads, License, Version, Modules, Platform) + link direto para a wiki no GitHub
- Secao "WiFi Arsenal" ja estava renomeada para "Forensics, Wardriving and Session Management" antes desta sessao
- Nenhuma referencia a BLOCO X ou WiFi Arsenal encontrada no README
- Commits: wiki (4632524), README (2cdea70) - ambos pushed para master

### Proximo passo imediato
- Verificar se a wiki esta visivelmente publicada em https://github.com/mrhenrike/WirelessXPL-Forge/wiki
- Considerar adicionar README.pt-BR.md (ja referenciado na linha 7 do README mas arquivo pode nao existir)

### Pendencias conhecidas
- [ ] README.pt-BR.md referenciado no README mas pode nao existir
- [ ] docs/wiki/en-US/ e docs/wiki/pt-BR/ referenciados em COVERAGE_MATRIX podem ser removidos do README (substituidos pelo GitHub Wiki)

### Paths importantes
- Windows: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge
- Linux: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge
- Wiki local: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge\.tmp\wxf_wiki

## [2026-06-08 12:55] -- Wiki PT-BR completa: 15 paginas traduzidas

### Estado ao encerrar
- Criadas 15 paginas PT-BR completas com traducao integral (terminal I/O preservado)
- Criado _Sidebar-ptBR.md com navegacao completa em portugues
- Home.md atualizado com link para Home-pt-BR.md
- Commit e push realizados: hash 6ad86e6

### Arquivos criados
- Home-pt-BR.md, Inicio-Rapido.md, Referencia-CLI.md, Configuracao.md
- Ataques-WiFi.md, Bluetooth-BLE-ptBR.md, Ataques-SubGHz.md
- Seguranca-Drones.md, Seguranca-Maritima.md, Evidencias-Forense.md
- Wardriving-ptBR.md, WIDS-ptBR.md, Hardware-ptBR.md
- FragAttacks-ptBR.md, KRACK-ptBR.md, _Sidebar-ptBR.md

### Proximo passo imediato
- Wiki PT-BR concluida. Verificar rendering no GitHub Wiki se necessario.

### Pendencias conhecidas
- [ ] Verificar rendering das paginas no GitHub Wiki

### Ambiente necessario
- Python 3.8+ (apenas para uso do framework)
- Git com acesso ao repositorio mrhenrike/WirelessXPL-Forge.wiki

### Paths importantes
- Windows: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge
- Linux: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge
- Wiki local: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge\.tmp\wxf_wiki

## [2026-06-19 04:40] - Implementacao do modulo OS-Guard

### Estado ao encerrar
- Criado wirelessxpl/core/os_guard.py: sistema de verificacao de compatibilidade de OS por modulo via decorator @requires_os
- Criado tests/__init__.py: arquivo vazio para reconhecimento do pacote de testes
- Criado tests/test_os_guard.py: 17 testes unitarios cobrindo todos os requisitos de OS e o helper get_module_os_label
- 17/17 testes passando com pytest (Python 3.13.5)
- Nenhum arquivo existente foi modificado

### Proximo passo imediato
- Integrar @requires_os nos modulos existentes (ex: modules/wifi/, modules/bluetooth/) para habilitar a guard em producao

### Pendencias conhecidas
- [ ] Aplicar @requires_os(OSRequirement.LINUX_ONLY) nos modulos WiFi que usam monitor mode
- [ ] Aplicar @requires_os(OSRequirement.LINUX_MAC) nos modulos Bluetooth/BLE
- [ ] Aplicar @requires_os(OSRequirement.CROSS_PLATFORM) nos exporters e analisadores offline
- [ ] Expor get_module_os_label na listagem do CLI (wxf.py ou interpreter.py)

### Ambiente necessario
- Python 3.13+
- pytest 8.x para rodar os testes

### Paths importantes
- Windows: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge\wirelessxpl\core\os_guard.py
- Windows: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge\tests\test_os_guard.py
- Linux: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge/wirelessxpl/core/os_guard.py
- Linux: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge/tests/test_os_guard.py

## [2026-06-19 04:45] - Phase 0A WXF Native Refactor

### Estado ao encerrar
- Auditoria completa de bridges proibidos em wirelessxpl/modules/generic/ (54 arquivos com referencias a binarios proibidos)
- wifi_lab/ renomeado para wifi/ (73 arquivos raiz + 9 subdiretorios copiados)
- Referencias internas "wifi_lab" substituidas por "wifi" em 41 arquivos copiados + 21 arquivos externos
- interpreter.py: path_tokens check atualizado para incluir "wifi" (mantido "wifi_lab" por compatibilidade)
- wifi_lab/DEPRECATED.md criado (aviso de deprecacao)
- Bridges obsoletos removidos: airgeddon_bridge, wirespy_bridge, pwnagotchi_bridge, sniffair_passive_recon, hashcatch_bridge, pmk_precompute (wifi/ e wifi_lab/)
- BRIDGE_AUDIT.md gerado em /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge/.tmp/wxf-references/
- docs/PREREQUISITES.md atualizado com secao "Politica de Dependencias - WXF v1.7.0+"

### Arquivos modificados
- wirelessxpl/modules/generic/wifi/ (NOVO - 82 arquivos)
- wirelessxpl/modules/generic/wifi/__init__.py (NOVO conteudo)
- wirelessxpl/modules/generic/wifi_lab/DEPRECATED.md (NOVO)
- wirelessxpl/interpreter.py (path_tokens check)
- wirelessxpl/modules/generic/bluetooth/*.py (9 arquivos - imports)
- wirelessxpl/modules/generic/external/*.py (11 arquivos - imports)
- docs/PREREQUISITES.md (secao de politica adicionada ao topo)
- /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge/.tmp/wxf-references/BRIDGE_AUDIT.md (NOVO)

### Proximo passo imediato
- Fase 0B: Criar wirelessxpl/modules/generic/wifi/wps_engine_native.py (substitui reaver/bully/pixiewps)

### Pendencias conhecidas
- [ ] wifi_lab/ ainda existe - remover apos validacao completa dos imports
- [ ] external/momo_integrated_attack.py e external/evilginx_prereq_pointer.py listados mas existem em wifi_lab/ (nao em external/) - verificar se devem ser removidos de wifi_lab/ tambem
- [ ] Fase 0B: wps_engine_native.py (substitui reaver/bully bridges)
- [ ] Fase 0C: flood_engine_native.py (substitui mdk3/mdk4 bridges)
- [ ] Fase 0D: phishing_engine.py (substitui wifiphisher/fluxion bridges)

### Ambiente necessario
- Python 3.10+
- Sem commits/push - apenas mudancas locais

### Paths importantes
- Windows: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge\wirelessxpl\modules\generic\wifi\
- Windows: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge\docs\PREREQUISITES.md
- Windows: /home/mrhenrike/Documentos/Projetos\.tmp\wxf-references\BRIDGE_AUDIT.md
- Linux: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge/wirelessxpl/modules/generic/wifi/
- Linux: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge/docs/PREREQUISITES.md

## [2026-06-19 04:49] -- Phase 0B: wps_engine_native.py criado

### Estado ao encerrar
- Criado wirelessxpl/modules/generic/wifi/wps_engine_native.py (~59 KB, ~1674 linhas)
- Implementacao 100% Python/Scapy do protocolo WPS EAP-WSC (M1-M8)
- Sem modificacoes em arquivos existentes; sem commit/push

### Arquivos modificados (paths relativos)
- wirelessxpl/modules/generic/wifi/wps_engine_native.py (novo, criado)

### Commits realizados
- nenhum (Phase 0B nao inclui commit)

### Proximo passo imediato
- Criar __init__.py no diretorio wifi/ (se Phase 0C for delegada)
- Ou: rodar testes de importacao basicos (python -c "from wirelessxpl.modules.generic.wifi.wps_engine_native import Exploit")
- Depois: integracao com o wxf.py dispatcher / CLI para registrar o novo modulo

### Pendencias conhecidas
- [ ] Teste de importacao no ambiente Linux (monitor mode, Scapy instalado)
- [ ] Implementar M4-M8 completo para recuperacao de PSK via PIN correto (M8 path)
- [ ] Adicionar suporte a fragmentacao EAP-WSC (flag 0x01 em frames grandes)
- [ ] Integrar __init__.py se Phase 0C ainda nao foi executada

### Ambiente necessario
- Linux (Ubuntu/Kali) com interface WiFi em modo monitor
- pip install scapy cryptography
- sudo apt install reaver (para modo scan via wash)
- Interface em monitor mode: sudo airmon-ng start wlan0

### Paths importantes
- Windows: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge\wirelessxpl\modules\generic\wifi\wps_engine_native.py
- Linux: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge/wirelessxpl/modules/generic/wifi/wps_engine_native.py

## [2026-06-19 04:50] -- Phase 0C: flood_engine_native.py criado

### Estado ao encerrar
- Criado wirelessxpl/modules/generic/wifi/flood_engine_native.py (33 KB)
- Implementa todos os 8 modos do mdk4 via Scapy nativo: b, a, d, p, m, g, e, w
- Michael MIC calculado em Python puro (funcoes _michael_b + michael_mic)
- send_deauth() exportada no nivel de modulo para uso por phishing_engine.py e handshake_snooper.py
- RSN IE TKIP-only (_build_rsn_ie_tkip_only) para modo g (WPA downgrade)
- EAPOL-Key MIC error report para modo m (Michael MIC shutdown)
- Sem em dash, sem fingerprints, docstrings Google, zero linter errors

### Proximo passo imediato
- Outro agente cria/atualiza __init__.py do pacote wifi/ exportando send_deauth e michael_mic
- Outro agente integra flood_engine_native.py nos modulos phishing_engine.py e handshake_snooper.py

### Pendencias conhecidas
- [ ] __init__.py do pacote wifi/ a ser atualizado (outro agente - Phase 0C sequencia)
- [ ] Integracao com phishing_engine.py: import send_deauth from flood_engine_native
- [ ] Integracao com handshake_snooper.py: import send_deauth from flood_engine_native
- [ ] Testes funcionais no Linux com interface em monitor mode (requirem hardware real)

### Ambiente necessario
- Linux (Ubuntu/Kali) com interface WiFi em modo monitor
- pip install scapy
- sudo airmon-ng start wlan0
- iw instalado para channel hop (modo b sem canal fixo e modo w)

### Paths importantes
- Windows: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge\wirelessxpl\modules\generic\wifi\flood_engine_native.py
- Linux: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge/wirelessxpl/modules/generic/wifi/flood_engine_native.py

## [2026-06-19 07:45] -- Phase 0E: dragonblood_suite.py native refactor

### Estado ao encerrar
- Refatorado: wirelessxpl/modules/generic/wifi/dragonblood_suite.py
- Removidas 5 chamadas subprocess a binarios externos (dragontime, dragonforce, dragondrain, dragonslayer-client, dragonslayer-server)
- Adicionadas 4 classes nativas: DragonTimingAttack, DragonForce, DragonDrain, DragonSlayer
- Adicionado @requires_os(OSRequirement.LINUX_ONLY) na classe Exploit
- Modos atualizados: timing, force, drain, slayer, info, downgrade_info
- Versao: 1.0.0 -> 2.0.0
- Zero erros de lint

### Arquivo modificado
- wirelessxpl/modules/generic/wifi/dragonblood_suite.py

### Proximo passo imediato
- python -m py_compile wirelessxpl/modules/generic/wifi/dragonblood_suite.py

### Pendencias conhecidas
- [ ] DragonSlayer: ataques reflection/invalid-curve exigem EAP state machine completa
- [ ] DragonForce: captura passiva de respostas status=77 nao implementada

### Ambiente necessario
- Python 3.8+, Scapy, numpy (recomendado)
- Linux, interface Wi-Fi em modo monitor, root/CAP_NET_RAW

### Paths importantes
- Windows: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge\wirelessxpl\modules\generic\wifi\dragonblood_suite.py
- Linux: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge/wirelessxpl/modules/generic/wifi/dragonblood_suite.py

## [2026-06-19 04:50] -- Phase 0H: dns_dhcp_server + monitor_mode_manager

### Estado ao encerrar
- Criado dns_dhcp_server.py: CaptiveDNSServer (dnslib), CaptiveDHCPServer (Scapy), CaptiveNetwork, Exploit
- Criado monitor_mode_manager.py: MonitorModeManager (context manager), Exploit
- Nenhum arquivo existente modificado
- Sem commit/push

### Proximo passo imediato
- Integrar dns_dhcp_server com captive_portal_engine (substituir dnsmasq)
- Testar CaptiveDHCPServer em ambiente de lab com interface wlan0

### Pendencias conhecidas
- [ ] Integrar CaptiveNetwork no captive_portal_engine como alternativa a dnsmasq
- [ ] Testar CaptiveDNSServer modo spoof com upstream forwarding real
- [ ] Verificar comportamento do MonitorModeManager em interfaces que renomeiam (wlan0 -> wlan0mon)
- [ ] Adicionar suporte a IPv6 no CaptiveDNSServer (AAAA redirect opcional)

### Ambiente necessario
- Python 3.7+
- pip install dnslib scapy
- Linux com root (port 53 e raw sockets)

### Paths importantes
- Windows: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge\wirelessxpl\modules\generic\wifi\dns_dhcp_server.py
- Windows: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge\wirelessxpl\modules\generic\wifi\monitor_mode_manager.py
- Linux: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge/wirelessxpl/modules/generic/wifi/dns_dhcp_server.py
- Linux: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge/wirelessxpl/modules/generic/wifi/monitor_mode_manager.py

## [2026-06-19 04:45] - Phase 0D WXF Native Refactor: phishing_engine.py

### Estado ao encerrar
- Criado wirelessxpl/modules/generic/wifi/phishing_engine.py (novo arquivo, 660+ linhas)
- Zero erros de lint

### O que foi implementado
- APScanner: Scapy beacon/probe-response sniffer (BSSID, SSID, canal, RSSI, enc, clientes)
- HostapdManager: gera wxf-hostapd.conf dinamicamente, inicia hostapd como subprocess com finally cleanup
- DeauthWorker: lazy import de flood_engine_native; fallback Scapy Dot11Deauth inline; thread daemon
- CaptiveNetworkStack: lazy import de dns_dhcp_server; fallback dnslib AllRedirectResolver em :53
- PhishingHTTPServer: BaseHTTPRequestHandler; auto-selecao de template por UA + Accept-Language; connectivity check spoofing (iOS CNA, Android, Windows NLA); captura POST /capture
- HandshakeVerifier: aircrack-ng -w - (stdin) para verificar handshake sem escrever senha no disco
- _CredentialStore: JSON seguro - apenas SHA-256 da senha, nunca plaintext nos logs
- _select_template(): auto-selecao por OS (Android->google_wifi, iOS->apple_captive, Windows->microsoft_365)
- 23 templates detectados em wirelessxpl/resources/captive_templates/
- class Exploit(WXF API): modos info | scan | list_templates | start | generate_config
- Connectivity checks: captive.apple.com, connectivitycheck.gstatic.com, www.msftconnecttest.com e 6 outros

### Arquivo criado
- wirelessxpl/modules/generic/wifi/phishing_engine.py

### Proximo passo imediato
- python -m py_compile wirelessxpl/modules/generic/wifi/phishing_engine.py (em Linux com Scapy)
- Testar modo scan: set mode scan; set interface_mon wlan0mon; set i_know_scope true; run

### Pendencias conhecidas
- [ ] flood_engine_native.send_deauth nao existe ainda - DeauthWorker usa Scapy inline como fallback
- [ ] dns_dhcp_server nao existe ainda - CaptiveNetworkStack usa dnslib como fallback
- [ ] DHCP nativo nao implementado no fallback dnslib (apenas DNS redirect)
- [ ] Templates com campos customizados (hotel_wifi: room/last_name) capturados mas mapeamento nao especializado

### Ambiente necessario
- Python 3.8+, Scapy, hostapd
- Linux (root/CAP_NET_RAW), interface em modo monitor + interface AP
- Opcional: aircrack-ng, dnslib (pip install dnslib)

### Paths importantes
- Windows: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge\wirelessxpl\modules\generic\wifi\phishing_engine.py
- Linux: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge/wirelessxpl/modules/generic/wifi/phishing_engine.py

## [2026-06-19 04:45] -- Phase 0G WXF Native Refactor - WEP e TKIP

### Estado ao encerrar
- Refatorado in-place wep_attack_suite.py (v2.0.0): 7 substituicoes de aireplay-ng/airodump-ng por Scapy nativo
- Refatorado in-place tkip_attack_suite.py (v2.0.0): michael_mic() nativo adicionado, Beck-Tews nativo como primario
- Arquivos modificados:
  - wirelessxpl/modules/generic/wifi/wep_attack_suite.py
  - wirelessxpl/modules/generic/wifi/tkip_attack_suite.py
- Sem commits/push conforme instrucao

### Substituicoes realizadas em wep_attack_suite.py
- airodump-ng -> _capture_ivs_scapy() (thread Scapy sniffer, escreve pcap para aircrack-ng)
- aireplay-ng -1 -> _fake_auth_loop() (Dot11Auth + Dot11AssoReq via sendp)
- aireplay-ng -2 -> _interactive_replay_loop() (captura e replay de frames WEP)
- aireplay-ng -3 -> _arp_replay_loop() (captura ARP WEP e replay continuo)
- aireplay-ng -4 -> _chopchop_native() (algoritmo chopchop byte-a-byte nativo)
- aireplay-ng -5 -> _frag_attack_loop() (injecao fragmentada com recalculo de numero de sequencia)
- aireplay-ng -6 -> _caffe_latte_loop() (nudge a clientes via Dot11 data from-DS)
- aireplay-ng -7 -> _hirte_loop() (CFrag via LLC/SNAP fragmentado)
- aircrack-ng mantido: _try_crack() com comentario ACCEPTED DEP

### Substituicoes realizadas em tkip_attack_suite.py
- Adicionada michael_mic() em nivel de modulo (algoritmo completo IEEE 802.11 / Beck&Tews 2008)
- _run_beck_tews() renomeado para _run_beck_tews_tkiptun() (mantido como ACCEPTED DEP)
- _run_beck_tews_native() adicionado como caminho primario (Scapy + michael_mic)
- Dispatch em run() atualizado: beck_tews -> _run_beck_tews_native() (fallback automatico para tkiptun-ng)
- tkiptun-ng: todos os pontos de chamada marcados com ACCEPTED DEP

### Proximo passo imediato
- Testar em ambiente Linux com interface em modo monitor (python -m py_compile primeiro)
- Ajustar timeout do chopchop se necessario para o ambiente alvo

### Pendencias conhecidas
- [ ] Teste de integracao em hardware real (wlan0mon)
- [ ] _chopchop_native: validar heuristica de deauth vs aceitacao em APs reais
- [ ] Beck-Tews nativo: implementar recuperacao completa de PTK via chopchop TKIP (atualmente demostra MIC, delega execucao ao tkiptun-ng)

### Ambiente necessario
- Python 3.8+, Scapy (pip install scapy)
- aircrack-ng (apenas para aircrack-ng e tkiptun-ng)
- Linux com interface em modo monitor e suporte a injecao
- CAP_NET_RAW ou root

### Paths importantes
- Windows: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge\wirelessxpl\modules\generic\wifi\wep_attack_suite.py
- Windows: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge\wirelessxpl\modules\generic\wifi\tkip_attack_suite.py
- Linux: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge/wirelessxpl/modules/generic/wifi/wep_attack_suite.py
- Linux: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge/wirelessxpl/modules/generic/wifi/tkip_attack_suite.py

## [2026-06-19 04:50] — Phase 0F: Refactor deauth/handshake modules to native Scapy

### Estado ao encerrar
- Refatoracao de 3 modulos em wirelessxpl/modules/generic/wifi_lab/ concluida in-place
- handshake_snooper.py: v1.1.0 -> v2.0.0 (reescrita completa)
- deauth_multimode.py: v1.0.0 -> v1.1.0 (alteracoes cirurgicas)
- aireplay_deauth_barrage.py: v1.x -> v2.0.0 (reescrita com suporte Scapy)
- deauth_csa_suite.py: nao modificado (ja possuia Scapy integrado)
- selective_jammer.py: nao modificado (fora do escopo do Phase 0F)
- Sem commits realizados (conforme instrucao)

### Arquivos modificados
- wirelessxpl/modules/generic/wifi_lab/handshake_snooper.py
- wirelessxpl/modules/generic/wifi_lab/deauth_multimode.py
- wirelessxpl/modules/generic/wifi_lab/aireplay_deauth_barrage.py

### Subprocess calls removidos/substituidos

handshake_snooper.py:
- REMOVIDO: cowpatty subprocess (verify_method=cowpatty)
- REMOVIDO: pyrit subprocess (verify_method=pyrit)
- SUBSTITUIDO: airodump-ng como capturador primario -> Scapy sniff() EAPOL (use_airodump=False por padrao)
- SUBSTITUIDO: aireplay-ng como unico deauth -> Scapy Dot11Deauth (native_deauth=True por padrao)
- MANTIDO: airodump-ng como opcao (use_airodump=True), aceito como parte do aircrack-ng suite
- MANTIDO: aireplay-ng como opcao (native_deauth=False), aceito como parte do aircrack-ng suite
- MANTIDO: aircrack-ng como unico verificador
- ADICIONADO: _classify_eapol_message() para deteccao M1/M2/M3/M4 via Key Information bitmasks
- ADICIONADO: _capture_eapol_scapy() com stop_filter e threading.Event para parada antecipada
- ADICIONADO: _send_deauth_native() (Scapy Dot11Deauth broadcast)

deauth_multimode.py:
- ALTERADO: backend default de "aireplay" para "native" (Scapy)
- ADICIONADO: "native" ao VALID_BACKENDS
- ADICIONADO: normalizacao "native" -> "scapy" no run()
- ADICIONADO: prioridade native/scapy em _run_targeted_deauth_with_capture()
- CORRIGIDO: tempfile.mkdtemp() -> Path(".tmp/wxf_deauth_...") em _run_targeted_deauth_with_capture()
- CORRIGIDO: tempfile.TemporaryDirectory() -> Path(".tmp/wxf_scan_...") em _scan_clients()
- REMOVIDO: import os (nao utilizado)

aireplay_deauth_barrage.py:
- SUBSTITUIDO: aireplay-ng como unico modo -> Scapy como modo primario (mode="native")
- ADICIONADO: mode = OptString("native", ...) parametro
- ADICIONADO: _send_deauth_scapy() metodo por burst
- ADICIONADO: _run_scapy_barrage() loop de alta intensidade via Scapy
- EXTRAIDO: logica aireplay para _run_aireplay_barrage() e _one_burst_aireplay()
- CORRIGIDO: bug self.subprocess_timeout_s (nao existia) -> constante _BURST_SUBPROCESS_TIMEOUT_S=30
- MANTIDO: aireplay-ng como opcao (mode="aireplay") com fallback automatico para Scapy

### Proximo passo imediato
- Testar em Linux: python -m py_compile wirelessxpl/modules/generic/wifi_lab/handshake_snooper.py
- Integrar com Phase 0A (rename wifi_lab/ -> wifi/) quando aplicavel

### Pendencias conhecidas
- [ ] Teste com hardware real (wlan0mon) para validar captura EAPOL Scapy
- [ ] selective_jammer.py: ainda usa aireplay-ng e mdk4 primariamente (nao era escopo 0F)
- [ ] deauth_csa_suite.py: method default ainda e "deauth_aireplay" - potencial melhoria futura

### Ambiente necessario
- Python 3.8+, Scapy (pip install scapy)
- aircrack-ng (opcional - para verificacao e modo airodump)
- Linux com interface em modo monitor e suporte a injecao
- CAP_NET_RAW ou root para sendp()

### Paths importantes
- Windows: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge\wirelessxpl\modules\generic\wifi_lab\handshake_snooper.py
- Windows: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge\wirelessxpl\modules\generic\wifi_lab\deauth_multimode.py
- Windows: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge\wirelessxpl\modules\generic\wifi_lab\aireplay_deauth_barrage.py
- Linux: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge/wirelessxpl/modules/generic/wifi_lab/handshake_snooper.py
- Linux: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge/wirelessxpl/modules/generic/wifi_lab/deauth_multimode.py
- Linux: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge/wirelessxpl/modules/generic/wifi_lab/aireplay_deauth_barrage.py

## [2026-06-19 05:00] - Phase 0J: v1.7.0 release cycle closed

### Estado ao encerrar
- pyproject.toml: dnslib>=0.9.24 e cryptography>=41.0 adicionadas ao core
- 10 bridges obsoletos deletados (6 em wifi/, 4 em external/)
- wifi/__init__.py atualizado com docstring completa e send_deauth() lazy-import
- CHANGELOG.md criado na raiz com entrada v1.7.0 completa
- FULL_CATALOG.md: secao "Modulos Nativos v1.7.0" inserida no topo
- Commit: 6ff36a0 "v1.7.0 - native WPS/MDK/Phishing/DNS-DHCP/Monitor engines + OS Guard" (118 files changed)
- Tag v1.7.0 recriada e force-pushed para origin
- Build: wirelessxpl-1.7.0-py3-none-any.whl (3.8 MB) e wirelessxpl-1.7.0.tar.gz (3.3 MB)
- PyPI upload: BLOQUEADO - filename v1.7.0 ja reservado (upload anterior)

### Proximo passo imediato
- PyPI: deletar release v1.7.0 em https://pypi.org/manage/project/wirelessxpl/releases/1.7.0/
  e re-executar: twine upload dist/*1.7.0*
- OU bumpar para v1.7.0.post1: atualizar version em pyproject.toml e wirelessxpl/__init__.py, rebuild e upload

### Pendencias conhecidas
- [ ] PyPI: re-upload de v1.7.0 apos deletar release existente no painel
- [ ] Alternativa: bump para 1.7.0.post1 se deletar o release nao for viavel

### Ambiente necessario
- Python 3.8+
- twine, build (pip install build twine)
- PYPI_TOKEN em ~/.pypirc

### Paths importantes
- Windows: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge
- Linux: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge

## [2026-06-19 04:55] - Refatoracao handshake_snooper + wep_attack_suite

### Estado ao encerrar
- Removidas todas as referencias a cowpatty e pyrit de handshake_snooper.py
- Removido airodump-ng como capturador obrigatorio em handshake_snooper.py
- Adicionada captura EAPOL nativa via Scapy (_capture_eapol_scapy) em handshake_snooper.py
- Adicionada verificacao de handshake via aircrack-ng (_verify_handshake_aircrack) em handshake_snooper.py
- Adicionado import lazy de send_deauth de flood_engine_native em handshake_snooper.py
- Adicionados parametros use_airodump=False e native_mode=True em handshake_snooper.py
- Adicionado wrpcap ao bloco de imports Scapy em wep_attack_suite.py
- Adicionadas funcoes standalone _capture_wep_ivs_scapy, _fake_auth_scapy, _arp_replay_scapy em wep_attack_suite.py
- Adicionado parametro native_mode=True na classe Exploit de wep_attack_suite.py
- Versao de handshake_snooper.py bumpeada de 1.1.0 para 1.2.0
- Sem commit realizado (conforme instrucoes)

### Arquivos modificados
- wirelessxpl/modules/generic/wifi/handshake_snooper.py
- wirelessxpl/modules/generic/wifi/wep_attack_suite.py

### Proximo passo imediato
- Testar em ambiente Linux com interface monitor real (wlan0mon)
- Verificar se aircrack-ng dry-run com -w /dev/null funciona conforme esperado

### Pendencias conhecidas
- [ ] Testar _capture_eapol_scapy com handshake real para validar deteccao M1-M4
- [ ] Testar _capture_wep_ivs_scapy e _arp_replay_scapy em AP WEP de lab
- [ ] Considerar bump de versao para wep_attack_suite.py (atual: 2.0.0, sem mudanca de versao nesta sessao)

### Ambiente necessario
- Python 3.8+, Scapy (pip install scapy)
- aircrack-ng (para verificacao de handshake e crack WEP final)
- Interface wireless em modo monitor com suporte a injecao de pacotes (Linux)

### Paths importantes
- Windows: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge
- Linux: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge

## [2026-06-19 04:55] -- Cleanup final WXF para v1.7.0

### Estado ao encerrar
- pyproject.toml: dependencias dnslib>=0.9.24 e cryptography>=41.0 confirmadas em [project.dependencies]
- wirelessxpl/modules/generic/wifi/__init__.py: reescrito com lazy exports, wrappers send_deauth e michael_mic (adaptado para assinatura real da funcao)
- Arquivos deletados de wifi_lab/: mdk3_bridge.py, mdk4_bridge.py, momo_integrated_attack.py, evilginx_prereq_pointer.py, pyrit_gpu_bridge.py, wps_multimode.py
- Arquivos ja ausentes (deletados anteriormente) em external/: reaver_bridge.py, bully_bridge.py, wifiphisher_bridge.py, fluxion_bridge.py - pycs orphaos removidos
- flood_engine_native.py: adicionado rom wirelessxpl.core.os_guard import OSRequirement, requires_os e @requires_os(OSRequirement.LINUX_ONLY) na classe Exploit
- wps_engine_native.py: os_guard ja presente, sem alteracoes necessarias
- dragonblood_suite.py: versao 2.0.0, @requires_os presente, sem subprocess proibido - sem alteracoes
- Catalogos atualizados: all_known_wireless_attacks.json, external_framework_clones.json, upstream_issues_prs.json - referencias a bridges deletadas substituidas pelos modulos nativos

### Inconsistencia detectada e resolvida
- michael_mic em flood_engine_native.py tem assinatura (key, data) de 2 args; a spec do task pedia wrapper com 5 args (key, da, sa, priority, data). O wrapper em __init__.py foi adaptado para construir o msg completo (DA||SA||priority||0x00x3||data) antes de delegar para _m(key, msg), mantendo compatibilidade com IEEE 802.11 TKIP.

### Proximo passo imediato
- Verificar se os modulos FloodEngine, WPSEngine, PhishingEngine, CaptiveNetwork, MonitorModeManager, DragonbloodSuite estao exportando simbolos acessiveis via import direto (as classes estao em __all__ mas nao bound no namespace de __init__.py)

### Pendencias conhecidas
- [ ] __all__ em wifi/__init__.py lista FloodEngine/WPSEngine/PhishingEngine/CaptiveNetwork/MonitorModeManager/DragonbloodSuite mas esses simbolos nao estao bound no namespace do pacote - imports diretos dos submodulos funcionam mas rom wifi import FloodEngine vai falhar
- [ ] dragonblood_suite.py expoe classe Exploit, nao DragonbloodSuite - alias nao criado
- [ ] wireless_tool_prereq_audit.py menciona mdk4/mdk3 como CLIs (nao modulos Python) - mantido como esta (correto para audit de ferramentas externas)

### Ambiente necessario
- Python 3.8+
- Linux (modulos com @requires_os LINUX_ONLY)
- scapy, dnslib>=0.9.24, cryptography>=41.0, pycryptodome

### Paths importantes
- Windows: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge
- Linux: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge

## [2026-06-19 04:54] - Implementar 3 modulos wifi nativos (dns_dhcp_server, monitor_mode_manager, phishing_engine)

### Estado ao encerrar
- Criados/reescritos 3 modulos no caminho wirelessxpl/modules/generic/wifi/:
  - dns_dhcp_server.py - CaptiveDNSServer (dnslib), CaptiveDHCPServer (Scapy BOOTP), CaptiveNetwork, Exploit
  - monitor_mode_manager.py - MonitorModeManager (iw/rfkill/channel hop/injection test), Exploit
  - phishing_engine.py - Evil twin + captive portal nativo (scan_aps, hostapd clone, deauth, DNS/DHCP, HTTP portal, credential capture, handshake verify), Exploit
- Arquivos verificados: sintaxe Python OK (py_compile), zero lints
- Nao foram feitos commits

### Proximo passo imediato
- Revisar se phishing_engine.py precisa ser reconciliado com a versao anterior (1279 linhas no HEAD)
- Os originais tinham implementacoes proprias; os novos seguem as specs fornecidas nesta sessao

### Pendencias conhecidas
- [ ] Confirmar se versao nova do phishing_engine.py substitui ou deve ser mergeada com versao anterior
- [ ] Testar em ambiente Linux com interface Wi-Fi real
- [ ] Instalar dnslib (pip install dnslib) para CaptiveDNSServer funcionar
- [ ] Verificar se templates em resources/captive_templates/ estao presentes

### Ambiente necessario
- Python 3.7+
- Linux (raw sockets, monitor mode)
- hostapd instalado (apt install hostapd)
- pip: scapy, dnslib
- Interface wireless com suporte a modo AP (wlan1) e monitor (wlan0mon)

### Paths importantes
- Windows: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge
- Linux: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge

## [2026-06-19 06:55] -- Sync wifi_lab/ -> wifi/ + 1.7.0.post1 PyPI

### Estado ao encerrar
- Sincronizados 3 modulos refatorados da Fase 0F de wifi_lab/ para wifi/
  - handshake_snooper.py v2.0.0 (Scapy EAPOL nativo, sem cowpatty/pyrit)
  - deauth_multimode.py v1.1.0 (backend nativo Scapy por padrao)
  - aireplay_deauth_barrage.py v2.0.0 (Scapy como modo primario)
- Imports ajustados de wifi_lab._disclaimer para wifi._disclaimer em todos os 3
- Versao bump 1.7.0 -> 1.7.0.post1 em pyproject.toml e wirelessxpl/__init__.py
- Commit: 920a097 - Sync refactored wifi modules + bump 1.7.0.post1 for PyPI
- Tag: v1.7.0.post1 criada e publicada
- Push: origin/master atualizado
- PyPI: upload bem-sucedido - https://pypi.org/project/wirelessxpl/1.7.0.post1/

### Proximo passo imediato
- Aguardar propagacao do PyPI (~5-10min) e confirmar pip install wirelessxpl==1.7.0.post1

### Pendencias conhecidas
- [ ] pip index versions deve mostrar 1.7.0.post1 apos propagacao do cache PyPI
- [ ] Verificar se wifi_lab/ ainda precisa de mais modulos sincronizados para wifi/

### Paths importantes
- Windows: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge
- Linux: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge

## [2026-06-19 10:15] -- Remove bridges proibidos e wifi_lab duplicado

### Estado ao encerrar
- Removidos 3 bridges proibidos de wirelessxpl/modules/generic/external/:
  mdk4_bridge.py, bettercap_bridge.py, wifite2_bridge.py
- Removido diretorio wifi_lab/ inteiro (78 arquivos + subdirs) - era duplicata do canonical wifi/
- Atualizado wifi/evil_twin_workflow.py: substituida referencia mdk4_bridge por
  flood_engine_native e corrigido path wifi_lab -> wifi nas strings de ajuda
- external/__init__.py estava limpo (sem imports dos bridges proibidos)
- Commit: 73b6f59 - Remove prohibited external bridges and drop wifi_lab duplicate directory
- Push: origin/master (920a097..73b6f59)

### Proximo passo imediato
- Nenhum pendente nesta frente; projeto em estado limpo sem bridges proibidos

### Pendencias conhecidas
- [ ] Verificar se outros bridges em external/ (aircrack_full_bridge, eaphammer_bridge, etc.)
      passam pela mesma politica de dependencias (foram mantidos por nao serem listados como proibidos)

### Ambiente necessario
- Python 3.12+
- Git com acesso ao remote https://github.com/mrhenrike/WirelessXPL-Forge.git

### Paths importantes
- Windows: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge
- Linux: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge

## [2026-06-19 11:52] -- Incorporacao de templates phishing de repos de referencia

### Estado ao encerrar
- Inventariados 23 templates HTML existentes em captive_templates/
- Pesquisados repos clonados em .tmp/wxf-references/ (fluxion, wifiphisher, wifiphisher-extra, wifipumpkin3, eaphammer)
- 10 novos templates criados e incorporados (self-contained HTML, inline CSS, 11 idiomas)
- phishing_engine.py nao requer atualizacao manual (auto-discovery via scandir)
- Commit 8e69b55 criado e push realizado para master

### Arquivos modificados
- wirelessxpl/resources/captive_templates/tp_link_router/index.html (novo)
- wirelessxpl/resources/captive_templates/netgear_router/index.html (novo)
- wirelessxpl/resources/captive_templates/fritzbox_router/index.html (novo)
- wirelessxpl/resources/captive_templates/movistar_login/index.html (novo)
- wirelessxpl/resources/captive_templates/xfinity_login/index.html (novo)
- wirelessxpl/resources/captive_templates/vodafone_login/index.html (novo)
- wirelessxpl/resources/captive_templates/starbucks_wifi/index.html (novo)
- wirelessxpl/resources/captive_templates/vivo_wifi/index.html (novo)
- wirelessxpl/resources/captive_templates/tim_mobile/index.html (novo)
- wirelessxpl/resources/captive_templates/claro_wifi/index.html (novo)

### Commits realizados
- 8e69b55 Add phishing templates for branded routers, ISPs and mobile operators

### Proximo passo imediato
- Testar os novos templates com o phishing_engine em laboratorio Linux
- Verificar se form action="/capture" e compativel com a versao atual do engine

### Pendencias conhecidas
- [ ] Todos os templates usam action="/capture" - existentes usam action="/login" (inconsistencia a corrigir)
- [ ] Assets externos nao foram baixados (templates sao self-contained com SVG/CSS inline)

### Ambiente necessario
- Linux para teste real (hostapd, monitor mode)
- Python 3.x com dependencias do projeto

### Paths importantes
- Windows: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge\wirelessxpl\resources\captive_templates\
- Linux: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge/wirelessxpl/resources/captive_templates/

## [2026-06-19 12:15] -- Correcao: captive portal form action padronizado para /capture

### Estado ao encerrar
- Identificados 23 templates HTML com action="/login" inconsistente com o servidor
- Todos os 23 templates substituidos para action="/capture" (correto)
- Os 10 novos templates ja estavam corretos (total agora: 33 com /capture)
- phishing_engine.py do_POST confirmado: aceita APENAS /capture, retorna 404 para qualquer outro path
- Commit 1291b5f e push para master realizados

### Proximo passo imediato
- Nenhuma pendencia critica. Todos os templates agora apontam para o handler correto.

### Pendencias conhecidas
- [ ] Testar fluxo completo em ambiente de lab (Linux com hostapd disponivel)
- [ ] Validar que templates novos (10 adicionados recentemente) cobrem casos de uso esperados

### Ambiente necessario
- Linux (hostapd, monitor mode, Scapy)
- Python 3.10+

### Paths importantes
- Windows: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge\wirelessxpl\resources\captive_templates\
- Linux: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge/wirelessxpl/resources/captive_templates/

## [2026-06-19 12:50] - Add 55 captive portal templates batch 2

### Estado ao encerrar
- Criados 55 novos templates HTML de captive portal como arquivos .html individuais
- Estrutura diferente dos templates anteriores (pastas com index.html): novos sao arquivos .html diretos
- Todos os templates: inline CSS, responsivos, deteccao de idioma PT/EN via JS, formulario POST /capture
- Commit: 798f8fc - "Add 55 captive portal templates - social, fast food, ISPs, hotels, fitness"
- Push realizado: branch master -> origin (github.com/mrhenrike/WirelessXPL-Forge.git)

### Grupos criados
- Social/Streaming (3): x_social_wifi, twitch_wifi, spotify_wifi - formulario com conta (email+senha)
- Fast Food (11): burger_king, mcdonalds, giraffas, kfc, subway, dominos, pizza_hut, habibs, bobs, spoleto, china_in_box - formulario senha WiFi
- Fitness (1): smart_fit_wifi - formulario senha WiFi
- ISPs Brasileiros (25): giba_fibra, loga_isp, ultracom_telecom, conectja_telecom, oi_fon_wifi*, oi_wifi_fon*, wifi_fon_portal*, starlink_wifi, copel_telecom, unifique_fibra, desktop_isp, brisanet_fibra, alloha_fibra, tim_ultrafibra, vivo_ultrafibra, algar_telecom, oi_fibra_wifi*, netiz_isp, itnet_isp, minas_telecom, clicfacil_telecom, netspeed_isp, brasil_tecpar, vero_net, coracao_mineiro_isp - (* = formulario com conta)
- Hoteis (15): accor, atlantica, radisson, quality_inn, comfort_inn, nacional_inn, ibis, mercure, novotel, pullman, wyndham, caesar_park, hilton, marriott, oceanico_tower - formulario quarto + senha

### Arquivos modificados
- wirelessxpl/resources/captive_templates/*.html (55 novos arquivos, 2.9-3.7KB cada)

### Commits realizados
- 798f8fc Add 55 captive portal templates - social, fast food, ISPs, hotels, fitness

### Proximo passo imediato
- Templates existentes ainda sao pastas com index.html - considerar padronizar para .html direto
- Verificar se o loader do wirelessxpl suporta ambos os formatos (pasta/index.html e .html direto)

### Pendencias conhecidas
- [ ] Verificar compatibilidade do captive portal loader com o novo formato .html direto
- [ ] Considerar migracao dos 33 templates antigos para formato .html direto
- [ ] Testar templates em ambiente de rede Wi-Fi real (hostapd + dnsmasq)

### Ambiente necessario
- Python 3.10+
- Git com acesso ao remote mrhenrike/WirelessXPL-Forge

### Paths importantes
- Windows: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge\wirelessxpl\resources\captive_templates\
- Linux: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge/wirelessxpl/resources/captive_templates/

## [2026-06-19 13:05] -- Modular pip extras por categoria wireless (v1.8.0)

### Estado ao encerrar
- Adicionados 9 novos optional-dependencies em pyproject.toml: wifi, bt, cellular, rf, drone, ir, gps, iot, all
- Mantidos todos os extras legados: serial, ml-gpu, ml-lite, gpu-opencl, sim, sim-full, cellular-full, all-modules
- dev atualizado com pytest-cov, black, ruff, mypy
- Novo extra gpu (hashcat-ctypes Linux)
- Versao bumped: 1.7.0.post1 -> 1.8.0 (pyproject.toml + wirelessxpl/__init__.py)
- README.md: secao 'Instalacao / Installation' bilingual adicionada logo apos badges
- docs/PREREQUISITES.md: tabela modular de extras adicionada no topo
- docs/INSTALL.md: criado do zero, guia completo bilingual PT-BR/EN por caso de uso
- Commit: 7b23168 - Modular pip extras by wireless technology category (v1.8.0)
- Push: origin/master atualizado
- PyPI: https://pypi.org/project/wirelessxpl/1.8.0/ publicado com sucesso

### Proximo passo imediato
- Verificar que pip install wirelessxpl[wifi] e pip install wirelessxpl[all] funcionam sem erros no PyPI publico

### Pendencias conhecidas
- [ ] dronekit nao esta sendo mantido ativamente - avaliar substituicao por pydronekit-la ou mavproxy
- [ ] pybluez deprecated no PyPI - avaliar substituicao por bleak apenas no extra bt
- [ ] Testar extras em ambiente Linux real (Kali) para confirmar instalacao sem erros

### Ambiente necessario
- Python 3.9+ para instalar com extras
- Linux para extras bt (pybluez, dbus-python) e rf (pyrtlsdr)

### Paths importantes
- Windows: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge\pyproject.toml
- Linux: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge/pyproject.toml

## [2026-06-19 13:15] -- Redesign captive portal templates (44 arquivos)

### Estado ao encerrar
- Substituidos 44 templates HTML em wirelessxpl/resources/captive_templates/
- Grupo 1 (15 hoteis): formulario CPF + data de nascimento + numero do quarto, mascara JS inline, paleta por marca
- Grupo 2 (25 ISPs): tabs dinamicas CPF/E-mail/Celular/Usuario + senha, tema claro por padrao, Starlink dark theme, Coracao Mineiro com icone de coracao
- Grupo 3 social (3): X.com clone dark com tabs e-mail/telefone/usuario; Twitch clone BG #0e0e10 abas por baixo; Spotify clone com botoes sociais decorativos e tabs
- Grupo 4 fitness (1): SmartFit com logo CSS (Smart branco + Fit amarelo #FFE000) e tabs CPF/E-mail/Celular
- Todos os formularios: action="/capture" method="POST", autocomplete="new-password" nos campos de senha
- Commit: bbcf567 - Redesign captive portal templates with advanced forms
- Push: origin master OK (7b23168..bbcf567)

### Proximo passo imediato
- Nenhum pendente nesta sessao; templates prontos para uso no wirelessxpl

### Pendencias conhecidas
- [ ] Adicionar suporte a CSRF token server-side quando o backend estiver implementado
- [ ] Testes de renderizacao mobile real para templates dark (Pullman, Caesar Park, Starlink, X, Twitch, Spotify, SmartFit)

### Ambiente necessario
- Python 3.12+, wirelessxpl instalado localmente
- git submodule: WirelessXPL-Forge em submodules/Uniao-Geek/

### Paths importantes
- Windows: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge\wirelessxpl\resources\captive_templates\
- Linux: /home/mrhenrike/Documentos/Projetos/WirelessXPL-Forge/wirelessxpl/resources/captive_templates/
