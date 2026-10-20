    "karma": (
        "KARMA Attack",
        "attack",
        "AP responde a TODOS os probe requests afirmando ser a rede procurada. "
        "Clientes que procuram redes salvas se conectam automaticamente. "
        "Evolução: MANA (Management Frame Attack) de Sensepost.",
        "Não há uso legítimo.",
        "Capturar clientes que procuram redes públicas salvas (Starbucks, aeroportos). "
        "Requer hostapd-mana ou configuração especial de hostapd.",
    ),
    "ssl_strip": (
        "SSL Stripping",
        "attack",
        "Ataque MITM que faz downgrade de HTTPS para HTTP reescrevendo links. "
        "Criado por Moxie Marlinspike (2009). Parcialmente mitigado por HSTS.",
        "Não há uso legítimo.",
        "MITM reescreve 'https://' para 'http://' em respostas HTML. "
        "WXF arp_mitm_proxy.py implementa SSL strip nativo. "
        "Limitação: HSTS impede em sites modernos.",
    ),
    "xss_mitm": (
        "XSS via MITM Injection",
        "attack",
        "Injeção de código JavaScript malicioso em respostas HTTP em trânsito. "
        "O atacante modifica corpo HTML em tempo real ao proxy interceptar.",
        "Não há uso legítimo.",
        "WXF arp_mitm_proxy.py injeta: <script>alert('WXF em execução — MITM ativo')</script>. "
        "Adiciona banner vermelho em todas as páginas HTTP interceptadas.",
    ),
    "deauth_attack": (
        "Deauth Attack / Deauthentication Attack",
        "attack",
        "Injeção de frames de deauthentication forjados com endereço MAC do AP. "
        "Desconecta clientes forçando reconexão → captura do 4-way handshake.",
        "Não há uso legítimo.",
        "Clássico: funciona quando PMF=disabled ou PMF=capable (opcional). "
        "BLOQUEADO por: PMF Required (802.11w), clientes iOS 16+, Android 10+. "
        "Bypass: CSA injection, espera por reconexão natural.",
    ),
    "mac_spoof": (
        "MAC Spoofing / MAC Rotation",
        "attack",
        "Alterar o endereço MAC da interface para um valor arbitrário. "
        "No Linux: ip link set <iface> address <mac>. "
        "MAC local-admin: bit 1 do primeiro byte = 1 (ex: 02:xx:xx:xx:xx:xx).",
        "Privacidade: iOS/Android randomizam MAC em probe requests.",
        "WPS lockout bypass (CVE-2026-36612): trocar MAC → reseta contador de lockout. "
        "Bypass de MAC filtering (fraca segurança). "
        "Anonimato em scans passivos.",
    ),
    "wardrive": (
        "Wardriving",
        "attack",
        "Varredura itinerante de redes Wi-Fi com GPS para mapeamento geográfico. "
        "Histórico: praticado desde os anos 1990 em veículos (daí o nome).",
        "Segurança: mapear redes em uma área. Planejamento de infraestrutura.",
        "Identificar alvos para ataques posteriores. "
        "WiGLE: base de dados pública de wardriving geolocalizado. "
        "WXF wardrive_logger.py e wardriving_deauth_loop.py.",
    ),
    "pixie_dust_wps": (
        "Pixie Dust Attack (WPS)",
        "attack",
        "Ja descrito acima em 'wps'. Consulte tambem: wps.",
        "",
        "",
    ),
    "mitm": (
        "MITM — Man-in-the-Middle",
        "attack",
        "Posição de ataque onde o adversário intercepta comunicação entre duas partes. "
        "Métodos para Wi-Fi: ARP poisoning, evil twin, DNS spoofing, SSL strip.",
        "Não há uso legítimo.",
        "Captura de credenciais, cookies, tokens. "
        "Injeção de conteúdo malicioso (XSS, XXE). "
        "WXF arp_mitm_proxy.py = MITM completo nativo.",
    ),
    "dos": (
        "DoS — Denial of Service",
        "attack",
        "Ataque que torna serviço/recurso indisponível. Em Wi-Fi: "
        "deauth flood, beacon flood, auth flood, SAE commit flood, WPS lockout.",
        "Não há uso legítimo.",
        "Auth flood: sobrecarregar AP com requisições de autenticação. "
        "Beacon flood: 200+ SSIDs falsos por segundo → scanners travem. "
        "SAE flood: 500 commit frames → CPU do AP a 100%.",
    ),
    "tpms": (
        "TPMS — Tire Pressure Monitoring System",
        "rf",
        "Sistema de monitoramento de pressão de pneus que transmite via Sub-GHz "
        "(315 MHz EUA, 433 MHz Europa). Cada sensor tem ID único de 32 bits.",
        "Segurança veicular obrigatória nos EUA desde 2008.",
        "TPMS tracking: ID único permite rastrear veículo. "
        "TPMS spoofing: injetar dados falsos de pressão → triggerar alarme no painel. "
        "RTL-SDR + rtl_433: decodificar passivamente.",
    ),

    # ── IEEE & Standards ───────────────────────────────────────────────────
    "ieee": (
        "IEEE — Institute of Electrical and Electronics Engineers",
        "standard",
        "Organização que publica padrões técnicos globais. "
        "Padrões relevantes para Wi-Fi: 802.11 (Wi-Fi), 802.3 (Ethernet), "
        "802.1X (port-auth), 802.15.1 (Bluetooth), 802.15.4 (Zigbee).",
        "Define COMO os protocolos funcionam tecnicamente.",
        "Entender os padrões IEEE é essencial para ataques: "
        "802.11w §9.4.2.18 define CSA IE (usado no CSA bypass), "
        "802.11i define 4-way handshake (base de todo WPA cracking).",
    ),
    "wfa": (
        "WFA — Wi-Fi Alliance",
        "standard",
        "Consórcio industrial que certifica produtos Wi-Fi interoperáveis. "
        "Criou: WPA, WPA2, WPA3, WPS, WMM, Wi-Fi Direct, Wi-Fi 6/6E/7.",
        "Garante que dispositivos de diferentes fabricantes se comunicam.",
        "WPS foi criado pela WFA — protocolo com falhas de design fundamentais. "
        "Certificação WFA não garante segurança de implementação.",
    ),
    "nist": (
        "NIST — National Institute of Standards and Technology",
        "standard",
        "Agência americana que publica padrões criptográficos (FIPS). "
        "AES (FIPS 197), SHA-256 (FIPS 180-4), PBKDF2 (SP 800-132).",
        "Base de toda criptografia usada em WPA2/WPA3.",
        "PBKDF2 no WPA2 PMK: 4096 iterações → lento para bruteforce. "
        "GPU hashcat: 3M H/s ainda lento para senhas longas.",
    ),
    "cve": (
        "CVE — Common Vulnerabilities and Exposures",
        "standard",
        "Sistema de identificação único de vulnerabilidades. "
        "Formato: CVE-ANO-NÚMERO. Mantido pelo MITRE com suporte do NVD/NIST.",
        "Referenciar vulnerabilidades de forma padronizada.",
        "CVEs relevantes: CVE-2014-9527 (Pixie Dust), CVE-2017-13077 (KRACK), "
        "CVE-2019-9494 (Dragonblood), CVE-2020-26140 (FragAttacks), "
        "CVE-2023-24023 (BLUFFS), CVE-2026-36612 (Mercusys WPS lockout).",
    ),
    "cvss": (
        "CVSS — Common Vulnerability Scoring System",
        "standard",
        "Sistema de pontuação 0-10 para severidade de vulnerabilidades. "
        "Base Score: AV (vetor), AC (complexidade), PR (privilégios), UI, C/I/A impact.",
        "Priorizar remediação de vulnerabilidades.",
        "CVE-2026-36612 CVSS: 6.4 (AV:A/AC:H). "
        "CVE-2019-9494 CVSS: 3.7 (local, timing). "
        "CVSS alto não significa exploração fácil — contexto importa.",
    ),
    "dh": (
        "DH — Diffie-Hellman Key Exchange (RFC 3526)",
        "crypto",
        "Protocolo de troca de chaves onde duas partes derivam segredo compartilhado "
        "sem transmitir a chave. WPS usa DH-1536 (grupo MODP). "
        "Static PKE: usar priv=1 → PKR=DH_G^1 mod P = 2 (DH_G=2).",
        "Estabelecer chave de sessão segura sem canal previamente seguro.",
        "WPS Static PKE (--dh-small): priv=1, PKR=2 → AP faz menos cálculo. "
        "Equivalente a reaver --dh-small. WXF wps_engine_native.py static_pke=True.",
    ),
    "hmac": (
        "HMAC — Hash-based Message Authentication Code",
        "crypto",
        "MAC que usa uma função de hash criptográfica + chave secreta. "
        "HMAC-SHA1 usado em: WPS E-Hash, WPA2 MIC. HMAC-SHA256 em WPA3.",
        "Verificar integridade e autenticidade de mensagens.",
        "WPS Pixie Dust: se nonces são previsíveis, HMAC-SHA1 pode ser revertido. "
        "WPA2 MIC: verificação do 4-way handshake para cracking offline.",
    ),
    "pbkdf2": (
        "PBKDF2 — Password-Based Key Derivation Function 2 (RFC 2898)",
        "crypto",
        "Função de derivação de chave que aplica HMAC-SHA1 iterativamente. "
        "WPA2 PMK: PBKDF2(PSK, SSID, 4096 iterações, 256 bits). "
        "Objetivo: tornar bruteforce custoso.",
        "Transformar senha em chave criptográfica robusta.",
        "4096 iterações → GPU RTX 4060 faz ~3 MH/s. "
        "hashcat -m 22000 usa GPU para testar milhões de candidatos. "
        "Senha fraca ainda pode ser encontrada com wordlists.",
    ),
    "ipsec": (
        "IPsec — Internet Protocol Security",
        "protocol",
        "Suite de protocolos para segurança na camada IP. "
        "Modos: transport, tunnel (VPN). Protocolos: AH, ESP, IKE.",
        "VPNs site-to-site e cliente-to-site.",
        "Bypass via evil twin: redirecionar DNS/tráfego antes do IPsec se estabelecer. "
        "Não afeta diretamente WPA2 mas pode ser objetivo final do MITM.",
    ),
    "dns_spoof": (
        "DNS Spoofing / DNS Hijacking",
        "attack",
        "Retornar resposta DNS falsa para redirecionar domínio para IP do atacante. "
        "Requer posição MITM ou acesso ao resolvedor DNS.",
        "Não há uso legítimo.",
        "Junto com evil twin: redirecionar todos os domínios para captive portal. "
        "WXF dns_dhcp_server.py implementa DNS redirect nativo. "
        "dnslib AllRedirectResolver: redireciona todos os queries para IP do atacante.",
    ),
    "pcap": (
        "PCAP — Packet Capture",
        "tool",
        "Formato de arquivo para armazenar capturas de tráfego de rede. "
        "Extensões: .pcap (libpcap), .pcapng (próxima geração, mais metadados). "
        "Ferramentas: Wireshark, tcpdump, hcxdumptool.",
        "Armazenar e analisar tráfego capturado.",
        "Handshake em .pcapng → hcxpcapngtool → hash hashcat 22000. "
        "WXF salva todos os handshakes em .pcapng para análise posterior.",
    ),
    "nmap": (
        "Nmap — Network Mapper",
        "tool",
        "Scanner de rede mais popular. Detecção de hosts, portas, serviços, OS. "
        "Timing: T0 (paranoid/5min) a T5 (insane/0ms). "
        "WXF implementa timing equivalente na config global (T0-T5).",
        "Descoberta de hosts e serviços em redes.",
        "Pós-MITM: escanear rede 192.168.x.0/24 para descobrir dispositivos. "
        "WXF timing T3=normal(100ms), T4=aggressive(20ms), T5=insane(0ms).",
    ),
    "t0_t5": (
        "T0-T5 — Nmap Timing Templates",
        "tool",
        "Perfis de velocidade/agressividade: "
        "T0/paranoid=5min delay, T1/sneaky=15s, T2/polite=400ms, "
        "T3/normal=100ms (default), T4/aggressive=20ms, T5/insane=0ms. "
        "WXF global config: set timing T3 | normal | aggressive | 4",
        "Controlar velocidade de scans para evitar detecção ou maximizar velocidade.",
        "T0/T1: evasão de IDS. T4/T5: máxima velocidade em lab autorizado. "
        "WXF: todos os módulos respeitam timing global.",
    ),
    "rsn": (
        "RSN — Robust Security Network",
        "wifi",
        "Nome da camada de segurança Wi-Fi introduzida no IEEE 802.11i. "
        "RSN IE (ID=48) no beacon anuncia: ciphers, AKM suites, PMF capabilities.",
        "Base de segurança do WPA2/WPA3.",
        "Analisar RSN IE = determinar PMF, ciphers suportados, WPA version. "
        "AssocReq para WPS NÃO deve ter RSN IE (evita AP enviar Deauth).",
    ),
    "akm": (
        "AKM — Authentication and Key Management Suite",
        "wifi",
        "Campo no RSN IE que define como autenticação e gerenciamento de chaves funciona. "
        "00-0F-AC:2 = PSK, 00-0F-AC:8 = SAE, 00-0F-AC:1 = 802.1X.",
        "Define se a rede usa senha (PSK), WPA3 (SAE), ou certificados (Enterprise).",
        "AKM:2 (PSK) = alvo de cracking offline (4-way handshake). "
        "AKM:8 (SAE) = WPA3, cracking offline impossível. "
        "Transition mode: ambos AKM:2 e AKM:8 = downgrade possível.",
    ),
    "zigbee": (
        "Zigbee (IEEE 802.15.4)",
        "protocol",
        "Protocolo de comunicação IoT de baixo consumo. Frequências: 868/915 MHz, 2.4 GHz. "
        "Range: 10-100m. Mesh networking. Usado em automação residencial (Hue, Ikea).",
        "Luzes inteligentes, sensores, termostatos, fechaduras.",
        "Touchlink factory reset: comando especial que reseta dispositivos Zigbee à distância. "
        "Key extraction: sniffar network key não criptografada em join. "
        "Replay attack: retransmitir comandos capturados.",
    ),
    "lora": (
        "LoRa / LoRaWAN",
        "protocol",
        "Protocolo de comunicação LPWAN (Low Power Wide Area Network). "
        "Sub-GHz (433/868/915 MHz). Range: até 15 km. Baixa taxa de dados.",
        "IoT industrial, sensores de cidade inteligente, medidores remotos.",
        "Bit-flipping attacks em LoRaWAN 1.0 (sem integridade em alguns frames). "
        "Replay attacks em redes sem counter checks adequados.",
    ),
    "vrrp": (
        "VRRP — Virtual Router Redundancy Protocol (RFC 5798)",
        "protocol",
        "Protocolo que permite múltiplos roteadores compartilhar um IP virtual. "
        "O 'master' responde pelo IP. Prioridade determina quem é master.",
        "Alta disponibilidade em redes corporativas.",
        "VRRP takeover: injetar anúncio VRRP com prioridade maior → torna-se master → MITM. "
        "WXF vrrp_takeover.py implementa este ataque.",
    ),
    "llmnr": (
        "LLMNR — Link-Local Multicast Name Resolution",
        "protocol",
        "Resolução de nomes em redes locais sem DNS (Windows). "
        "Quando DNS falha, host faz broadcast perguntando 'quem é X?'. "
        "Vulnerável a poisoning sem autenticação.",
        "Descoberta de nomes em redes Windows pequenas.",
        "LLMNR poisoning: responder todas as queries → capturar NTLMv2 hashes. "
        "Ferramenta: Responder.py. WXF responder_wifi.py implementa similar.",
    ),
    "nbns": (
        "NBT-NS — NetBIOS Name Service",
        "protocol",
        "Protocolo legacy Windows para resolução de nomes NetBIOS via broadcast UDP 137. "
        "Similar ao LLMNR, sem autenticação.",
        "Resolução de nomes em redes Windows antigas.",
        "NBT-NS poisoning: responder broadcasts → capturar NTLMv2. "
        "Responder.py + NBT-NS = gold standard para credential capture em redes Windows.",
    ),
}


# ---------------------------------------------------------------------------
# Query functions
# ---------------------------------------------------------------------------

def _normalize(term: str) -> str:
    return term.lower().strip().replace("-", "_").replace(" ", "_")


def search_term(query: str) -> list[tuple[str, tuple[str, str, str, str, str]]]:
    """Search for terms matching query (substring, case-insensitive)."""
    q = _normalize(query)
    results = []
    for key, value in GLOSSARY.items():
        # Match key or full_name
        if q in _normalize(key) or q in _normalize(value[0]):
            results.append((key, value))
    return sorted(results, key=lambda x: (0 if _normalize(x[0]) == q else 1, x[0]))


def format_entry(key: str, entry: tuple[str, str, str, str, str]) -> str:
    full_name, category, description, normal_use, attack_relevance = entry
    cat_color = _C.get(category, "\033[97m")
    lines = [
        f"{_BOLD}{cat_color}{'─' * 70}{_RST}",
        f"{_BOLD}  {key.upper()}{_RST}  —  {cat_color}{full_name}{_RST}",
        f"  {_BOLD}Categoria:{_RST} {cat_color}{category.upper()}{_RST}",
        "",
        f"  {_BOLD}O que é:{_RST}",
        f"  {description}",
    ]
    if normal_use:
        lines += [
            "",
            f"  {_BOLD}\033[92mUso normal:{_RST}",
            f"  {normal_use}",
        ]
    if attack_relevance:
        lines += [
            "",
            f"  {_BOLD}\033[91mUso em ataques:{_RST}",
            f"  {attack_relevance}",
        ]
    lines.append(f"{cat_color}{'─' * 70}{_RST}")
    return "\n".join(lines)


def format_compact_list(filter_category: str | None = None) -> str:
    """Return a compact table of all terms."""
    header = (
        f"{_BOLD}{'TERMO':<20} {'CATEGORIA':<12} NOME COMPLETO{_RST}\n"
        f"{'─'*80}"
    )
    rows = [header]
    for key, (full_name, category, *_) in sorted(GLOSSARY.items()):
        if filter_category and category != filter_category.lower():
            continue
        cat_color = _C.get(category, "\033[97m")
        short_full = full_name[:45] + "…" if len(full_name) > 46 else full_name
        rows.append(
            f"  {cat_color}{key:<20}{_RST} {category:<12} {short_full}"
        )
    rows.append(f"{'─'*80}")
    rows.append(f"  {len([r for r in rows if r.startswith('  ')])} termos")
    return "\n".join(rows)


def glossary_help() -> str:
    cats = sorted(set(v[1] for v in GLOSSARY.values()))
    return (
        f"{_BOLD}WXF Glossário de Termos de Segurança Wireless{_RST}\n"
        f"{'─'*60}\n"
        f"  glossary                     → listar todos os termos\n"
        f"  glossary <termo>             → detalhar termo específico\n"
        f"  glossary <a> <b> <c>         → múltiplos termos\n"
        f"  glossary --list              → tabela compacta\n"
        f"  glossary --category <cat>    → filtrar por categoria\n"
        f"\n"
        f"  Categorias: {', '.join(cats)}\n"
        f"  Total de termos: {len(GLOSSARY)}\n"
        f"{'─'*60}"
    )
