        "Diffie-Hellman sobre curva elíptica ou grupo finito. "
        "Cada autenticação gera forward secrecy — captura offline não é possível.",
        "Autenticação WPA3 Personal — mais segura que PSK.",
        "SAE Commit: primeiro frame (grupo + scalar + element). "
        "SAE Confirm: segundo frame com verificação. "
        "SAE flood: enviar centenas de SAE Commits → DoS no AP.",
    ),
    "owe": (
        "OWE — Opportunistic Wireless Encryption (RFC 8110)",
        "protocol",
        "Substitui redes Wi-Fi abertas (sem senha) com criptografia automática. "
        "Cada conexão tem chave única via ECDH sem autenticação de identidade.",
        "Hotspots públicos mais seguros sem exigir senha.",
        "OWE transition mode: rogue AP open pode ser preferido ao OWE. "
        "Ataque passivo: qualquer um no ar pode capturar tráfego não criptografado.",
    ),
    "radius": (
        "RADIUS — Remote Authentication Dial-In User Service (RFC 2865)",
        "protocol",
        "Protocolo AAA (Authentication, Authorization, Accounting) usado em WPA-Enterprise. "
        "O AP atua como NAS (Network Access Server) → encaminha credenciais ao RADIUS.",
        "Autenticação corporativa Wi-Fi com servidores Active Directory/LDAP.",
        "Rogue RADIUS: hostapd-wpe captura credentials EAP (user/senha ou hash NTLMv2). "
        "Certificate bypass: clientes que não validam certificado do servidor RADIUS.",
    ),
    "dot1x": (
        "802.1X — Port-Based Network Access Control",
        "protocol",
        "Padrão IEEE para controle de acesso em redes. Usado em WPA-Enterprise. "
        "Define supplicant (cliente), authenticator (AP/switch), authentication server (RADIUS).",
        "Autenticação individual por porta em redes corporativas.",
        "Evil twin + hostapd-wpe: captura credenciais 802.1X. "
        "EAP method downgrade: aceitar métodos fracos como EAP-MD5.",
    ),
    "csa": (
        "CSA — Channel Switch Announcement (IE 37, IEEE 802.11-2020 §9.4.2.18)",
        "wifi",
        "Information Element em beacon/action frames que anuncia mudança de canal iminente. "
        "Campos: mode (1=stop TX), new_channel, channel_switch_count. "
        "CRÍTICO: CSA não é protegido por PMF (beacons são sempre broadcast).",
        "APs usam CSA para migrações de canal sem desconectar clientes.",
        "CSA injection (PMF bypass): spoofar beacon com CSA IE apontando para canal falso. "
        "Cliente tenta trocar de canal, falha, re-associa → 4-way handshake capturado. "
        "Funciona mesmo com PMF Required. wikikit v0.6.0, Politician library.",
    ),
    "mfpc": (
        "MFPC — Management Frame Protection Capable",
        "wifi",
        "Bit 7 do campo RSN Capabilities no RSN IE do beacon. "
        "MFPC=1 significa o AP SUPORTA PMF mas não exige.",
        "AP anuncia suporte a PMF.",
        "MFPC=1, MFPR=0: PMF opcional — deauth clássico ainda pode funcionar. "
        "MFPC=1, MFPR=1: PMF obrigatório — deauth BLOQUEADO, usar CSA.",
    ),
    "mfpr": (
        "MFPR — Management Frame Protection Required",
        "wifi",
        "Bit 6 do campo RSN Capabilities no RSN IE do beacon. "
        "MFPR=1 significa PMF é OBRIGATÓRIO — todos os clientes devem usar PMF.",
        "AP exige que clientes usem PMF para conectar.",
        "MFPR=1: deauth/disassoc clássicos são silenciosamente descartados. "
        "Bypass: CSA injection, ou esperar reconexão natural.",
    ),
    "rsnie": (
        "RSN IE — Robust Security Network Information Element (ID=48)",
        "wifi",
        "IE no beacon/AssocReq que define capacidades de segurança: "
        "group cipher, pairwise ciphers, AKM suites, RSN Capabilities (PMF bits).",
        "AP anuncia que suporta WPA2/WPA3 e quais ciphers aceita.",
        "Parsear RSN IE = detectar PMF (MFPC/MFPR). "
        "WPS attack: AssocReq SEM RSN IE para enrollment funcionar. "
        "AKM 0x000FAC02 = PSK, 0x000FAC08 = SAE.",
    ),
    "tkip": (
        "TKIP — Temporal Key Integrity Protocol",
        "crypto",
        "Cifra usada no WPA (e opcionalmente WPA2). Baseada em RC4 com Michael MIC. "
        "Considerada insegura — Beck-Tews attack (2008) quebra Michael MIC.",
        "Cifra legacy de WPA. WPA2 prefere AES-CCMP.",
        "Beck-Tews: recuperar bytes do keystream ARP via chop-chop. "
        "Michael MIC countermeasures: AP bloqueia rede por 60s após 2 erros de MIC. "
        "WXF: flood_engine_native.py implementa Michael MIC nativo.",
    ),
    "ccmp": (
        "CCMP — Counter Mode with CBC-MAC Protocol",
        "crypto",
        "Cifra principal do WPA2/WPA3. Baseada em AES-128 em modo CCM. "
        "Provê confidencialidade + integridade + replay protection.",
        "Cifra padrão para tráfego WPA2/WPA3.",
        "Sem vulnerabilidades conhecidas na implementação padrão. "
        "KRACK abusa do protocolo de gerenciamento de chaves, não do AES em si.",
    ),
    "gcmp": (
        "GCMP — Galois/Counter Mode Protocol",
        "crypto",
        "Cifra alternativa no WPA3-Enterprise 192-bit. AES-256 em modo GCM. "
        "Mais eficiente que CCMP em hardware com instruções AES-NI.",
        "WPA3-Enterprise de alta segurança.",
        "Sem vulnerabilidades práticas conhecidas.",
    ),
    "anonce": (
        "ANonce — Authenticator Nonce",
        "crypto",
        "Nonce aleatório de 32 bytes gerado pelo AP no M1 do 4-way handshake. "
        "Junto com SNonce, é usado para derivar a PTK.",
        "Garante freshness da sessão — cada conexão tem ANonce único.",
        "Para cracking offline: ANonce (do M1) + SNonce (do M2) + MIC (do M2) "
        "permite verificar candidatos de senha. ESSENCIAL no par M1+M2.",
    ),
    "snonce": (
        "SNonce — Supplicant Nonce",
        "crypto",
        "Nonce aleatório de 32 bytes gerado pelo cliente (STA) no M2 do 4-way handshake.",
        "Garante que o cliente contribui com entropia para a PTK.",
        "Junto com ANonce, forma o material para derivar PTK e verificar MIC. "
        "captura M1+M2 da mesma sessão = cracking offline possível.",
    ),
    "mic": (
        "MIC — Message Integrity Code",
        "crypto",
        "Código de integridade nos frames M2, M3, M4 do 4-way handshake. "
        "Calculado com HMAC-SHA1 (WPA2) ou HMAC-SHA256 (WPA3) sobre o frame completo.",
        "Garante que M2/M3/M4 não foram adulterados.",
        "Para cracking: testa candidatos de senha até o MIC calculado bater com o capturado. "
        "hashcat -m 22000 implementa isso via GPU (bilhões de testes/s).",
    ),

    # ── Bluetooth ──────────────────────────────────────────────────────────
    "ble": (
        "BLE — Bluetooth Low Energy (Bluetooth 4.0+)",
        "bt",
        "Versão de baixo consumo do Bluetooth (IEEE 802.15.1). Usa canais de 40 (3 advertising + 37 data). "
        "Frequência: 2.4GHz. Alcance: 10-100m. Advertising, GATT, ATT, L2CAP.",
        "Beacons IoT, wearables, sensores, rastreadores (AirTag, Tile).",
        "BLE scan: descobrir todos os dispositivos broadcasting. "
        "GATT enum: ler serviços e características sem pareamento. "
        "BLUFFS (CVE-2023-24023): forçar session keys fracas. "
        "BLE phishing: spoofar nome de dispositivo Apple/Samsung para popups falsos.",
    ),
    "gatt": (
        "GATT — Generic Attribute Profile (Bluetooth)",
        "protocol",
        "Protocolo BLE que define como dispositivos expõem dados. "
        "Hierarquia: Services > Characteristics > Descriptors. "
        "Operações: Read, Write, Notify, Indicate.",
        "Sensor de temperatura expõe valor via GATT characteristic UUID.",
        "GATT enum: mapear todas as characteristics de um dispositivo. "
        "Unauthorized write: devices que não exigem pairing para escrita. "
        "Characteristic spoofing: modificar valores expostos.",
    ),
    "att": (
        "ATT — Attribute Protocol (Bluetooth)",
        "protocol",
        "Protocolo de baixo nível que o GATT usa para acessar atributos. "
        "Server/Client model. Handles são índices numéricos dos atributos.",
        "Base de toda comunicação GATT.",
        "ATT spoofing: forjar responses de servidor BLE. "
        "Handle enumeration: descobrir atributos não listados nos serviços.",
    ),
    "hci": (
        "HCI — Host Controller Interface (Bluetooth)",
        "bt",
        "Interface padronizada entre o host (OS) e o controller (chip BT). "
        "Permite comunicação com o chip BT via USB, UART, SDIO. "
        "Linux: hci0, hci1 = interfaces BT como vistas pelo sistema.",
        "hciconfig, hcitool, btmgmt são ferramentas que usam HCI diretamente.",
        "InternalBlue: patching de firmware via HCI para LMP injection. "
        "hci0/hci1: identificar qual adapter USB para ataques BT.",
    ),
    "l2cap": (
        "L2CAP — Logical Link Control and Adaptation Protocol (Bluetooth)",
        "protocol",
        "Camada de transporte Bluetooth acima do baseband. "
        "Multiplexação, segmentação/reassembly de frames. PSM identifica serviço. "
        "PSM 17 = HID Control, PSM 19 = HID Interrupt.",
        "Transporta RFCOMM, GATT, SDP e outros protocolos BT.",
        "BT HID injection: conectar em L2CAP PSM 17/19 e injetar keystrokes. "
        "L2CAP nativo no Linux: socket(AF_BLUETOOTH=31, SOCK_SEQPACKET, BTPROTO_L2CAP=0).",
    ),
    "rfcomm": (
        "RFCOMM — Radio Frequency Communication (Bluetooth)",
        "protocol",
        "Protocolo Bluetooth que emula portas seriais RS-232 via L2CAP. "
        "Usado por: Serial Port Profile, DUN, HSP, HFP.",
        "Pareamento de headsets, teclados legacy, SPP devices.",
        "RFCOMM shells: dispositivos industriais expõem shell serial via BT. "
        "KNOB attack afeta conexões RFCOMM/Classic BT.",
    ),
    "knob": (
        "KNOB — Key Negotiation of Bluetooth (CVE-2019-9506)",
        "attack",
        "Vulnerabilidade em Classic Bluetooth (BR/EDR) que permite forçar entropia de 1 byte "
        "na negociação da chave de sessão. Com 1 byte = 255 possibilidades = bruteforce trivial. "
        "Descoberta por Daniele Antonioli (2019).",
        "Não há uso legítimo.",
        "MITM: interceptar LMP_max_encryption_key_size e reduzir para 1. "
        "Afeta todos os dispositivos Bluetooth antes dos patches de 2019.",
    ),
    "bluffs": (
        "BLUFFS — Bluetooth Forward and Future Secrecy Attacks (CVE-2023-24023)",
        "attack",
        "Vulnerabilidades em Bluetooth 4.2-5.4 que permitem forçar session keys fracas "
        "e reutilizáveis, quebrando forward secrecy. Descobertas por Daniele Antonioli (2023).",
        "Não há uso legítimo.",
        "Requer posição MITM no ar. Session key de 1 byte → decriptar tráfego. "
        "Afeta iOS, Android, Linux, Windows sem patches.",
    ),
    "sweyntooth": (
        "SweynTooth — BLE Stack Vulnerabilities (CVE-2019-16336 a 17520)",
        "attack",
        "Família de 12 vulnerabilidades em BLE stacks embarcados "
        "(Cypress, NXP, Dialog, STMicro, Microchip, TI). "
        "Inclui: deadlock, crash, LLCP overflow, DH check bypass.",
        "Não há uso legítimo.",
        "Envia frames malformados L2CAP/LL → crash do dispositivo ou bypass de segurança. "
        "Afeta dispositivos médicos, smart locks, IoT industriais.",
    ),
    "bluezone": (
        "BlueZ",
        "tool",
        "Stack Bluetooth oficial do Linux. Inclui: bluetoothd (daemon), "
        "hcitools, bluetoothctl, hcidump, sdptool.",
        "Gerencia todos os dispositivos BT no Linux.",
        "BlueZ implementa BLE/Classic. Configuração via D-Bus. "
        "InternalBlue pode patchear firmware acessado via BlueZ.",
    ),

    # ── Radio Frequency ────────────────────────────────────────────────────
    "ism": (
        "ISM — Industrial, Scientific and Medical Band",
        "rf",
        "Bandas de frequência liberadas para uso sem licença: "
        "433 MHz, 868/915 MHz (Sub-GHz IoT), 2.4 GHz, 5.8 GHz. "
        "Wi-Fi, Bluetooth, Zigbee, Z-Wave, LoRa usam ISM.",
        "Comunicação sem fio de curto alcance sem licença especial.",
        "Sub-GHz attacks: replay de controles remotos de garagem, carros. "
        "KeeLoq: rolling code em 315/433 MHz — vulnerável a grabber attacks.",
    ),
    "ook": (
        "OOK — On-Off Keying",
        "rf",
        "Modulação digital mais simples: bit 1 = sinal transmitido, bit 0 = silêncio. "
        "Variante especial de ASK (Amplitude Shift Keying). Frequente em IoT/portões.",
        "Controles remotos simples de garagem, interruptores 433 MHz.",
        "Static code replay: gravar sinal OOK → retransmitir para abrir portão/carro. "
        "WXF: ook_encoder.py, static_code_replay.py.",
    ),
    "keeloq": (
        "KeeLoq — Rolling Code Algorithm",
        "crypto",
        "Algoritmo de código rotativo usado em sistemas de segurança automotiva (1990s). "
        "Cada pressionamento gera novo código — proteção contra simple replay. "
        "Chip: Microchip HCS200/300, NTQ105.",
        "Travamento remoto de carros, portões de garagem modernos.",
        "Relay attack: amplificar sinal da chave real para abrir carro distante. "
        "KeeLoq cryptanalysis (2008): reconstruir chave secreta com ~65k frames. "
        "CVE-2025-70994 (ev1527): veículos usando EV1527 sem rolling code.",
    ),
    "rtlsdr": (
        "RTL-SDR — Realtek Software Defined Radio",
        "tool",
        "Adaptador USB barato (~$20) baseado no chip Realtek RTL2832U. "
        "Recebe 25-1750 MHz. RX ONLY — não transmite. Resolução ~8 bits.",
        "Monitorar sinais de rádio: aviação, satélites, TPMS, meteosondas.",
        "TPMS decode: pressão/temperatura de pneus em 315/433 MHz. "
        "Passive surveillance: capturar sinais OOK, ASK de controles remotos. "
        "LTE sniffing: com rtl_lte capturar metadados de tráfego celular.",
    ),
    "hackrf": (
        "HackRF One",
        "tool",
        "SDR (Software Defined Radio) de propósito geral. RX+TX 1 MHz - 6 GHz. "
        "8-bit resolução. USB. ~$300. Ideal para RF offensive.",
        "Transmissão e recepção de qualquer sinal na faixa. Reverse engineering de protocolos.",
        "Jam Wi-Fi, replay de controles remotos, signal spoofing GPS. "
        "WXF selective_jammer.py requer HackRF para jamming.",
    ),
    "flipper": (
        "Flipper Zero",
        "tool",
        "Multi-tool RF portátil. Sub-GHz (315/433/868/915 MHz), NFC/RFID, IR, iButton, "
        "Bluetooth, BadUSB, GPIO. Tela e-ink. ~$200.",
        "Pentest físico portátil: clonar crachás RFID, replay Sub-GHz.",
        "Sub-GHz: replay portões, controles. NFC: clone de cartões. "
        "BadUSB: injetar keystrokes via USB. .sub files usados pelo WXF sub_file_parser.py.",
    ),

    # ── Security Tools ─────────────────────────────────────────────────────
    "aircrack": (
        "Aircrack-ng",
        "tool",
        "Suite de ferramentas para auditoria de redes Wi-Fi. Inclui: "
        "airmon-ng (monitor mode), airodump-ng (capture), aireplay-ng (injection), "
        "aircrack-ng (crack), hcxdumptool/hcxtools.",
        "Padrão da indústria para pentesting Wi-Fi.",
        "aircrack-ng: WEP crack, WPA dict. aireplay-ng: deauth, fake auth, ARP replay. "
        "WXF handshake_crack_engine.py usa aircrack como backend opcional.",
    ),
    "hashcat": (
        "Hashcat",
        "tool",
        "Ferramenta de cracking de hashes, suporte GPU (CUDA/OpenCL). "
        "Modo 22000: WPA-PBKDF2-PMKID+EAPOL. Modo 22001: WPA-PMKID. "
        "Suporta regras, máscaras, wordlists, Prince attack.",
        "Cracking offline de senhas — WPA2, WPA3 transition, NTLM, MD5.",
        "GPU RTX 4060: ~3 MH/s em WPA2. Wordlist + rules: enorme cobertura. "
        "WXF handshake_crack_engine.py: hashcat_gpu | hashcat_cpu | hashcat_auto.",
    ),
    "hcxdumptool": (
        "hcxdumptool",
        "tool",
        "Ferramenta para captura de PMKID e handshakes WPA2/WPA3. "
        "Versão 7.x: suporta BPF filters. Alternativa nativa ao airodump-ng.",
        "Captura PMKID sem precisar de cliente conectado.",
        "WXF pmkid_autopwn.py: reimplementação nativa em Scapy (sem hcxdumptool). "
        "Driver rt2800usb tem limitações com hcxdumptool — WXF usa Scapy como alternativa.",
    ),
    "reaver": (
        "Reaver",
        "tool",
        "Ferramenta WPS PIN brute-force. Modo -K 1 ativa Pixie Dust via pixiewps. "
        "Suporte a --dh-small (chave privada=1, PKR=2) para acelerar DH.",
        "Pentesting de redes com WPS habilitado.",
        "WXF wps_engine_native.py reimplementa Reaver em Python nativo. "
        "Modo pin_predict é mais rápido (BSSID-derived PINs primeiro).",
    ),
    "wireshark": (
        "Wireshark",
        "tool",
        "Analisador de protocolo de rede com GUI. Suporta 802.11, BLE, GSM, etc. "
        "Filtros: wlan.fc.type, wlan.fc.subtype, eapol, wpa_key.",
        "Análise de capturas pcap/pcapng. Debug de protocolos.",
        "Analisar handshakes capturados. Verificar PMF status no RSN IE. "
        "Filtro EAPOL: verificar M1-M4 estão na mesma sessão (mesmo ANonce).",
    ),
    "scapy": (
        "Scapy",
        "tool",
        "Biblioteca Python para manipulação de pacotes de rede. "
        "Suporta 802.11 (RadioTap, Dot11, Dot11Beacon, EAPOL, etc). "
        "WXF usa Scapy como camada única para TODA injeção e captura nativa.",
        "Prototipagem de exploits, análise de protocolos, forja de frames.",
        "WXF: todos os módulos nativos usam Scapy. "
        "sendp() = injetar frames. sniff() = capturar. "
        "Substitui aircrack-ng, aireplay-ng, airodump-ng para maioria das operações.",
    ),
    "mitmproxy": (
        "mitmproxy / arp_mitm_proxy",
        "tool",
        "Proxy HTTP/HTTPS transparente com interceptação e modificação. "
        "WXF arp_mitm_proxy.py: implementação nativa com ARP poison + HTTP proxy.",
        "Análise de tráfego web, SSL inspection.",
        "Image replacement, XSS injection, XXE injection, SSL stripping. "
        "WXF: ARP poison → iptables REDIRECT 80→8080 → proxy nativo Python.",
    ),

    # ── Attacks & Techniques ───────────────────────────────────────────────
    "arp_poison": (
        "ARP Poisoning / ARP Spoofing",
        "attack",
        "Envio de respostas ARP gratuitas falsas para associar o MAC do atacante "
        "ao IP do gateway (ou vítima). Coloca o atacante em posição MITM.",
        "Não há uso legítimo.",
        "Envenenar gateway: 'GW 192.168.1.1 está em MAC:ATACANTE'. "
        "Envenenar vítima: '192.168.1.5 está em MAC:ATACANTE'. "
        "Todo tráfego passa pelo atacante → capturar credenciais, injetar código.",
    ),
    "evil_twin": (
        "Evil Twin / Rogue AP",
        "attack",
        "AP falso que clona SSID/BSSID do AP legítimo e transmite sinal mais forte. "
        "Clientes se conectam pensando ser a rede real. "
        "Tipos: basic evil twin, karma (responde qualquer probe), MANA.",
        "Não há uso legítimo.",
        "Capturar credenciais WPA via portal cativo. "
        "MITM de tráfego HTTP/HTTPS. Enterprise: capturar credenciais EAP. "
        "WXF: phishing_engine.py + evil_twin_workflow.py.",
    ),
