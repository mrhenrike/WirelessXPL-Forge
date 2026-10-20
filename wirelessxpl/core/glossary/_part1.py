"""WXF Glossary — Wireless Security Terms, Acronyms and Attack Techniques.

Comprehensive reference for all acronyms, siglas, standards and concepts
used in WiFi/Bluetooth/RF security. Each entry includes:
  - Full name / expansão do acrônimo
  - Description (PT-BR)
  - Normal use / uso normal
  - Attack relevance / uso em ataques

Usage from WXF prompt:
    glossary                   → lists all terms (paginated)
    glossary wpa               → search term/acronym
    glossary bssid ssid rssi   → multiple terms
    glossary --list            → compact list
    glossary --category wifi   → filter by category
"""


# ---------------------------------------------------------------------------
# Category colors
# ---------------------------------------------------------------------------
_C = {
    "wifi":     "\033[94m",   # blue
    "bt":       "\033[95m",   # magenta
    "attack":   "\033[91m",   # red
    "crypto":   "\033[93m",   # yellow
    "protocol": "\033[92m",   # green
    "rf":       "\033[96m",   # cyan
    "standard": "\033[97m",   # white
    "tool":     "\033[33m",   # orange
}
_RST = "\033[0m"
_BOLD = "\033[1m"


# ---------------------------------------------------------------------------
# Glossary database
# ---------------------------------------------------------------------------
# Each entry: (full_name, category, description, normal_use, attack_relevance)
GLOSSARY: dict[str, tuple[str, str, str, str, str]] = {

    # ── WiFi Standards & Protocols ─────────────────────────────────────────
    "802.11": (
        "IEEE 802.11 — Wi-Fi Standard Family",
        "standard",
        "Família de padrões IEEE que define comunicação sem fio (Wi-Fi). "
        "Inclui variantes como .11a/b/g/n/ac/ax/be (Wi-Fi 1–7).",
        "Define como dispositivos se comunicam em redes sem fio a 2.4GHz, 5GHz e 6GHz.",
        "Qualquer ataque Wi-Fi opera dentro deste framework. "
        "Conhecer o padrão é essencial para injeção de frames e bypass de segurança.",
    ),
    "802.11w": (
        "IEEE 802.11w — Management Frame Protection (MFP/PMF)",
        "standard",
        "Extensão do padrão 802.11 que protege frames de gerenciamento (Auth, Deauth, "
        "AssocReq, Disassoc) com assinatura criptográfica. Mandatório no WPA3.",
        "Protege clientes modernos de desconexões forçadas por frames falsos.",
        "Quando PMF Required=1, deauth/disassoc clássicos são BLOQUEADOS. "
        "Bypass: CSA injection (beacons não são protegidos), ou aguardar reconexão natural.",
    ),
    "ssid": (
        "SSID — Service Set Identifier",
        "wifi",
        "Nome da rede Wi-Fi transmitido em beacon frames. Pode ter até 32 bytes. "
        "Pode ser 'hidden' (não transmitido em beacons) mas aparece em probe responses.",
        "Identifica a rede ao usuário (ex: 'UNIAOGEEK', 'MinhaRede123').",
        "Usado em: evil twin (clonar o SSID), karma attack (responder qualquer probe), "
        "SSID confusion attack (trocar SSID para confundir clientes), beacon flood (SSIDs aleatórios).",
    ),
    "bssid": (
        "BSSID — Basic Service Set Identifier",
        "wifi",
        "Endereço MAC do Access Point (rádio). Identifica unicamente um AP na rede. "
        "Em redes com múltiplos APs (ESS), cada AP tem um BSSID único.",
        "Identifica o AP físico em ferramentas como airodump-ng, iw scan.",
        "Alvo principal em ataques: deauth, handshake capture, WPS attack, PMKID. "
        "BSSID-based PIN prediction: algoritmos vendor derivam WPS PIN do BSSID.",
    ),
    "essid": (
        "ESSID — Extended Service Set Identifier",
        "wifi",
        "Equivalente a SSID no contexto de redes com múltiplos APs (Extended Service Set). "
        "Na prática, SSID e ESSID são usados de forma intercambiável.",
        "Nome da rede Wi-Fi como visto pelo usuário.",
        "Mesmo uso que SSID em ataques.",
    ),
    "rssi": (
        "RSSI — Received Signal Strength Indicator",
        "wifi",
        "Medida da potência do sinal recebido, tipicamente em dBm (negativo). "
        "Ex: -30 dBm = sinal excelente, -90 dBm = sinal fraco.",
        "Indica qualidade do sinal. Útil para wardriving e posicionamento.",
        "Quanto mais próximo de 0 (ex: -31 dBm), mais próximo o alvo e maior sucesso "
        "de ataques de injeção. RSSI > -60 = alvo prioritário.",
    ),
    "ap": (
        "AP — Access Point",
        "wifi",
        "Dispositivo que cria e gerencia uma rede Wi-Fi. Opera em modo infrastructure "
        "transmitindo beacons, gerenciando associações e encaminhando tráfego.",
        "Roteador ou ponto de acesso que distribui internet para clientes.",
        "Alvo em ataques: deauth, WPS, PMKID, evil twin, CSA injection.",
    ),
    "sta": (
        "STA — Station",
        "wifi",
        "Qualquer dispositivo cliente Wi-Fi (laptop, smartphone, IoT). "
        "Se conecta a um AP em modo infrastructure.",
        "Seu celular/notebook quando conectado ao Wi-Fi é uma Station.",
        "Alvo de ataques direcionados ao cliente: deauth (forçar reconexão), "
        "evil twin (capturar credenciais), BT HID injection.",
    ),
    "bss": (
        "BSS — Basic Service Set",
        "wifi",
        "Conjunto básico formado por um AP e as Stations associadas a ele. "
        "É a célula fundamental de uma rede Wi-Fi.",
        "Sua rede doméstica com um roteador é um BSS.",
        "Entender o BSS é fundamental para ataques de deauth e associação falsa.",
    ),
    "ess": (
        "ESS — Extended Service Set",
        "wifi",
        "Conjunto de múltiplos BSSs (múltiplos APs) com o mesmo SSID, "
        "interconectados por uma rede backbone (geralmente Ethernet).",
        "Redes corporativas com múltiplos APs formam um ESS.",
        "Roaming attacks: forçar clientes a roamear entre APs falsos e legítimos.",
    ),
    "ibss": (
        "IBSS — Independent Basic Service Set (Ad-hoc)",
        "wifi",
        "Rede Wi-Fi peer-to-peer sem AP. Dispositivos se comunicam diretamente.",
        "Transferência de arquivos entre dois notebooks sem roteador.",
        "Mesh flood: injetar beacons IBSS para sobrecarregar scanners.",
    ),
    "channel": (
        "Channel / Canal Wi-Fi",
        "wifi",
        "Subdivisão do espectro de frequência Wi-Fi. 2.4GHz tem 13 canais (sobreposição nos 1,6,11). "
        "5GHz tem 24+ canais. 6GHz (Wi-Fi 6E) adiciona mais 60 canais.",
        "Canal 1, 6 ou 11 para 2.4GHz evita interferência. 5GHz oferece mais canais não sobrepostos.",
        "Channel hopping: varrer todos os canais para detectar APs e clientes. "
        "CSA injection: forçar mudança para canal inexistente → reconexão → handshake.",
    ),
    "beacon": (
        "Beacon Frame",
        "wifi",
        "Frame de gerenciamento 802.11 transmitido periodicamente pelo AP (~10/s). "
        "Contém: SSID, BSSID, capacidades, RSN IE, WPS IE, canal, timestamp.",
        "Anuncia a existência do AP e suas capacidades.",
        "CSA injection: inserir IE 37 (Channel Switch) em beacon spoofado → PMF bypass. "
        "Beacon flood: inundar com beacons de SSIDs aleatórios confunde scanners. "
        "RSN IE no beacon revela PMF status (MFPC/MFPR bits).",
    ),
    "probe": (
        "Probe Request / Probe Response",
        "wifi",
        "Probe Request: frame enviado por STAs buscando redes conhecidas. "
        "Probe Response: AP responde a probe requests com suas capacidades.",
        "Seu celular envia probe requests procurando redes salvas.",
        "KARMA attack: responder todos os probe requests se passando pelo AP procurado. "
        "Hidden SSID: probe response revela SSID mesmo quando hidden. "
        "Device tracking: MAC do cliente em probe requests.",
    ),
    "assocreq": (
        "Association Request (AssocReq)",
        "wifi",
        "Frame de gerenciamento que o cliente envia ao AP para se associar. "
        "Contém: SSID, capacidades, taxas suportadas, RSN IE (se WPA), WPS IE (se WPS).",
        "Processo de conexão: Auth → AssocReq → AssocResp → EAPOL.",
        "WPS attack: AssocReq deve ter WPS IE e SEM RSN IE para enrollment funcionar. "
        "PMKID: AssocReq com RSN IE correto pode triggar AP a enviar EAPOL-Key M1 com PMKID.",
    ),
    "deauth": (
        "Deauthentication Frame",
        "wifi",
        "Frame de gerenciamento que termina a autenticação entre STA e AP. "
        "Antes do 802.11w, não era autenticado e podia ser forjado.",
        "AP envia deauth quando cliente é desconectado por inatividade ou erro.",
        "Deauth attack: forjar frames deauth com BSSID do AP → cliente desconecta → reconecta → "
        "4-way handshake capturado. BLOQUEADO por 802.11w/PMF Required.",
    ),
    "disassoc": (
        "Disassociation Frame",
        "wifi",
        "Similar ao deauth, mas apenas remove a associação (não a autenticação). "
        "Menos severo: cliente pode re-associar sem reautenticar.",
        "AP envia quando cliente sai da rede (roaming ou desligamento).",
        "Mesmo uso que deauth em ataques. Também bloqueado por PMF.",
    ),
    "wpa": (
        "WPA — Wi-Fi Protected Access",
        "crypto",
        "Protocolo de segurança Wi-Fi criado em 2003 como substituto emergencial do WEP. "
        "Usa TKIP (Temporal Key Integrity Protocol). Considerado inseguro.",
        "Versão transitória antes do WPA2. Ainda presente em hardware legado.",
        "Beck-Tews attack: recuperar bytes do keystream TKIP. Michael MIC countermeasures. "
        "Downgrade attack forçar WPA onde WPA2/3 deveria ser usado.",
    ),
    "wpa2": (
        "WPA2 — Wi-Fi Protected Access 2 (IEEE 802.11i)",
        "crypto",
        "Padrão de segurança Wi-Fi desde 2004. Usa AES-CCMP como cifra principal. "
        "PSK (Personal) ou Enterprise (802.1X/RADIUS). Ainda o mais usado mundialmente.",
        "Base da segurança Wi-Fi doméstica e corporativa.",
        "4-way handshake → captura → cracking offline com wordlist/hashcat. "
        "PMKID attack: captura sem cliente. KRACK: reinstalação de PTK. "
        "Downgrade de WPA3 Transition Mode para WPA2.",
    ),
    "wpa3": (
        "WPA3 — Wi-Fi Protected Access 3 (IEEE 802.11ax)",
        "crypto",
        "Padrão desde 2018. Usa SAE (Dragonfly) no lugar do PSK, resistente a offline cracking. "
        "Mandatory PMF. R3 (2022): Hash-to-Element, Transition Terminated Indication.",
        "Padrão mais seguro atual. iOS 16+, Android 10+, Windows 11.",
        "Dragonblood (2019): timing side-channel, SAE commit flood DoS. "
        "Transition Mode downgrade: forçar WPA2 via rogue AP. "
        "SAE flood: 500 SAE Commit frames sobrecarregam CPU do AP.",
    ),
    "wep": (
        "WEP — Wired Equivalent Privacy",
        "crypto",
        "Protocolo de segurança Wi-Fi obsoleto (1997). Usa RC4 com IVs de 24 bits. "
        "Completamente quebrado. NUNCA usar.",
        "Proteção básica em hardware dos anos 1990-2000.",
        "FMS attack, PTW attack: cracking em minutos com ~50k IVs. "
        "Chopchop: recuperar keystream byte a byte. "
        "Caffe-Latte: ataque a clientes WEP fora da rede.",
    ),
    "pmf": (
        "PMF — Protected Management Frames (IEEE 802.11w)",
        "crypto",
        "Proteção criptográfica de frames de gerenciamento 802.11 usando MIC (HMAC-SHA1). "
        "MFPC=1 (capable), MFPR=1 (required). Mandatório no WPA3.",
        "Previne deauth/disassoc forjados. iOS 16+, Android 10+ habilitam por padrão.",
        "PMF Required BLOQUEIA deauth clássico. Bypass via CSA injection (beacons não protegidos). "
        "SA Query timeout: teórico, não prático. Ver CVE-2019-9494.",
    ),
    "ptk": (
        "PTK — Pairwise Transient Key",
        "crypto",
        "Chave derivada durante o 4-way handshake para criptografar tráfego unicast. "
        "Gerada de: PMK + ANonce + SNonce + BSSID + STA_MAC. "
        "Composta de: KCK (confirm) + KEK (encrypt) + TK (tráfego).",
        "Chave que criptografa todos os seus dados Wi-Fi.",
        "KRACK: reinstalar PTK com nonce zerado → decriptar/forjar tráfego. "
        "4-way capture: captura ANonce+SNonce+MIC → offline cracking da PSK.",
    ),
    "gtk": (
        "GTK — Group Temporal Key",
        "crypto",
        "Chave compartilhada entre AP e todos os clientes para tráfego broadcast/multicast. "
        "Distribuída no M3 do 4-way handshake ou no Group Key Handshake.",
        "Criptografa frames broadcast (ex: ARPs, mDNS).",
        "KRACK GTK reinstallation (CVE-2017-13080): reinjetar GTK → replay broadcast. "
        "Se GTK for recuperada, todos os broadcasts da rede ficam expostos.",
    ),
    "pmk": (
        "PMK — Pairwise Master Key",
        "crypto",
        "Chave raiz derivada da PSK (ou RADIUS em Enterprise). "
        "WPA2-PSK: PMK = PBKDF2-SHA1(PSK, SSID, 4096 iterações, 32 bytes). "
        "Todas as PTKs são derivadas desta chave.",
        "Base da segurança WPA2 PSK. Não muda a menos que a senha mude.",
        "Offline cracking: se PMK for descoberta, PSK = senha da rede. "
        "hashcat -m 22000: computa PBKDF2 para cada candidato de senha.",
    ),
    "pmkid": (
        "PMKID — Pairwise Master Key Identifier",
        "crypto",
        "Hash de 16 bytes: PMKID = HMAC-SHA1-128(PMK, 'PMK Name' || AP_MAC || STA_MAC). "
        "Enviado pelo AP no EAPOL-Key M1 (primeiro frame do 4-way handshake). "
        "Descoberto por Jens Steube (hashcat) em 2018.",
        "Permite ao AP identificar se um PMK conhecido existe para um cliente.",
        "PMKID attack: capturar M1 de uma ÚNICA associação fake → offline cracking. "
        "Não precisa de cliente conectado. hashcat -m 22001. "
        "PMF Required bloqueia associações falsas em muitos APs modernos.",
    ),
    "handshake": (
        "4-Way Handshake (WPA2)",
        "protocol",
        "Protocolo de 4 mensagens EAPOL-Key entre AP e STA para derivar PTK e GTK. "
        "M1: AP→STA (ANonce). M2: STA→AP (SNonce + MIC). "
        "M3: AP→STA (GTK criptografada + MIC). M4: STA→AP (confirmação).",
        "Estabelece sessão criptografada ao conectar no Wi-Fi.",
        "Capturar M1+M2 permite cracking offline da PSK sem perguntar ao AP. "
        "hashcat -m 22000. Precisa pelo menos M1+M2 na MESMA sessão (mesmo ANonce).",
    ),
    "eapol": (
        "EAPOL — Extensible Authentication Protocol over LAN",
        "protocol",
        "Encapsulamento do protocolo EAP sobre camada 2 (802.3 ou 802.11). "
        "Tipos: EAP-Request(1), EAP-Response(2), EAP-Success(3), EAP-Failure(4), "
        "EAPOL-Start(1), EAPOL-Key(3).",
        "Transporta autenticação 802.1X em redes cabeadas e Wi-Fi.",
        "EAPOL-Key M1-M4 = 4-way handshake. "
        "EAPOL-Start flood: sobrecarregar AP com inicio de sessões. "
        "EAP timing attacks: variações de tempo revelam informações.",
    ),
    "eap": (
        "EAP — Extensible Authentication Protocol",
        "protocol",
        "Framework de autenticação usado em WPA-Enterprise (802.1X). "
        "Métodos: EAP-TLS, EAP-TTLS, EAP-PEAP, EAP-FAST, EAP-PWD, EAP-WSC (WPS).",
        "Autenticação corporativa Wi-Fi com credenciais individuais por usuário.",
        "EAP credential capture: rogue AP com hostapd-wpe captura usuário/senha. "
        "EAP downgrade: aceitar EAP-MD5 (fraco) em vez de PEAP. "
        "EAP timing: PEAP inner password bruteforce.",
    ),
    "wps": (
        "WPS — Wi-Fi Protected Setup (IEEE 802.11-2007)",
        "protocol",
        "Protocolo para simplificar conexão de dispositivos. Métodos: PIN (8 dígitos), "
        "PBC (Push Button), NFC, USB. Padrão define mensagens M1-M8 (EAP-WSC).",
        "Botão WPS no roteador: pressiona no AP e no dispositivo → conecta sem digitar senha.",
        "PIN brute-force: 11.000 combinações (design flaw). "
        "Pixie Dust: PRNG fraco → nonces previsíveis → PIN offline em segundos. "
        "NULL PIN: alguns APs aceitam 00000000. "
        "PBC hijack: detectar janela 120s e enrolar imediatamente.",
    ),
    "pixie_dust": (
        "Pixie Dust Attack (CVE-2014-9527)",
        "attack",
        "Ataque WPS offline descoberto por Dominique Bongard (2014). "
        "Explora PRNGs fracos (rand() com entropia limitada) em chips Ralink, Realtek, Broadcom. "
        "Captura uma troca M1-M3 → computar nonces offline → recuperar PIN em segundos.",
        "Não há uso legítimo — é exclusivamente um ataque.",
        "NetRise 2025: 80%+ dos dispositivos ainda vulneráveis. "
        "Firmware lançado em julho/2025 ainda usa PRNGs fracos. "
        "WXF mode=pixie_dust captura M2 e tenta recovery offline.",
    ),
    "eap_wsc": (
        "EAP-WSC — EAP with Wi-Fi Simple Config (WPS)",
        "protocol",
        "Método EAP usado pelo WPS para transportar mensagens M1-M8. "
        "EAP expanded type 0xFE com vendor ID Wi-Fi Alliance (00:37:2A).",
        "Protocolo interno do WPS — transporta a troca de chaves entre enrollee e registrar.",
        "Capturar M2 via EAP-WSC é necessário para Pixie Dust. "
        "EAPOL-Start após AssocReq com WPS IE (sem RSN IE) trigga EAP-WSC no AP.",
    ),
    "krack": (
        "KRACK — Key Reinstallation Attack (CVE-2017-13077 a 13088)",
        "attack",
        "Família de ataques descoberta por Mathy Vanhoef (2017). Explora o fato de que "
        "o protocolo 4-way handshake permite reinstalação de chaves com nonce zerado. "
        "Afeta WPA2 em quase todos os dispositivos da época.",
        "Não há uso legítimo.",
        "PTK reinstallation: decriptar/forjar tráfego unicast. "
        "GTK reinstallation: replay tráfego broadcast/multicast. "
        "Remediado com patches em 2017-2018. Detectar com krack_scanner.",
    ),
    "fragattacks": (
        "FragAttacks — Fragmentation and Aggregation Attacks (CVE-2020-24586 a 26147)",
        "attack",
        "Família de 12 vulnerabilidades descobertas por Mathy Vanhoef (2020-2021). "
        "Afeta praticamente todos os dispositivos Wi-Fi lançados desde 1997. "
        "Explora falhas em fragmentação e agregação de frames A-MSDU.",
        "Não há uso legítimo.",
        "A-MSDU injection: injetar frames em texto plano. "
        "Mixed key attack: reassembling com chaves diferentes. "
        "CVE-2020-26140: aceitar A-MSDU plaintext injetado. "
        "CVE-2020-26143: aceitar broadcast A-MSDU em texto plano.",
    ),
    "dragonblood": (
        "Dragonblood — WPA3 SAE Attacks (CVE-2019-9494 a 9499)",
        "attack",
        "Família de ataques contra WPA3 SAE (Dragonfly) por Mathy Vanhoef e Eyal Ronen (2019). "
        "Inclui timing side-channel, group downgrade, SAE commit flood DoS.",
        "Não há uso legítimo.",
        "Timing: diferenças de ~100ns revelam informações do hash-to-element. "
        "SAE commit flood: 500 frames de commit sobrecarregam CPU do AP. "
        "Downgrade: forçar WPA2 via rogue AP (Transition Mode). "
        "Remediado em patches 2019-2020.",
    ),
    "sae": (
        "SAE — Simultaneous Authentication of Equals (Dragonfly)",
        "protocol",
        "Substituiu o PSK no WPA3. Protocolo de troca de chaves baseado em "
