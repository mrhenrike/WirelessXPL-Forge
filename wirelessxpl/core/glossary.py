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
from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

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
GLOSSARY: Dict[str, Tuple[str, str, str, str, str]] = {

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
    "pixie_dust": (
        "Pixie Dust Attack (WPS)",
        "attack",
        "Já descrito acima em 'wps'. Consulte também: wps.",
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


def search_term(query: str) -> List[Tuple[str, Tuple[str, str, str, str, str]]]:
    """Search for terms matching query (substring, case-insensitive)."""
    q = _normalize(query)
    results = []
    for key, value in GLOSSARY.items():
        # Match key or full_name
        if q in _normalize(key) or q in _normalize(value[0]):
            results.append((key, value))
    return sorted(results, key=lambda x: (0 if _normalize(x[0]) == q else 1, x[0]))


def format_entry(key: str, entry: Tuple[str, str, str, str, str]) -> str:
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


def format_compact_list(filter_category: Optional[str] = None) -> str:
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
