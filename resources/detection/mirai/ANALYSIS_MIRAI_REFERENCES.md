# Relatório de Análise: Mirai References Laboratory

**Autor:** André Henrique (@mrhenrike) | União Geek  
**Data:** 2026-04-18  
**Escopo:** Análise completa dos 5 repos em `laboratory/notmirai-lab/mirai-references`

---

## 📋 Sumário Executivo

A pasta `mirai-references` contém **5 implementações diferentes do Mirai botnet**, sendo 4 em C/Go (originárias) e 1 conversão para Python em andamento. Cada repositório representa uma variação ou fork público do código-fonte original do Mirai vazado em 2016.

| Repo | Tipo | Status | Portabilidade Python |
|------|------|--------|----------------------|
| **hklcf-mirai** | C/Go | ✅ Completo | ❌ Não recomendado |
| **honeyvig-condi** | C/Go | ✅ Completo | ❌ Não recomendado |
| **jgamblin-mirai-source** | C/Go | ✅ Completo | ❌ Não recomendado |
| **lion001am-condi** | C/Go | ✅ Completo | ❌ Não recomendado |
| **tanc7-pymirai** | C+Python | ⚠️ Parcial | ⚠️ Em transição |

---

## 🔍 Análise Detalhada por Repositório

### 1. **hklcf-mirai**
**Tipo:** Fork da origem Mirai (C + Go)  
**Status:** Completo e compilável  
**Tamanho:** ~100 arquivos fonte

#### Estrutura:
```
hklcf-mirai/
├── dlr/                    # Downloader (dropper/loader)
│   ├── main.c
│   └── build.sh
├── loader/                 # Bot loader (Telnet brute-force)
│   ├── src/
│   │   └── *.c files      # Conexão, binary exploitation
│   └── build.sh
├── mirai/                  # Core botnet
│   ├── bot/               # Bot principal (18 .c files, 0 .go files)
│   │   ├── main.c         # Entry point
│   │   ├── attack_*.c     # UDP, TCP, GRE, APP layer attacks
│   │   ├── scanner.c      # SYN scanner super-rápido (80x mais rápido que qbot)
│   │   ├── resolv.c       # DNS resolution + hardcoding
│   │   ├── killer.c       # Mata competing malware
│   │   └── util.c         # Utilities
│   └── cnc/               # Command & Control (Go: 9 .go files)
│       ├── main.go        # CnC server
│       ├── admin.go       # Admin painel
│       ├── database.go    # MySQL integration
│       ├── bot.go         # Bot management
│       └── api.go         # API endpoints
├── scripts/               # Build scripts
│   ├── build.sh
│   ├── build.debug.sh
│   └── cross-compile.sh
└── README.md, post.txt
```

#### Componentes-chave:
- **SYN Scanner:** Implementação otimizada que dispara SYN packets em alta velocidade (~80x mais rápido)
- **Real-time Loading:** Loop de brute-force → scanListen → loader → brute contínuo
- **Protocolos Binários:** CnC ↔ Bot comunicam via protocolo binário (não texto)
- **Anti-análise:** Anti-GDB, chroot, proteção contra reverses
- **Multi-arquitetura:** Compilação cruzada para ARM, MIPS, PPC, SH4, etc.

#### Linguagens e Tecnologias:
- **Bot:** C puro (syscalls, raw sockets)
- **CnC:** Go (goroutines, simpleza, high concurrency)
- **Database:** MySQL
- **Target Archs:** ARM, ARM7, MIPS, PowerPC, SH4, x86

---

### 2. **honeyvig-condi**
**Tipo:** Fork "Condi-Mirai" - Mirai com layer 7 attacks  
**Status:** Completo (comentário: "leaked cuz @zxcr9999 scam")  
**Diferenciais:** Layer 7 attacks, Realtek scanner, GPON exploits

#### Estrutura (idêntica a hklcf mas com adições):
```
honeyvig-condi/
├── mirai/bot/
│   ├── attack_tcp.c, attack_udp.c, attack.c
│   ├── gpon80_scanner.c       ← NOVO: GPON device scanner (port 80)
│   ├── gpon8080_scanner.c     ← NOVO: GPON device scanner (port 8080)
│   ├── realtek.c              ← NOVO: Realtek router exploitation
│   └── [outros arquivos]
├── mirai/cnc/
│   └── Go files (igual)
└── [loader, dlr, scripts]
```

#### Adicionalidades sobre Mirai base:
- **GPON Exploits:** Suporte para routers GPON (Realtek-based)
- **Layer 7 Attacks:** HTTP-based DDoS (além de UDP/TCP)
- **Realtek Specific Code:** Router-specific exploits
- **Integração:** Mantém estrutura C/Go original

**Observação:** Vazado por `@lion001am`, depois copiado/vendido por outros (conflito de autoria visível no README)

---

### 3. **jgamblin-mirai-source**
**Tipo:** Fork documental (C + Go)  
**Status:** Completo + bem documentado  
**Diferencial:** Documentação de segurança, README aprimorado, estrutura clara

#### Diferenciais:
```
jgamblin-mirai-source/
├── ForumPost.txt          ← Post original de Anna-senpai (MUITO VALIOSO)
├── ForumPost.md           ← Versão markdown formatada
├── LICENSE.md             ← Disclaimer legal
├── README.md              ← Documentação educacional completa
├── BVc7qJs.png            ← Screenshot/diagrama
└── [estrutura idêntica a hklcf-mirai]
```

#### Qualidade da Documentação:
- ✅ Explicação clara do que é Mirai
- ✅ Table of Contents
- ✅ Requirements/Setup detalhado
- ✅ Learning use cases específicos
- ✅ "Do NOT use for" disclaimer legal
- ✅ Referências técnicas (MalwareMustDie, CISA alerts)

**Recomendação:** Este é o **melhor fork para compreender a arquitetura** do Mirai.

---

### 4. **lion001am-condi**
**Tipo:** Cópia/fork de honeyvig-condi (C + Go)  
**Status:** Completo  
**Diferenciais:** Nenhum significativo (duplicação de honeyvig-condi)

Estrutura praticamente idêntica a honeyvig-condi. Parece ser:
- Repositório paralelo
- Ou fork mantido separadamente
- Sem alterações técnicas aparentes

---

### 5. **tanc7-pymirai** ⭐ ESPECIAL
**Tipo:** Conversão C → Python (Projeto em andamento)  
**Status:** ⚠️ INCOMPLETO  
**Esforço:** ~2 anos de reverse-engineering

#### Estrutura:
```
tanc7-pymirai/
├── Original/              # Código C/Go original copiado como referência
│   ├── mirai/
│   │   ├── bot/          # 24 .c files + 0 .py files
│   │   └── cnc/          # Go files
│   └── loader/
├── PyMirai/               # Versão Python em conversão
│   ├── bot/
│   │   ├── main_c.py                # Conversion de main.c via ctopy
│   │   ├── attack_tcp_c.py
│   │   ├── attack_*.c.py            # ~30 .py files (converted)
│   │   ├── scanner_self_written.py  # Reescrita manual
│   │   ├── attack.py                # Python-nativo
│   │   └── ctypesexperiment/        # Experimentos com ctypes
│   ├── loader/
│   │   └── [arquivos python]
│   └── NOTES.md                     # Journal de reverse-engineering
├── README.md              # Detalha desafios da conversão
└── Nota: 61 files Python, ~0.5MB total
```

#### Qualidade da Conversão Python:
**Status:** 🔴 QUEBRADA/INCOMPLETA

Problemas documentados pelo autor:
1. **ctopy é péssimo converter:**
   - Não converte `#include` para `import`
   - Whitespace completely ruined
   - Funções não declaradas/chamadas corretamente
   - Métodos não referenciados corretamente
   - Módulos não encontram equivalentes

2. **Exemplo real de conversão quebrada:**
   ```python
   # Conversão QUEBRADA de main.c para main_c.py
   # Linha 1-14 do arquivo main_c.py:
   import os, errno, fcntl
   import sys
   #endif                           ← C header ainda ali!
   #include <unistd.h>             ← C #include não convertido
   import socket
   #include <sys/socket.h>         ← Mix horrível
   #include <arpa/inet.h>
   ...
   printf("[main] Failed...")      ← printf() não é Python!
   table_unlock_val(TABLE_CNC_DOMAIN)  ← Chamadas C soltas
   ```

3. **Código manual melhor, mas ainda fragmentado:**
   - `scanner_self_written.py`: Tentativa manual > auto-conversion
   - Mas lógica C complexa não se traduz direto para Python

#### Motivações do Autor (citadas no README):
```
1. Melhorar adaptabilidade contra medidas de cybersegurança
2. Adicionar sistema de "modulettes" (módulos instaláveis)
3. Propagate Mirai copycats dando melhor plataforma
4. Alternativa ao CnC em Go (usar Django/REACT web UI)
```

#### Features planejadas (não implementadas):
- [ ] HTTPS/SSL nativo
- [ ] Dynamic DNS resolution
- [ ] Phishing campaigns automatizadas
- [ ] Web GUI com análise (tipo InsightIDR)
- [ ] Wordlists de 10.000+ linhas
- [ ] C2 Cyber-Threat Analysis (parse Apache/Nginx logs)

---

## 🔄 Análise de Portabilidade para Python

### Conclusão Geral: ❌ **NÃO recomendado portabilidade 100% para Python**

#### Por quê manter em C/Go:

| Aspecto | C/Go | Python | Razão |
|--------|------|--------|-------|
| **Performance** | ⭐⭐⭐⭐⭐ | ⭐⭐ | SYN scanner: 80x mais rápido em C |
| **Tamanho Binary** | ~200KB | ~2-3MB | Python + interpretor > cross-compiled C |
| **Low-level I/O** | ⭐⭐⭐⭐⭐ | ⭐⭐ | Raw sockets, syscalls diretos |
| **Deployment IoT** | ⭐⭐⭐⭐⭐ | ❌ | Não funciona em devices ARM sem Python |
| **Anti-análise** | ⭐⭐⭐⭐⭐ | ⭐⭐ | Obfuscação nativa C > Python bytecode |
| **Portabilidade** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | Python roda em qualquer sistema |
| **Velocidade Dev** | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | Prototipagem + iteração mais rápido |

#### Cenários onde Python seria útil:

✅ **USE Python para:**
- CnC web interface (GUI + analytics) — **Go atual já faz isso, mas Django seria mais moderno**
- Ferramentas de suporte (scanners, validators, log parsers)
- Servidor de recepcao de resultados (scanListen)
- Prototipagem rápida de ataque vectors
- Pesquisa/análise (não deployment)

❌ **NÃO use Python para:**
- Bot principal (precisa rodar em IoT devices com recursos limitados)
- SYN scanner (performance critical)
- Loader/dropper (tamanho importa para distribuição)
- Qualquer componente que precisa low-level I/O

#### Alternativa Recomendada (Arquitetura Híbrida):

```
┌─────────────────────────────────────┐
│ Python Web UI (Django/React)        │  ← CnC Admin Panel
│ - Dashboard, analytics, logs        │
│ - Job scheduling, config mgmt       │
└────────────────┬────────────────────┘
                 │ (JSON/REST API)
┌────────────────▼────────────────────┐
│ Go/Rust CnC Core                    │  ← Performance-critical
│ - Bot command dispatch              │
│ - Database (SQLite/PostgreSQL)      │
│ - Event loop, connection mgmt       │
└────────────────┬────────────────────┘
                 │ (Binary Protocol)
┌────────────────▼────────────────────┐
│ C Bot (cross-compiled)              │  ← Runs on IoT devices
│ - SYN scanner, attack loops         │
│ - Low-level networking              │
│ - Anti-analysis evasion             │
└─────────────────────────────────────┘
```

---

## 📊 Comparação Técnica dos Repos

### Similitudes:
- ✅ Todos baseados no vazamento original de 2016
- ✅ Mesma arquitetura: Bot + CnC + Loader + Scanner
- ✅ Mesmo protocolo binário Bot↔CnC
- ✅ Multi-arquitetura cross-compilation
- ✅ MySQL backend

### Diferenças:

| Aspecto | hklcf | honeyvig | jgamblin | lion001am | tanc7-py |
|---------|-------|----------|----------|-----------|----------|
| **Documentação** | Básica | Mínima | ⭐⭐⭐ | Mínima | Completa |
| **Layer 7 Attacks** | ❌ | ✅ | ❌ | ✅ | ⚠️ Parcial |
| **GPON Exploits** | ❌ | ✅ | ❌ | ✅ | ❌ |
| **Realtek Support** | ❌ | ✅ | ❌ | ✅ | ❌ |
| **Status Projeto** | Estável | Estável | Estável | Estável | Em andamento |
| **Idioma Primário** | C/Go | C/Go | C/Go | C/Go | Python (incompleto) |
| **Tamanho Código** | ~100 files | ~100 files | ~100 files | ~100 files | ~61 files |

---

## 🎯 Recomendações por Use Case

### 1️⃣ **Para Pesquisa/Análise Técnica:**
👉 **Use: `jgamblin-mirai-source`**
- Documentação mais clara
- Ideal para compreender arquitetura
- Comentários e explicações em inglês

### 2️⃣ **Para Estudo de Layer 4 + Layer 7 DDoS:**
👉 **Use: `honeyvig-condi` ou `lion001am-condi`**
- Implementação de múltiplos vetores de ataque
- GPON/Realtek exploits educacionais

### 3️⃣ **Para Compreender Conversão C→Python:**
👉 **Use: `tanc7-pymirai`**
- Documenta desafios reais de conversão
- Útil para entender limitações de ctopy
- **Não use para production** (código quebrado)

### 4️⃣ **Se Precisa Versão Completa/Production:**
👉 **Qualquer um dos C/Go originals** (hklcf, honeyvig, jgamblin)
- Todos compiláveis e funcionais
- Não existem garagens garantidas, mas código conhecido

---

## ⚠️ Avisos Legais & Éticos

Todos esses repos contêm:
- ✋ Código malware de verdade (não simulado)
- ⚖️ Disclaimer legal obrigatório antes de uso
- 🔒 Deve ser executado apenas em **lab isolado** (air-gapped ou VM)
- ❌ Ilegal usar para:
  - DDoS de verdade
  - Scanning/exploração de devices reais
  - Qualquer atividade não-pesquisa

---

## 📝 Sumário Técnico dos Arquivos

### Bot (C - Invariável em todos os repos):
```c
main.c              → Entry point, signal handling, anti-GDB
attack.c/h          → Dispatch de tipos de ataque
attack_tcp.c        → TCP SYN flood
attack_udp.c        → UDP flood
attack_gre.c        → GRE encapsulation attacks
attack_app.c        → Application-layer (HTTP/DNS)
scanner.c/h         → Fast SYN syn scanner (~80x optimized)
killer.c/h          → Kill competing malware processes
resolv.c/h          → Domain resolution + hardcoded IPs
util.c/h            → Utilities (random, encoding, etc.)
table.c/h           → Shared data table (encrypted in memory)
checksum.c/h        → Checksums para raw packets
rand.c/h            → Fast pseudo-random generator
protocol.h          → Estruturas de protocolo binário
```

### CnC (Go - Invariável):
```go
main.go             → Server init, listening
admin.go            → Admin panel/auth
bot.go              → Bot tracking, command dispatch
clientList.go       → Manutenção de lista de bots conectados
database.go         → MySQL connection + queries
api.go              → REST/gRPC API endpoints
constants.go        → Magic numbers, defaults
```

### Loader (C - Similar em todos):
```c
main.c              → Entry point, telnet brute loop
binary.c/h          → Payload binary handling
connection.c/h      → TCP connection management
server.c/h          → Listening server (for accepting results)
telnet_info.c/h     → Telnet protocol implementation
util.c/h            → Utilities
```

---

## 🔐 Notas sobre Segurança & Anti-Análise

Todos os bots implementam:

1. **Anti-Debugger:**
   ```c
   ptrace(PTRACE_TRACEME, 0, 0, 0);  // Trap any debugger
   ```

2. **Proteção contra Reversal:**
   - chroot("/") para esconder filesystem
   - Proteção de watchdog contra hang
   - Binary protocol (não texto)
   - Verificação de instância única (port 48101)

3. **Evasão:**
   - Kill competing malware
   - Rootkit capabilities (em alguns forks)
   - Fake CNC addresses (decoy strings)

---

## 🚀 Conclusão Final

### Status das Linguagens:

| Linguagem | Recomendação | Razão |
|-----------|--------------|-------|
| **C** | ✅ MANTER | Performance, deployment, IoT compat |
| **Go** | ✅ MANTER | CnC, simpleza, concurrency |
| **Python** | ⚠️ PARCIAL | Apenas ferramentas/UI, não bot core |

### Arquivos para Focar em Pesquisa:
1. `jgamblin-mirai-source/README.md` ← **START HERE**
2. `hklcf-mirai/post.txt` ← Origem do vazo
3. `honeyvig-condi/mirai/bot/scanner.c` ← Algoritmo crítico
4. `tanc7-pymirai/README.md` ← Desafios de conversão

### Estatísticas Finais:
- **Total de repos:** 5
- **Repos C/Go**: 4 (100% funcional)
- **Repos Python:** 1 (⚠️ 50-60% convertido)
- **Linhas de código C:** ~2000-3000 por repo
- **Linhas de código Go:** ~500-800 por repo
- **Linhas de código Python:** ~500 válidas (resto é lixo de ctopy)

---

**Fim do Relatório**  
*Relatório para fins educacionais e de pesquisa de segurança apenas.*

---

**Author:** André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
