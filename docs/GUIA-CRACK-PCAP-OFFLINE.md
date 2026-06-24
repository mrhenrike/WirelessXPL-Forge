<!--
Author: André Henrique (@mrhenrike)
Guia: Quebra offline de handshake WPA/WPA2 a partir de PCAP com o WirelessXPL-Forge (WXF)
-->

# Guia — Quebra Offline de PCAP (WPA/WPA2) com o WXF

Este guia mostra como crackear um **handshake capturado em `.pcap`/`.pcapng`** de
forma **offline** no **WirelessXPL-Forge (`wxf.py`)**, escolhendo o motor de
quebra: **aircrack-ng**, **hashcat (GPU/CPU)**, **John the Ripper** ou **cowpatty**.

É o equivalente ao fluxo manual `wpaclean` + `aircrack-ng -w wordlist`, porém com
seleção de backend e conversão automática de formato.

> Escopo: laboratório autorizado / treinamento. Use apenas em capturas próprias
> ou com autorização explícita.
>
> **Capturas de exemplo** (ex.: `ColetaTF01.pcap`, `ColetaTF04.pcap`) ficam no
> repositório irmão [PCAPTrafficAnalysis](https://github.com/mrhenrike/PCAPTrafficAnalysis).
> O WXF **não versiona** arquivos `.pcap`/`.cap` — aponte `input_file` para o
> caminho local onde você clonou as capturas.

---

## 1. Módulo e backends disponíveis

**Módulo:** `generic/wifi/handshake_crack_engine` — *WPA Crack Engine (multi-backend)*

| Backend        | Ferramenta     | Quando usar |
|----------------|----------------|-------------|
| `auto`         | (cascata)      | Tenta `hashcat_gpu → hashcat_cpu → aircrack → john` (padrão) |
| `hashcat_gpu`  | hashcat `-D 2` | GPU CUDA/OpenCL — **mais rápido** |
| `hashcat_cpu`  | hashcat `-D 1 --force` | Máquina sem GPU |
| `hashcat_auto` | hashcat        | hashcat escolhe o melhor dispositivo |
| `aircrack`     | aircrack-ng    | Lê `.pcap/.pcapng` **direto**, sem conversão |
| `john`         | John the Ripper| CPU, suporte a **rules/mangling** (formato `wpapsk`) |
| `cowpatty`     | cowpatty       | Ataque WPA-PSK direcionado (pré-cálculo `genpmk`) |

O módulo **converte automaticamente** o formato quando necessário
(`hcxpcapngtool` → `.hash`/`22000` para hashcat/john). Entradas aceitas:
`.pcap`, `.pcapng`, `.cap`, `.hash`, `.22000`, `.hccapx`.

> Listar backends a qualquer momento: `set backend list` e `run`.

---

## 2. Opções do módulo (`show options`)

| Opção        | Padrão   | Descrição |
|--------------|----------|-----------|
| `backend`    | `auto`   | `auto \| hashcat_gpu \| hashcat_cpu \| hashcat_auto \| aircrack \| john \| cowpatty \| list` |
| `input_file` | —        | Caminho do `.pcap/.pcapng` ou hash (`.hash/.22000/.hccapx`) |
| `wordlist`   | (wlist_brasil) | Caminho da wordlist |
| `wl_order`   | `random` | Ordem de varredura: `random \| forward \| reverse` |
| `essid`      | —        | ESSID alvo: nome exato \| `all` \| índices `1,2,3` \| range `1-3` (vazio = lista e pergunta) |
| `rules`      | —        | Arquivos de regra do hashcat (ex.: `best64,dive`) ou `none` |
| `use_rules`  | `false`  | Aplica `best64` à wordlist (~64× candidatos) |
| `masks`      | —        | Máscara hashcat para brute-force (ex.: `?d?d?d?d?d?d?d?d`) |
| `potfile`    | —        | Caminho do potfile do hashcat (vazio = padrão) |
| `timeout_s`  | `0`      | Tempo máximo em segundos (0 = ilimitado) |
| `verbose`    | `false`  | Mostra a saída crua do backend |
| `check_only` | `false`  | Só valida/converte e mostra info, **não** crackeia |

---

## 3. Fluxo interativo (console)

```bash
python wxf.py
```

```text
wxf > use generic/wifi/handshake_crack_engine
wxf (WPA Crack Engine (multi-backend)) > show options
wxf (WPA Crack Engine (multi-backend)) > set input_file /caminho/ColetaTF01.pcap
wxf (WPA Crack Engine (multi-backend)) > set wordlist /caminho/yellow.txt
wxf (WPA Crack Engine (multi-backend)) > set backend aircrack
wxf (WPA Crack Engine (multi-backend)) > run
```

Se o PCAP tiver **vários ESSIDs com handshake** e `essid` estiver vazio, o módulo
**lista as redes** e pede a escolha (ou use `set essid <nome|índice|range>`).

---

## 4. Os exercícios traduzidos (mesmo fluxo do aircrack)

Gere a wordlist no **WFH** (veja `WordListsForHacking/labs/GUIA-WORDLIST-POR-PADROES.md`)
e crackeie no **WXF** escolhendo o backend.

### 4.1. Exercício "yellow" (ColetaTF01) — com aircrack-ng
**Manual (referência):**
```bash
wpaclean capturaLimpaYellow.cap ColetaTF01.pcap
aircrack-ng -w yellow.txt capturaLimpaYellow.cap
```
**No WXF (não-interativo):**
```bash
python wxf.py -m generic/wifi/handshake_crack_engine \
  backend=aircrack \
  input_file=ColetaTF01.pcap \
  essid=yellow \
  wordlist=yellow.txt
```

### 4.2. Exercício "azul/azzular" (ColetaTF04) — com hashcat GPU
```bash
python wxf.py -m generic/wifi/handshake_crack_engine \
  backend=hashcat_gpu \
  input_file=ColetaTF04.pcap \
  wordlist=azzular-wlist.txt
```
> O módulo converte o `.pcap` para o formato `22000` automaticamente (via
> `hcxpcapngtool`) antes de chamar o hashcat.

### 4.3. Mesma captura, John the Ripper (CPU + rules)
```bash
python wxf.py -m generic/wifi/handshake_crack_engine \
  backend=john \
  input_file=ColetaTF01.pcap \
  wordlist=yellow.txt \
  use_rules=true
```

### 4.4. Deixar o WXF decidir (cascata automática)
```bash
python wxf.py -m generic/wifi/handshake_crack_engine \
  backend=auto \
  input_file=ColetaTF04.pcap \
  wordlist=azzular-wlist.txt
```

---

## 5. Variações úteis

### 5.1. Brute-force por máscara (sem wordlist)
```text
wxf (WPA Crack Engine (multi-backend)) > set backend hashcat_gpu
wxf (WPA Crack Engine (multi-backend)) > set input_file ColetaTF01.pcap
wxf (WPA Crack Engine (multi-backend)) > set masks ?d?d?d?d?d?d?d?d
wxf (WPA Crack Engine (multi-backend)) > run
```

### 5.2. Só validar/converter (sem crackear)
```bash
python wxf.py -m generic/wifi/handshake_crack_engine \
  input_file=ColetaTF04.pcap check_only=true
```

### 5.3. Ordem de varredura e limite de tempo
```text
set wl_order reverse      # começa pela última linha da wordlist
set timeout_s 1800        # para após 30 min
set verbose true          # mostra saída crua do backend
```

### 5.4. Pipe direto WFH → WXF (wordlist em streaming)
Gere a wordlist e salve, depois aponte o `wordlist=` para o arquivo. Para
listas enormes, prefira gerar em disco uma vez e reaproveitar.

---

## 6. Equivalência manual (referência rápida)

Se quiser rodar as ferramentas “na mão”, o WXF executa o equivalente a:

```bash
# aircrack-ng (lê pcap/pcapng direto)
aircrack-ng -w yellow.txt -e yellow ColetaTF01.pcap

# hashcat (converte antes p/ modo 22000 = WPA-EAPOL-PBKDF2)
hcxpcapngtool -o ColetaTF01.22000 ColetaTF01.pcap
hashcat -m 22000 ColetaTF01.22000 yellow.txt           # +GPU: -D 2
hashcat -m 22000 ColetaTF01.22000 -a 3 ?d?d?d?d?d?d?d?d # brute-force por máscara

# John the Ripper (formato wpapsk)
hcxpcapngtool -o ColetaTF01.hash ColetaTF01.pcap
john --format=wpapsk --wordlist=yellow.txt ColetaTF01.hash
```

> Modos hashcat WPA: **22000** (EAPOL/handshake, recomendado) e **22001** (PMKID).

---

## 7. Resumo rápido (cola)

| Objetivo                       | Comando WXF |
|--------------------------------|-------------|
| aircrack-ng (yellow/TF01)      | `python wxf.py -m generic/wifi/handshake_crack_engine backend=aircrack input_file=ColetaTF01.pcap essid=yellow wordlist=yellow.txt` |
| hashcat GPU (azul/TF04)        | `python wxf.py -m generic/wifi/handshake_crack_engine backend=hashcat_gpu input_file=ColetaTF04.pcap wordlist=azzular-wlist.txt` |
| John + rules                   | `python wxf.py -m generic/wifi/handshake_crack_engine backend=john input_file=ColetaTF01.pcap wordlist=yellow.txt use_rules=true` |
| Backend automático             | `python wxf.py -m generic/wifi/handshake_crack_engine backend=auto input_file=ColetaTF04.pcap wordlist=azzular-wlist.txt` |
| Brute-force por máscara        | `set masks ?d?d?d?d?d?d?d?d` + `run` |
| Só validar/converter           | `... input_file=ColetaTF04.pcap check_only=true` |
| Listar backends                | `set backend list` + `run` |

> Pré-requisitos externos (não instalados via pip): `aircrack-ng`, `hashcat`,
> `john`, `cowpatty`, `hcxtools` (`hcxpcapngtool`). Veja `docs/PREREQUISITES.md`.
