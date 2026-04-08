# Introdução, escopo e instalação

**Idioma:** pt-BR. **English (en-US):** [../en-US/01-introduction-and-installation.md](../en-US/01-introduction-and-installation.md)

## Para que serve o WirelessXPL-Forge

É um **framework modular** em Python para pesquisa e testes **autorizados** em **segurança wireless**: **802.11**, **Bluetooth / BLE**, **Zigbee**, **RFID**, **pipelines PCAP**, fluxos **serial / ESP32 (Bruce)** e **bridges** para ferramentas ofensivas comuns.

**Mapa completo da superfície de ataque (estilo MikrotikAPI-BF — galeria por classe de dispositivo no [README da wiki](../README.md)):**

![WirelessXPL — mapa completo](../../img/architecture/rxf_arch_wirelessxpl_full_attack_surface.png)

**Exemplo adicional (classe SOHO, vocabulário compartilhado com RouterXPL-Forge em laboratório):**

![Router SOHO — superfície de ataque e cobertura da ferramenta](../../img/architecture/rxf_arch_router_soho.png)

## Uso legal e ético

**Utilize apenas em redes e equipamentos para os quais você tenha autorização explícita.** O mantenedor e colaboradores **não** se responsabilizam pelo uso indevido. Em ambientes corporativos, siga o contrato de pentest e o roteiro aprovado.

## Requisitos

- **Python 3.8 a 3.13**
- Dependências principais com **`pip install wirelessxpl`** (veja abaixo) ou `pip install -r requirements.txt` a partir do clone
- Em **Python 3.13+**, o pacote `telnetlib3` substitui o `telnetlib` removido da biblioteca padrão
- Módulos **PCAP** dependem de **Scapy**; no Windows, captura ao vivo pode exigir Npcap — análise **offline** de `.pcap` costuma bastar o Python

## Instalação via PyPI (recomendado)

```bash
python3 -m pip install -U pip
pip install wirelessxpl
# extras opcionais:
pip install "wirelessxpl[serial]"    # pyserial / Bruce ESP32
pip install "wirelessxpl[ml-lite]"   # ML leve
```

Após instalar, os entry points **`wxf`** e **`python -m wirelessxpl`** ficam no seu `PATH` (ver [projeto no PyPI](https://pypi.org/project/wirelessxpl/)).

## Instalação a partir do código fonte

```bash
git clone https://github.com/mrhenrike/WirelessXPL-Forge.git
cd WirelessXPL-Forge
python3 -m venv .venv
source .venv/bin/activate   # Linux/macOS
# .venv\Scripts\activate    # Windows
python3 -m pip install -r requirements.txt
pip install -e .   # opcional — modo editável
```

## Diagnóstico

```bash
python tools/env_doctor.py
```

Verifica importação de dependências núcleo. **Scapy** pode não aparecer no *doctor*; se `generic/pcap/*` falhar, instale o Scapy manualmente.

## Iniciar o programa

```bash
wxf
# ou
python wxf.py
# ou
python -m wirelessxpl
```

O shell interativo exige **TTY** (`stdin` interativo). Para automação use o modo `-m`/`-s` (ver [04-modo-nao-interativo.md](04-modo-nao-interativo.md)).

## Arquivo de log

O arquivo **`wirelessxpl.log`** (na pasta de trabalho de onde você invocou o comando) recebe mensagens de logging do bootstrap. Gire ou apague o arquivo em ambientes de laboratório para não acumular dados sensíveis.

## Histórico de comandos

O interpretador usa tipicamente **`~/.wxf_history`** para histórico readline.

---

[Wiki hub](../README.md)
