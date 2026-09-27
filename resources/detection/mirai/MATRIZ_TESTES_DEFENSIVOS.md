# Matriz de Testes Defensivos - NotMirai Lab

**Objetivo:** Estudar padrões de Mirai e variantes através de **análise estática** e **simulação controlada de tráfego** em rede isolada.

**Autor:** André Henrique (@mrhenrike) | União Geek

## 1. Referências Estáticas (mirai-references/)

| Repositório | Foco Principal | O que analisar (estático) | IOCs a extrair |
|-------------|----------------|---------------------------|---------------|
| jgamblin/mirai-source-code | Código original | Protocolo C2, strings de autenticação, comandos | Strings de Telnet, user/pass defaults, C2 messages |
| hklcf/Mirai | Variante | Diferenças no loader e bot | Novas strings, modificações no scan |
| tanc7/PyMirai | Port Python | Lógica de tradução C→Python | Padrões de brute-force |
| honeyvig-condi / lion001am-condi | Variantes modernas | Melhorias L4/L7 | Novas técnicas de ofuscação |

**Regra:** **Nunca compile ou execute** os componentes `bot`, `loader` ou `cnc` fora de VM completamente isolada e desconectada da internet.

## 2. Matriz de Comportamentos Observáveis (para regras de detecção)

| Comportamento | Padrão Mirai | Regra de Detecção Sugerida | Ferramenta |
|---------------|--------------|---------------------------|------------|
| Telnet Scan | Porta 23 + brute force com wordlist pequena | Suricata: `alert tcp any any -> any 23 (msg:"Mirai Telnet Scan";)` | Suricata/YARA |
| C2 Communication | Conexões persistentes em portas não-padrão | YARA rule on binary strings | YARA |
| DDoS Signatures | SYN flood, UDP flood, GRE | Rate limiting + behavioral | Snort/Suricata |
| Default Credentials | root/admin, admin/admin, etc. | Monitor login attempts | Log correlation |

## 3. Procedimento FortiGate + HIN (POC Harpia)

**Importante:** Apenas testes de **baixa taxa** e **janela acordada**.

1. Use o `.env` do `poc-harpia` (local, não versionado).
2. Teste apenas tráfego sintético controlado contra o FortiGate.
3. Verifique logs no HIN (`pipeline_fortinet.conf`).
4. Monitore contadores de bloqueio e eventos de UTM.

**Nunca** execute floods de alto volume.

## 4. Scripts de Análise

Veja `scripts/analysis/` para ferramentas de captura e parsing.

**Todas as atividades devem respeitar:**
- Rede isolada (Docker `internal: true` ou VM host-only)
- `.tmp/` para todos outputs temporários
- Análise estática prioritária

> Created by André Henrique (@mrhenrike) — União Geek
