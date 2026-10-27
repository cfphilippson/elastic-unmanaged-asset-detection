# UC-07 — NDR Attack on Unmanaged Asset

> Detecção em Elastic Security que cruza **detecções comportamentais do NDR** com o **inventário do EDR** para responder a uma pergunta que nenhuma das duas ferramentas responde sozinha:
>
> **"Este ativo que o NDR acabou de ver se comportando como atacante tem um agente EDR olhando por ele?"**

Quando a resposta é não, o SOC fica sem telemetria de processo, sem isolamento por agente e sem capacidade de resposta no endpoint. A única visão passa a ser a rede e, com sorte, o log do sistema operacional. É exatamente onde um adversário prefere operar.

Este repositório documenta o caso de uso de ponta a ponta: o desenho, o workflow que traz o inventário do EDR para dentro do Elastic, a regra ES|QL com `LOOKUP JOIN`, os controles de falso positivo, o mapeamento MITRE ATT&CK em duas camadas e, principalmente, **o que deu errado no caminho e como foi resolvido**.

> **Nota:** todos os nomes de produtos (exceto Elastic), hosts, IPs, organização e volumes foram mascarados ou generalizados. O código é genérico e deve ser adaptado à API e aos campos do seu ambiente.

---

## Sumário

1. [O problema](#1-o-problema)
2. [A ideia](#2-a-ideia)
3. [Arquitetura](#3-arquitetura)
4. [Inventário do EDR: o workflow](#4-inventário-do-edr-o-workflow)
5. [O índice lookup](#5-o-índice-lookup)
6. [A regra](#6-a-regra)
7. [Controles de falso positivo](#7-controles-de-falso-positivo)
8. [MITRE ATT&CK em duas camadas](#8-mitre-attck-em-duas-camadas)
9. [Validação com dados reais](#9-validação-com-dados-reais)
10. [Lições aprendidas](#10-lições-aprendidas)
11. [Como implantar](#11-como-implantar)
12. [Estrutura do repositório](#12-estrutura-do-repositório)

---

## 1. O problema

O NDR gera detecções comportamentais em categorias como *Lateral Movement*, *Discovery* e *Exfiltration*. A triagem padrão de uma detecção dessas começa no EDR: árvore de processos, linha de comando, usuário, isolamento.

Essa triagem pressupõe que o host tem agente. Quando ele não tem, por ser um servidor esquecido no rollout, um agente desinstalado, uma VM criada fora do processo ou um dispositivo que nunca deveria estar na rede, o analista abre o console do EDR, não encontra nada e normalmente segue para o próximo alerta.

O caso de uso transforma essa ausência em sinal: **uma detecção de ataque em um ativo sem EDR conectado é, por si só, mais grave do que a mesma detecção em um ativo coberto.**

## 2. A ideia

- O alerta de NDR traz `source.ip`.
- O inventário do EDR traz, para cada endpoint, os IPs, o status do agente (`CONNECTED`, `DISCONNECTED`, `LOST`, `UNINSTALLED`) e o último contato.
- Com o inventário dentro do Elastic em um índice `index.mode: lookup`, a regra ES|QL faz o `LOOKUP JOIN` em tempo de execução e alerta quando **nenhum agente conectado** responde por aquele IP.

Sem pipeline de enriquecimento, sem enrich policy para reexecutar e sem dado duplicado nos índices de log.

## 3. Arquitetura

```mermaid
flowchart LR
    subgraph EDR
        API[API de inventário<br/>de endpoints]
    end
    subgraph Elastic
        WF[Elastic Workflow<br/>2x por dia]
        LK[(edr_endpoints_lookup<br/>index.mode: lookup)]
        NDR[(logs-ndr.detection-*)]
        RULE[Regra ES|QL UC-07<br/>a cada 15 min]
        HEALTH[Regra de saúde<br/>do inventário]
        AL[Alerta]
    end
    API -- paginação 100/pg --> WF
    WF -- _bulk idempotente<br/>+ expurgo seguro --> LK
    NDR --> RULE
    LK -- LOOKUP JOIN ON edr_ip --> RULE
    RULE -- connected_agents == 0 --> AL
    LK --> HEALTH
```

## 4. Inventário do EDR: o workflow

Arquivo: [`workflow/edr-inventory-sync.yaml`](workflow/edr-inventory-sync.yaml)

| Etapa | O que faz | Por quê |
|---|---|---|
| Criação do índice | `PUT` explícito com `index.mode: lookup` e `dynamic: false` | O step tipado de criação descartou o mapping na versão testada (ver [lições](#10-lições-aprendidas)) |
| Guarda de mapping | Lê o tipo de `edr_ip`; se não for `ip`, não expurga | `LOOKUP JOIN` exige o mesmo tipo dos dois lados |
| Paginação | `while` de 100 em 100, ordenado por `endpoint_id`, `max-iterations: 300` | Ordem estável evita pular ou duplicar endpoints entre páginas |
| Escrita | `_bulk` por página, `_id = <ip>_<endpoint_id>` | Idempotente: reexecutar não duplica |
| Verificação do bulk | Lê `errors` de cada resposta | `_bulk` responde **HTTP 200 mesmo com itens rejeitados** |
| Identidade da execução | `edr.run_id = execution.id` em cada documento | Separa com segurança os dados desta execução dos anteriores |
| Expurgo | Só se: coleta completa (`fetched >= total`), zero erro de bulk, mapping correto **e** documentos do `run_id` atual confirmados no índice após refresh | Uma coleta parcial ou uma escrita silenciosamente falha nunca apaga o inventário bom |
| Filtro do expurgo | Na URL (`?q=NOT edr.run_id:"<id>"`), não no body | Não depende de o body ser enviado; ver [lições](#10-lições-aprendidas) |
| Log final | Endpoints coletados/total, documentos gravados, removidos e restantes | A execução se auto-documenta |

**Conector:** HTTP connector do Kibana com **Authentication = None** e a API key em um **header secreto**. Os detalhes estão nas [lições](#10-lições-aprendidas).

**Ponto de adaptação:** `path`, corpo da requisição e os caminhos da resposta (`data.items`, `data.count`, `data.total`, `ip_addresses`, `hostname`, `status`, `group`, `last_seen`) estão genéricos e precisam ser ajustados à API do seu EDR.

## 5. O índice lookup

Arquivo: [`index/edr_endpoints_lookup.json`](index/edr_endpoints_lookup.json)

Três decisões de modelagem:

1. **Um documento por IP + endpoint.** Um endpoint tem vários IPs (IPv4, IPv6, interfaces virtuais) e um IP pode aparecer em mais de um endpoint (DHCP, NAT, VDI). Achatar em "um documento por IP" exigiria escolher um vencedor na ingestão. Em vez disso, a regra colapsa depois do join: **basta um agente `CONNECTED` no IP para a origem ser considerada gerenciada.**
2. **Prefixo `edr.*` em todos os campos de inventário.** No `LOOKUP JOIN`, campos do índice lookup com o mesmo nome de campos da origem **sobrescrevem** os valores da origem. Um `host.name` no lookup apagaria o `host.name` do alerta.
3. **Chave de junção dedicada (`edr_ip`, tipo `ip`).** A regra cria `edr_ip = source.ip` com `EVAL` antes do join. Nome e tipo precisam ser idênticos dos dois lados.

## 6. A regra

Arquivo: [`rules/uc07-ndr-attack-on-unmanaged-asset.esql`](rules/uc07-ndr-attack-on-unmanaged-asset.esql)

| Parâmetro | Valor |
|---|---|
| Tipo | ES|QL |
| Schedule / additional look-back | 15 min / 1 h 45 min |
| Janela de correlação | `event.start >= NOW() - 2 hours` |
| Supressão | `source.ip`, 24 h (um alerta por ativo por dia) |
| Severidade / risk score | High / 73 |
| Colunas extras no alerta | `coverage_context`, `mitre`, `ipam_host`, `ipam_group`, `edr_status`, `edr_last_seen`, `inventory_date` |

Fluxo da query:

1. Detecções `Attack:*` do NDR, **exceto Command and Control** (ver controle de FP abaixo).
2. `EVAL mitre = CASE(...)` traduz o nome da detecção em técnica ATT&CK.
3. `STATS ... BY source.ip`: uma linha por origem.
4. `EVAL edr_ip = source.ip` → `LOOKUP JOIN edr_endpoints_lookup ON edr_ip`.
5. `STATS connected_agents = SUM(is_connected) BY source.ip`: colapsa os múltiplos endpoints por IP.
6. `WHERE connected_agents == 0`.
7. `EVAL coverage_context = CASE(...)` classifica *por que* não há EDR.

Detalhe de editor: o editor ES|QL do Kibana não aceita `NOT`/`CASE` dentro das agregações do `STATS`. Toda condição é pré-calculada em `EVAL` antes.

## 7. Controles de falso positivo

| Risco | Evidência | Controle |
|---|---|---|
| Ativos sem agente **por desenho** (OT, IoT, CFTV, impressoras) | Segmentos que nunca recebem EDR | Exclusão por sub-rede/grupo de IPAM com controle compensatório documentado e owner. A lista é construída a partir dos alertas da fase de observação, não por suposição. |
| C2 com IOC de reputação compartilhada | Na validação, 2 de 3 resultados eram a mesma família de RAT batendo em infraestrutura usada por muitos hosts | Categoria *Command and Control* excluída deste UC. C2 é tratado por outro caso de uso, com filtro de prevalência do IOC e confirmação no firewall, **independente de ter agente**. |
| Inventário vencido ou parcial | Workflow parado ou API falhando faria endpoints novos parecerem não gerenciados | Expurgo condicionado (seção 4), regra de saúde ([`rules/health-edr-inventory-stale.esql`](rules/health-edr-inventory-stale.esql)) e `inventory_date` exposto no alerta. |
| Agente recém-desconectado | Notebook em trânsito aparece `DISCONNECTED` entre duas cargas | A triagem compara `edr_last_seen` com o horário da detecção; menos de 24 h rebaixa a prioridade, mas não suprime. |

## 8. MITRE ATT&CK em duas camadas

Mapear só pela categoria do NDR perde o que torna este caso relevante. O mapeamento tem duas camadas:

- **Contexto**: por que não há EDR. Vai para o alerta na coluna `coverage_context`.
- **Comportamento**: o que o NDR viu. Vai para o alerta na coluna `mitre`.

Regras ES|QL só aceitam mapeamento MITRE **estático**, por isso o campo `threat` da regra recebe a união das duas camadas e as colunas carregam a técnica específica de cada alerta.

### Camada de contexto

| Tática | Técnica | Subtécnica | Quando |
|---|---|---|---|
| TA0001 Initial Access | T1200 Hardware Additions | — | IP desconhecido do EDR **e** fora do IPAM |
| TA0005 Defense Evasion | T1564 Hide Artifacts | T1564.006 Run Virtual Instance | VM desconhecida em segmento de servidores (técnica usada por operadores de ransomware para rodar fora do alcance do EDR) |
| TA0005 Defense Evasion | T1562 Impair Defenses | T1562.001 Disable or Modify Tools | Agente existe, mas está `DISCONNECTED`, `LOST` ou `UNINSTALLED` |
| — | — | — | Ativo inventariado que nunca teve agente: lacuna de cobertura (controle), sem técnica |

### Camada de comportamento

| Tática | Técnica | Subtécnica | Detecção do NDR |
|---|---|---|---|
| TA0002 Execution | T1569 System Services | T1569.002 Service Execution | Serviço remoto estilo PsExec |
| TA0007 Discovery | T1046 Network Service Discovery | — | Varredura interna, portas de gerência |
| TA0007 Discovery | T1087 Account Discovery | T1087.002 Domain Account | Enumeração de AD |
| TA0007 Discovery | T1069 Permission Groups Discovery | T1069.002 Domain Groups | Enumeração de AD |
| TA0007 Discovery | T1482 Domain Trust Discovery | — | Enumeração de trusts |
| TA0008 Lateral Movement | T1021 Remote Services | T1021.001 Remote Desktop Protocol | RDP de alto volume |
| TA0008 Lateral Movement | T1021 Remote Services | T1021.002 SMB/Windows Admin Shares | PsExec, `ADMIN$`, PE via SMB |
| TA0008 Lateral Movement | T1021 Remote Services | T1021.006 Windows Remote Management | WinRM inédito |
| TA0008 Lateral Movement | T1570 Lateral Tool Transfer | — | Transferência de executável via SMB |
| TA0010 Exfiltration | T1048 Exfiltration Over Alternative Protocol | — | RDP de alto volume, transferência para VPS |
| TA0010 Exfiltration | T1048 Exfiltration Over Alternative Protocol | T1048.003 Exfiltration Over Unencrypted Non-C2 Protocol | Escrita em FTP externo |

Todas as detecções não-C2 dos últimos 30 dias do ambiente estão cobertas pelo `CASE`. Uma detecção nova cai no fallback por tática (`TA0008 (técnica não mapeada)`) e aparece na observação para ser mapeada.

## 9. Validação com dados reais

Janela de 7 dias, logo após a primeira carga do inventário (mais de 10 mil endpoints):

| Resultado | Classificação | Tratamento |
|---|---|---|
| Origem A: C2 de família de RAT conhecida | IOC de reputação compartilhada | Fora do UC-07 (categoria C2 excluída), coberto pelo UC de C2 |
| Origem B: mesma família, mesmo padrão | IOC de reputação compartilhada | Idem |
| **Origem C** | **Verdadeiro positivo de cobertura** | Ver abaixo |

**Origem C:**

- **Contexto:** ativo inventariado no IPAM, ativo e enviando logs Windows ao SIEM, **sem nenhum registro no EDR** (nem por hostname, nem por IP).
- **Comportamento:** WinRM inédito (TA0008 / T1021.006).
- **Hipótese benigna:** remoting administrativo legítimo.
- **Complicador:** o enriquecimento de eventos do NDR falhou para essa detecção (timeout), então ela não trouxe destino.
- **Como confirmar:** PowerShell Operational 4103/4104 no horário da detecção, logons 4624 tipo 3 nos destinos prováveis e sessões tcp/5985-5986 no firewall.
- **Encaminhamento:** instalação do agente e revisão de ativos com o mesmo perfil.

Benigno ou não, o achado justifica o caso de uso: um ativo sem EDR só apareceu porque o NDR viu um comportamento e o inventário mostrou que não havia ninguém olhando para aquele host.

Volume esperado após o ajuste: **cerca de 1 alerta por semana**.

## 10. Lições aprendidas

O detalhamento de cada problema (sintoma, causa e correção) está em [`docs/lessons-learned.md`](docs/lessons-learned.md). Em resumo:

1. **API key em Basic auth → 401.** A API espera a chave crua no header `Authorization`. O conector precisa de *Authentication = None* e headers customizados (a chave como *Secret*).
2. **O editor de workflows valida settings com chave tipada.** `index.mode` foi recusado como propriedade; aninhar resolveu no step tipado.
3. **Acesso dinâmico a output com colchetes é rejeitado pelo editor.** A solução foi serializar com `| json` e testar com `contains`.
4. **`_bulk` devolve 200 com `errors: true`.** Sem checar `errors`, a execução termina "DONE" sem ter gravado nada.
5. **O expurgo apagou o inventário inteiro, inclusive o que acabara de ser gravado.** A comparação por timestamp não protegeu os documentos da execução corrente. A correção foi trocar para `run_id` por execução, mover o filtro para a URL e contar os documentos da execução antes de apagar.
6. **O índice "lookup" nasceu com a chave como `text`.** O step tipado de criação aplicou `index.mode` mas descartou o mapping, e o dynamic mapping fez o resto. O `LOOKUP JOIN` falhou com `JOIN left field [edr_ip] of type [IP] is incompatible with right field [edr_ip] of type [TEXT]`. A correção foi `PUT` explícito mais guarda de mapping no workflow.
7. **`while` é do-while.** A primeira iteração sempre roda, então qualquer condição de "não coletar" precisa estar na condição de saída e no gate do expurgo.
8. **`LOOKUP JOIN` sobrescreve campos homônimos.** Por isso o prefixo `edr.*` e a chave dedicada.

## 11. Como implantar

1. **Conector HTTP** no Kibana: base URL da API do EDR, *Authentication = None*, headers de autenticação do seu EDR (chave como *Secret*). Use uma key somente leitura com acesso ao inventário.
2. **Workflow:** importe [`workflow/edr-inventory-sync.yaml`](workflow/edr-inventory-sync.yaml), ajuste o `connector-id` e os pontos de adaptação da API, salve **desabilitado**.
3. **Primeira carga:** rode manualmente. O último step deve ser `log_ok` com `fetched/total` iguais.
4. **Valide o índice:**
   ```
   GET edr_endpoints_lookup/_mapping/field/edr_ip      // "type": "ip"
   GET edr_endpoints_lookup/_settings/index.mode       // "lookup"
   ```
   ```esql
   FROM edr_endpoints_lookup
   | STATS docs = COUNT(*), endpoints = COUNT_DISTINCT(edr.endpoint_id),
           ips = COUNT_DISTINCT(edr_ip), inv = MAX(edr.inventory_date)
     BY edr.endpoint_status
   ```
5. **Rode de novo manualmente.** É o teste real do expurgo: o total de documentos deve se manter.
6. **Habilite o agendamento** do workflow.
7. **Regra de saúde:** crie [`rules/health-edr-inventory-stale.esql`](rules/health-edr-inventory-stale.esql), notificando o time do SIEM.
8. **Meça antes de criar a regra:** rode a query do UC-07 no Discover com `NOW() - 7 days` e classifique os resultados.
9. **Crie a regra UC-07 desabilitada**, com os parâmetros da seção 6 e o `threat` da seção 8.
10. **Observe por 14 dias** sem ações de notificação. Cada falso positivo vira exclusão documentada. Depois, ative as ações.

**Requisitos:** Elastic Security com ES|QL, `LOOKUP JOIN` e índices `index.mode: lookup`, e Elastic Workflows com HTTP connector.

## 12. Estrutura do repositório

```
.
├── README.md
├── docs/
│   └── lessons-learned.md
├── index/
│   └── edr_endpoints_lookup.json
├── rules/
│   ├── uc07-ndr-attack-on-unmanaged-asset.esql
│   └── health-edr-inventory-stale.esql
└── workflow/
    └── edr-inventory-sync.yaml
```

---

**Autor:** Carlos Quintas | SOC | CSIRT | SIEM Tech Leader · [LinkedIn](https://www.linkedin.com/in/carlosfpquintas) · [GitHub](https://github.com/cfphilippson)

Licença MIT. Use, adapte e, se melhorar, abra um PR.
