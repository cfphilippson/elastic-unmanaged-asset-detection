# Lições aprendidas — do primeiro 401 ao primeiro verdadeiro positivo

Registro dos problemas encontrados na implantação do UC-07, na ordem em que apareceram. Cada um tem sintoma, causa e correção. Nenhum deles aparece na documentação de nenhuma ferramenta como "cuidado com isso".

---

## 1. `401 Unauthorized` no conector HTTP

**Sintoma:** primeira chamada à API do EDR retorna `401 Unauthorized`.

**Causa:** o conector foi configurado com *Basic authentication*, com a key no campo de senha. O Kibana envia `Authorization: Basic base64(user:key)`, enquanto a API espera a key crua no header `Authorization` e o ID da key em um header próprio.

**Correção:** *Authentication = None* e headers customizados: `Authorization` com a key (tipo *Secret*) e o header de ID (tipo *Config*). APIs que exigem assinatura por requisição (nonce + timestamp + hash) não funcionam com header estático; nesse caso, use o nível de key que aceita header fixo.

**Como isolar rápido:** o mesmo request via `curl` fora do Elastic. Se o `curl` passar, o problema é o conector. Se falhar, é a key.

---

## 2. `Property index.mode is not allowed`

**Sintoma:** o editor de workflows recusa o YAML no step tipado de criação de índice.

**Causa:** o editor valida `settings` contra o schema tipado do Elasticsearch, que não aceita chave pontuada.

**Correção:** aninhar (`index:` → `mode: lookup`). No fim, esse step foi substituído (ver item 6).

---

## 3. `Invalid property path: steps.x.output[consts.y]...`

**Sintoma:** erro de validação ao acessar a saída de um step com chave dinâmica entre colchetes.

**Causa:** o validador estático do editor não resolve acesso dinâmico.

**Correção:** serializar e testar por conteúdo:

```liquid
{% assign m = steps.get_mapping.output | json %}
{% if m contains '"type":"ip"' %}ip{% else %}NOT-IP {{ m }}{% endif %}
```

---

## 4. Execução "DONE" com índice vazio

**Sintoma:** o workflow termina com sucesso e o índice tem 0 documentos.

**Causa:** `_bulk` responde **HTTP 200 mesmo quando todos os itens falham**. O erro fica em `errors: true` e em `items[].index.error`, e o step é marcado como sucesso.

**Correção:** um step após cada `_bulk` lê `errors`, registra o primeiro `reason` e marca a execução como incompleta, o que bloqueia o expurgo.

---

## 5. O expurgo apagou o inventário inteiro

**Sintoma:** `log_ok` com coleta completa (`N/N endpoints`) e `stale removidos` igual ao total de documentos que a própria execução tinha acabado de gravar. Índice vazio.

**Causa:** o expurgo era um `_delete_by_query` com `range` em `inventory_date < run_ts`. Os documentos da execução corrente deveriam ter `inventory_date == run_ts` e sobreviver, mas não sobreviveram. Não foi possível isolar se o body do request foi descartado (o que vira `match_all`) ou se a comparação de datas falhou. **A lição é não depender de nenhuma das duas coisas.**

**Correção, em três camadas:**

1. **Identidade por execução, não por tempo:** cada documento recebe `edr.run_id = execution.id`.
2. **Filtro na URL:** `_delete_by_query?q=NOT edr.run_id:"<id>"`. Mesmo que o body seja descartado, o filtro vai junto.
3. **Contagem antes de apagar:** após `_refresh`, contar os documentos com o `run_id` atual. Se for zero, não expurga.

O log final passou a mostrar gravados, removidos e restantes, de modo que um expurgo errado fica evidente na própria execução.

---

## 6. `JOIN left field [edr_ip] of type [IP] is incompatible with right field [edr_ip] of type [TEXT]`

**Sintoma:** a regra falha no `LOOKUP JOIN`, mesmo com o índice criado pelo workflow e com `index.mode: lookup`.

**Causa:** o step tipado de criação de índice aplicou o `settings` e **descartou o bloco `mappings`**. Com isso, o dynamic mapping criou a chave como `text` + `keyword`. Tipo de campo não muda in place.

**Correção:**

- `DELETE` + `PUT` explícito no Dev Tools com o mapping de [`index/edr_endpoints_lookup.json`](../index/edr_endpoints_lookup.json).
- No workflow, a criação passou a ser `PUT` via `elasticsearch.request`, que envia o body completo.
- Uma guarda lê `_mapping/field/edr_ip` a cada execução e bloqueia o expurgo se o tipo não for `ip`.

**Verificação que deveria ser padrão** após criar qualquer índice lookup:

```
GET <index>/_mapping/field/<join_key>
GET <index>/_settings/index.mode
```

---

## 7. `while` é do-while

A primeira iteração sempre roda. Um "não colete se X" precisa estar no gate do expurgo, e não só na condição do loop, porque uma página será buscada e escrita de qualquer forma.

---

## 8. `LOOKUP JOIN` sobrescreve campos homônimos

Campos do índice lookup com o mesmo nome de campos da origem **substituem** os valores da origem nas linhas que casam. Por isso todo o inventário vive sob `edr.*` e a chave de junção é um campo dedicado (`edr_ip`), criado com `EVAL` antes do join.

---

## 9. Editor ES|QL do Kibana: `NOT` e `CASE` dentro do `STATS`

O editor recusa `Function NOT not allowed in STATS` em agregações condicionais. O padrão que funciona é pré-calcular colunas em `EVAL` (`is_connected = CASE(...)`) e agregar a coluna (`SUM(is_connected)`).

---

## 10. A detecção que veio sem destino

O verdadeiro positivo da validação veio com a falha de enriquecimento do NDR (timeout na consulta de eventos), então a detecção não trazia o destino da conexão WinRM. Esse buraco foi coberto pela telemetria de host disponível (PowerShell Operational, logons) e pelo firewall. A lição é mapear, no investigation guide, **as fontes alternativas para cada campo crítico do alerta**.
