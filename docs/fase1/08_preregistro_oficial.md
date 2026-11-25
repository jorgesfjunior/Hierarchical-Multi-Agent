# Fase 1 — 08. Pré-registro da execução OFICIAL (confirmatória)

Status: **CONGELADO.** A data e a hora UTC e o hash do commit estão em
`docs/fase1/08_preregistro_oficial.freeze.json`. Este documento é escrito e comitado **antes** de
qualquer código ou execução da fase oficial. Nada dele muda depois de ver resultados; qualquer
desvio é declarado com data no relatório (`09_relatorio_oficial.md`).

- **Origem das hipóteses:** o piloto EXPLORATORY da Fase 1b (pré-registro `06_preregistro_1b.md`,
  commit `5d6d300`; resultados em `results/fase1b_pilot/`). O piloto **gerou** as hipóteses; esta
  execução as **testa** com seeds novas.
- **Afirmação a testar:** o MAS (SN) une a **coordenação** do monolito à **localidade** do
  distribuído.
- As referências [1]–[14] remetem a `01_especializacoes.md`, e [15]–[20] ao fim de
  `05_desenho_1b.md`. "SM" = suposição de modelagem.

## 1. O que fica igual à Fase 1b (congelado)

Nada do código, dos limiares, das famílias ou dos parâmetros congelados da 1b muda.

| Item | Valor | Identificação |
|---|---|---|
| Limiares | os da Fase 1, sem recalibração | `config/fase1/thresholds_by_profile.yaml`, sha256 `b95552ff220743be0518d5d30fa15c2993754821f70f007b9d9a7cf375c522ba` |
| Domínios do SN | os da Fase 1 | `config/fase1/domains_sn.yaml`, sha256 `8725e227a8b0009dd35d3d9fae8b2390f85e8cba21139d3a0d1df34245d2ba37` |
| Braços e knobs da 1b | `06_preregistro_1b.md` §2 | `simulation/fase1b_experiments.py`, sha256 `6a0b9a3a73f1e1339a795f62be1166a921abb9130b607156288438d33368f3bc` |
| Famílias, fundo benigno e parâmetros SM da `campaign_e1_e2` | `06_preregistro_1b.md` §3 | `simulation/fase1.py`, sha256 `b3f6f0089d2083098370bbab7ad34f11b6e42069dd54b4eedad9d5802ff6508e` |
| Modelo de fronteira | `Boundary` (lote, fila de banda, latência) | `simulation/transport.py`, sha256 `29a78cc4fe12b02a79347be82a7a83c6d2201c8898ce4dd90f55625c379c2fcb` |
| Modelo de dano | efetividade 0,50; fração restaurável 0,43; liberação da segmentação na contenção, teto 3 600 s | `simulation/fase1_experiments.py`, `fase1b_experiments.py` |
| Custos internos | local 0,001 s; serviço 0,01 s | `simulation/fase1_experiments.py` (`INTRA`) |

**Código congelado:** o commit deste pré-registro. O único código novo permitido depois do
congelamento é o **driver da fase oficial** (agenda as células, grava o manifest, calcula os testes
abaixo) e os seus testes. Ele **reutiliza** as funções da 1b (`scenario`, `run_arm` em forma
equivalente, `damage_params`, `evaluate`, `mechanism`) e não altera nenhum módulo de simulação,
agente, baseline ou detecção. Para garantir isso, a pré-condição R (§6) inclui reproduzir byte a
byte linhas do piloto da 1b com o driver oficial.

## 2. Braços

Os três braços da Fase 1b, com a mesma configuração:

| Braço | O que é |
|---|---|
| **SN** | MAS proposto: especialistas por segmento + coordenador; avisos especialista → coordenador → especialista |
| **U1** | MAPE-K monolítico (B1-SSL atrás da fronteira); o nó central forma o vínculo e despacha a precaução |
| **B2L** | distribuído sem agentes: uma instância B2-SSL por segmento, sem comunicação entre segmentos |

## 3. Fatores e níveis

| Fator | Níveis |
|---|---|
| **F1 Arquitetura** | SN, U1, B2L |
| **F2 Custo de fronteira** | (0) **oráculo** = custo zero; (1) **restrita** = lote 60 s + latência 10 s + 32 KiB/s (valor congelado da Fase 1); (2) **lote 5 min** = lote 300 s + 10 s + 32 KiB/s; (3) **lote 15 min** = lote 900 s + 10 s + 32 KiB/s |
| **F3 Heterogeneidade h** | 0, 1 |
| **F4 Família** | `encryption_stream`, `campaign_multihost`, `split_visibility_late_confirm`, `interleaved`, `campaign_e1_e2` |
| **F5 p_pre** (só `campaign_e1_e2`, h = 1, restrita) | 0,2; 0,5; 0,8 |

**Níveis novos de F2 (só valores de configuração).** Os níveis 2 e 3 são instâncias da mesma classe
`Boundary` (`simulation/transport.py`) com `batch_s` = 300 ou 900; latência e banda são iguais às da
restrita. Nenhum código de transporte muda.

**Justificativa dos níveis novos [13].** A página do Azure Monitor sobre tempo de ingestão de logs
informa, para métricas, logs de recursos e logs de atividade do Azure, latência de **30 s a 20 min**;
os logs de recursos ficam disponíveis, em geral, em **3 a 10 min**, e alguns serviços (Azure SQL
Database, Azure Virtual Network) entregam logs **a cada cinco minutos**. Os níveis de 5 e 15 min estão
dentro dessa faixa. (O pedido original citava "30 s a 15 min"; a página consultada em 2026-11-03 diz
"30 s a 20 min". Os níveis não mudam.)

**Índice do nível de F2** (usado em H4): oráculo = 0, restrita = 1, lote 5 min = 2, lote 15 min = 3.

## 4. Grade e seeds

| Bloco | Células | Braços |
|---|---|---|
| **Principal** | F2 ∈ {oráculo, restrita} × F3 ∈ {0, 1} × F4 (5 famílias) | SN, U1, B2L (+ NO-DEFENSE no oráculo, como na 1b, só descritivo) |
| **Varredura de fronteira** | F2 ∈ {lote 5 min, lote 15 min} × h = 1 × F4 | SN, U1, B2L |
| **Varredura de p_pre** | F5 ∈ {0,2; 0,5; 0,8} × `campaign_e1_e2` × h = 1 × restrita | SN, B2L |

- **Seeds: 5000–5499 (500 por célula), as mesmas em todas as células**, de modo que cada campanha é
  pareada entre braços **e** entre níveis de F2 e de p_pre.
- O nível p_pre = 0,5 da varredura repete a célula principal (`campaign_e1_e2`, h = 1, restrita,
  seeds 5000–5499) nos braços SN e B2L. As linhas têm de ser idênticas; isso é uma verificação de
  determinismo, não uma amostra nova.
- **Faixas já usadas (todas disjuntas de 5000–5499):**

| Faixa | Uso |
|---|---|
| 0–29 | Fases 3, 4, 4b, 4c, 5b, 7a (teste 0–4), 7b; sanity 0–19 |
| 0–4 | Fase 8 (piloto; regressão 0–2) e teste de H0 da Fase 1 |
| 0–99 | análise de estrutura de cenário (Fase 1) |
| 100–119 | calibração (Fase 1); 100–104 calibração da Fase 7a |
| 200–209 | piloto da Fase 1 |
| 300–399 | diagnóstico (Fase 1 / 1b; testes 300–305) |
| 1000–1199 | piloto da Fase 1b |
| 2000–2199, 3000–3199, 4000–4199 | varredura de p_pre da Fase 1b |
| 7, 42 | sementes literais de testes unitários antigos |

  O maior seed usado antes é 4199. **Não há sobreposição.**
- **Custo:** principal 4 × 5 × 500 = 10 000 jobs (3 braços cada); fronteira 2 × 5 × 500 = 5 000
  jobs; p_pre 3 × 500 jobs (2 braços). ≈ 47 000 runs de braço.
- **Execução:** um comando por (célula, família), ≈ 500 jobs, ≤ 5 min cada, com checkpoint: um bloco
  cujo arquivo bruto já existe e confere com o manifest não é refeito.

## 5. Métricas

- **Unidade:** campanha maliciosa, pareada entre braços (e entre níveis) por (família, seed,
  campanha).
- **Primária:** p = proporção de campanhas contidas antes do impacto = média de
  `1 − impact_started`.
- **Restrição:** média por run de `unavailability_fraction`(SN) − `unavailability_fraction`
  (comparador) ≤ **0,05**, no mesmo recorte do teste, pareada por (família, seed).
- **Secundárias (descritivas):** `data_loss_per_host`, indisponibilidade (total e componentes
  `cost_*`), latência dos avisos (`advisory_latency_mean_s`), avisos falsos (`advisories_false`).

## 6. Pré-condições (fora da família de Holm)

Se qualquer uma falhar, **a execução para e a falha é reportada.** Nada é ajustado.

| Teste | Definição | Passa se |
|---|---|---|
| **R** | Regressão: (a) Fase 8, 34 unidades (`tests/test_fase1_phase8_regression.py`); (b) Fase 1, 16 unidades do piloto (`tests/test_fase1b.py`); (c) Fase 1b, seed 1000 × 5 famílias × 4 células do piloto, rodadas **pelo driver oficial** e comparadas com `results/fase1b_pilot/pilot_rows_*.csv` | todas idênticas byte a byte (linhas canônicas) |
| **H0** | Oráculo, 5 famílias, Δ = p(SN) − p(U1), em h = 0 e em h = 1 | IC95 % de Δ (bootstrap de clusters, §7) **dentro de [−0,05; +0,05]** nos dois h |
| **C0** | h = 0, `campaign_e1_e2`, restrita, Δ = p(SN) − p(B2L) | IC95 % de Δ dentro de [−0,05; +0,05] |

R, H0 e C0 são executados e avaliados **antes** das demais células. Ordem: R; células oráculo h = 0
e h = 1 → H0; célula restrita h = 0 → C0; só então o resto.

## 7. Família confirmatória (4 testes, Holm, α = 0,05, unilaterais)

Procedimentos comuns:
- **Bootstrap de clusters:** cluster = **seed** (todas as campanhas de todas as famílias com aquele
  seed, no recorte do teste). 10 000 reamostragens com reposição dos 500 seeds,
  `numpy.random.default_rng(0)`; Δ* = (soma das diferenças por unidade nos clusters sorteados) /
  (número de unidades sorteadas). IC95 % bilateral = percentis 2,5 e 97,5.
- **McNemar exato pareado, unilateral:** b = unidades em que o SN contém e o comparador não; c = o
  inverso; p = P(X ≥ b), X ~ Binomial(b + c; 0,5). Se b + c = 0, p = 1.
- **Holm** sobre os 4 p brutos (`analysis/stats.py: holm`).
- **Critério:** hipótese **confirmada** se p ajustado por Holm < 0,05 **e** a restrição de
  indisponibilidade foi cumprida no recorte dela (em H4, em cada um dos 4 níveis).
- Todos os Δ são reportados com IC95 % do bootstrap de clusters.

### H1 — Agêntico × sem agentes

- **Recorte:** `campaign_e1_e2`, h = 1, restrita. **Hipótese:** p(SN) > p(B2L).
- **Teste:** McNemar exato pareado, unilateral.
- **Expectativa (do piloto):** Δ ≈ +0,12 (piloto: +0,120 [0,080; 0,170], 24 discordantes em 200).
- **Se NÃO for confirmada:** o artigo não pode dizer que a coordenação entre segmentos do MAS
  contém mais ataques que regras locais isoladas, nem na família construída para isso. O ganho do
  piloto vira um achado exploratório não replicado, e a afirmação "une a coordenação do monolito"
  cai.

### H2 — Distribuído × monolito, não inferioridade

- **Recorte:** 5 famílias, h = 1, restrita. **Hipótese:** p(SN) − p(U1) > −0,05.
- **Teste:** limite inferior do IC unilateral de 95 % (percentil 5 do bootstrap de clusters) acima
  de −0,05. **p bruto** = (1 + #{Δ* ≤ −0,05}) / (10 000 + 1); o limite inferior fica acima de −0,05
  se e somente se esse p < 0,05.
- **Expectativa:** confirmada (piloto: +0,021 [0,013; 0,029]).
- **Se NÃO for confirmada:** distribuir a decisão custa contenção em relação ao monolito; o artigo
  não pode afirmar que o MAS "preserva a coordenação do monolito" e teria de apresentar o SN como
  troca (localidade por eficácia), não como união.

### H3 — Distribuído × monolito, superioridade

- **Recorte:** o mesmo de H2. **Hipótese:** p(SN) > p(U1).
- **Teste:** McNemar exato pareado, unilateral, sobre todas as campanhas.
- **Declaração:** hipótese **gerada pelo piloto**; o efeito esperado é **pequeno (≈ 2 pp)** e vem
  da localidade (precursores que chegam poucos segundos antes do impacto e que o U1 recebe depois da
  fronteira). Os pares discordantes devem ser poucos (piloto: 23 em 1 094).
- **Limitação declarada:** o McNemar trata as campanhas como pares independentes; campanhas do
  mesmo seed e família podem ser correlacionadas. O IC do bootstrap de clusters é reportado ao lado.
- **Se NÃO for confirmada:** o SN empata com o monolito; a "localidade" não se traduz em mais
  contenção mensurável com a fronteira congelada, e o artigo fica com "o MAS iguala o monolito sem
  centralizar", sem vantagem de localidade sobre ele.

### H4 — Dose–resposta da localidade

- **Recorte:** 5 famílias, h = 1, braços SN e U1, os 4 níveis de F2 (oráculo e restrita da grade
  principal; 5 e 15 min da varredura de fronteira).
- **Hipótese:** Δ(SN − U1) cresce com o custo de fronteira (oráculo < restrita < 5 min < 15 min).
- **Teste:** regressão logística do desfecho (contida = 1) com
  `logit P = β0 + β1·SN + β2·k + β3·(SN × k)`, k = índice do nível (0–3). Erros-padrão robustos por
  cluster (seed), estimador sanduíche CR1 com correção G/(G − 1) · (N − 1)/(N − K). **Hipótese:
  β3 > 0.** p bruto unilateral = 1 − Φ(β3 / EP). Implementação em numpy (IRLS), sem dependência
  nova.
- **Também reportados (descritivos):** Δ e IC95 % em cada nível.
- **Expectativa:** β3 > 0. O SN decide localmente o que o U1 só decide depois do lote; quanto maior o
  lote, mais impactos chegam antes da decisão do U1. **Risco declarado:** o aviso do SN também cruza a
  fronteira; com lote de 15 min, parte dos avisos em `campaign_e1_e2` pode chegar depois do impacto
  (600–1 800 s após o movimento), o que reduz o ganho de coordenação do SN **e** do U1 igualmente.
- **Limitação declarada:** o teste está na escala logit; Δ em pontos percentuais por nível é
  reportado para leitura direta. Com o oráculo, o piloto teve Δ = 0 exato.
- **Se NÃO for confirmada:** a vantagem do SN sobre o monolito não cresce com o custo de fronteira;
  o artigo não pode usar o argumento de "localidade" como explicação de dose-resposta, e a ligação
  com latências reais de telemetria [13] fica sem sustentação.

## 8. Descritivas (sem teste)

- B2L × U1 (5 famílias, h = 1, restrita), com Δ e IC95 %.
- Cada família isolada, SN × U1 × B2L (h = 1, restrita).
- Varredura de p_pre: SN × B2L nos 3 níveis.
- Varredura de fronteira: B2L nos níveis 5 e 15 min.
- Indisponibilidade por braço (total e componentes), perda por host, latência dos avisos, avisos
  falsos, por célula.

## 9. Gráficos e relatório (definidos antes de rodar)

Oito gráficos de barras com a **proporção absoluta** de cada braço (0–100 %), IC95 % por bootstrap de
clusters, SN em azul `#4A6FB0`, comparadores em cinza: (1) SN × B2L, H1; (2) SN × U1, H2/H3;
(3) B2L × U1; (4) SN × U1 nos 4 níveis de F2; (5) SN × B2L em h = 0 e h = 1 (`campaign_e1_e2`,
restrita); (6) SN × U1 × B2L por família; (7) SN × B2L por p_pre; (8) indisponibilidade por braço
(h = 1, restrita). Relatório em `docs/fase1/09_relatorio_oficial.md`.

## 10. Ameaças e limitações

As da Fase 1b (`06_preregistro_1b.md` §8) continuam valendo integralmente: família construída;
pressupostos de observação; custo dos avisos possivelmente subestimado; SN diferente do da Fase 1;
`restrict_privileges` com flag em hosts benignos; malha aberta, limiares fixos e regras
determinísticas (**nenhum resultado sustenta, sozinho, que o sistema é "adaptativo"**); compressão
temporal. Acrescentam-se:

1. **Hipóteses geradas pelos mesmos modelos do piloto.** As seeds são novas, mas o simulador, os
   limiares e as famílias são os mesmos. A confirmação vale para este modelo; não é validação
   externa.
2. **H3 é pequena e foi sugerida pelo piloto.** Mesmo confirmada, é um efeito de ≈ 2 pp.
3. **Pareamento entre níveis de F2:** os mesmos cenários aparecem nos 4 níveis; a regressão de H4
   trata essa dependência pelos erros robustos por seed.
4. **Valores de 5 e 15 min** representam a cauda da latência de ingestão [13]; não são medidas de
   um ambiente específico.

## 11. Congelamento

Ficam congelados, e é proibido ajustá-los depois de ver resultados: braços, fatores e níveis
(incluindo os valores de 5 e 15 min), a grade, as seeds 5000–5499, a métrica primária, a restrição
de 0,05, as pré-condições e os seus limites, os 4 testes, o procedimento de bootstrap (cluster =
seed, 10 000, seed 0), a correção de Holm, o critério e os gráficos. Qualquer desvio é declarado com
data no relatório.
