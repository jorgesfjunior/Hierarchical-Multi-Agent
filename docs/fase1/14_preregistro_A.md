# Fase 1 — 14. Pré-registro do caminho A (submissão AINA)

Status: **CONGELADO** quando existir `docs/fase1/14_preregistro_A.freeze.json` (data UTC, commit e sha256
deste arquivo, do driver, da análise e dos testes). Escrito **antes** de qualquer execução com as seeds
8000–8699; o rascunho foi comitado antes do piloto (`ff901ff`). Depois do congelamento, nada muda;
qualquer desvio é declarado com data no relatório (`15_relatorio_A.md`).

- **Decisão (2026-11-17):** a submissão ao AINA segue o **caminho A**: dois experimentos, em simulação,
  com o protocolo oficial (`08_preregistro_oficial.md`). O desenho maior (`13_desenho_hierarquia.md`)
  fica como plano para a versão de periódico e **não** é implementado.
- **Origem da hipótese:** o piloto EXPLORATORY da ablação (`11_ablacao.md`, seeds 7000–7099, commits
  `57427b5` e `a6d135f`). Lá, A1, A2 e A3 tiveram Δ = 0,00 pp [0,00; 0,00] em relação ao SN, com 0 pares
  discordantes, nos dois níveis de fronteira. **Esta execução testa essa observação com seeds novas.**
  O simulador, os limiares e as variantes são os mesmos: a confirmação vale para este modelo, não é
  validação externa.
- **Escopo reduzido (decisão de 2026-11-17, antes do congelamento):** o E1 roda só SN e A3 (U1 e B2L já
  estão na rodada oficial; A1 e A2 não entram no artigo); o E2 roda SN, U1 e B2L (o A3 toma as mesmas
  decisões do SN).

## 1. O que fica igual (congelado)

| Item | Identificação |
|---|---|
| Limiares por perfil | `config/fase1/thresholds_by_profile.yaml`, sha256 `b95552ff220743be0518d5d30fa15c2993754821f70f007b9d9a7cf375c522ba` (o mesmo do `08`) |
| Domínios do SN | `config/fase1/domains_sn.yaml`, sha256 `8725e227a8b0009dd35d3d9fae8b2390f85e8cba21139d3a0d1df34245d2ba37` (o mesmo do `08`) |
| Famílias, fundo benigno, campanha | `simulation/fase1.py`, sha256 `b3f6f008…6508e` (o mesmo do `08`) |
| Braços e knobs da 1b, avaliação | `simulation/fase1b_experiments.py`, sha256 `6a0b9a3a…68f3bc` (o mesmo do `08`) |
| Variante A3 | `simulation/fase1_ablacao_experiments.py` (`VARIANTS["A3"]`, `run_arm`), sha256 `ddbfbc5d…dd08`; `graph/build_sn_graph.py`, sha256 `c510d483…53da`; `simulation/transport.py`, sha256 `284c2a9f…8b51` (os da ablação) |
| Modelo de dano | `simulation/damage_model.py`, sha256 `c4edee28…229f`; efetividade 0,50; fração restaurável após inibição 0,43; liberação da segmentação na contenção, teto 3 600 s |
| Fronteiras | `restricted` = lote 60 s + 10 s + 32 KiB/s; `batch15m` = lote 900 s + 10 s + 32 KiB/s (`08` §3) |

Os sha256 completos estão no `freeze.json`.

**Código novo:** só o driver `simulation/fase1_A_experiments.py` (agenda os blocos, grava raw, extras e
manifest; aplica o multiplicador do E2; registra o que disparou cada isolamento de host benigno) e a
análise `analysis/fase1_A.py`. Nenhum módulo de simulação, agente, baseline ou detecção muda. O driver
reutiliza `run_arm` da ablação (que, para U1 e B2L, chama o driver oficial), `scenario`, `damage_params`
e `evaluate` da 1b, `instrumentation` da Fase 1 e `extras` da Etapa 3.

## 2. Pré-condições (fora do teste; se uma falhar, a execução para e a falha é reportada)

| Teste | Passa se | Situação no congelamento |
|---|---|---|
| **R1** regressão completa do repositório | todos os testes passam, exceto a falha conhecida abaixo | rodada em 2026-11-17 sobre o código existente (nenhum arquivo existente mudou desde `8d5d08e`; o código novo é só o driver, a análise e os testes deles). Todos passam, exceto a falha conhecida. Os testes longos de `tests/test_phase7b.py` (`test_hl1b_precondition_queue_nonempty…`, ≈ 8 min) rodaram em segundo plano e passaram. Por decisão sua, R1 não é refeita a menos que código fora do driver novo mude |
| **R2** golden e testes do código novo (`tests/test_fase1_A.py`) | (a) o E1 reproduz byte a byte (texto CSV) as linhas SN e A3 da ablação publicadas para a seed 7000 (`interleaved`, `restricted`); (b) o E2 com m = 1,0 reproduz byte a byte as linhas oficiais da seed 5000 (`campaign_e1_e2`, `restricted`, SN/U1/B2L); (c) m = 1,0 devolve a tabela congelada sem alteração; (d) o multiplicador é monótono e não sai da escala; (e) as seeds são novas e disjuntas; (f) os blocos cobrem a grade uma vez só; (g) TOST, bootstrap pareado e McNemar da análise | refeita imediatamente antes da rodada oficial |

**Falha conhecida declarada (decisão Q3: manter, não mudar agora):**
`tests/test_phase4b.py::test_playbook_v1_is_unchanged_and_default` **já falha no commit `8d5d08e`**,
antes de qualquer mudança deste caminho. Ele espera 5 técnicas no playbook padrão, e a Fase 1 acrescentou
T1190 (exposição de serviço vulnerável). A falha não tem relação com E1 ou E2.

## 3. E1 — Ablação confirmatória das camadas de cima

**Braços:**

| Braço | Configuração |
|---|---|
| **SN** | completo, como na rodada oficial (especialistas + coordenadores + estratégico) |
| **A3** | a variante A3 de `11_ablacao.md` §1, exatamente como implementada: sem estratégico, coordenador sem despacho e sem telemetria pela fronteira (`sn_layers = specialist_only`, `dispatch_on_flag::coordinator = False`); só os avisos entre segmentos sobem |

**Condições.** As 5 famílias (`encryption_stream`, `campaign_multihost`, `split_visibility_late_confirm`,
`interleaved`, `campaign_e1_e2`, p_pre = 0,5); h = 1; fronteira **lote 60 s** (`restricted`) e **lote
15 min** (`batch15m`).

**Seeds: 8000–8499** (500), as mesmas nos dois níveis e nos dois braços. Unidade: a campanha, pareada
entre braços por (família, seed, campanha).

**Métrica primária.** p = proporção de campanhas contidas antes do impacto
(`contained_before_impact`), juntando as 5 famílias.

### 3.1 Hipótese H5 (equivalência)

> **H5:** remover as camadas de cima não muda a taxa de proteção: p(A3) − p(SN) fica dentro de
> **±1 pp**, nos dois níveis de fronteira.

- **Δ** = p(A3) − p(SN), média das diferenças por campanha.
- **Teste (TOST) em cada nível**, por bootstrap de clusters como no `08` §7 (cluster = seed; 10 000
  reamostragens dos 500 seeds; `numpy.random.default_rng(0)`; Δ\* = soma das diferenças nos clusters
  sorteados / número de unidades sorteadas):
  p_inf = (1 + #{Δ\* ≤ −m}) / 10 001; p_sup = (1 + #{Δ\* ≥ +m}) / 10 001; **p_TOST = máx(p_inf, p_sup)**.
  Isso equivale a exigir que o IC90 % do bootstrap (percentis 5 e 95) fique dentro de (−m, +m).
- **Critério:** H5 **confirmada** se p_TOST < 0,05 **nos dois níveis**, com **m = 1 pp** (decisão Q1). É
  um teste de interseção-união: cada nível tem de passar com α = 0,05, e não há correção de
  multiplicidade. H5 é o único teste confirmatório deste pré-registro.
- **Justificativa da margem de 1 pp.** O mesmo artigo confirma como efeito real a diferença SN − U1 de
  **+1,6 pp** [IC95 +1,2; +2,1] (H3 do `09`). Com ±2 pp, o artigo chamaria de "equivalente" uma diferença
  maior que outra que ele chama de "efeito". ±1 pp fica abaixo do limite inferior de H3 e coincide com a
  regra do piloto de ablação (`11` §2). Com ≈ 2 760 campanhas por nível e pares discordantes na taxa de
  H3, a meia-largura do IC90 fica em ≈ 0,4 pp.
- **Verificação secundária:** o mesmo TOST com **m = 2 pp** (a margem originalmente pedida), reportado ao
  lado, sem entrar no critério.
- **Reportado junto (descritivo):** Δ com IC95 %; pares discordantes (A3 contém e o SN não; o inverso);
  McNemar exato bilateral; Δ por família; Δ em `data_loss_per_host`.

**Leitura de cada desfecho (decidida agora; todos são reportados):**

| Resultado (em cada nível, m = 1 pp) | Leitura |
|---|---|
| IC90 dentro de (−1, +1) pp nos dois níveis | **H5 confirmada:** neste modelo, coordenadores e estratégico não acrescentam proteção; o que protege é o especialista local mais o aviso entre segmentos |
| IC90 inteiramente em ≤ −1 pp em algum nível | **A3 protege menos:** as camadas de cima contribuem para a proteção naquele nível; contradiz o piloto e é reportado como tal, com o mecanismo (famílias onde Δ aparece, rótulos perdidos) |
| IC90 inteiramente em ≥ +1 pp em algum nível | **A3 protege mais:** as camadas de cima atrapalham a proteção naquele nível; reportado com o mecanismo |
| qualquer outro caso | **inconclusivo:** nem equivalência nem diferença demonstradas; reportado assim, sem reinterpretação |

**Resultado esperado (declarado com honestidade).** Pelo `11_ablacao.md` esperamos **equivalência**, e
mais que isso: **Δ = 0 exato**, sem nenhum par discordante, nos dois níveis. O mecanismo observado no
piloto é estrutural, não estatístico. O coordenador roda o mesmo detector, com os mesmos limiares, sobre
o mesmo histórico de host, e as ações dele chegam depois das do especialista. As duas ações exclusivas
do estratégico (`trigger_backup_restore`, `segment_network`) não alcançaram nenhuma campanha que escapa. O
aviso entre segmentos é do especialista e existe em A3. Se o mecanismo se repetir, o TOST passa com
p = 1/10 001 (o menor valor possível), porque todo Δ\* é zero. **O teste confirma uma propriedade do
modelo, não uma descoberta empírica sobre redes reais:** esperamos que o E1 mostre que **as camadas de
cima não acrescentam nada à proteção** neste modelo. Um único par discordante já seria um fato novo e
será examinado e reportado.

### 3.2 Secundárias (descritivas, sem teste)

Por braço e nível, com IC95 % por bootstrap de clusters (seed; 10 000 para médias e razões, 2 000 para
quantis; `default_rng(0)`):
- **Mensagens pela fronteira por run** (`crossings_boundary`) e bytes; **mensagens em todos os enlaces**
  (soma de `tr.crossings`: local, fronteira, coordenador → estratégico); **mensagens entre agentes**
  (`message_sent`, `extras.comm.agent_messages`); razões A3/SN.
- **Indisponibilidade** (`unavailability_fraction`, média por run).
- **Tempo até a primeira ação** por campanha (mediana e P90, `extras.campaigns.first_action_s`).
- Perda por host, hosts benignos isolados por run, avisos (total e falsos) por run, e rótulos
  exclusivos do estratégico (para confirmar que somem em A3).

## 4. E2 — Varredura de limiares (descritiva, sem teste de hipótese)

**Pergunta:** qual o custo em falsos positivos de cada nível de proteção, e ele muda entre arquiteturas?

**Braços:** SN, U1, B2L. **Condição:** 5 famílias, h = 1, lote 60 s (`restricted`).
**Seeds: 8500–8699** (200). **Multiplicadores m:** 0,5; 0,75; **1,0 (oficial)**; 1,25; 1,5; 2,0. O mesmo m
vale para todos os braços e todos os segmentos (perfis E1, E2, E3).

### 4.1 Regra do multiplicador (decisão Q2: aceita)

m > 1 = limiares mais exigentes (menos alertas); m < 1 = mais sensíveis. São escalados **todos** os
limiares numéricos que a tabela por perfil aceita (`detection/early_signals.py`,
`detection/late_signals.py`), partindo do valor efetivo congelado de cada perfil (a linha do perfil, ou a
constante do módulo quando o perfil não a define). Com m = 1,0 a tabela congelada é usada **sem nenhuma
alteração** (golden R2c).

| Tipo | Limiares | Regra |
|---|---|---|
| contínuos sem teto prático | `recon_hosts_per_second`, `file_access_rate`, `overwrite_ratio`, `rename_rate`, `mass_rate_multiplier` | m · valor |
| contagens | `c2_min_beacons`, `lateral_min_new_peers`, `min_directories` | arredonda m · valor (meio para cima), mínimo 1 |
| escores com máximo | `entropy_high_bits` (máx. 8 bits/byte), `exposure_min_severity` (máx. 10) | máx − (máx − valor) / m: a **folga até o máximo** é dividida por m |
| contagem com máximo | `min_corroborating` (3 corroboradores existem) | arredonda m · valor, limitado a [1, 3] |

**Por que a regra não é "m · valor" em todos.** Multiplicar a entropia (7,8 bits) por 1,25 daria 9,75
bits, acima do máximo de 8 bits por byte; a severidade do E2 (9,0 × 1,25) passaria de 10; e
`min_corroborating` do E1 (3 × 1,25 → 4) passaria de 3. "Mais exigente" **desligaria** o detector. O
`baseline_files_per_second` não é limiar (é a base de `mass_rate_multiplier`) e não é escalado, para não
aplicar m duas vezes.

**Valores resultantes** (m = 0,5 / 0,75 / **1,0** / 1,25 / 1,5 / 2,0):

| Limiar | E1 | E2 | E3 |
|---|---|---|---|
| `recon_hosts_per_second` | 0,25 / 0,375 / **0,5** / 0,625 / 0,75 / 1,0 | igual ao E1 | 0,5 / 0,75 / **1,0** / 1,25 / 1,5 / 2,0 |
| `file_access_rate` | 2,5 / 3,75 / **5,0** / 6,25 / 7,5 / 10,0 | igual | igual |
| `overwrite_ratio` | 0,15 / 0,225 / **0,3** / 0,375 / 0,45 / 0,6 | igual | igual |
| `rename_rate` | 1,0 / 1,5 / **2,0** / 2,5 / 3,0 / 4,0 | igual | igual |
| `mass_rate_multiplier` | 2,5 / 3,75 / **5,0** / 6,25 / 7,5 / 10,0 | igual | igual |
| `c2_min_beacons` | 2 / 2 / **3** / 4 / 5 / 6 | igual ao E1 | 1 / 2 / **2** / 3 / 3 / 4 |
| `lateral_min_new_peers` | 2 / 2 / **3** / 4 / 5 / 6 | igual | igual |
| `min_directories` | 2 / 2 / **3** / 4 / 5 / 6 | igual | igual |
| `entropy_high_bits` | 7,6 / 7,733 / **7,8** / 7,84 / 7,867 / 7,9 | igual ao E1 | 7,0 / 7,333 / **7,5** / 7,6 / 7,667 / 7,75 |
| `exposure_min_severity` | 4,0 / 6,0 / **7,0** / 7,6 / 8,0 / 8,5 | 8,0 / 8,667 / **9,0** / 9,2 / 9,333 / 9,5 | igual ao E1 |
| `min_corroborating` | 2 / 2 / **3** / 3 / 3 / 3 | 1 / 2 / **2** / 3 / 3 / 3 | igual ao E2 |

**Limitações da varredura (declaradas):**
1. Os limiares inteiros andam em degraus; alguns níveis vizinhos são iguais (por exemplo, 0,5 e 0,75 em
   várias contagens), e `min_corroborating` do E1 não fica mais exigente acima de 1,0.
2. **Não são escalados:** o detector de escalada de privilégio, que não tem limiar (todo
   `privilege_escalation_attempt` gera sinal com confiança 0,6); a regra de precaução com um sinal; a
   constante de corroboração antecipada (`EARLY_MIN_DISTINCT_SIGNAL_TYPES = 2`, no classificador, fora da
   tabela); as listas de categorias e de comandos. Essas fontes formam um **piso de FP** que nenhum m
   remove, e esse piso é **reportado como resultado** (§4.3).
3. A regra para escores com máximo é uma escolha de modelagem: ela torna a entropia pouco sensível a m
   (7,6–7,9 bits). A curva mostra o efeito **desta** parametrização, não de toda forma possível de
   ajustar o detector.

### 4.2 Métricas (por braço e m; IC95 % por bootstrap de clusters, seed, 10 000; `default_rng(0)`)

| Métrica | Definição |
|---|---|
| **Taxa de proteção** | p, como no E1 (5 famílias juntas) |
| **Hosts benignos isolados por run** | média por run (família, seed) do número de hosts benignos do fundo (9 por run) que receberam `isolate_host` (`extras.benign[*].isolated`); também reportados os hosts benignos com **qualquer** ação |
| **Precisão de qualquer ação de contenção** | Σ VP / Σ (VP + FP) na base `any_containment` da classificação por incidente (`extras.classification`; negativos = fundo benigno e iscas), razão de somas |
| **Precisão dos avisos** | Σ (avisos − avisos falsos) / Σ avisos (`advisories`, `advisories_false` do raw), razão de somas; não se aplica ao B2L, que não emite avisos entre segmentos |
| **Indisponibilidade** | média por run de `unavailability_fraction` |

**Saída:** uma tabela (braço × m × métrica, com IC95 %) e **uma figura**:
`results/fase1_A/figs/E2_protecao_vs_isolados.{png,pdf}`. No eixo y, a taxa de proteção (%); no eixo x,
os hosts benignos isolados por run. Uma linha por braço, ligando os 6 pontos em ordem de m, cada ponto
rotulado com o seu m e com barras de IC95 % nos dois eixos. SN em azul `#4A6FB0`; U1 e B2L em cinza,
diferenciados pelo traço e pelo marcador.

### 4.3 Piso de FP (reportado como resultado, decisão Q2)

Para cada despacho com `isolate_host` num host benigno, o driver registra o **tipo** (aviso entre
segmentos; veredito positivo; precaução por um sinal) e o **tipo do evento que o disparou**
(`extras.benign_isolation_triggers`). Por braço e m são reportados:
- **hosts benignos isolados por run por um evento `privilege_escalation_attempt`** (o detector sem
  limiar), com IC95 %, e a fração que isso representa dos hosts benignos isolados;
- a **composição dos despachos de isolamento benignos** por tipo de evento disparador e por tipo de
  despacho (a fração "precaução" mede o peso da regra de um sinal);
- o **valor da curva no m menos sensível (2,0)**, como piso empírico total.

Limitação declarada: a contribuição da constante de corroboração antecipada fica dentro dos despachos
"veredito positivo" e não pode ser separada sem mudar o detector, o que este pré-registro não permite.

**Expectativa (não é regra):** U1 e B2L ficam abaixo do SN em proteção com o lote de 60 s, como em H3.
Nos três braços, menor m dá mais proteção e mais hosts benignos isolados. A precisão dos avisos muda
pouco com m, porque os avisos falsos vêm de conexões administrativas cuja origem tem sinal de escalada de
privilégio, que não é escalado. O piso deve ser uma parte grande dos isolamentos benignos em m = 2,0.

## 5. Piloto (EXPLORATORY) e execução

- **Piloto (feito):** seeds **9000–9019**, rótulo EXPLORATORY, saída em `results/fase1_A_pilot/` (commit
  `094257f`). Rodou o escopo original (E1 com 6 braços, E2 com 4) **só** para verificar a execução e medir
  tempos. Nenhuma tabela de desfecho foi calculada ou olhada. As seeds do piloto nunca entram na
  confirmação.
- **Blocos oficiais** (`python3 simulation/fase1_A_experiments.py blocks`): um por (experimento, nível ou
  m, família, faixa de seeds), com faixas de 50 seeds em `campaign_multihost`, 125 em `campaign_e1_e2` e
  250 nas demais. São 40 blocos no E1 e 54 no E2 (94 no total), cada um ≤ 5 min, com checkpoint por
  sha256 no manifest. A divisão por faixas não muda nenhuma linha. Os comandos usam `run-all --budget-s`
  para que nenhum comando passe de 5 min.
- **Ordem:** R2 → congelamento (`14_preregistro_A.freeze.json`) → E1 → E2 → análise
  (`python3 analysis/fase1_A.py`) → relatório `15_relatorio_A.md`.

## 6. Decisões (tomadas em 2026-11-17, antes do congelamento)

- **Q1** margem do TOST: **±1 pp** (primária); ±2 pp como verificação secundária.
- **Q2** regra do multiplicador da §4.1, aceita; piso de FP reportado como resultado (§4.3).
- **Q3** `test_phase4b.py::test_playbook_v1_is_unchanged_and_default`: falha conhecida declarada, não
  alterada.
- **Q4** estimativa aprovada com o escopo reduzido (§7).

## 7. Estimativa de tempo da rodada oficial

**Piloto** (2026-11-17, seeds 9000–9019, 10 processos; `results/fase1_A_pilot/manifest.json`): 40 blocos,
sem exceções; soma dos tempos dos blocos E1 181 s (6 braços), E2 334 s (4 braços); bloco mais longo 64 s.

| Experimento | Execuções de braço | Estimativa (piloto e ablação, escalados para o número de braços) |
|---|---|---|
| E1 (500 seeds × 2 níveis × 2 braços) | 10 000 | ≈ 18–25 min |
| E2 (200 seeds × 6 m × 3 braços) | 18 000 | ≈ 31–42 min |
| Início de processo (94 blocos) | — | ≈ 10 min |
| **Total** | 28 000 | **≈ 1 h – 1 h 20** de relógio |

## 8. Ameaças e limitações

As do `08` §10 e do `11` §5 continuam valendo: mesmo simulador, limiares fixos, regras determinísticas,
famílias construídas, compressão temporal. Acrescentam-se:
1. **Equivalência por construção do mecanismo.** Se Δ = 0 exato se repetir, o TOST é trivialmente
   satisfeito. O resultado diz que, **neste modelo**, as camadas de cima repetem decisões do especialista
   e não acrescentam proteção. Ele não diz que nenhuma hierarquia ajudaria em nenhuma rede; os papéis
   que poderiam ajudar estão em `13_desenho_hierarquia.md` e não foram testados.
2. **Só SN × A3.** A1 e A2 (remoções parciais) não são rodados aqui; os números deles ficam os do piloto
   de ablação (exploratório).
3. **E2 é descritivo:** nenhuma comparação entre braços no E2 é teste; as curvas não podem ser lidas como
   confirmação.
4. **Os hosts benignos isolados por run** vêm de 9 hosts benignos numa janela média de ≈ 36 min
   (`10` §0); não são taxas por dia.

## 9. Congelamento

Ficam congelados, quando o `freeze.json` existir: braços, condições, seeds (8000–8499 e 8500–8699), a
métrica primária, H5 com m = 1 pp e a verificação com 2 pp, o procedimento do TOST e do bootstrap
(cluster = seed, 10 000, seed 0), o critério nos dois níveis, a regra do multiplicador, as métricas, o
piso de FP e a figura do E2.
