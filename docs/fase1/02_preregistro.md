# Fase 1 — 02. Pré-registro (EXPLORATORY)

Status: **CONGELADO.** Data e hora UTC e hash do commit de congelamento estão em
`docs/fase1/02_preregistro.freeze.json`. Aprovado com ajustes em 2026-10-17; os ajustes estão
aplicados abaixo. Base do desenho: `01_especializacoes.md`. As referências [n] seguem a lista
daquele documento, que inclui [13] e [14]. "SM" = suposição de modelagem.

**Pergunta.** Uma arquitetura multiagente com especialistas por segmento (SN) protege melhor que um
MAPE-K monolítico com o **mesmo** conhecimento (U1) [12] quando o ambiente é heterogêneo e o que
cruza a fronteira de um segmento tem custo? Pergunta complementar: o ganho, se houver, vem da
camada agêntica ou só de decidir localmente (B2-SSL-local)?

## 1. Hipóteses

- **H1 (principal).** Com heterogeneidade `h = 1` e restrição de fronteira ativa, SN > U1 na métrica
  primária. Formalmente: Δ = perda(U1) − perda(SN) > 0 (§7).
- **H1-loc (atribuição).** Na mesma condição, Δ_loc = perda(B2-SSL-local) − perda(SN), julgado com
  as mesmas regras e a mesma margem (§7).
- **H0 (sanidade, não é hipótese de pesquisa).** Com o central oráculo (sem custo de fronteira),
  SN ≈ U1, tanto em `h = 0` quanto em `h = 1`.
  - **Tolerância:** o IC95 % de Δ precisa ficar inteiro dentro de ±1 000 arquivos por host, a
    margem já registrada no projeto (`docs/hypotheses.md:395, 549`).
  - **Se H0 falhar,** o piloto para e a causa é investigada e reportada. Nada é ajustado para H0
    passar.
  - **Por que H0 é plausível por construção:** o incidente é a chave do host
    (`scenario_generator.py:115-117`) e cada host pertence a um só segmento, então o histórico local
    do segmento é o histórico inteiro do incidente.
  - **O que H0 não cobre:** o SN e o U1 diferem também em autoridade (§2.1). Por isso H0 pode falhar
    nas unidades em que a restauração ou a segmentação global importam. Nesse caso, a falha é
    reportada como achado, não corrigida.
- **Contraste secundário (interação).** [Δ em `h = 1`, restrita] − [Δ em `h = 0`, restrita].
  Descritivo, sem critério de decisão.

## 2. Braços

Todos com precaução ligada (regra de sinal único) e `preventive_actions` = todas. Os três leem os
limiares dos detectores do **mesmo arquivo**, `config/fase1/thresholds_by_profile.yaml`, escolhidos
pelo perfil do host do evento. O playbook é o mesmo nos três.

| Braço | Definição | Onde decide | O que cruza a fronteira (e paga) |
|---|---|---|---|
| **SN** | MAS-D com especialistas E1/E2/E3, um por segmento (perfil), roteados pelo perfil do host de origem. Os coordenadores atuais (`proactive`/`reactive`, por fase da cadeia, `DomainCoordinatorAgent`) ficam **fora** dos segmentos, com autoridade delegada, mais o Strategic. Autonomia local: §3. | especialista dentro do segmento; coordenador e Strategic fora | relatório especialista → coordenador (com o evento); escrita no Knowledge; ações de coordenador e Strategic de volta ao host |
| **U1** | B1-SSL: `MAPEKLoop` + `single_signal_containment`, todas as fases [12] | central, fora de todos os segmentos | todo evento (sobe); toda ação (desce) |
| **B2-SSL-local** | uma instância B2-SSL (`MAPEKLoop` + SSL) **por segmento**, sem comunicação entre instâncias, com o **mesmo conjunto de ações locais do especialista do SN** (§3): `containment`, `eradication`, `prevent_host` e `prevent_segment` no próprio segmento | dentro do segmento | nada |

O B2-SSL fora dos segmentos foi **retirado** do piloto e substituído pelo B2-SSL-local.

### 2.1 Capacidades do SN que o B2-SSL-local não tem (item 9)

Análise feita sobre o código de `8b0aac1`.

| Capacidade do SN | Onde no código | Pode alterar a métrica primária? Em quais famílias/condições, e por qual mecanismo |
|---|---|---|
| **Diretiva global do Strategic com recuperação** (`global_containment_directive` → `trigger_backup_restore`) | `agents/strategic_governance.py:162-173`; recuperação só na autoridade do Strategic (`agents/mape.py:78-82`); o B2-SSL-local não tem a fase `recovery` | **Sim**, onde houver impacto apesar da precaução local: a restauração devolve `restorable_fraction` dos arquivos cifrados no host observado (`damage_model.py:60-65`). Casos: hosts IoT em `h = 1` sem sinal de rede antes do impacto (`campaign_multihost`, `interleaved`), e qualquer unidade em que a precaução local falhe. Hosts alcançados só pelo espalhamento modelado nunca são restaurados. |
| **Segmentação global preventiva** (`segment_network`, `prevent_global`) | `agents/mitigation.py:89-96` (`T1018`/`T1135` → `prevent_global`; só o Strategic tem essa autoridade); efeito em `damage_model.py:541-542, 607-612` | **Sim**, em `campaign_multihost`. A evidência do paciente zero (segmento A) chega ao Strategic, que segmenta a rede; os saltos para hosts de **outros** segmentos são bloqueados com probabilidade `e`. Os movimentos laterais ocorrem 683–2 056 s depois (seeds 0–99), bem depois do atraso de fronteira (≤ 80 s + fila). Evidência da Fase 8: P1, `segment_network`, perda total do MAS-D −20 000 em 1 de 5 campanhas. Cuidado: na métrica **por host**, prevenir movimentos pode piorar o valor (artefato F1, `REPORT.md`). |
| Contenção e prevenção no nível do coordenador | `agents/domain_coordinator.py:146-199` | **Não exclusiva em efeito.** Os alvos são os hosts do incidente (`mape.py:312-319`), isto é, o mesmo host e o mesmo segmento que o especialista já cobre. |
| **Correlação entre segmentos / troca de evidência via Knowledge** | `mape.py:244-251` (escopo do incidente); `repository.py:148-163` | **Não. É inerte por construção:** o incidente é o host (`scenario_generator.py:115-117`), então nenhuma análise junta evidência de dois hosts, e muito menos de dois segmentos. |
| **Ação preventiva dirigida a outro segmento** (ex.: proteger o backup do E2 após evidência do E1) | alvos em `mape.py:312-319` e `mitigation.py:348-358`; mapeamento em `damage_model.py:272-274` | **Não. Impossível no código atual:** todo alvo é derivado do host do incidente, e `segment@h` é mapeado para o segmento de `h`. A única ação que alcança outros segmentos é a global (`segment_network`, acima). |
| Reconciliação após falha | `agents/reconciliation.py` | Não se aplica: o piloto não tem falhas. |

**Decisão (regra do item 9).** Há capacidades exclusivas do SN que podem alterar a métrica (as duas
primeiras linhas), então o pré-registro é congelado e a Etapa B segue.

**Escopo da atribuição.** Essas capacidades são de **autoridade hierárquica** (recuperação e ação
global por escalonamento), não de **troca de informação** entre segmentos, que é inerte por
construção. Portanto:
- **SN > B2-SSL-local** atribui o ganho à **escalada para autoridade central** (recuperação e
  segmentação global) da camada agêntica hierárquica, e **não** à correlação ou à coordenação
  informacional entre segmentos.
- **Testar a coordenação informacional** exigiria um mecanismo novo, por exemplo um aviso de um
  especialista que dispara ação preventiva no segmento de outro especialista. Ele fica registrado
  como extensão futura e **não** faz parte deste piloto.

## 3. Autonomia local no SN (J5): parte da definição do braço

**Problema.** No MAS-D atual, a precaução de `service_stop_attempt` e de `backup_recovery_tamper`
acontece no **coordenador**, porque a confiança isolada (0,30 e 0,425) supera o limiar de
escalonamento do especialista (`01_eventos.md` §1). Se a decisão protetora tiver de cruzar a
fronteira, o SN paga o mesmo custo que o U1, e H1 fica impossível **por construção**.

**Regra.** No SN, o especialista do segmento é dono da precaução e da contenção no seu segmento. A
justificativa é a autoridade delegada do MAS-D: os agentes agem e depois escalam
(`agents/mape.py:96-104`).

| Especialista | Decide localmente, sem cruzar a fronteira | Escala (cruza a fronteira e paga) |
|---|---|---|
| E1 estação | precaução a qualquer sinal (`isolate_host`, `restrict_share_write`); com flag: `kill_process` + `isolate_host` + `prevent_segment` no próprio segmento | relatório de todo evento; recuperação; ações globais |
| E2 servidor | precaução a qualquer sinal (incluindo T1490 e `vulnerable_service_exposure`); `protect_backup` no próprio segmento; com flag: idem E1 | relatório; recuperação; ações globais |
| E3 IoT | quarentena (`isolate_host`) e bloqueio (`block_network_segment` do próprio segmento) a qualquer sinal de rede | relatório; recuperação; ações globais |

Mudanças em relação ao MAS-D atual, só no braço SN:
1. O especialista **age e também escala**, independentemente do limiar de escalonamento.
2. A autoridade local é `containment`, `eradication`, `prevent_host` e `prevent_segment` (só o
   próprio segmento). A precaução usa as fases da regra SSL (`containment` + `prevent_host`).
3. O B2-SSL-local recebe exatamente o mesmo conjunto local.

## 4. Condições

Fatorial: `h ∈ {0, 1}` × restrição ∈ {oráculo, restrita}.
- **Perfis e segmentos:** `profiles` ativo em todas as condições, com segmentos E1/E2/E3 de 70/20/10
  hosts.
- **Fundo benigno:** ligado em todas as condições.
- **`h = 0`:**
  - Todos os hosts são observáveis, nenhum tipo de evento novo é emitido e os ataques não mudam.
  - Os 9 hosts benignos usam o gerador benigno **genérico**: escrita de arquivo com 10 % compactada,
    runas de admin raro, reinício de serviço não relacionado à segurança.
  - Os limiares são as constantes atuais, iguais para todos os perfis (linha `homogeneous` do
    arquivo de limiares).
- **`h = 1`:** os geradores, assinaturas e limiares por perfil de `01_especializacoes.md`.
- **Custos internos ao segmento**, iguais nas duas condições e em todos os braços:
  `local_latency_s = 0,001` e `service_time_s = 0,01` por nó analisador.
- **Enlace entre coordenador e Strategic:** local, porque os dois ficam fora dos segmentos e não há
  fronteira entre eles.

**Restrição de fronteira** (vale igualmente para os três braços):

| Parâmetro | Oráculo | Restrita | Justificativa |
|---|---|---|---|
| Agregação (lote) da telemetria e dos relatórios que sobem | nenhuma | **lote de 60 s** por segmento; cada mensagem espera o fim da janela; o conteúdo vai inteiro | O agente do Azure Monitor envia logs em lotes a cada 30 s–2 min, e a maioria dos dados sobe em até 1 min [13]. |
| Latência por mensagem que cruza, em cada sentido | 0 | **10 s** | A latência média de ingestão depois da entrega ao serviço é < 10 s [13]. |
| Banda de subida por segmento | ilimitada | **32 KiB/s**, FIFO, tamanho = bytes JSON da mensagem | SM. Durante a cifragem, as amostras de 4 KiB a 2–8 escritas/s saturam o enlace. |
| Custo por evento processado | `service_time_s = 0,01` | idem | Já existe; é o mesmo nos braços. |
| Knowledge entre segmentos | gratuito | paga como mensagem que cruza: coordenador e Strategic só leem um evento depois que ele chegou | Regra de fronteira. |

**Nota.** Os valores são conservadores. Num SOC, o tempo total até a detecção soma ainda a latência
de processamento de regras e a de reconhecimento pelo analista [14]. Nenhuma das duas é modelada.

**Conteúdo restrito pelo tempo (B3).** Um nó só analisa quando o evento lhe chega, e só com o que já
chegou. Como as análises são por incidente (host) e os eventos de um host sobem por um único enlace
FIFO, a ordem de chegada dentro do incidente é a ordem de geração. Por isso o conteúdo visível ao nó
no instante da análise é exatamente o prefixo do incidente, e a restrição age sobre o **tempo** das
decisões. Isso será verificado por teste.

## 5. Métricas

Nenhuma métrica nova é criada.

**Primária: `data_loss_per_host`**, no ponto primário da Fase 8 (`e = 0,50`, `r_inh = 0,43`,
horizonte de 86 400 s), por campanha maliciosa (`docs/hypotheses.md:544`).

**Secundárias** (já calculadas):
- **Dano:** `data_loss` (total; ver o artefato F1 na §2.1), `files_encrypted`, `hosts_compromised`,
  `observed_hosts`, `prevented_moves`, `contained`.
- **Antecedência:** `impact_time_s`, `first_prevention_s_*`, `prevented_before_impact_*`,
  `lead_time_s_*`, `preventive_dispatches_*`.
- **Disponibilidade / falso positivo:** `unavailability_fraction`, `weighted_host_seconds`,
  `cost_*`. Contagem `fp` (`classification()`, base `any_containment`) sobre os hosts benignos.
- **Comunicação:** `crossings`, `crossing_bytes`, `message_sent`.

**Instrumentação do item 9** (por run; contadores derivados dos logs existentes, não métricas de
decisão):
1. Decisões locais por especialista e por instância do B2-SSL-local: número de `action_dispatched`
   em cada nó local.
2. Avisos entre segmentos: número de despachos cuja ação cobre um segmento diferente do segmento do
   host que originou a evidência. Pelo §2.1, só `segment_network` pode fazê-lo.
3. Para cada ação preventiva que cobre outro segmento: se chegou antes do primeiro impacto em algum
   host daquele segmento da mesma campanha.

## 6. Seeds, calibração e escopo

- **Calibração:** seeds 100–119 (20), usadas **só** para escolher os limiares.
- **Avaliação (piloto):** seeds 200–209 (10), disjuntas da calibração e das seeds 0–4 da Fase 8.
- **Famílias:** `encryption_stream`, `campaign_multihost`, `split_visibility_late_confirm` e
  `interleaved`, todas com o fundo benigno.
- **Calibração:** grade por perfil, nas seeds de calibração, no braço **U1** com `h = 1` e oráculo.
  Calibrar no U1 favorece o U1, o que é conservador para H1.
  - **Grade:**

    | Perfil | Parâmetro 1 | Parâmetro 2 |
    |---|---|---|
    | E1 | entropia {7,0; 7,5; 7,8} | corroboradores {1, 2, 3} |
    | E2 | entropia {7,0; 7,5; 7,8} | `exposure_min_severity` {5, 7, 9} |
    | E3 | recon {0,25; 0,5; 1,0} hosts/s | `c2_min_beacons` {2, 3, 5} |

  - **Objetivo:** minimizar a média de `data_loss_per_host` sujeito a `unavailability_fraction` ≤ 0,05
    (desvio aprovado em relação a "maximizar a métrica primária"). Desempate: menor
    `unavailability_fraction`.
  - **Saída:** `config/fase1/thresholds_by_profile.yaml`, com o comando, as seeds e o hash.
- **Piloto:** 3 braços × 4 condições × 4 famílias × 10 seeds = 480 runs, mais NO-DEFENSE. Rótulo
  **EXPLORATORY**. Sem correção de Holm e sem afirmação de significância.

## 7. Critério de decisão (EXPLORATORY), congelado

Unidade: campanha maliciosa, pareada por (família, seed, campanha). As quatro famílias são
agregadas.
- Δ = perda(U1) − perda(SN) e Δ_loc = perda(B2-SSL-local) − perda(SN), em arquivos por host.
- Média com IC95 % por bootstrap (`analysis/stats.py:91`, seed 0).
- Margem **M = 1 000** arquivos/host.

**Pré-condição:** H0 passou nas duas condições oráculo. Sem isso, H1 e H1-loc não são interpretados.

| Resultado (`h = 1`, restrita), para Δ e para Δ_loc | Regra |
|---|---|
| **SN ganhou** | média ≥ M, limite inferior do IC > 0, e `unavailability_fraction`(SN) − (outro) ≤ +0,05 |
| **Empate** | IC95 % inteiro em [−M, +M] |
| **O outro braço ganhou** | média ≤ −M e limite superior do IC < 0 |
| **Inconclusivo** | nenhum dos casos acima |

| Δ (SN × U1) | Δ_loc (SN × B2-SSL-local) | Leitura para o artigo |
|---|---|---|
| SN ganhou | empate | O ganho é da **localidade**, não do multiagente. |
| SN ganhou | SN ganhou | Parte do ganho é atribuível à camada agêntica, no sentido restrito da §2.1: escalada para autoridade central (recuperação e segmentação global). Não à troca de evidência entre segmentos. |
| empate | qualquer | Com o mesmo conhecimento, especializar não paga nem sob custo de fronteira, com estes parâmetros. Reporta-se como achado negativo. |
| U1 ganhou | qualquer | O custo de coordenação do SN supera o ganho local. Achado negativo. |
| inconclusivo | qualquer | Calcula-se o tamanho de amostra para uma execução oficial. Nenhuma afirmação. |

**Congelamento.** Ficam congelados com este pré-registro:
- os parâmetros de restrição (60 s, 10 s, 32 KiB/s);
- a margem M;
- este critério de decisão;
- as seeds, as famílias e a grade de calibração.

**É proibido ajustá-los depois de ver qualquer resultado do piloto**, seja para cruzar a margem, seja
para fazer H0 passar. Qualquer mudança posterior é um desvio declarado, com data, e invalida a
leitura confirmatória do item alterado.

**Expectativa declarada antes de rodar** (calculada com os valores congelados e só a partir da
estrutura dos cenários, nas seeds 0–99, sem rodar nenhum braço):
- **Atraso do U1:** espera do lote U(0, 60) s + 10 s de subida + 10 s de descida + serviço, isto é,
  **20–80 s**, sem contar a fila de banda.
- **SN e B2-SSL-local:** a precaução local chega em ≈ 0,01 s.
- **Intervalo entre o primeiro sinal e o impacto no host:**
  - `encryption_stream`: 40–113 s (mediana 71);
  - demais famílias: ≥ 222 s.
- **Consequência:** a precaução do U1 chega **depois** do impacto em ≈ **20 %** das unidades de
  `encryption_stream` e, em praticamente nenhuma, nas outras famílias.
- **Quanto custa perder a precaução:** na Fase 8, o B1 nunca sinaliza `encryption_stream` e perde
  ≈ 97 000 arquivos/host quando a precaução não acontece. Então Δ esperado ≈ 0,20 × 97 000 ≈
  **19 500** em `encryption_stream` e ≈ 0 nas outras, ou ≈ **4 900** agregado com peso igual por
  família, acima de M.
  - É uma estimativa grosseira e **bimodal**: em cada unidade o resultado é 0 ou ≈ 97 000. A fila de
    banda aumentaria o atraso, e os limiares por perfil em `h = 1` podem mudar a detecção.
- **Δ_loc esperado ≈ 0,** exceto em `campaign_multihost` via segmentação global e restauração (§2.1).

## 8. Ameaças, limitações e escopo da afirmação

1. **Localidade × agência:** resolvido pela inclusão do B2-SSL-local. A atribuição tem o alcance
   restrito da §2.1.
2. **Privesc e T1490 sem portão:** aceito sem portão novo (limitação). Todo evento desses tipos,
   mesmo benigno, gera precaução. O custo de falso positivo é o mesmo nos três braços.
3. **Malha aberta e dano idêntico entre perfis** (`01_especializacoes.md` §6): limitações
   declaradas.
4. **Métrica por host e prevenção lateral:** prevenir movimentos pode piorar `data_loss_per_host`
   (artefato F1). `data_loss` total é reportado como secundária.
5. **Desvio aprovado:** calibração com restrição de disponibilidade (§6).
6. **Escopo da afirmação.** Esta fase testa **especialização, localidade e coordenação**, não
   **adaptação em tempo de execução**: os limiares são fixos, calibrados offline, e a malha é aberta.
   **Nenhum resultado desta fase sustenta, sozinho, a afirmação de que o sistema é "adaptativo".**
