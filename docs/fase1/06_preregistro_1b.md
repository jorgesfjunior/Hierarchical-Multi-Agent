# Fase 1b — 06. Pré-registro (EXPLORATORY)

Status: **CONGELADO.** Data e hora UTC e hash do commit estão em
`docs/fase1/06_preregistro_1b.freeze.json`. Aprovado com ajustes em 2026-10-17; os ajustes estão
aplicados. Desenho: `05_desenho_1b.md`. Fase 1: `02_preregistro.md` (congelado) e `04_relatorio.md`.
As referências [1]–[14] remetem a `01_especializacoes.md`, e [15]–[20] ao fim de
`05_desenho_1b.md`. "SM" = suposição de modelagem.

## 1. Hipóteses

- **H1b (principal).** Na família `campaign_e1_e2`, com `h = 1` e restrição de fronteira, o SN
  contém antes do impacto uma proporção maior de campanhas que o B2-SSL-local:
  Δp_loc = p(SN) − p(B2L) > 0.
  - O mecanismo testado é a **coordenação entre segmentos** (aviso → precaução no segmento avisado),
    que o B2-SSL-local não pode executar entre segmentos.
- **H1b-U1.** SN × U1, Δp = p(SN) − p(U1), agregando as 5 famílias, com `h = 1` e restrição.
  - **Expectativa declarada:** **empate** dentro da margem. O SN e o U1 executam o mesmo mecanismo
    de coordenação e pagam a mesma fronteira. A única vantagem do SN é a localidade, que na Fase 1
    afetou ≈ 4 % das campanhas (2 de 45), menos que a margem Mp.
  - Em `campaign_e1_e2`, SN ≈ U1 é esperado, porque o aviso chega ao alvo em 20–80 s mais fila, e o
    impacto ocorre 600–1 800 s depois.
- **H0 (mantido, sanidade).** Com o oráculo, SN ≈ U1 em `h = 0` e em `h = 1`, nas 5 famílias.
  - **Tolerância:** IC95 % de Δp dentro de ±0,05 **e** IC95 % de Δ`data_loss_per_host` dentro de
    ±1 000 (margem da Fase 1).
  - Se H0 falhar, o piloto para e a causa é reportada. Nada é ajustado.
- **Controle negativo (C0).** Em `campaign_e1_e2` com `h = 0`, o tipo `lateral_movement_signature` é
  inativo, então não há vínculo nem aviso, e SN ≈ B2L é esperado.
  - Se o SN "ganhar" em C0, há um vazamento de mecanismo, e H1b não é interpretado.
- **Regressão (R).** Com todos os knobs da 1b no padrão, o código reproduz exatamente a regressão da
  Fase 8 e o piloto da Fase 1. Para isso, uma fixture nova congela `results/fase1_pilot/pilot_rows.csv`.

## 2. Braços

Os três braços usam `config/fase1/thresholds_by_profile.yaml` (o mesmo arquivo da Fase 1,
sha256 `b95552ff…c522ba`, sem recalibração), o mesmo mapa de perfis, a mesma precaução (regra SSL) e
o mesmo playbook.

| Braço | Base (Fase 1) | Knobs da 1b ligados |
|---|---|---|
| **SN** | SN | `coordinator_precaution = "none"`; `segment_network_scope = "incident_segments"`, `segment_network_release = "containment"` (teto de 3 600 s); `campaign_links = True` (aviso especialista → coordenador → especialista) |
| **U1** | B1-SSL atrás da fronteira | `segment_network_scope` e `segment_network_release` iguais aos do SN; `campaign_links = True` (o central forma o vínculo e despacha a precaução para o host avisado) |
| **B2-SSL-local** | uma instância B2-SSL por segmento | `campaign_links = True` **só dentro do segmento**: a instância vê os dois hosts e não se comunica com as demais. Sem autoridade global, como na Fase 1. |

## 3. Condições e famílias

- **Condições:** `h ∈ {0, 1}` × {oráculo, restrita}, com os **mesmos valores congelados da
  Fase 1** (lote de 60 s, 10 s, 32 KiB/s [13]; oráculo = custo zero). Custos internos: local 0,001 s
  e serviço 0,01 s.
- **Famílias:** as quatro da Fase 1 (`encryption_stream`, `campaign_multihost`,
  `split_visibility_late_confirm`, `interleaved`) **mais** `campaign_e1_e2` (`05_desenho_1b.md` A3).
- **Fundo benigno:** o da Fase 1 (3 hosts por perfil), mais **conexões administrativas benignas**
  com `peer_hosts`, para que o aviso tenha um custo de falso positivo.
  - Com `h = 1`, cada host E1 benigno emite `lateral_movement_signature` a 0,2/h (SM), com 1–2 pares
    sorteados entre os servidores benignos, a partir do stream `"benign"`.
  - Se esse host E1 já tiver um sinal de precaução (por exemplo, runas), o vínculo gera um **aviso
    falso** e o isolamento de um servidor benigno.
- **Parâmetros da família `campaign_e1_e2`** (SM):
  - p_pre = 0,5 (direção p_pre < 1: [16]);
  - movimento em U(60, 600) s após o acesso inicial;
  - impacto em U(600, 1 800) s após o movimento;
  - `lateral_movement_signature` emitido pelo sensor de host da estação de origem U(1, 5) s após o
    movimento [19];
  - o logon no servidor é indistinguível de um logon administrativo legítimo [17] e não produz
    sinal.
- **Suposição:** o registro de conexões de rede está habilitado no sensor da estação. No Sysmon, o
  Event ID 3 vem desligado por padrão [19].

## 4. Métrica

**Primária: proporção de campanhas maliciosas contidas antes do impacto,** p = média de
`1 − impact_started`.
- `impact_started` é um campo **existente** de `AttackOutcome` (`simulation/damage_model.py`): o
  atacante detonou a cifragem em algum host da campanha antes do horizonte. A linha de saída passa a
  incluí-lo. Nenhuma métrica nova é criada.
- **Por quê:** o resultado da Fase 1 é bimodal (0 ou ≈ 100 000 arquivos por host). A proporção mede
  diretamente o evento que gera a bimodalidade e tem poder calculável.

**Restrição:** a média de `unavailability_fraction`(SN) − (comparador) ≤ 0,05 (margem de P3, mantida
da Fase 1).

**Secundárias** (já calculadas):
- `data_loss_per_host` (margem M = 1 000) e `data_loss`;
- `files_encrypted`, `hosts_compromised`, `prevented_moves`;
- antecedência (`first_prevention_s_*`, `lead_time_s_*`);
- componentes de indisponibilidade (`cost_*`);
- `fp_benign_hosts` e a comunicação (`crossings_boundary`, `crossing_bytes_boundary`).

## 5. Tamanho de amostra

Aproximação normal, α = 0,05 bilateral, poder de 0,80.

- **H1b:**
  - **Valor esperado por desenho:** p(B2L) ≈ p_pre = 0,5, porque o servidor só é protegido quando
    tem precursor local, e p(SN) ≈ 1,0.
  - **Diferença usada no cálculo:** **δ = 0,20** (0,50 → 0,70), que é **40 % da diferença esperada**
    (0,5). Assim o estudo continua com poder se o aviso falhar numa fração grande das unidades, por
    fila de banda, flag local precoce ou falha do vínculo. δ também é o dobro da margem Mp = 0,10 da
    §7.
  - **Resultado:** n = **93** campanhas por braço sem pareamento. Pareado (McNemar, discordância de
    0,20), n = 37.
- **H1b-U1:** para detectar a diferença de localidade observada na Fase 1 (4,4 pontos, 0,956 → 1,0),
  n = **186** sem pareamento e 177 com McNemar.
- **Escolha: 200 seeds por família.** `campaign_e1_e2` tem 1 campanha por seed. H1b-U1 agrega ≈ 1 100
  campanhas.
- **Seeds de avaliação: 1000–1199.** São novas e disjuntas de todas as anteriores:
  - 0–4 (Fase 8 e teste de H0);
  - 0–99 (análise de estrutura de cenário);
  - 100–119 (calibração);
  - 200–209 (piloto da Fase 1);
  - 300–399 (diagnóstico desta etapa).
- **Custo:** 5 famílias × 200 seeds × 4 condições × 3 braços = 12 000 runs, ≈ 0,5 s cada, ≈ 10 min
  com 10 núcleos. São executadas em comandos de ≤ 5 min (uma condição por comando).

### 5.1 Varredura de p_pre (DESCRITIVA, sem critério de decisão)

- **Escopo:** só `campaign_e1_e2`, com `h = 1` e restrição, nos três braços.
- **Níveis:** p_pre ∈ {0,2; 0,5; 0,8}, cada um com **200 seeds novas e disjuntas**:
  - p_pre = 0,2: seeds 2000–2199;
  - p_pre = 0,5: seeds 3000–3199;
  - p_pre = 0,8: seeds 4000–4199.
- **O valor congelado de H1b continua p_pre = 0,5** nas seeds 1000–1199. A varredura não entra em
  nenhum critério.
- **Reporta-se** Δp_loc por nível, com IC95 %.
- **Expectativa declarada:** Δp_loc ≈ 1 − p_pre (0,8; 0,5; 0,2). O B2L só protege o servidor quando
  há precursor local, e o SN protege também pelo aviso.

## 6. Instrumentação de mecanismo (por run)

1. **Decisões locais** por especialista ou instância (`action_dispatched` em nós locais): como na
   Fase 1.
2. **Avisos:**
   - número total;
   - quantos cruzaram a fronteira e quantos foram locais;
   - latência do aviso até a ação no host avisado;
   - avisos falsos (destino benigno).
3. **Ação preventiva no segmento avisado:** se chegou **antes ou depois** do primeiro impacto no host
   avisado.
4. **Segmentação com escopo:** disparos, segmentos cobertos, duração até a liberação e custo de
   indisponibilidade.
5. **Componentes de indisponibilidade** por ação (`cost_*`) e `fp_benign_hosts`.
6. **Contadores da Fase 1:** ações preventivas que cobrem outro segmento e se chegaram antes do
   impacto.

## 7. Critério de decisão (EXPLORATORY)

- **Unidade:** campanha maliciosa, pareada entre braços por (família, seed, campanha).
- **IC95 %:** bootstrap pareado (`analysis/stats.py:91`, 2 000 reamostragens, seed 0).
- **Margem:** **Mp = 0,10** (10 pontos percentuais de campanhas). É metade da diferença usada no
  cálculo de n.
- **Pré-condições:** R passou; H0 passou; C0 não mostra "SN ganhou".

| Resultado, para Δp_loc (H1b) e Δp (H1b-U1) | Regra |
|---|---|
| **SN ganhou** | Δp ≥ Mp, limite inferior do IC > 0, e média de Δunav (SN − comparador) ≤ 0,05 |
| **Empate** | IC95 % inteiro em [−Mp, +Mp] |
| **Comparador ganhou** | Δp ≤ −Mp e limite superior do IC < 0 |
| **Inconclusivo** | nenhum dos casos acima |

| H1b (SN × B2L) | H1b-U1 (SN × U1) | Leitura para o artigo |
|---|---|---|
| SN ganhou | empate | **Coordenação entre segmentos** tem valor mensurável (na família construída), e o U1, que vê tudo, a obtém igualmente. A arquitetura distribuída com coordenação reproduz o que o central faz, com a localidade como bônus. |
| SN ganhou | SN ganhou | Coordenação **e** localidade. A parte de localidade deve ser lida com a ressalva da Fase 1 (eventos raros). |
| empate | qualquer | O mecanismo de aviso não muda a contenção nem na família em que deveria. Isso se reporta como achado negativo: com regras determinísticas, o SN não supera uma regra local isolada. |
| B2L ganhou | qualquer | O custo dos avisos (atraso ou falsos) supera o ganho. Achado negativo. |
| inconclusivo | qualquer | Nenhuma afirmação; registra-se o σ observado. |

**Congelamento.** Ficam congelados com este pré-registro, e é **proibido ajustá-los depois de ver
resultados**:
- os parâmetros de fronteira (os da Fase 1);
- Mp, M e a restrição de indisponibilidade;
- este critério e as seeds;
- as famílias e os parâmetros SM da `campaign_e1_e2` e do fundo benigno;
- o teto de 3 600 s.

Qualquer mudança posterior é um desvio declarado, com data.

**Expectativa declarada antes de rodar:**
- **H1b:** Δp_loc ≈ +0,5 em `campaign_e1_e2`, `h = 1`, restrita e também oráculo.
- **Δunav (SN − B2L):** ≤ ≈ 0,02 (segmentação com escopo) mais o custo dos avisos falsos, cada um
  ≈ 0,01 (um servidor isolado por 24 h). Pode ficar **perto do limite de 0,05**. Isso é um risco,
  declarado agora.
- **H1b-U1:** empate.
- **C0:** empate.

## 8. Ameaças e limitações

1. **Família construída.** `campaign_e1_e2` é desenhada para que a coordenação importe. Um resultado
   positivo mostra que **o mecanismo é capaz**, não que ele é **frequente**.
   - Só a direção de p_pre < 1 tem referência [16]; o valor 0,5 é SM.
   - A varredura (§5.1) mostra como o efeito depende desse valor.
2. **Pressupostos de observação:**
   - o vínculo depende de o sensor de host da estação registrar a conexão e nomear o destino
     (`peer_hosts`) [19], com o registro de conexões habilitado (suposição; desligado por padrão no
     Sysmon);
   - a regra de vínculo por grafo de logins segue [18];
   - o logon com conta válida não produz sinal porque é indistinguível de um logon legítimo [17];
   - o atraso de segundos do sensor é SM.
3. **Custo dos avisos possivelmente subestimado.** Isolar um servidor por aviso tem custo de
   disponibilidade de um host. O modelo não pondera a criticidade do servidor (dano e peso idênticos
   entre perfis, limitação da Fase 1).
4. **O braço SN mudou em relação à Fase 1** (precaução do coordenador e segmentação com escopo). Os
   resultados da Fase 1 continuam válidos **para o desenho da Fase 1**. A 1b não os reinterpreta.
5. **`restrict_privileges` com flag em hosts benignos** (≈ 0,28) continua igual nos três braços:
   pesa no total, não nas diferenças.
6. **Malha aberta, limiares fixos calibrados offline e regras determinísticas.** Esta fase testa
   **coordenação e localidade**, não adaptação. **Nenhum resultado sustenta, sozinho, a afirmação
   de que o sistema é "adaptativo".**
7. **Análise exploratória:** sem Holm e sem afirmação de significância. Os n foram calculados para o
   poder, mas o rótulo continua EXPLORATORY.
8. **Compressão temporal.**
   - **O problema:** o tempo de permanência real do ransomware é de **dias** (mediana de 4 dias em
     casos de resposta a incidentes e de 3 dias em MDR [20]). O horizonte do modelo é de 24 h, e a
     linha do tempo de `campaign_e1_e2` foi comprimida (impacto 600–1 800 s após o movimento).
   - **Por que isso não cria a vantagem do SN sobre o B2L:**
     - o B2L não depende do tempo. Sem comunicação, ele não tem como avisar o segmento do servidor;
       protege o servidor só quando há precursor local, com ou sem compressão;
     - o SN e o U1 alcançam o alvo pelo aviso em ≈ 20–80 s mais fila, bem antes do impacto já na
       linha comprimida. Com dias de permanência, a folga seria ainda maior.
     - A compressão, portanto, não cria a vantagem SN × B2L.
   - **Por que isso não favorece o SN contra o U1:** os dois pagam a mesma fronteira, e ambos
     chegam antes do impacto. Encurtar a permanência só aproximaria o impacto do atraso do U1, o
     que favoreceria o SN apenas por localidade, efeito já medido e separado (H1b-U1). A linha
     comprimida mantém a folga ≥ 600 s ≫ 80 s.
9. **Lacunas de referência:** resolvidas com [15]–[20] (tabela no fim de `05_desenho_1b.md`). O
   valor de p_pre e os atrasos de sensor continuam SM.
