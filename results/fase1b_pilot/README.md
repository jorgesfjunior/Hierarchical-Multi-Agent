# Fase 1b — piloto (EXPLORATORY)

> **EXPLORATORY.** Sem Holm e sem afirmação de significância. Pré-registro congelado:
> `docs/fase1/06_preregistro_1b.md` (`06_preregistro_1b.freeze.json`: 2026-10-17T19:52:23Z, commit
> `5d6d300`). Desenho: `docs/fase1/05_desenho_1b.md`.

- **Comandos:**
  - `python3 simulation/fase1b_experiments.py pilot --cell <h>:<condição>` (4 células);
  - `... sweep`;
  - `... analyze`.
- **Tamanho:** 5 famílias × 200 seeds (1000–1199) × 4 condições × 3 braços = 12 000 runs. A varredura
  soma 3 × 200 seeds × 3 braços.
- **Saídas:** `pilot_rows_h{0,1}_{oracle,restricted}.csv`, `sweep_rows.csv` e `pilot_table.csv`.
- **Limiares:** os mesmos da Fase 1 (`config/fase1/thresholds_by_profile.yaml`, sha256 `b95552ff…c522ba`).

## Pré-condições

| Teste | Resultado | Veredito |
|---|---|---|
| **R:** regressão da Fase 8 (34 unidades) + 16 unidades do piloto da Fase 1, com os knobs da 1b no padrão | idênticas byte a byte | **passa** |
| **H0:** oráculo, SN × U1, 5 famílias, h = 0 | Δp = 0 [0, 0]; Δperda = 0 [0, 0] (n = 1 094) | **passa** |
| **H0:** oráculo, SN × U1, 5 famílias, h = 1 | Δp = 0 [0, 0]; Δperda = 0 [0, 0] (n = 1 094) | **passa** |
| **C0:** `campaign_e1_e2`, h = 0, restrita, SN × B2L | Δp_loc = 0 [0, 0], 0 pares discordantes | empate (**passa**: nenhum vazamento de mecanismo) |

## Métrica primária: proporção de campanhas contidas antes do impacto

| Teste (h = 1, restrita) | n | p(SN) | p(outro) | Δp | IC95 % | discordantes | Δunav (SN − outro) | Veredito |
|---|---|---|---|---|---|---|---|---|
| **H1b:** `campaign_e1_e2`, SN × B2L | 200 | 0,755 | 0,635 | **+0,120** | **[0,080; 0,170]** | 24 | +0,006 | **SN ganhou** |
| **H1b-U1:** 5 famílias, SN × U1 | 1 094 | 0,942 | 0,921 | **+0,021** | **[0,013; 0,029]** | 23 | +0,0002 | **empate** |

**Leitura pela tabela congelada (SN ganhou × empate).** A coordenação entre segmentos tem valor
mensurável na família construída, e o U1, que vê tudo, a obtém igualmente. A arquitetura distribuída
com coordenação reproduz o que o central faz, com a localidade como bônus. A ressalva da §8.1 do
pré-registro vale integralmente: o resultado mostra que **o mecanismo é capaz**, não que ele é
**frequente**.

## Descritivo e secundárias (sem critério)

| Comparação | Δ | IC95 % | Nota |
|---|---|---|---|
| H1b no oráculo (h = 1) | +0,120 | [0,080; 0,170] | Idêntico ao restrito: o ganho é de coordenação, não de localidade. |
| SN × U1 só em `campaign_e1_e2` (restrita) | +0,035 | [0,010; 0,065] | 7 discordantes: o precursor T1490 chega 5–60 s antes do impacto, e o U1 o recebe tarde (localidade). |
| Perda/host, SN × B2L, `campaign_e1_e2` | 4 333 | [2 179; 6 846] | Secundária. |
| Perda/host, SN × U1, 5 famílias | 1 088 | [532; 1 715] | Secundária: localidade. |
| SN × B2L nas 4 famílias da Fase 1 (h = 1, restrita) | 0 | [0, 0] | Nessas famílias a coordenação não tem papel (`05_desenho_1b.md` A3). |

**Varredura de p_pre** (descritiva; `campaign_e1_e2`, h = 1, restrita; 200 seeds novas por nível):

| p_pre | seeds | p(SN) | p(B2L) | Δp_loc | IC95 % | Expectativa declarada (1 − p_pre) |
|---|---|---|---|---|---|---|
| 0,2 | 2000–2199 | 0,735 | 0,525 | +0,210 | [0,155; 0,265] | 0,8 |
| 0,5 | 3000–3199 | 0,740 | 0,585 | +0,155 | [0,105; 0,205] | 0,5 |
| 0,8 | 4000–4199 | 0,730 | 0,680 | +0,050 | [0,020; 0,085] | 0,2 |

A direção é a esperada: o ganho cai com p_pre. A magnitude fica em ≈ 0,26–0,31 × (1 − p_pre), não em
1 − p_pre. A causa está na seção seguinte.

## Mecanismo, e por que Δp_loc ficou abaixo de +0,5

Decomposição das 200 unidades de H1b (o precursor sai do gerador; nenhum braço foi rodado de novo):

| Precursor no servidor | SN | B2L | U1 | Unidades |
|---|---|---|---|---|
| sim | contém | contém | contém | 73 |
| sim | contém | contém | **falha** | 3 (localidade) |
| sim | falha | falha | falha | 24 |
| não | contém | **falha** | contém | **24 (coordenação)** |
| não | contém | contém | falha | 4 (localidade) |
| não | contém | contém | contém | 47 |
| não | falha | falha | falha | 25 |

1. **O aviso funcionou em todas as unidades.** Os 200 avisos do SN (e os 200 do U1) em
   `campaign_e1_e2` chegaram ao servidor **antes** do impacto, com latência média de 51 s na condição
   restrita e ≈ 0 no oráculo. O B2L não emitiu nenhum aviso entre segmentos.
2. **Por que ainda há 49 falhas do SN (todas com o servidor isolado a tempo).** No modelo de dano, o
   impacto da campanha faz **todo ponto de apoio ainda ativo** começar a cifrar
   (`simulation/damage_model.py`, "Impact").
   - A estação E1 continua ativa quando o único sinal dela é o recon: o playbook de T1018 bloqueia o
     segmento, mas não isola o host.
   - Isso ocorre quando o evento de movimento tem menos de 3 pares novos (≈ 50 %) e por isso não gera
     o sinal de T1021, que isola.
   - Nesses casos, os três braços falham juntos.
3. **Por que o B2L contém em 47 unidades sem precursor.** Falsos positivos de cifragem em servidores
   benignos de backup disparam `block_network_segment` com flag no segmento E2 **antes** do movimento.
   O modelo então impede o movimento em todos os braços.
4. **As três semânticas são do modelo existente e idênticas nos braços.** Elas diluem a diferença
   sem enviesá-la. Nada foi ajustado.

## Indisponibilidade (média por run; h = 1, restrita)

| Componente | SN | U1 | B2L | Fase 1 (SN / U1 / B2L) |
|---|---|---|---|---|
| **total** | **0,295** | **0,294** | **0,291** | 0,780 / 0,706 / 0,335 |
| `segment_network` (com escopo e prazo) | 0,0017 | 0,0017 | 0 | 0,372 / 0,372 / 0 |
| `restrict_privileges` | 0,235 | 0,235 | 0,235 | 0,350 / 0,276 / 0,276 |
| isolamento | 0,039 | 0,039 | 0,038 | 0,040 / 0,040 / 0,040 |

- **As correções A1 eliminaram as duas fontes de excesso.**
  - SN − U1: de +0,074 para +0,0002.
  - SN − B2L: de +0,446 para +0,006.
- **Segmentação com escopo:** ≈ 9,3 intervalos por run, cada um durando em média ≈ 170 s até a
  liberação na contenção.
- **O que sobra** de `restrict_privileges` (≈ 0,235, sobretudo com flag em hosts benignos) é igual
  nos três braços. É uma limitação já declarada.

## Avisos (h = 1, restrita; média por run nas 5 famílias)

| | SN | U1 | B2L |
|---|---|---|---|
| Avisos | 0,46 | 0,46 | 0 |
| … que cruzaram a fronteira | 0,46 | 0,46 | 0 |
| … falsos (servidor benigno avisado após uma conexão administrativa de uma estação com precaução) | 0,26 (56 %) | 0,26 | 0 |
| Decisões locais | 89,9 | 0 | 89,4 |

O custo dos avisos falsos está incluído na indisponibilidade acima.

## Desvios e notas (declarados)

1. **A expectativa de Δp_loc ≈ +0,5 não se confirmou (+0,12).** A causa, explicada acima, são
   semânticas pré-existentes do modelo de dano, iguais nos braços: a detonação em todo ponto de apoio
   ativo, o recon que não isola e os bloqueios de segmento por falso positivo. Nenhum parâmetro foi
   alterado. A regra congelada foi aplicada como estava.
2. **Uma célula passou do limite de 5 min por comando** (regra de trabalho da Fase 8): a oráculo
   `h = 1` levou 326 s. As outras células e a varredura ficaram entre 71 e 252 s.
3. **Valores de implementação não fixados no pré-registro** (SM):
   - mensagem de aviso de 256 bytes, contada como 2 travessias da fronteira (subida e descida);
   - o atraso do aviso inclui o serviço do coordenador e o do especialista avisado;
   - a liberação da segmentação usa a chegada de `isolate_host` ou `kill_process` de qualquer nó.
4. **R cobre 16 das 160 unidades do piloto da Fase 1** (seed 200 de cada família × h × condição),
   além das 34 unidades da Fase 8.
5. **Os testes usam as seeds de diagnóstico 300–305**, fora da avaliação e da varredura.
