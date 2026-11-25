# Fase 1 — piloto (EXPLORATORY)

> **EXPLORATORY.** 10 seeds de avaliação (200–209). Sem afirmação confirmatória, sem Holm, sem
> significância. Pré-registro congelado: `docs/fase1/02_preregistro.md`
> (`02_preregistro.freeze.json`: 2026-10-17T18:21:34Z, commit `1a12cd2`).

- **Comando:** `python3 simulation/fase1_experiments.py pilot`, depois `... analyze`.
- **Tamanho:** 160 jobs × 3 braços = 480 runs, 26 s.
- **Saídas brutas:** `pilot_rows.csv` (uma linha por campanha maliciosa × braço; NO-DEFENSE nas
  condições oráculo). Tabela: `pilot_table.csv`.
- **Limiares usados:** `config/fase1/thresholds_by_profile.yaml`, sha256 `b95552ff…c522ba`
  (calibração: `results/fase1_calibration/`).

## Métrica primária: `data_loss_per_host` (arquivos/host, 24 h; e = 0,50, r_inh = 0,43)

n = 45 campanhas por célula. Média e IC95 % por bootstrap (2 000 reamostragens, seed 0).
`unav` = `unavailability_fraction` média por run.

| h | condição | SN | U1 | B2-SSL-local | unav SN / U1 / B2L |
|---|---|---|---|---|---|
| 0 | oráculo | 0 [0, 0] | 0 [0, 0] | 0 [0, 0] | 0,775 / 0,721 / 0,349 |
| 0 | restrita | 0 [0, 0] | 10 [0, 30] | 0 [0, 0] | 0,775 / 0,721 / 0,349 |
| 1 | oráculo | 2 222 [0, 6 667] | 2 222 [0, 6 667] | 2 222 [0, 6 667] | 0,780 / 0,706 / 0,335 |
| 1 | restrita | 2 222 [0, 6 667] | 4 457 [0, 11 124] | 2 222 [0, 6 667] | 0,780 / 0,706 / 0,335 |

## Diferenças pareadas e veredito pelo critério congelado (§7)

| h | condição | comparação | média | IC95 % | pares ≠ 0 | Δunav (SN − outro) | veredito |
|---|---|---|---|---|---|---|---|
| 0 | oráculo | Δ = U1 − SN | 0 | [0, 0] | 0 | +0,054 | empate (**H0 passa**) |
| 1 | oráculo | Δ = U1 − SN | 0 | [0, 0] | 0 | +0,074 | empate (**H0 passa**) |
| 0 | restrita | Δ = U1 − SN | 10 | [0, 30] | 1 | +0,054 | empate |
| **1** | **restrita** | **Δ = U1 − SN (H1)** | **2 235** | **[0, 6 692]** | **2** | **+0,074** | **inconclusivo** |
| 0 | oráculo | Δ_loc = B2L − SN | 0 | [0, 0] | 1 (< 0,5 arquivo) | +0,426 | empate |
| 1 | oráculo | Δ_loc = B2L − SN | 0 | [0, 0] | 0 | +0,446 | empate |
| 0 | restrita | Δ_loc = B2L − SN | 0 | [0, 0] | 1 (< 0,5 arquivo) | +0,426 | empate |
| **1** | **restrita** | **Δ_loc = B2L − SN (H1-loc)** | **0** | **[0, 0]** | **0** | **+0,446** | **empate** |

### Leitura permitida pelo critério

- **H0 passou** nas duas condições oráculo. A pré-condição está satisfeita.
- **H1 é inconclusivo.** A média (2 235) supera M = 1 000, mas o limite inferior do IC é 0.
  - Toda a diferença vem de 2 de 45 pares:
    - `encryption_stream` seed 207: o U1 perde a precaução para o atraso de fronteira e o host é
      todo cifrado (100 000 arquivos/host);
    - `interleaved` seed 202: 566 arquivos.
  - Pela regra congelada, nenhuma afirmação é feita, e calcula-se o tamanho de amostra: σ(Δ) =
    14 905. Pela aproximação normal, n ≈ 171 campanhas por célula para o limite inferior ficar
    acima de 0, e n ≈ 349 para poder de 0,80.
  - A distribuição é bimodal (0 ou ≈ 100 000 por unidade), então a aproximação normal é grosseira.
- **Mesmo com perda favorável, o SN não "ganharia".** A regra exige Δunav ≤ +0,05, e o observado
  foi +0,074 contra o U1.
- **H1-loc é empate:** em nenhum par a camada hierárquica (restauração e segmentação global via
  Strategic) mudou a perda em relação ao B2-SSL-local.
- **Secundária, descritiva:** o SN é ≈ 0,45 mais indisponível que o B2-SSL-local. A causa é a
  segmentação global permanente emitida pelo Strategic (`cost_segment_network` ≈ 3,2 × 10⁶
  host-segundos ponderados por run, ausente no B2L), mais o `restrict_privileges` emitido pelo
  coordenador. É o mesmo mecanismo do achado P3 da Fase 8.
- **Comparação com a expectativa pré-registrada** (≈ 20 % das unidades de `encryption_stream`
  perdidas pelo U1): o observado foi 1 de 10 unidades, ou 10 %.

## Instrumentação do item 9 (média por run)

| h | condição | braço | decisões locais | ações preventivas que cobrem outro segmento | … com impacto em outro segmento | … chegando antes desse impacto | hosts benignos com ação (de 9) | mensagens que cruzam a fronteira |
|---|---|---|---|---|---|---|---|---|
| 0 | ambas | SN | 76,4 | 3,3 | 0,2 | 0,1 | 4,2 | 230,2 |
| 0 | ambas | U1 | 0 | 3,3 | 0,2 | 0,1 | 4,2 | 230,2 |
| 0 | ambas | B2L | 76,4 | 0 | 0 | 0 | 4,2 | 0 |
| 1 | ambas | SN | 116,2 | 37,1 | 0,5 | 0,3–0,4 | 3,1 | 446,1 |
| 1 | ambas | U1 | 0 | 37,1 | 0,5 | 0,3–0,4 | 3,1 | 446,1 |
| 1 | ambas | B2L | 116,2 | 0 | 0 | 0 | 3,1 | 0 |

- **Ações que cobrem outro segmento:** são todas `segment_network`, que é global. Nenhuma ação
  dirigida a outro segmento ocorreu, como previsto (§2.1).
- **Fronteira:** o SN e o U1 cruzam a fronteira o mesmo número de vezes e com os mesmos bytes, então
  a regra de fronteira foi aplicada por igual.
- **Falsos positivos:** idênticos nos três braços (mesma regra de precaução e mesmos limiares).

## Desvios em relação ao pré-registro (declarados)

1. **Calibração.** A restrição `unavailability_fraction ≤ 0,05` é **inviável**: todos os 27 pontos
   ficaram entre 0,69 e 0,75. O código caiu em "minimizar a perda e desempatar pela menor
   indisponibilidade". O limite não foi alterado. Escolhidos:
   - E1: entropia 7,8, corroboradores 3;
   - E2: entropia 7,8, severidade 9;
   - E3: `c2_min_beacons` 2, recon 1,0.
   - Ressalva: em E1/E2 a perda empatou entre vários pontos, e a escolha foi decidida pelo desempate.
2. **Valores de implementação não fixados no pré-registro** (todos suposição de modelagem, fixados
   antes de rodar o piloto):
   - gerador benigno genérico (`h = 0`) a 35 escritas/h;
   - beacons IoT benignos a 12/h, com 2 % para destino desconhecido;
   - exposição benigna de servidor: uma por host, exposta com p = 0,5 e corrigida com p = 0,7;
   - rajadas de leitura benignas no E1 a 1/h, com razão de sobrescrita U(0; 0,35). Essa faixa cruza o
     limiar de 0,3, e a tabela 2(b) dizia "sem sobrescrita".
   - As janelas de lote são ancoradas no primeiro evento observado do run.
3. **Teste de H0 adicional** nas seeds 0–4 (`tests/test_fase1.py`), além do H0 pré-registrado nas
   seeds de avaliação. Ambos passaram.
4. **Restrição de conteúdo pelo tempo** (B3), implementada pelo argumento do §4 do pré-registro
   (incidente = host, enlace FIFO por segmento) e verificada por teste, em vez de uma barreira
   temporal explícita no Knowledge.
