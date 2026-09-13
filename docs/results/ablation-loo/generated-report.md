# Publication benchmark summary

Attack success is lower-is-better. Utility columns are higher-is-better. Intervals are descriptive Wilson intervals; scenario-clustered paired effects should be used for the paper's hypothesis tests.

| model | condition | attack success | utility under attack | benign utility | gate prompts/run | errors |
|---|---|---|---|---|---:|---:|
| `scripted` | `plain/loo-no-actions/gate-approve` | 31.6% (12/38; 95% CI 19.1-47.5%) | 52.6% (20/38; 95% CI 37.3-67.5%) | 52.6% (20/38; 95% CI 37.3-67.5%) | 0.68 | 0 |
| `scripted` | `plain/loo-no-actions/gate-deny` | 2.6% (1/38; 95% CI 0.5-13.5%) | 7.9% (3/38; 95% CI 2.7-20.8%) | 7.9% (3/38; 95% CI 2.7-20.8%) | 0.71 | 0 |
| `scripted` | `plain/loo-no-constraints/gate-approve` | 73.7% (28/38; 95% CI 58.0-85.0%) | 81.6% (31/38; 95% CI 66.6-90.8%) | 81.6% (31/38; 95% CI 66.6-90.8%) | 1.01 | 0 |
| `scripted` | `plain/loo-no-constraints/gate-deny` | 2.6% (1/38; 95% CI 0.5-13.5%) | 15.8% (6/38; 95% CI 7.4-30.4%) | 15.8% (6/38; 95% CI 7.4-30.4%) | 1.01 | 0 |
| `scripted` | `plain/loo-no-flows/gate-approve` | 28.9% (11/38; 95% CI 17.0-44.8%) | 52.6% (20/38; 95% CI 37.3-67.5%) | 52.6% (20/38; 95% CI 37.3-67.5%) | 0.00 | 0 |
| `scripted` | `plain/loo-no-flows/gate-deny` | 28.9% (11/38; 95% CI 17.0-44.8%) | 52.6% (20/38; 95% CI 37.3-67.5%) | 52.6% (20/38; 95% CI 37.3-67.5%) | 0.00 | 0 |
| `scripted` | `plain/loo-no-limits/gate-approve` | 31.6% (12/38; 95% CI 19.1-47.5%) | 52.6% (20/38; 95% CI 37.3-67.5%) | 52.6% (20/38; 95% CI 37.3-67.5%) | 0.71 | 0 |
| `scripted` | `plain/loo-no-limits/gate-deny` | 0.0% (0/38; 95% CI 0.0-9.2%) | 7.9% (3/38; 95% CI 2.7-20.8%) | 7.9% (3/38; 95% CI 2.7-20.8%) | 0.71 | 0 |
| `scripted` | `plain/loo-no-sequences/gate-approve` | 28.9% (11/38; 95% CI 17.0-44.8%) | 52.6% (20/38; 95% CI 37.3-67.5%) | 52.6% (20/38; 95% CI 37.3-67.5%) | 0.68 | 0 |
| `scripted` | `plain/loo-no-sequences/gate-deny` | 0.0% (0/38; 95% CI 0.0-9.2%) | 7.9% (3/38; 95% CI 2.7-20.8%) | 7.9% (3/38; 95% CI 2.7-20.8%) | 0.71 | 0 |
| `scripted` | `plain/standard/gate-approve` | 28.9% (11/38; 95% CI 17.0-44.8%) | 52.6% (20/38; 95% CI 37.3-67.5%) | 52.6% (20/38; 95% CI 37.3-67.5%) | 0.68 | 0 |
| `scripted` | `plain/standard/gate-deny` | 0.0% (0/38; 95% CI 0.0-9.2%) | 7.9% (3/38; 95% CI 2.7-20.8%) | 7.9% (3/38; 95% CI 2.7-20.8%) | 0.71 | 0 |

## Run receipts

- `0e475752a890673f` — `effb26e594eea8befd89d4f00f32b88023f9f835` — corpus `9860ea2c4584b9725eefd07623257efc1bad4b10e9b992bd64be3a8f1f91d686`
- `eb5fcf534beb2a8b` — `effb26e594eea8befd89d4f00f32b88023f9f835` — corpus `9860ea2c4584b9725eefd07623257efc1bad4b10e9b992bd64be3a8f1f91d686`
- `309c2589123559ad` — `effb26e594eea8befd89d4f00f32b88023f9f835` — corpus `9860ea2c4584b9725eefd07623257efc1bad4b10e9b992bd64be3a8f1f91d686`
- `4b6ebba4932fad21` — `effb26e594eea8befd89d4f00f32b88023f9f835` — corpus `9860ea2c4584b9725eefd07623257efc1bad4b10e9b992bd64be3a8f1f91d686`
