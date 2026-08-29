# External benchmark summary

Lower attack success is better; higher utility is better. Wilson intervals are descriptive. Overall effect intervals use a predeclared two-way cluster bootstrap over user and injection tasks; benign-utility intervals cluster over user tasks. Exact McNemar tests are descriptive.

## Overall

| model | suite | condition | attack success | utility under attack | benign utility | valid-goal ASR | attack intervention | benign intervention | errors |
|---|---|---|---|---|---|---|---|---|---:|
| `nvidia/nemotron-3-super-120b-a12b` | `ALL` | `direct` | 30.7% (259/844; 95% CI 27.7-33.9%) | 63.7% (538/844; 95% CI 60.4-66.9%) | 82.4% (70/85; 95% CI 72.9-89.0%) | 43.5% (236/542; 95% CI 39.4-47.7%) | 0.0% (0/844; 95% CI 0.0-0.5%) | 0.0% (0/85; 95% CI 0.0-4.3%) | 0 |
| `nvidia/nemotron-3-super-120b-a12b` | `ALL` | `tripwire-deny` | 4.0% (34/844; 95% CI 2.9-5.6%) | 31.8% (268/844; 95% CI 28.7-35.0%) | 36.5% (31/85; 95% CI 27.0-47.1%) | 6.3% (34/542; 95% CI 4.5-8.6%) | 64.8% (547/844; 95% CI 61.5-68.0%) | 47.1% (40/85; 95% CI 36.8-57.6%) | 0 |

### Overall paired effects against direct

- `tripwire-deny`: ASR -26.7 points over 844 pairs (95% crossed-cluster CI -33.6 to -19.8 points); direct-only breaches 229, defended-only breaches 4; descriptive exact McNemar p=0.0000. Benign utility -45.9 points (95% user-cluster CI -56.5 to -35.3).

## Per-suite results

| model | suite | condition | attack success | utility under attack | benign utility | valid-goal ASR | attack intervention | benign intervention | errors |
|---|---|---|---|---|---|---|---|---|---:|
| `nvidia/nemotron-3-super-120b-a12b` | `banking` | `direct` | 60.7% (71/117; 95% CI 51.6-69.1%) | 62.4% (73/117; 95% CI 53.4-70.6%) | 69.2% (9/13; 95% CI 42.4-87.3%) | 67.0% (61/91; 95% CI 56.9-75.8%) | 0.0% (0/117; 95% CI 0.0-3.2%) | 0.0% (0/13; 95% CI 0.0-22.8%) | 0 |
| `nvidia/nemotron-3-super-120b-a12b` | `banking` | `tripwire-deny` | 0.0% (0/117; 95% CI 0.0-3.2%) | 33.3% (39/117; 95% CI 25.4-42.3%) | 38.5% (5/13; 95% CI 17.7-64.5%) | 0.0% (0/91; 95% CI 0.0-4.1%) | 76.1% (89/117; 95% CI 67.6-82.9%) | 30.8% (4/13; 95% CI 12.7-57.6%) | 0 |
| `nvidia/nemotron-3-super-120b-a12b` | `slack` | `direct` | 85.6% (77/90; 95% CI 76.8-91.4%) | 65.6% (59/90; 95% CI 55.3-74.6%) | 100.0% (18/18; 95% CI 82.4-100.0%) | 85.6% (77/90; 95% CI 76.8-91.4%) | 0.0% (0/90; 95% CI 0.0-4.1%) | 0.0% (0/18; 95% CI 0.0-17.6%) | 0 |
| `nvidia/nemotron-3-super-120b-a12b` | `slack` | `tripwire-deny` | 32.2% (29/90; 95% CI 23.5-42.4%) | 7.8% (7/90; 95% CI 3.8-15.2%) | 22.2% (4/18; 95% CI 9.0-45.2%) | 32.2% (29/90; 95% CI 23.5-42.4%) | 85.6% (77/90; 95% CI 76.8-91.4%) | 77.8% (14/18; 95% CI 54.8-91.0%) | 0 |
| `nvidia/nemotron-3-super-120b-a12b` | `travel` | `direct` | 59.7% (71/119; 95% CI 50.7-68.0%) | 33.6% (40/119; 95% CI 25.8-42.5%) | 70.6% (12/17; 95% CI 46.9-86.7%) | 57.8% (59/102; 95% CI 48.1-67.0%) | 0.0% (0/119; 95% CI 0.0-3.1%) | 0.0% (0/17; 95% CI 0.0-18.4%) | 0 |
| `nvidia/nemotron-3-super-120b-a12b` | `travel` | `tripwire-deny` | 4.2% (5/119; 95% CI 1.8-9.5%) | 38.7% (46/119; 95% CI 30.4-47.6%) | 47.1% (8/17; 95% CI 26.2-69.0%) | 4.9% (5/102; 95% CI 2.1-11.0%) | 75.6% (90/119; 95% CI 67.2-82.5%) | 29.4% (5/17; 95% CI 13.3-53.1%) | 0 |
| `nvidia/nemotron-3-super-120b-a12b` | `workspace` | `direct` | 7.7% (40/518; 95% CI 5.7-10.3%) | 70.7% (366/518; 95% CI 66.6-74.4%) | 83.8% (31/37; 95% CI 68.9-92.3%) | 15.1% (39/259; 95% CI 11.2-19.9%) | 0.0% (0/518; 95% CI 0.0-0.7%) | 0.0% (0/37; 95% CI 0.0-9.4%) | 0 |
| `nvidia/nemotron-3-super-120b-a12b` | `workspace` | `tripwire-deny` | 0.0% (0/518; 95% CI 0.0-0.7%) | 34.0% (176/518; 95% CI 30.0-38.2%) | 37.8% (14/37; 95% CI 24.1-53.9%) | 0.0% (0/259; 95% CI 0.0-1.5%) | 56.2% (291/518; 95% CI 51.9-60.4%) | 45.9% (17/37; 95% CI 31.0-61.6%) | 0 |

### Per-suite paired effects against direct

- `banking` / `tripwire-deny`: ASR -60.7 points over 117 pairs; direct-only breaches 71, defended-only breaches 0; exact McNemar p=0.0000.
- `slack` / `tripwire-deny`: ASR -53.3 points over 90 pairs; direct-only breaches 48, defended-only breaches 0; exact McNemar p=0.0000.
- `travel` / `tripwire-deny`: ASR -55.5 points over 119 pairs; direct-only breaches 70, defended-only breaches 4; exact McNemar p=0.0000.
- `workspace` / `tripwire-deny`: ASR -7.7 points over 518 pairs; direct-only breaches 40, defended-only breaches 0; exact McNemar p=0.0000.
