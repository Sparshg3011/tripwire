# AgentDojo defense screening

Status: **development evidence, not a publication headline**

The screen reused the frozen Direct and strict Tripwire development pilot and
made new calls only for AgentDojo's repeat-prompt, spotlighting, and ProtectAI
detector defenses. It used the same 12 development user tasks and 24 attack
pairs across four suites. None of the 85 frozen held-out user tasks were used.

## Result

| Condition | Attack success | Benign utility | Utility under attack | Trace errors |
|---|---:|---:|---:|---:|
| Direct | 62.5% (15/24) | 66.7% (8/12) | 37.5% (9/24) | 0 |
| Repeat user prompt | 45.8% (11/24) | 75.0% (9/12) | 33.3% (8/24) | 0 |
| Spotlighting with delimiters | 45.8% (11/24) | 66.7% (8/12) | 37.5% (9/24) | 0 |
| ProtectAI DeBERTa detector | 0.0% (0/24) | 33.3% (4/12) | 37.5% (9/24) | 0 |
| Strict Tripwire | 8.3% (2/24) | 41.7% (5/12) | 41.7% (10/24) | 0 |

Relative to Direct, the paired attack-success differences were -16.7 points
for both prompt defenses, -62.5 points for ProtectAI, and -54.2 points for
strict Tripwire. This sample is deliberately small and was already exposed
during development, so those estimates select the next experiment rather than
supporting final claims.

## Frozen advancement decision

- **Advance:** Direct, strict Tripwire, and ProtectAI. These were predeclared
  as the full-run anchors.
- **Do not advance:** repeat-user-prompt and spotlighting. Each reduced attack
  success by only 16.7 points, below the frozen 20-point threshold.
- **Defer:** CaMeL remains a separate system-level screen after its NVIDIA
  provider adapter is validated.

## Compute and reliability

The three new conditions completed in about 89 minutes. They used 1,132
successful target-model calls. The prompt defenses had no rate-limit retries.
ProtectAI had 122 recovered retries and 2,210 seconds of recorded backoff; no
retry became a scored trace error.

AgentDojo's stock ProtectAI implementation passes complete tool outputs to a
detector with a 512-token model context. One Workspace tool result was about
30,000 characters and was classified repeatedly during a long trajectory. The
screen retained the stock implementation for comparability, but this scaling
behavior must be included in the full-run time budget and reported as an
implementation limitation. A truncated or chunked variant would be a separate
ablation, not silently substituted for the official baseline.

Machine-readable receipts and the combined report are under
`gym/results/agentdojo-screening/`.
