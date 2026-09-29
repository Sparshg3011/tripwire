# Recipe policies

One policy per benchmark suite, drafted by `tripwire recipe` from the
suite's tool listing alone, with no one choosing a rule per suite:
AgentDojo v1.2.2's banking, slack, travel and workspace, and AgentDyn's
github, shopping and dailylife.

| file | arm |
|---|---|
| `<suite>.yaml` | primary: every write and fetch gated after untrusted content, `unless: anchored` |
| `strict/<suite>.yaml` | the same with no write `self_scoped`, so a write naming nothing anchorable is gated too |
| `taint/<suite>.yaml` | the same without `unless: anchored`: every tainted write and fetch gated, the comparator for anchoring |

`tools/<suite>.json` is the listing each was drafted from: tool names and
input schemas, with every description and title taken out. The header of
each policy records the recipe version and the sha256 of its listing and
of the recipe's word tables.

Regenerate everything with:

```bash
./gym/make_recipe_policies.sh
```

It dumps AgentDojo's suites with `.venv/bin/python` and AgentDyn's with
`.venv-agentdyn/bin/python` (see `setup_external_benchmarks.sh`), then
drafts all three arms. Nothing in it reads a task, an injection or a
ground truth. `tests/test_recipe_policies.py` checks that drafting from
the committed listings gives back the committed policies byte for byte,
and, where a suite is installed, that dumping it gives back its listing.

A run uses them with `--recipe primary|strict|taint` in place of
`--policy`:

```bash
.venv/bin/python -m tripwire_benchmarks.agentdojo --suite banking \
  --condition tripwire-deny --recipe primary --model ... --out ...
```
