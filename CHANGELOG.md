# Changelog

Follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[semantic versioning](https://semver.org/).

**A breaking change to the policy schema is a major version bump.** A
policy that validates today keeps validating for the life of the major
version — you should never discover a schema change because your proxy
refused to start.

## [Unreleased]

### Changed

- **Breaking:** a policy that loaded before is now refused at startup if it
  gives a key twice in one mapping (a second `<<` merge key included), sets a
  NaN or infinite `min`, `max` or `sum_per_session` `max`, or uses the `u`
  flag, `(?u)` or `(?u:...)`, in a `regex`. Each let a policy mean something
  other than what it reads as.
- A value must match a policy regex both in ASCII mode and under Unicode
  rules. `\d`, `\s` and `\w` admit ASCII characters only, and ignoring case,
  by `case_insensitive: true` or an inline `(?i)`, admits ASCII case variants
  only, so `admın` no longer passes for `admin`. `\D`, `\S`, `\W` and `[^\s]`
  still refuse Unicode digits, whitespace and word characters.
- `case_insensitive` matches under `re.IGNORECASE` instead of casefolding the
  pattern and the value, so `\D` keeps its meaning and the value checked is
  the value forwarded.
- `max_length` is checked before `regex`, so an over-long value never reaches
  the pattern.
- NaN and ±Infinity fail `type: number`, `min`/`max` and `sum_per_session`,
  and are never added to a running total.
- With `unknown_tools: allow` or `require_approval`, a tool without an entry
  still goes through sequences and flows.
- Canonicalization rewrites only the arguments a tool's rule reads, its
  constraint keys, its `sum_per_session` field and its contract's authority
  arguments, and forwards the rest exactly as they arrived. `--tx-db` keys each call by the arguments it
  forwards, which in shadow mode are all of them as they arrived.
- `evaluate()` never raises: an error during evaluation is a block with rule
  id `evaluator_error`.
- A call that fails upstream taints the session whatever the tool's source
  class, since the agent is handed the exception's text.

### Fixed

- Include benchmark scenarios, policies, and frozen protocols in the wheel so
  installed benchmark commands work outside a repository checkout.
- Exercise the installed wheel on Python 3.11 through 3.14 before publishing,
  and run the same CI and dependency audit for tags as for pull requests.
- Preserve all five leave-one-out policy conditions across both approval
  brackets in the ablation runner.
- Keep `allowed_args` admitting what a removed mechanism read in the
  leave-one-out policies, and refuse to generate them from a policy file the
  proxy would refuse.
- Run the gym scripts from a checkout whose path contains a space, and the
  held-out AgentDojo script under macOS's bash 3.2 without
  `ALLOW_TRANSPORT_RESUME=1`.
- Quote the paths in the aggregation command the leave-one-out ablation
  prints, so it can be pasted as shown.

### Added

- Argument anchoring. A flow may say `unless: anchored`, and then skips a call
  whose every target, selector and credential value came from the user's task
  text, a `known` value, a trusted tool's field first seen there, or an id this
  session's own create call returned. Tool rules gain an argument contract
  (`args`), `destructive` and `self_scoped`; policies gain `known`. Content of
  an outward call may only link to vouched hosts, by URLs someone else wrote.
  Anchoring discharges only its own flow. Refusals it or a contract decides
  carry a code, a fixed explanation and a JSON object for the agent; the audit
  log gains `task`, `intent_rejected` and `provenance_observed` records and
  the decision's code and anchor report; `tripwire trace` and both approval
  gates say where each checked value came from; `tripwire validate` warns
  about a tool such a flow can never discharge. Task text reaches a session
  through the library's `Interceptor.add_task()`, or through a file
  `tripwire serve --task-file` (or `TRIPWIRE_TASK_FILE`) reads before each
  call.
- `allowed_args` on a tool rule: an argument neither listed there nor read by
  the rule (a constraint key or the `sum_per_session` field) blocks the call.
- `turns: session` on a sequence rule keeps it in force for the rest of the
  session, where a numeric window can be padded out with harmless calls.
- Python 3.14 support, with CI running the test suite on macOS as well.
- Experimental library-only exact pre-approvals: host-authorized full calls,
  one use, live-session binding, expiry, and revocation; no default-policy
  relaxation and no claim of improved AgentDojo utility yet.
- Reproducible paired benign-utility diagnosis, separating 40 regressions and
  one improvement from the net loss of 39 tasks.
- MCP proxy over stdio: tools are discovered upstream and re-advertised
  unchanged, so agents see the same toolbox
- Policy language v1: per-tool actions, argument constraints,
  per-session and summed budgets, sequence rules, information-flow rules
- Session taint tracking; untrusted tool results tighten what may follow
- Approval gates, terminal and localhost web, with a per-run token
- Transactional execution with an idempotency ledger
- Hash-chained audit log, `tripwire verify`
- Forensics: `tripwire trace` rebuilds a session as a causal chain,
  `tripwire report` summarises what a policy is doing
- `tripwire replay` re-judges recorded traffic under a candidate policy
- Shadow mode: full evaluation, zero blocking
- The gym: adversarial benchmark with a real agent, scripted toolboxes,
  benign twins, and the security/utility frontier chart. 38 attack
  scenarios across seven families, each with a twin, each verified to
  land undefended, plus an ablation isolating what each policy layer
  contributes.
- Frozen AgentDojo `v1.2.2` held-out evaluation with 844 paired attacks
  and 85 benign tasks per condition, clustered effect intervals,
  completeness and transport-resume receipts, and compact reproducibility
  artifacts.
- Completed full-minus-one scripted ablation: 912 runs across six policies
  and both approval brackets, with zero runner errors and compact evidence.

[Unreleased]: https://github.com/Sparshg3011/tripwire/commits/main
