# Changelog

Follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[semantic versioning](https://semver.org/).

**A breaking change to the policy schema is a major version bump.** A
policy that validates today keeps validating for the life of the major
version — you should never discover a schema change because your proxy
refused to start.

## [Unreleased]

### Fixed

- Include benchmark scenarios, policies, and frozen protocols in the wheel so
  installed benchmark commands work outside a repository checkout.
- Exercise the installed wheel on Python 3.11 through 3.14 before publishing,
  and run the same CI and dependency audit for tags as for pull requests.
- Preserve all five leave-one-out policy conditions across both approval
  brackets in the ablation runner.
- Run the gym scripts from a checkout whose path contains a space, and the
  held-out AgentDojo script under macOS's bash 3.2 without
  `ALLOW_TRANSPORT_RESUME=1`.
- Quote the paths in the aggregation command the leave-one-out ablation
  prints, so it can be pasted as shown.

### Added

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
