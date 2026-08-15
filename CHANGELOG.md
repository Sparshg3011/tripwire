# Changelog

Follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[semantic versioning](https://semver.org/).

**A breaking change to the policy schema is a major version bump.** A
policy that validates today keeps validating for the life of the major
version — you should never discover a schema change because your proxy
refused to start.

## [Unreleased]

### Added

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

[Unreleased]: https://github.com/Sparshg3011/tripwire/commits/main
