# Releasing tripwire-agent

The distribution is `tripwire-agent`; the command is `tripwire`. Version 0.1.0
is the first alpha release. The firewall's enforcement guarantees are scoped
to MCP tool calls, as described in [THREAT_MODEL.md](../THREAT_MODEL.md).
The AgentDojo result includes a material benign-utility penalty and does not
establish production readiness.

## Evidence for the first release

[EVIDENCE.md](../EVIDENCE.md) carries what the release claims: the held-out
AgentDojo result with its utility cost beside it, the complete ProtectAI
comparison on the same pairs, and the scripted full-minus-one ablation as
mechanism evidence only, with both approval bounds and no claim that the
scripted agent measures human or model utility. AgentDyn, AutoDojo and broader
model replications are follow-up research, not results of this release.

In this release and every later one, numbers quoted in the README come from
complete runs only.

## Verify the distribution

```bash
python -m pip install build twine
python -m build
python -m twine check --strict dist/*
python scripts/check_distribution.py
python -m venv /tmp/tripwire-installed
/tmp/tripwire-installed/bin/pip install dist/*.whl
(cd /tmp && /tmp/tripwire-installed/bin/python "$OLDPWD/scripts/smoke_installed.py")
```

The smoke check runs from outside the checkout, so nothing in it can stand in
for a file the wheel is missing. It validates the bundled policies and corpus,
checks `tripwire --version`, runs `tripwire demo`, and runs the scripted gym on
the defended and undefended exfiltration case plus its benign twin. No
optional model packages or credentials are needed.

CI runs this check on Python 3.11–3.14, once with the newest mcp and once with
the oldest one `pyproject.toml` accepts, as well as the unit and integration
tests, static checks, external adapter tests, and dependency audit.

Pushing a `v*` tag runs `.github/workflows/release.yml`. It reruns all of CI,
builds the sdist and wheel once, runs the smoke check on that wheel on each
supported Python, uploads those same files to PyPI, and attaches them to a
GitHub release.

If `tripwire demo` prints something new, re-record `docs/img/demo.gif` with
[VHS](https://github.com/charmbracelet/vhs): `vhs demo.tape`, from the
repository root with tripwire installed.

## One-time PyPI setup

Sign in to [PyPI's account publishing page](https://pypi.org/manage/account/publishing/)
and configure a pending GitHub publisher using these exact values:

| Field | Value |
|---|---|
| PyPI project name | `tripwire-agent` |
| GitHub owner | `Sparshg3011` |
| Repository | `tripwire` |
| Workflow filename | `release.yml` |
| Environment name | `pypi` |

The workflow uses short-lived GitHub OIDC credentials; it does not need a PyPI
API token in this repository. A pending publisher creates the package on its
first successful upload; it does not reserve the name in advance. See the
[official PyPI instructions](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/).

On GitHub, under Settings → Environments, create an environment named `pypi`.
Adding yourself as a required reviewer there makes every upload wait for your
approval.

## Publish

After all evidence is complete and CI passes, merge the reviewed release
branch, date the changelog, and ensure the version in `pyproject.toml` matches
the release tag. Push `v0.1.0` for version `0.1.0`; the build refuses a tag
that doesn't match. The workflow publishes to PyPI, then attaches the wheel and
source archive to a GitHub release.

Verify the uploaded package in another clean environment using
`pip install tripwire-agent==0.1.0`, `pip check`, and the same installed smoke
check. Record the wheel and source hashes, CI run, and package/release URLs.

Raw benchmark transcripts are excluded from Git and both package formats.
Any separately shared raw-evidence archive must first be checked for secrets,
accompanied by hashes and source provenance, and described in the release
notes. The tracked compact evidence is included in the source archive.

If a released version is defective, publish a new patch version and yank the
affected version on PyPI when appropriate. Never replace or silently relabel
an existing version or result.
