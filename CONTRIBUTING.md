# Contributing

Read [AGENTS.md](AGENTS.md) first. It applies to people as much as to agents.
`python3 tools/vac.py gen --write` writes it from `tools/vac_rules.py`; do not edit
it by hand. It lists the rules `python3 tools/vac.py check` enforces and the
rules no check enforces yet. Which changes need the maintainer is
[ci/lanes.toml](ci/lanes.toml). When a change makes a claim stale, see
[docs/verification.md](docs/verification.md).

Contributions are dual licensed under MIT or Apache-2.0, as described in the
[README](README.md#license).
