# xdp-system-compat

Standalone diagnostic CLI that probes host-level compatibility constraints relevant to Agave XDP retransmit.

This tool is intentionally decoupled from the Agave monorepo codebase:

- No local/workspace crate dependencies
- No validator config input required
- No preferred configuration generation
- Reports constraints and incompatibilities only

## What it checks

Current rule IDs:

- `XDP001`: non-Linux host (error)
- `XDP002`: AF_XDP unavailable (error)
- `XDP003`: no physical NIC detected (error)
- `XDP004`: default route interface missing (warn)
- `XDP005`: default route points to bond/non-physical interface (warn)
- `XDP006`: physical interface with zero TX queues (warn)
- `XDP007`: missing `CAP_NET_ADMIN`/`CAP_NET_RAW` (warn)
- `XDP008`: missing `CAP_BPF`/`CAP_PERFMON` (warn)
- `XDP009`: no interface with IPv4 detected (warn)
- `XDP010`: memlock likely too low for UMEM (warn)
- `XDP011`: memlock limit unreadable (warn)

## Usage

```bash
cargo run -- --format text
cargo run -- --format json
```

## Exit codes

- `0`: no findings
- `1`: warnings only
- `2`: one or more errors
- `3`: internal tool failure (for example JSON serialization failure)

## Local development

```bash
make fmt
make lint
make test
make build
```

## CI and release

- CI workflow: `.github/workflows/ci.yml`
- Tag-based release workflow: `.github/workflows/release.yml`

Note: update repository URLs in `Cargo.toml` before publishing from an external repository.
