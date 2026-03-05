# xdp-system-compat

Standalone diagnostic CLI that probes host-level compatibility constraints relevant to Agave XDP retransmit.

This tool is intentionally decoupled from the Agave monorepo codebase:

- No local/workspace crate dependencies
- No validator config input required
- No preferred configuration generation
- Reports constraints and incompatibilities only

## Probe ordering and dependencies

The probe pipeline is dependency-aware:

1. Always-safe probes: OS, kernel release, page size, memlock
2. Passive system inventory: interface list, queue count, bond/physical traits, default route
3. Capability context: `CapPrm` from `/proc/self/status`
4. Active probes: AF_XDP socket probe (capability-gated), per-interface IPv4 ioctl probes
5. Rule evaluation with explicit handling for blocked/unavailable probes

Probe outcomes are tracked as:

- `ok`
- `blocked`
- `failed`
- `unavailable`

## What it checks

Current rule IDs:

- `XDP001`: non-Linux host (error)
- `XDP002`: AF_XDP unavailable (error, confirmed probe failure)
- `XDP003`: no physical NIC detected (error, only when interface inventory is conclusive)
- `XDP004`: default route interface missing (warn)
- `XDP005`: default route points to bond/non-physical interface (warn)
- `XDP006`: physical interface with zero TX queues (warn)
- `XDP007`: missing `CAP_NET_ADMIN`/`CAP_NET_RAW` (warn)
- `XDP008`: missing `CAP_BPF`/`CAP_PERFMON` (warn)
- `XDP009`: no interface with IPv4 detected (warn, only when conclusive)
- `XDP010`: memlock likely too low for UMEM (warn)
- `XDP011`: memlock probe inconclusive (warn)
- `XDP012`: AF_XDP probe blocked/unavailable (warn)
- `XDP013`: interface inventory probe inconclusive (warn)
- `XDP014`: default-route probe inconclusive (warn)
- `XDP015`: capability probe inconclusive (warn)
- `XDP016`: IPv4 probe inconclusive (warn)

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
