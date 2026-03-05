# Changelog

## 0.1.0 - 2026-03-05

- Initial standalone release scaffold.
- System-only host probing for XDP compatibility constraints.
- Rule engine with IDs `XDP001` through `XDP016`.
- Dependency-aware probe ordering:
  - always-safe probes
  - passive sysfs/proc inventory
  - capability context
  - active probes (AF_XDP/IPv4)
- Tri-state probe outcomes (`ok`, `blocked`, `failed`, `unavailable`) to avoid false incompatibility findings in restricted environments.
- Text and JSON report output modes with observability counters.
- Exit code contract for CI/automation.
