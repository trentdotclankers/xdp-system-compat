use crate::model::{Finding, HostSnapshot, Severity};

const CAP_NET_ADMIN: &str = "CAP_NET_ADMIN";
const CAP_NET_RAW: &str = "CAP_NET_RAW";
const CAP_BPF: &str = "CAP_BPF";
const CAP_PERFMON: &str = "CAP_PERFMON";

const ESTIMATED_MEMLOCK_PER_QUEUE_BYTES: u64 = 16 * 1024 * 1024;

pub fn evaluate(snapshot: &HostSnapshot) -> Vec<Finding> {
    let mut findings = Vec::new();

    if snapshot.os != "linux" {
        findings.push(Finding {
            id: "XDP001",
            severity: Severity::Error,
            title: "Unsupported operating system for XDP retransmit",
            details: format!(
                "This host reports os='{}'. Agave XDP retransmit is Linux-only.",
                snapshot.os
            ),
            remediation:
                "Use a Linux host for any configuration that enables experimental XDP retransmit."
                    .to_string(),
        });
        return findings;
    }

    if !snapshot.af_xdp_supported {
        findings.push(Finding {
            id: "XDP002",
            severity: Severity::Error,
            title: "AF_XDP socket support is unavailable",
            details: "Creating an AF_XDP socket failed on this host, so XDP retransmit cannot be initialized.".to_string(),
            remediation: "Use a kernel/NIC stack with AF_XDP support enabled; verify kernel config and driver support.".to_string(),
        });
    }

    let physical_ifaces = snapshot
        .interfaces
        .iter()
        .filter(|iface| iface.has_device)
        .collect::<Vec<_>>();

    if physical_ifaces.is_empty() {
        findings.push(Finding {
            id: "XDP003",
            severity: Severity::Error,
            title: "No physical network interfaces detected",
            details: "No /sys/class/net/* interface with a backing device was found.".to_string(),
            remediation:
                "Run on a host with at least one physical NIC before enabling XDP retransmit."
                    .to_string(),
        });
    }

    if snapshot.default_route_interface.is_none() {
        findings.push(Finding {
            id: "XDP004",
            severity: Severity::Warn,
            title: "No default route interface detected",
            details: "Unable to identify the default route interface from /proc/net/route.".to_string(),
            remediation: "If relying on implicit XDP interface selection, configure a default route or set an explicit XDP interface at validator startup.".to_string(),
        });
    }

    if let Some(default_iface) = snapshot.default_route_interface.as_deref() {
        if let Some(iface) = snapshot.interfaces.iter().find(|i| i.name == default_iface) {
            if !iface.has_device || iface.is_bond {
                findings.push(Finding {
                    id: "XDP005",
                    severity: Severity::Warn,
                    title: "Default route interface may be incompatible with zero-copy XDP",
                    details: format!(
                        "Default route interface '{}' is {}{}.",
                        iface.name,
                        if iface.is_bond { "bonded" } else { "non-physical" },
                        if iface.is_bond { " (bond master)" } else { "" }
                    ),
                    remediation: "When using XDP zero-copy, select a real physical interface explicitly instead of a bond/virtual interface.".to_string(),
                });
            }
        }
    }

    for iface in &snapshot.interfaces {
        if iface.has_device && iface.tx_queues == 0 {
            findings.push(Finding {
                id: "XDP006",
                severity: Severity::Warn,
                title: "Physical interface reports zero TX queues",
                details: format!(
                    "Interface '{}' is physical but no tx-* queues were discovered under /sys/class/net/{}/queues.",
                    iface.name, iface.name
                ),
                remediation: "Verify NIC driver initialization; XDP retransmit threads require available TX queues.".to_string(),
            });
        }
    }

    if !snapshot.capabilities_permitted.cap_net_admin
        || !snapshot.capabilities_permitted.cap_net_raw
    {
        let mut missing = Vec::new();
        if !snapshot.capabilities_permitted.cap_net_admin {
            missing.push(CAP_NET_ADMIN);
        }
        if !snapshot.capabilities_permitted.cap_net_raw {
            missing.push(CAP_NET_RAW);
        }
        findings.push(Finding {
            id: "XDP007",
            severity: Severity::Warn,
            title: "Required Linux capabilities for XDP setup are not currently permitted",
            details: format!("Missing permitted capabilities: {}.", missing.join(", ")),
            remediation: "Permit CAP_NET_ADMIN and CAP_NET_RAW for the validator process before enabling XDP retransmit.".to_string(),
        });
    }

    if !snapshot.capabilities_permitted.cap_bpf || !snapshot.capabilities_permitted.cap_perfmon {
        let mut missing = Vec::new();
        if !snapshot.capabilities_permitted.cap_bpf {
            missing.push(CAP_BPF);
        }
        if !snapshot.capabilities_permitted.cap_perfmon {
            missing.push(CAP_PERFMON);
        }
        findings.push(Finding {
            id: "XDP008",
            severity: Severity::Warn,
            title: "Capabilities for XDP zero-copy/eBPF attachment are missing",
            details: format!("Missing permitted capabilities: {}.", missing.join(", ")),
            remediation: "If planning to enable XDP zero-copy, permit CAP_BPF and CAP_PERFMON for the validator process.".to_string(),
        });
    }

    if !snapshot.interfaces.iter().any(|iface| iface.has_ipv4) {
        findings.push(Finding {
            id: "XDP009",
            severity: Severity::Warn,
            title: "No interface with IPv4 address detected",
            details: "XDP transmit source-IP inference requires a usable IPv4 address.".to_string(),
            remediation: "Ensure at least one candidate retransmit interface has IPv4 configured, or provide explicit networking that resolves source IP correctly.".to_string(),
        });
    }

    if let Some(memlock) = snapshot.memlock_bytes {
        if memlock < ESTIMATED_MEMLOCK_PER_QUEUE_BYTES {
            findings.push(Finding {
                id: "XDP010",
                severity: Severity::Warn,
                title: "Current memlock limit is likely too low for XDP UMEM",
                details: format!(
                    "memlock={} bytes; estimated minimum per XDP queue is ~{} bytes.",
                    memlock, ESTIMATED_MEMLOCK_PER_QUEUE_BYTES
                ),
                remediation: "Increase process memlock limits (for example via systemd LimitMEMLOCK) before enabling XDP retransmit.".to_string(),
            });
        }
    } else {
        findings.push(Finding {
            id: "XDP011",
            severity: Severity::Warn,
            title: "Unable to read memlock limit",
            details: "Could not parse /proc/self/limits for Max locked memory.".to_string(),
            remediation: "Verify memlock limits manually; low limits can prevent XDP startup."
                .to_string(),
        });
    }

    findings
}

#[cfg(test)]
mod tests {
    use crate::model::{CapabilityState, HostSnapshot, InterfaceInfo, Severity};

    use super::evaluate;

    fn linux_snapshot() -> HostSnapshot {
        HostSnapshot {
            os: "linux".to_string(),
            kernel_release: Some("6.6.0".to_string()),
            af_xdp_supported: true,
            interfaces: vec![InterfaceInfo {
                name: "eth0".to_string(),
                has_device: true,
                is_bond: false,
                tx_queues: 8,
                has_ipv4: true,
            }],
            default_route_interface: Some("eth0".to_string()),
            capabilities_permitted: CapabilityState {
                cap_net_admin: true,
                cap_net_raw: true,
                cap_bpf: true,
                cap_perfmon: true,
            },
            memlock_bytes: Some(2_000_000_000),
            page_size_bytes: 4096,
        }
    }

    #[test]
    fn no_findings_on_well_configured_host() {
        let findings = evaluate(&linux_snapshot());
        assert!(findings.is_empty(), "unexpected findings: {findings:#?}");
    }

    #[test]
    fn non_linux_is_hard_error() {
        let mut snapshot = linux_snapshot();
        snapshot.os = "macos".to_string();
        let findings = evaluate(&snapshot);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "XDP001");
        assert_eq!(findings[0].severity, Severity::Error);
    }

    #[test]
    fn capability_gaps_reported() {
        let mut snapshot = linux_snapshot();
        snapshot.capabilities_permitted.cap_net_admin = false;
        snapshot.capabilities_permitted.cap_perfmon = false;
        let findings = evaluate(&snapshot);
        let ids = findings.iter().map(|f| f.id).collect::<Vec<_>>();
        assert!(ids.contains(&"XDP007"));
        assert!(ids.contains(&"XDP008"));
    }

    #[test]
    fn low_memlock_reported() {
        let mut snapshot = linux_snapshot();
        snapshot.memlock_bytes = Some(1_000_000);
        let findings = evaluate(&snapshot);
        assert!(findings.iter().any(|f| f.id == "XDP010"));
    }
}
