use crate::model::{Finding, HostSnapshot, InterfaceInfo, ProbeResult, RulePass, Severity};

const CAP_NET_ADMIN: &str = "CAP_NET_ADMIN";
const CAP_NET_RAW: &str = "CAP_NET_RAW";
const CAP_BPF: &str = "CAP_BPF";
const CAP_PERFMON: &str = "CAP_PERFMON";

const ESTIMATED_MEMLOCK_PER_QUEUE_BYTES: u64 = 16 * 1024 * 1024;

pub struct Evaluation {
    pub findings: Vec<Finding>,
    pub passes: Vec<RulePass>,
}

pub fn evaluate(snapshot: &HostSnapshot) -> Evaluation {
    let mut findings = Vec::new();
    let mut passes = Vec::new();

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
        return Evaluation { findings, passes };
    } else {
        passes.push(RulePass {
            id: "XDP001",
            title: "Host operating system supports XDP retransmit requirements",
            details: "Host reports linux.".to_string(),
        });
    }

    match &snapshot.af_xdp_supported {
        ProbeResult::Ok { value } => {
            if !value {
                findings.push(Finding {
                    id: "XDP002",
                    severity: Severity::Error,
                    title: "AF_XDP socket support is unavailable",
                    details: "AF_XDP probe returned unsupported on this host.".to_string(),
                    remediation: "Use a kernel/NIC stack with AF_XDP support enabled; verify kernel config and driver support.".to_string(),
                });
            } else {
                passes.push(RulePass {
                    id: "XDP002",
                    title: "AF_XDP socket probe succeeded",
                    details: "AF_XDP socket creation is available from this runtime context."
                        .to_string(),
                });
            }
        }
        ProbeResult::Failed { reason } => {
            findings.push(Finding {
                id: "XDP002",
                severity: Severity::Error,
                title: "AF_XDP socket support is unavailable",
                details: format!(
                    "AF_XDP socket probing failed, so XDP retransmit cannot be initialized: {reason}"
                ),
                remediation: "Use a kernel/NIC stack with AF_XDP support enabled; verify kernel config and driver support.".to_string(),
            });
        }
        ProbeResult::Blocked { reason } => {
            findings.push(Finding {
                id: "XDP012",
                severity: Severity::Warn,
                title: "AF_XDP compatibility probe was blocked",
                details: format!(
                    "The tool could not validate AF_XDP support because probing was blocked: {reason}"
                ),
                remediation:
                    "Run the tool with sufficient privileges/capabilities to validate AF_XDP support conclusively."
                        .to_string(),
            });
        }
        ProbeResult::Unavailable { reason } => {
            findings.push(Finding {
                id: "XDP012",
                severity: Severity::Warn,
                title: "AF_XDP compatibility probe was unavailable",
                details: format!(
                    "The tool could not validate AF_XDP support in this environment: {reason}"
                ),
                remediation: "Run the tool in a Linux environment with AF_XDP probing support."
                    .to_string(),
            });
        }
    }

    let mut interfaces = None;
    match &snapshot.interfaces {
        ProbeResult::Ok { value } => interfaces = Some(value),
        ProbeResult::Blocked { reason }
        | ProbeResult::Failed { reason }
        | ProbeResult::Unavailable { reason } => {
            findings.push(Finding {
                id: "XDP013",
                severity: Severity::Warn,
                title: "Network interface inventory probe was inconclusive",
                details: format!("Could not enumerate interfaces reliably: {reason}"),
                remediation: "Ensure /sys/class/net is readable from the tool runtime context."
                    .to_string(),
            });
        }
    }

    if let Some(interfaces) = interfaces {
        validate_interfaces(interfaces, &mut findings, &mut passes);
    } else {
        // no pass for XDP003 if inventory is inconclusive
    }

    match &snapshot.default_route_interface {
        ProbeResult::Ok { value } => match value {
            None => findings.push(Finding {
                id: "XDP004",
                severity: Severity::Warn,
                title: "No default route interface detected",
                details:
                    "Unable to identify the default route interface from /proc/net/route."
                        .to_string(),
                remediation: "If relying on implicit XDP interface selection, configure a default route or set an explicit XDP interface at validator startup.".to_string(),
            }),
            Some(default_iface) => {
                passes.push(RulePass {
                    id: "XDP004",
                    title: "Default route interface detected",
                    details: format!("Default route interface is '{default_iface}'."),
                });
                if let ProbeResult::Ok { value: interfaces } = &snapshot.interfaces {
                    if let Some(iface) = interfaces.iter().find(|i| i.name == *default_iface) {
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
                        } else {
                            passes.push(RulePass {
                                id: "XDP005",
                                title: "Default route interface is physical and non-bonded",
                                details: format!(
                                    "Default route interface '{}' is suitable for physical interface selection.",
                                    iface.name
                                ),
                            });
                        }
                    }
                }
            }
        },
        ProbeResult::Blocked { reason }
        | ProbeResult::Failed { reason }
        | ProbeResult::Unavailable { reason } => {
            findings.push(Finding {
                id: "XDP014",
                severity: Severity::Warn,
                title: "Default route probe was inconclusive",
                details: format!("Could not read default route information: {reason}"),
                remediation: "Ensure /proc/net/route is readable from the tool runtime context."
                    .to_string(),
            });
        }
    }

    match &snapshot.capabilities_permitted {
        ProbeResult::Ok { value: caps } => {
            if !caps.cap_net_admin || !caps.cap_net_raw {
                let mut missing = Vec::new();
                if !caps.cap_net_admin {
                    missing.push(CAP_NET_ADMIN);
                }
                if !caps.cap_net_raw {
                    missing.push(CAP_NET_RAW);
                }
                findings.push(Finding {
                    id: "XDP007",
                    severity: Severity::Warn,
                    title: "Required Linux capabilities for XDP setup are not currently permitted",
                    details: format!("Missing permitted capabilities: {}.", missing.join(", ")),
                    remediation: "Permit CAP_NET_ADMIN and CAP_NET_RAW for the validator process before enabling XDP retransmit.".to_string(),
                });
            } else {
                passes.push(RulePass {
                    id: "XDP007",
                    title: "Required setup capabilities are permitted",
                    details: "CAP_NET_ADMIN and CAP_NET_RAW are in the permitted set.".to_string(),
                });
            }

            if !caps.cap_bpf || !caps.cap_perfmon {
                let mut missing = Vec::new();
                if !caps.cap_bpf {
                    missing.push(CAP_BPF);
                }
                if !caps.cap_perfmon {
                    missing.push(CAP_PERFMON);
                }
                findings.push(Finding {
                    id: "XDP008",
                    severity: Severity::Warn,
                    title: "Capabilities for XDP zero-copy/eBPF attachment are missing",
                    details: format!("Missing permitted capabilities: {}.", missing.join(", ")),
                    remediation: "If planning to enable XDP zero-copy, permit CAP_BPF and CAP_PERFMON for the validator process.".to_string(),
                });
            } else {
                passes.push(RulePass {
                    id: "XDP008",
                    title: "Zero-copy/eBPF capabilities are permitted",
                    details: "CAP_BPF and CAP_PERFMON are in the permitted set.".to_string(),
                });
            }
        }
        ProbeResult::Blocked { reason }
        | ProbeResult::Failed { reason }
        | ProbeResult::Unavailable { reason } => {
            findings.push(Finding {
                id: "XDP015",
                severity: Severity::Warn,
                title: "Capability inventory probe was inconclusive",
                details: format!("Could not determine process capability set: {reason}"),
                remediation:
                    "Ensure /proc/self/status is readable so capability constraints can be assessed."
                        .to_string(),
            });
        }
    }

    match &snapshot.memlock_bytes {
        ProbeResult::Ok { value: memlock } => {
            if *memlock < ESTIMATED_MEMLOCK_PER_QUEUE_BYTES {
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
            } else {
                passes.push(RulePass {
                    id: "XDP010",
                    title: "Memlock limit meets baseline XDP estimate",
                    details: format!(
                        "memlock={} bytes is >= estimated minimum {} bytes.",
                        memlock, ESTIMATED_MEMLOCK_PER_QUEUE_BYTES
                    ),
                });
            }
        }
        ProbeResult::Blocked { reason }
        | ProbeResult::Failed { reason }
        | ProbeResult::Unavailable { reason } => {
            findings.push(Finding {
                id: "XDP011",
                severity: Severity::Warn,
                title: "Unable to verify memlock limit",
                details: format!("Memlock probe was inconclusive: {reason}"),
                remediation: "Verify memlock limits manually; low limits can prevent XDP startup."
                    .to_string(),
            });
        }
    }

    Evaluation { findings, passes }
}

fn validate_interfaces(
    interfaces: &[InterfaceInfo],
    findings: &mut Vec<Finding>,
    passes: &mut Vec<RulePass>,
) {
    let physical_ifaces = interfaces
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
    } else {
        passes.push(RulePass {
            id: "XDP003",
            title: "Physical network interfaces detected",
            details: format!("Detected {} physical interface(s).", physical_ifaces.len()),
        });
    }

    for iface in interfaces {
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

    let mut has_known_ipv4 = false;
    let mut ipv4_probe_unknown = false;
    for iface in interfaces {
        match &iface.has_ipv4 {
            ProbeResult::Ok { value } => {
                if *value {
                    has_known_ipv4 = true;
                }
            }
            ProbeResult::Blocked { .. }
            | ProbeResult::Failed { .. }
            | ProbeResult::Unavailable { .. } => ipv4_probe_unknown = true,
        }
    }

    if !has_known_ipv4 {
        if ipv4_probe_unknown {
            findings.push(Finding {
                id: "XDP016",
                severity: Severity::Warn,
                title: "Interface IPv4 probe was inconclusive",
                details: "No interface was confirmed with IPv4, but at least one IPv4 probe could not be completed.".to_string(),
                remediation: "Run the tool with sufficient permissions and verify IPv4 assignment on candidate retransmit interfaces.".to_string(),
            });
        } else {
            findings.push(Finding {
                id: "XDP009",
                severity: Severity::Warn,
                title: "No interface with IPv4 address detected",
                details: "XDP transmit source-IP inference requires a usable IPv4 address."
                    .to_string(),
                remediation: "Ensure at least one candidate retransmit interface has IPv4 configured, or provide explicit networking that resolves source IP correctly.".to_string(),
            });
        }
    } else {
        passes.push(RulePass {
            id: "XDP009",
            title: "At least one interface has IPv4 configured",
            details: "IPv4 source address inference has at least one candidate interface."
                .to_string(),
        });
    }
}

#[cfg(test)]
mod tests {
    use crate::model::{
        CapabilityState, CpuTopologyInfo, HostSnapshot, InterfaceInfo, NumaTopologyInfo,
        OperatorContext, ProbeResult, Severity,
    };

    use super::evaluate;

    fn linux_snapshot() -> HostSnapshot {
        HostSnapshot {
            os: "linux".to_string(),
            kernel_release: Some("6.6.0".to_string()),
            af_xdp_supported: ProbeResult::ok(true),
            interfaces: ProbeResult::ok(vec![InterfaceInfo {
                name: "eth0".to_string(),
                has_device: true,
                is_bond: false,
                rx_queues: 8,
                tx_queues: 8,
                driver: ProbeResult::ok(Some("ixgbe".to_string())),
                pci_address: ProbeResult::ok(Some("0000:3b:00.0".to_string())),
                numa_node: ProbeResult::ok(Some(0)),
                operstate: ProbeResult::ok("up".to_string()),
                mtu: ProbeResult::ok(1500),
                speed_mbps: ProbeResult::ok(Some(25_000)),
                has_ipv4: ProbeResult::ok(true),
            }]),
            operator_context: OperatorContext {
                cpu_topology: ProbeResult::ok(CpuTopologyInfo {
                    logical_core_count: 8,
                    online_cores: vec![0, 1, 2, 3, 4, 5, 6, 7],
                    core_to_numa: vec![],
                    smt_sibling_sets: vec![],
                }),
                numa_topology: ProbeResult::ok(NumaTopologyInfo { nodes: vec![] }),
                irq_topology: ProbeResult::ok(vec![]),
                queue_cpu_masks: ProbeResult::ok(vec![]),
                xdp_interface_status: ProbeResult::ok(vec![]),
                bpf_environment: ProbeResult::Unavailable {
                    reason: "not needed for rules test".to_string(),
                },
            },
            default_route_interface: ProbeResult::ok(Some("eth0".to_string())),
            capabilities_permitted: ProbeResult::ok(CapabilityState {
                cap_net_admin: true,
                cap_net_raw: true,
                cap_bpf: true,
                cap_perfmon: true,
            }),
            memlock_bytes: ProbeResult::ok(2_000_000_000),
            page_size_bytes: 4096,
        }
    }

    #[test]
    fn no_findings_on_well_configured_host() {
        let eval = evaluate(&linux_snapshot());
        assert!(
            eval.findings.is_empty(),
            "unexpected findings: {:#?}",
            eval.findings
        );
        assert!(!eval.passes.is_empty(), "expected affirmative pass outputs");
    }

    #[test]
    fn non_linux_is_hard_error() {
        let mut snapshot = linux_snapshot();
        snapshot.os = "macos".to_string();
        let eval = evaluate(&snapshot);
        assert_eq!(eval.findings.len(), 1);
        assert_eq!(eval.findings[0].id, "XDP001");
        assert_eq!(eval.findings[0].severity, Severity::Error);
    }

    #[test]
    fn capability_gaps_reported() {
        let mut snapshot = linux_snapshot();
        snapshot.capabilities_permitted = ProbeResult::ok(CapabilityState {
            cap_net_admin: false,
            cap_net_raw: true,
            cap_bpf: true,
            cap_perfmon: false,
        });
        let eval = evaluate(&snapshot);
        let ids = eval.findings.iter().map(|f| f.id).collect::<Vec<_>>();
        assert!(ids.contains(&"XDP007"));
        assert!(ids.contains(&"XDP008"));
    }

    #[test]
    fn low_memlock_reported() {
        let mut snapshot = linux_snapshot();
        snapshot.memlock_bytes = ProbeResult::ok(1_000_000);
        let eval = evaluate(&snapshot);
        assert!(eval.findings.iter().any(|f| f.id == "XDP010"));
    }

    #[test]
    fn blocked_af_xdp_probe_is_not_error() {
        let mut snapshot = linux_snapshot();
        snapshot.af_xdp_supported = ProbeResult::Blocked {
            reason: "missing CAP_NET_RAW".to_string(),
        };
        let eval = evaluate(&snapshot);
        assert!(eval.findings.iter().any(|f| f.id == "XDP012"));
        assert!(!eval.findings.iter().any(|f| f.id == "XDP002"));
    }
}
