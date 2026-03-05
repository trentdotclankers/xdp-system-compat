use xdp_system_compat::{
    model::{
        CapabilityState, CpuTopologyInfo, HostSnapshot, InterfaceInfo, NumaTopologyInfo,
        OperatorContext, ProbeResult,
    },
    rules::evaluate,
};

#[test]
fn default_route_missing_generates_warning() {
    let snapshot = HostSnapshot {
        os: "linux".to_string(),
        kernel_release: Some("6.8.0".to_string()),
        af_xdp_supported: ProbeResult::ok(true),
        interfaces: ProbeResult::ok(vec![InterfaceInfo {
            name: "eth0".to_string(),
            has_device: true,
            is_bond: false,
            rx_queues: 4,
            tx_queues: 4,
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
        },
        default_route_interface: ProbeResult::ok(None),
        capabilities_permitted: ProbeResult::ok(CapabilityState {
            cap_net_admin: true,
            cap_net_raw: true,
            cap_bpf: true,
            cap_perfmon: true,
        }),
        memlock_bytes: ProbeResult::ok(2_000_000_000),
        page_size_bytes: 4096,
    };

    let findings = evaluate(&snapshot);
    assert!(findings.iter().any(|f| f.id == "XDP004"));
}
