use xdp_system_compat::{
    model::{CapabilityState, HostSnapshot, InterfaceInfo, ProbeResult},
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
            tx_queues: 4,
            has_ipv4: ProbeResult::ok(true),
        }]),
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
