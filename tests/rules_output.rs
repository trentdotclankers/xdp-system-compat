use xdp_system_compat::{
    model::{CapabilityState, HostSnapshot, InterfaceInfo},
    rules::evaluate,
};

#[test]
fn default_route_missing_generates_warning() {
    let snapshot = HostSnapshot {
        os: "linux".to_string(),
        kernel_release: Some("6.8.0".to_string()),
        af_xdp_supported: true,
        interfaces: vec![InterfaceInfo {
            name: "eth0".to_string(),
            has_device: true,
            is_bond: false,
            tx_queues: 4,
            has_ipv4: true,
        }],
        default_route_interface: None,
        capabilities_permitted: CapabilityState {
            cap_net_admin: true,
            cap_net_raw: true,
            cap_bpf: true,
            cap_perfmon: true,
        },
        memlock_bytes: Some(2_000_000_000),
        page_size_bytes: 4096,
    };

    let findings = evaluate(&snapshot);
    assert!(findings.iter().any(|f| f.id == "XDP004"));
}
