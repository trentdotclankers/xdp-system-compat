use crate::model::{
    CapabilityState, CpuCoreInfo, CpuTopologyInfo, HostSnapshot, InterfaceInfo, InterfaceIrqInfo,
    InterfaceQueueAffinity, IrqInfo, NumaNodeInfo, NumaTopologyInfo, OperatorContext, ProbeResult,
    QueueCpuMaskInfo,
};
use std::{
    ffi::CString,
    fs, io, mem,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    path::Path,
};

pub fn collect_snapshot() -> HostSnapshot {
    // Phase A: always-safe probes.
    let os = std::env::consts::OS.to_string();
    let kernel_release = fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|s| s.trim().to_string());
    let page_size_bytes = page_size();
    let memlock_bytes = parse_memlock_limit();

    // Phase C: passive sysfs/proc reads.
    let cpu_topology = probe_cpu_topology();
    let numa_topology = probe_numa_topology();
    let mut interfaces = probe_interfaces();
    let default_route_interface = default_route_interface();
    let irq_topology = probe_irq_topology(&interfaces);
    let queue_cpu_masks = probe_queue_cpu_masks(&interfaces);

    // Phase B: capability context.
    let capabilities_permitted = probe_capabilities();

    // Phase D: active probes gated by capability context.
    let af_xdp_supported = af_xdp_supported(&os, capabilities_permitted.as_ref());
    probe_interface_ipv4(&mut interfaces);

    HostSnapshot {
        os,
        kernel_release,
        af_xdp_supported,
        interfaces,
        operator_context: OperatorContext {
            cpu_topology,
            numa_topology,
            irq_topology,
            queue_cpu_masks,
        },
        default_route_interface,
        capabilities_permitted,
        memlock_bytes,
        page_size_bytes,
    }
}

fn af_xdp_supported(os: &str, capabilities: ProbeResult<&CapabilityState>) -> ProbeResult<bool> {
    if os != "linux" {
        return ProbeResult::Unavailable {
            reason: "AF_XDP probing is only implemented on Linux".to_string(),
        };
    }

    let caps = match capabilities {
        ProbeResult::Ok { value } => value,
        ProbeResult::Blocked { reason }
        | ProbeResult::Failed { reason }
        | ProbeResult::Unavailable { reason } => {
            return ProbeResult::Blocked {
                reason: format!("capability context unavailable: {reason}"),
            };
        }
    };

    if !caps.cap_net_raw {
        return ProbeResult::Blocked {
            reason: "CAP_NET_RAW is not permitted; AF_XDP socket probe skipped".to_string(),
        };
    }

    #[cfg(target_os = "linux")]
    {
        use caps::Capability::CAP_NET_RAW;

        with_temporary_effective_caps(&[CAP_NET_RAW], || {
            // Safety: direct libc socket call.
            let fd = unsafe { libc::socket(libc::AF_XDP, libc::SOCK_RAW, 0) };
            if fd < 0 {
                let err = io::Error::last_os_error();
                if matches!(err.raw_os_error(), Some(libc::EPERM | libc::EACCES)) {
                    return ProbeResult::Blocked {
                        reason: format!("AF_XDP probe blocked by permissions: {err}"),
                    };
                }
                return ProbeResult::Failed {
                    reason: format!("AF_XDP socket creation failed: {err}"),
                };
            }

            // Safety: fd was just returned by socket and is valid.
            let _owned = unsafe { OwnedFd::from_raw_fd(fd) };
            ProbeResult::ok(true)
        })
    }

    #[cfg(not(target_os = "linux"))]
    {
        ProbeResult::Unavailable {
            reason: "AF_XDP probing is only implemented on Linux".to_string(),
        }
    }
}

#[cfg(target_os = "linux")]
fn with_temporary_effective_caps<T>(
    required: &[caps::Capability],
    probe: impl FnOnce() -> ProbeResult<T>,
) -> ProbeResult<T> {
    use caps::CapSet;

    let permitted = match caps::read(None, CapSet::Permitted) {
        Ok(permitted) => permitted,
        Err(err) => {
            return ProbeResult::Failed {
                reason: format!("failed to read permitted capability set: {err}"),
            };
        }
    };

    for cap in required {
        if !permitted.contains(cap) {
            return ProbeResult::Blocked {
                reason: format!("required capability {cap:?} is not in the permitted set"),
            };
        }
    }

    let effective = match caps::read(None, CapSet::Effective) {
        Ok(effective) => effective,
        Err(err) => {
            return ProbeResult::Failed {
                reason: format!("failed to read effective capability set: {err}"),
            };
        }
    };

    let mut elevated = Vec::new();
    for cap in required {
        if effective.contains(cap) {
            continue;
        }
        if let Err(err) = caps::raise(None, CapSet::Effective, *cap) {
            return ProbeResult::Blocked {
                reason: format!("failed to raise {cap:?} into effective set: {err}"),
            };
        }
        elevated.push(*cap);
    }

    let mut result = probe();

    for cap in elevated.into_iter().rev() {
        if let Err(err) = caps::drop(None, CapSet::Effective, cap) {
            result = ProbeResult::Failed {
                reason: format!(
                    "probe succeeded but failed to drop {cap:?} from effective set: {err}"
                ),
            };
            break;
        }
    }

    result
}

#[cfg(not(target_os = "linux"))]
fn with_temporary_effective_caps<T>(
    _required: &[()],
    probe: impl FnOnce() -> ProbeResult<T>,
) -> ProbeResult<T> {
    probe()
}

fn probe_interfaces() -> ProbeResult<Vec<InterfaceInfo>> {
    let net_dir = Path::new("/sys/class/net");
    let entries = match fs::read_dir(net_dir) {
        Ok(entries) => entries,
        Err(err) => {
            return ProbeResult::Failed {
                reason: format!("failed to read /sys/class/net: {err}"),
            };
        }
    };

    let mut interfaces = Vec::new();

    for entry in entries.flatten() {
        let iface = entry.file_name().to_string_lossy().to_string();
        let base = net_dir.join(&iface);
        let has_device = base.join("device").exists();
        let is_bond = base.join("bonding").exists();
        let rx_queues = count_rx_queues(&base);
        let tx_queues = count_tx_queues(&base);

        interfaces.push(InterfaceInfo {
            name: iface,
            has_device,
            is_bond,
            rx_queues,
            tx_queues,
            driver: probe_interface_driver(&base),
            pci_address: probe_interface_pci_address(&base),
            numa_node: probe_interface_numa_node(&base),
            operstate: probe_interface_operstate(&base),
            mtu: probe_interface_mtu(&base),
            speed_mbps: probe_interface_speed(&base),
            has_ipv4: ProbeResult::Unavailable {
                reason: "IPv4 probe not executed yet".to_string(),
            },
        });
    }

    interfaces.sort_by(|a, b| a.name.cmp(&b.name));
    ProbeResult::ok(interfaces)
}

fn count_rx_queues(base: &Path) -> usize {
    let queue_dir = base.join("queues");
    let entries = match fs::read_dir(queue_dir) {
        Ok(entries) => entries,
        Err(_) => return 0,
    };

    entries
        .flatten()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| name.starts_with("rx-"))
        .count()
}

fn count_tx_queues(base: &Path) -> usize {
    let queue_dir = base.join("queues");
    let entries = match fs::read_dir(queue_dir) {
        Ok(entries) => entries,
        Err(_) => return 0,
    };

    entries
        .flatten()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| name.starts_with("tx-"))
        .count()
}

fn default_route_interface() -> ProbeResult<Option<String>> {
    let route = match fs::read_to_string("/proc/net/route") {
        Ok(route) => route,
        Err(err) => {
            return ProbeResult::Failed {
                reason: format!("failed to read /proc/net/route: {err}"),
            };
        }
    };

    for line in route.lines().skip(1) {
        let cols = line.split_whitespace().collect::<Vec<_>>();
        if cols.len() < 3 {
            continue;
        }
        let iface = cols[0];
        let destination = cols[1];
        if destination == "00000000" {
            return ProbeResult::ok(Some(iface.to_string()));
        }
    }
    ProbeResult::ok(None)
}

fn probe_irq_topology(
    interfaces: &ProbeResult<Vec<InterfaceInfo>>,
) -> ProbeResult<Vec<InterfaceIrqInfo>> {
    let interfaces = match interfaces {
        ProbeResult::Ok { value } => value,
        ProbeResult::Blocked { reason } => {
            return ProbeResult::Blocked {
                reason: format!("interface inventory blocked: {reason}"),
            };
        }
        ProbeResult::Failed { reason } => {
            return ProbeResult::Failed {
                reason: format!("interface inventory failed: {reason}"),
            };
        }
        ProbeResult::Unavailable { reason } => {
            return ProbeResult::Unavailable {
                reason: format!("interface inventory unavailable: {reason}"),
            };
        }
    };

    let mut by_iface = Vec::new();
    for iface in interfaces {
        let mut irqs = probe_irqs_for_interface(&iface.name);
        irqs.sort_by_key(|i| i.irq);
        by_iface.push(InterfaceIrqInfo {
            interface: iface.name.clone(),
            irqs,
        });
    }
    ProbeResult::ok(by_iface)
}

fn probe_irqs_for_interface(interface: &str) -> Vec<IrqInfo> {
    let mut irq_ids = Vec::<u32>::new();

    let msi_dir = Path::new("/sys/class/net")
        .join(interface)
        .join("device/msi_irqs");
    if let Ok(entries) = fs::read_dir(msi_dir) {
        for entry in entries.flatten() {
            if let Ok(name) = entry.file_name().into_string() {
                if let Ok(irq) = name.parse::<u32>() {
                    irq_ids.push(irq);
                }
            }
        }
    }

    if irq_ids.is_empty() {
        if let Ok(interrupts) = fs::read_to_string("/proc/interrupts") {
            for line in interrupts.lines() {
                if !line.contains(interface) {
                    continue;
                }
                if let Some((irq_field, _)) = line.split_once(':') {
                    if let Ok(irq) = irq_field.trim().parse::<u32>() {
                        irq_ids.push(irq);
                    }
                }
            }
        }
    }

    irq_ids.sort_unstable();
    irq_ids.dedup();

    irq_ids
        .into_iter()
        .map(|irq| IrqInfo {
            irq,
            smp_affinity_list: read_string_probe(Path::new(&format!(
                "/proc/irq/{irq}/smp_affinity_list"
            ))),
        })
        .collect()
}

fn probe_queue_cpu_masks(
    interfaces: &ProbeResult<Vec<InterfaceInfo>>,
) -> ProbeResult<Vec<InterfaceQueueAffinity>> {
    let interfaces = match interfaces {
        ProbeResult::Ok { value } => value,
        ProbeResult::Blocked { reason } => {
            return ProbeResult::Blocked {
                reason: format!("interface inventory blocked: {reason}"),
            };
        }
        ProbeResult::Failed { reason } => {
            return ProbeResult::Failed {
                reason: format!("interface inventory failed: {reason}"),
            };
        }
        ProbeResult::Unavailable { reason } => {
            return ProbeResult::Unavailable {
                reason: format!("interface inventory unavailable: {reason}"),
            };
        }
    };

    let mut mappings = Vec::new();
    for iface in interfaces {
        let queues_dir = Path::new("/sys/class/net").join(&iface.name).join("queues");
        let entries = match fs::read_dir(&queues_dir) {
            Ok(entries) => entries,
            Err(err) => {
                mappings.push(InterfaceQueueAffinity {
                    interface: iface.name.clone(),
                    queues: vec![QueueCpuMaskInfo {
                        queue: "<queues_unavailable>".to_string(),
                        rps_cpus: ProbeResult::Failed {
                            reason: format!("failed to read queues directory: {err}"),
                        },
                        xps_cpus: ProbeResult::Failed {
                            reason: format!("failed to read queues directory: {err}"),
                        },
                    }],
                });
                continue;
            }
        };

        let mut queue_masks = Vec::new();
        for entry in entries.flatten() {
            let queue = entry.file_name().to_string_lossy().to_string();
            let qpath = entry.path();
            queue_masks.push(QueueCpuMaskInfo {
                queue,
                rps_cpus: read_string_probe(&qpath.join("rps_cpus")),
                xps_cpus: read_string_probe(&qpath.join("xps_cpus")),
            });
        }
        queue_masks.sort_by(|a, b| a.queue.cmp(&b.queue));
        mappings.push(InterfaceQueueAffinity {
            interface: iface.name.clone(),
            queues: queue_masks,
        });
    }

    ProbeResult::ok(mappings)
}

fn read_string_probe(path: &Path) -> ProbeResult<String> {
    match fs::read_to_string(path) {
        Ok(v) => ProbeResult::ok(v.trim().to_string()),
        Err(err) => {
            if err.kind() == io::ErrorKind::NotFound {
                ProbeResult::Unavailable {
                    reason: format!("{} not present", path.display()),
                }
            } else if err.kind() == io::ErrorKind::PermissionDenied {
                ProbeResult::Blocked {
                    reason: format!("permission denied for {}", path.display()),
                }
            } else {
                ProbeResult::Failed {
                    reason: format!("failed to read {}: {err}", path.display()),
                }
            }
        }
    }
}

fn probe_cpu_topology() -> ProbeResult<CpuTopologyInfo> {
    let online = match fs::read_to_string("/sys/devices/system/cpu/online") {
        Ok(online) => online,
        Err(err) => {
            return ProbeResult::Failed {
                reason: format!("failed to read CPU online list: {err}"),
            };
        }
    };

    let online_cores = match parse_cpu_list(online.trim()) {
        Ok(cores) => cores,
        Err(reason) => return ProbeResult::Failed { reason },
    };

    let mut core_to_numa = Vec::with_capacity(online_cores.len());
    let mut sibling_sets = Vec::<Vec<usize>>::new();
    for core in &online_cores {
        let cpu_dir = format!("/sys/devices/system/cpu/cpu{core}");
        let numa_node = probe_cpu_numa_node(Path::new(&cpu_dir));
        core_to_numa.push(CpuCoreInfo {
            core_id: *core,
            numa_node,
        });

        if let Ok(siblings) = fs::read_to_string(format!("{cpu_dir}/topology/thread_siblings_list"))
        {
            if let Ok(mut set) = parse_cpu_list(siblings.trim()) {
                set.sort_unstable();
                if !sibling_sets.contains(&set) {
                    sibling_sets.push(set);
                }
            }
        }
    }
    sibling_sets.sort();

    ProbeResult::ok(CpuTopologyInfo {
        logical_core_count: online_cores.len(),
        online_cores,
        core_to_numa,
        smt_sibling_sets: sibling_sets,
    })
}

fn probe_cpu_numa_node(cpu_dir: &Path) -> Option<usize> {
    let entries = fs::read_dir(cpu_dir).ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if let Some(id) = name.strip_prefix("node") {
            if let Ok(node_id) = id.parse::<usize>() {
                return Some(node_id);
            }
        }
    }
    None
}

fn probe_numa_topology() -> ProbeResult<NumaTopologyInfo> {
    let node_dir = Path::new("/sys/devices/system/node");
    let entries = match fs::read_dir(node_dir) {
        Ok(entries) => entries,
        Err(err) => {
            return ProbeResult::Unavailable {
                reason: format!("failed to read NUMA node directory: {err}"),
            };
        }
    };

    let mut nodes = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let Some(id) = name.strip_prefix("node") else {
            continue;
        };
        let Ok(node_id) = id.parse::<usize>() else {
            continue;
        };
        let meminfo = fs::read_to_string(entry.path().join("meminfo")).ok();
        let (mem_total_kb, mem_free_kb) = parse_numa_meminfo(meminfo.as_deref());
        nodes.push(NumaNodeInfo {
            node_id,
            mem_total_kb,
            mem_free_kb,
        });
    }
    nodes.sort_by_key(|n| n.node_id);

    if nodes.is_empty() {
        return ProbeResult::Unavailable {
            reason: "no NUMA node entries found".to_string(),
        };
    }

    ProbeResult::ok(NumaTopologyInfo { nodes })
}

fn parse_numa_meminfo(meminfo: Option<&str>) -> (Option<u64>, Option<u64>) {
    let Some(meminfo) = meminfo else {
        return (None, None);
    };
    let mut total = None;
    let mut free = None;
    for line in meminfo.lines() {
        if line.contains("MemTotal") {
            total = parse_last_u64(line);
        } else if line.contains("MemFree") {
            free = parse_last_u64(line);
        }
    }
    (total, free)
}

fn parse_last_u64(line: &str) -> Option<u64> {
    line.split_whitespace()
        .rev()
        .find_map(|t| t.parse::<u64>().ok())
}

fn parse_cpu_list(list: &str) -> Result<Vec<usize>, String> {
    if list.is_empty() {
        return Ok(Vec::new());
    }
    let mut cpus = Vec::new();
    for part in list.split(',') {
        if let Some((start, end)) = part.split_once('-') {
            let start = start
                .parse::<usize>()
                .map_err(|e| format!("invalid CPU range start '{start}': {e}"))?;
            let end = end
                .parse::<usize>()
                .map_err(|e| format!("invalid CPU range end '{end}': {e}"))?;
            if end < start {
                return Err(format!("invalid descending CPU range '{part}'"));
            }
            cpus.extend(start..=end);
        } else {
            let cpu = part
                .parse::<usize>()
                .map_err(|e| format!("invalid CPU id '{part}': {e}"))?;
            cpus.push(cpu);
        }
    }
    cpus.sort_unstable();
    cpus.dedup();
    Ok(cpus)
}

fn probe_interface_driver(base: &Path) -> ProbeResult<Option<String>> {
    if !base.join("device").exists() {
        return ProbeResult::Unavailable {
            reason: "interface has no backing device".to_string(),
        };
    }
    match fs::read_link(base.join("device/driver")) {
        Ok(path) => ProbeResult::ok(path.file_name().map(|s| s.to_string_lossy().to_string())),
        Err(err) => ProbeResult::Failed {
            reason: format!("failed to read driver link: {err}"),
        },
    }
}

fn probe_interface_pci_address(base: &Path) -> ProbeResult<Option<String>> {
    if !base.join("device").exists() {
        return ProbeResult::Unavailable {
            reason: "interface has no backing device".to_string(),
        };
    }
    match fs::read_link(base.join("device")) {
        Ok(path) => ProbeResult::ok(path.file_name().map(|s| s.to_string_lossy().to_string())),
        Err(err) => ProbeResult::Failed {
            reason: format!("failed to read device symlink: {err}"),
        },
    }
}

fn probe_interface_numa_node(base: &Path) -> ProbeResult<Option<usize>> {
    if !base.join("device").exists() {
        return ProbeResult::Unavailable {
            reason: "interface has no backing device".to_string(),
        };
    }
    let path = base.join("device/numa_node");
    match fs::read_to_string(path) {
        Ok(value) => {
            let value = value.trim();
            let parsed = value.parse::<i32>().ok();
            match parsed {
                Some(v) if v >= 0 => ProbeResult::ok(Some(v as usize)),
                Some(_) => ProbeResult::ok(None),
                None => ProbeResult::Failed {
                    reason: format!("failed to parse numa_node value '{value}'"),
                },
            }
        }
        Err(err) => ProbeResult::Failed {
            reason: format!("failed to read interface numa_node: {err}"),
        },
    }
}

fn probe_interface_operstate(base: &Path) -> ProbeResult<String> {
    match fs::read_to_string(base.join("operstate")) {
        Ok(state) => ProbeResult::ok(state.trim().to_string()),
        Err(err) => ProbeResult::Failed {
            reason: format!("failed to read operstate: {err}"),
        },
    }
}

fn probe_interface_mtu(base: &Path) -> ProbeResult<u32> {
    match fs::read_to_string(base.join("mtu")) {
        Ok(mtu) => match mtu.trim().parse::<u32>() {
            Ok(v) => ProbeResult::ok(v),
            Err(err) => ProbeResult::Failed {
                reason: format!("failed to parse mtu '{}': {err}", mtu.trim()),
            },
        },
        Err(err) => ProbeResult::Failed {
            reason: format!("failed to read mtu: {err}"),
        },
    }
}

fn probe_interface_speed(base: &Path) -> ProbeResult<Option<u64>> {
    match fs::read_to_string(base.join("speed")) {
        Ok(speed) => {
            let speed = speed.trim();
            match speed.parse::<i64>() {
                Ok(v) if v >= 0 => ProbeResult::ok(Some(v as u64)),
                Ok(_) => ProbeResult::ok(None),
                Err(err) => ProbeResult::Failed {
                    reason: format!("failed to parse speed '{}': {err}", speed),
                },
            }
        }
        Err(err) => {
            if matches!(
                err.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
            ) {
                ProbeResult::Unavailable {
                    reason: format!("interface speed is not available: {err}"),
                }
            } else {
                ProbeResult::Failed {
                    reason: format!("failed to read speed: {err}"),
                }
            }
        }
    }
}

fn probe_capabilities() -> ProbeResult<CapabilityState> {
    #[cfg(target_os = "linux")]
    {
        use caps::{
            CapSet,
            Capability::{CAP_BPF, CAP_NET_ADMIN, CAP_NET_RAW, CAP_PERFMON},
        };

        let permitted = match caps::read(None, CapSet::Permitted) {
            Ok(permitted) => permitted,
            Err(err) => {
                return ProbeResult::Failed {
                    reason: format!("failed to read permitted capability set: {err}"),
                };
            }
        };

        ProbeResult::ok(CapabilityState {
            cap_net_admin: permitted.contains(&CAP_NET_ADMIN),
            cap_net_raw: permitted.contains(&CAP_NET_RAW),
            cap_bpf: permitted.contains(&CAP_BPF),
            cap_perfmon: permitted.contains(&CAP_PERFMON),
        })
    }

    #[cfg(not(target_os = "linux"))]
    {
        ProbeResult::Unavailable {
            reason: "Capability probing via caps crate is only implemented on Linux".to_string(),
        }
    }
}

fn parse_memlock_limit() -> ProbeResult<u64> {
    let limits = match fs::read_to_string("/proc/self/limits") {
        Ok(limits) => limits,
        Err(err) => {
            return ProbeResult::Failed {
                reason: format!("failed to read /proc/self/limits: {err}"),
            };
        }
    };

    for line in limits.lines() {
        if !line.starts_with("Max locked memory") {
            continue;
        }

        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 4 {
            return ProbeResult::Failed {
                reason: "unexpected Max locked memory line format".to_string(),
            };
        }

        let soft = fields[3];
        if soft.eq_ignore_ascii_case("unlimited") {
            return ProbeResult::ok(u64::MAX);
        }

        return match soft.parse::<u64>() {
            Ok(value) => ProbeResult::ok(value),
            Err(err) => ProbeResult::Failed {
                reason: format!("failed to parse memlock value '{soft}': {err}"),
            },
        };
    }

    ProbeResult::Unavailable {
        reason: "Max locked memory line not found in /proc/self/limits".to_string(),
    }
}

fn page_size() -> u64 {
    // Safety: sysconf call with static name.
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if size <= 0 { 4096 } else { size as u64 }
}

fn probe_interface_ipv4(interfaces: &mut ProbeResult<Vec<InterfaceInfo>>) {
    let ProbeResult::Ok { value: interfaces } = interfaces else {
        return;
    };

    for iface in interfaces {
        iface.has_ipv4 = iface_has_ipv4(&iface.name);
    }
}

fn iface_has_ipv4(iface: &str) -> ProbeResult<bool> {
    #[cfg(target_os = "linux")]
    {
        iface_has_ipv4_linux(iface)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = iface;
        ProbeResult::Unavailable {
            reason: "IPv4 ioctl probing is only implemented on Linux".to_string(),
        }
    }
}

#[cfg(target_os = "linux")]
fn iface_has_ipv4_linux(iface: &str) -> ProbeResult<bool> {
    let ifname = match CString::new(iface) {
        Ok(ifname) => ifname,
        Err(_) => {
            return ProbeResult::Failed {
                reason: "interface name is not a valid C string".to_string(),
            };
        }
    };

    // Safety: direct libc socket call.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        let err = io::Error::last_os_error();
        if matches!(err.raw_os_error(), Some(libc::EPERM | libc::EACCES)) {
            return ProbeResult::Blocked {
                reason: format!("IPv4 probe socket blocked by permissions: {err}"),
            };
        }
        return ProbeResult::Failed {
            reason: format!("failed to create IPv4 probe socket: {err}"),
        };
    }
    // Safety: fd is valid.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };

    // Safety: zeroed is valid for plain old data struct.
    let mut req: libc::ifreq = unsafe { mem::zeroed() };
    let name = ifname.as_bytes_with_nul();
    let len = name.len().min(libc::IF_NAMESIZE);
    // Safety: destination is valid and len is bounded by IF_NAMESIZE.
    unsafe {
        std::ptr::copy_nonoverlapping(
            name.as_ptr() as *const libc::c_char,
            req.ifr_name.as_mut_ptr(),
            len,
        );
    }

    // Safety: ioctl invocation with valid fd and ifreq pointer.
    let res = unsafe { libc::ioctl(owned.as_raw_fd(), libc::SIOCGIFADDR, &mut req) };
    if res < 0 {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::AddrNotAvailable
            || err.raw_os_error() == Some(libc::EADDRNOTAVAIL)
            || err.raw_os_error() == Some(libc::ENODEV)
        {
            return ProbeResult::ok(false);
        }
        if matches!(err.raw_os_error(), Some(libc::EPERM | libc::EACCES)) {
            return ProbeResult::Blocked {
                reason: format!("IPv4 ioctl blocked by permissions: {err}"),
            };
        }
        return ProbeResult::Failed {
            reason: format!("IPv4 ioctl probe failed: {err}"),
        };
    }

    ProbeResult::ok(true)
}
