use crate::model::{CapabilityState, HostSnapshot, InterfaceInfo, ProbeResult};
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
    let mut interfaces = probe_interfaces();
    let default_route_interface = default_route_interface();

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
        let tx_queues = count_tx_queues(&base);

        interfaces.push(InterfaceInfo {
            name: iface,
            has_device,
            is_bond,
            tx_queues,
            has_ipv4: ProbeResult::Unavailable {
                reason: "IPv4 probe not executed yet".to_string(),
            },
        });
    }

    interfaces.sort_by(|a, b| a.name.cmp(&b.name));
    ProbeResult::ok(interfaces)
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
