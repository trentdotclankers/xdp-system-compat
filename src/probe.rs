use crate::model::{CapabilityState, HostSnapshot, InterfaceInfo};
use std::{
    ffi::CString,
    fs, io, mem,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    path::Path,
};

const CAP_NET_ADMIN_BIT: u32 = 12;
const CAP_NET_RAW_BIT: u32 = 13;
const CAP_PERFMON_BIT: u32 = 38;
const CAP_BPF_BIT: u32 = 39;

pub fn collect_snapshot() -> HostSnapshot {
    let os = std::env::consts::OS.to_string();
    let kernel_release = fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|s| s.trim().to_string());
    let af_xdp_supported = af_xdp_supported();
    let interfaces = probe_interfaces();
    let default_route_interface = default_route_interface();
    let capabilities_permitted = probe_capabilities();
    let memlock_bytes = parse_memlock_limit();
    let page_size_bytes = page_size();

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

fn af_xdp_supported() -> bool {
    #[cfg(target_os = "linux")]
    {
        // Safety: direct libc socket call.
        let fd = unsafe { libc::socket(libc::AF_XDP, libc::SOCK_RAW, 0) };
        if fd < 0 {
            return false;
        }
        // Safety: fd was just returned by socket and is valid.
        let _owned = unsafe { OwnedFd::from_raw_fd(fd) };
        true
    }

    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

fn probe_interfaces() -> Vec<InterfaceInfo> {
    let net_dir = Path::new("/sys/class/net");
    let mut interfaces = Vec::new();

    let entries = match fs::read_dir(net_dir) {
        Ok(entries) => entries,
        Err(_) => return interfaces,
    };

    for entry in entries.flatten() {
        let iface = entry.file_name().to_string_lossy().to_string();
        let base = net_dir.join(&iface);
        let has_device = base.join("device").exists();
        let is_bond = base.join("bonding").exists();
        let tx_queues = count_tx_queues(&base);
        let has_ipv4 = iface_has_ipv4(&iface);

        interfaces.push(InterfaceInfo {
            name: iface,
            has_device,
            is_bond,
            tx_queues,
            has_ipv4,
        });
    }

    interfaces.sort_by(|a, b| a.name.cmp(&b.name));
    interfaces
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

fn default_route_interface() -> Option<String> {
    let route = fs::read_to_string("/proc/net/route").ok()?;
    for line in route.lines().skip(1) {
        let cols = line.split_whitespace().collect::<Vec<_>>();
        if cols.len() < 3 {
            continue;
        }
        let iface = cols[0];
        let destination = cols[1];
        if destination == "00000000" {
            return Some(iface.to_string());
        }
    }
    None
}

fn probe_capabilities() -> CapabilityState {
    let mut cap_prm = 0u64;

    if let Ok(status) = fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if let Some(hex) = line.strip_prefix("CapPrm:\t") {
                if let Ok(bits) = u64::from_str_radix(hex.trim(), 16) {
                    cap_prm = bits;
                }
                break;
            }
        }
    }

    CapabilityState {
        cap_net_admin: bit_set(cap_prm, CAP_NET_ADMIN_BIT),
        cap_net_raw: bit_set(cap_prm, CAP_NET_RAW_BIT),
        cap_bpf: bit_set(cap_prm, CAP_BPF_BIT),
        cap_perfmon: bit_set(cap_prm, CAP_PERFMON_BIT),
    }
}

fn bit_set(mask: u64, bit: u32) -> bool {
    if bit >= 64 {
        return false;
    }
    (mask & (1u64 << bit)) != 0
}

fn parse_memlock_limit() -> Option<u64> {
    let limits = fs::read_to_string("/proc/self/limits").ok()?;

    for line in limits.lines() {
        if !line.starts_with("Max locked memory") {
            continue;
        }

        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 4 {
            return None;
        }

        // format: Max locked memory  8388608  8388608  bytes
        let soft = fields[3];
        if soft.eq_ignore_ascii_case("unlimited") {
            return Some(u64::MAX);
        }

        return soft.parse::<u64>().ok();
    }

    None
}

fn page_size() -> u64 {
    // Safety: sysconf call with static name.
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if size <= 0 { 4096 } else { size as u64 }
}

fn iface_has_ipv4(iface: &str) -> bool {
    #[cfg(target_os = "linux")]
    {
        iface_has_ipv4_linux(iface).unwrap_or(false)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = iface;
        false
    }
}

#[cfg(target_os = "linux")]
fn iface_has_ipv4_linux(iface: &str) -> io::Result<bool> {
    let ifname = CString::new(iface)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid iface"))?;

    // Safety: direct libc socket call.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
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
        return if err.kind() == io::ErrorKind::AddrNotAvailable
            || err.raw_os_error() == Some(libc::EADDRNOTAVAIL)
            || err.raw_os_error() == Some(libc::ENODEV)
        {
            Ok(false)
        } else {
            Err(err)
        };
    }

    Ok(true)
}
