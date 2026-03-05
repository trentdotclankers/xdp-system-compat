use {
    crate::model::{
        E2eInterfaceResult, E2eReport, E2eStatus, E2eSummary, HostSnapshot, ProbeResult,
    },
    std::{
        ffi::CString,
        io,
        net::{Ipv4Addr, SocketAddrV4, UdpSocket},
        os::fd::{AsRawFd, FromRawFd},
        time::Duration,
    },
};

#[derive(Debug, Clone)]
pub struct E2eConfig {
    pub interfaces: Option<Vec<String>>,
    pub include_non_physical: bool,
    pub timeout_ms: u64,
    pub retries: u32,
    pub port_base: u16,
}

pub fn run(snapshot: &HostSnapshot, config: &E2eConfig) -> E2eReport {
    let mut results = Vec::new();

    if snapshot.os != "linux" {
        results.push(E2eInterfaceResult {
            interface: "<all>".to_string(),
            status: E2eStatus::Skip,
            reason: "e2e xdp tests are only supported on linux".to_string(),
            packets_sent: 0,
            packets_received: 0,
            attempts: 0,
        });
        return finalize(results);
    }

    let ifaces = match &snapshot.interfaces {
        ProbeResult::Ok { value } => value,
        ProbeResult::Blocked { reason }
        | ProbeResult::Failed { reason }
        | ProbeResult::Unavailable { reason } => {
            results.push(E2eInterfaceResult {
                interface: "<all>".to_string(),
                status: E2eStatus::Skip,
                reason: format!("interface inventory unavailable: {reason}"),
                packets_sent: 0,
                packets_received: 0,
                attempts: 0,
            });
            return finalize(results);
        }
    };

    for (index, iface) in ifaces.iter().enumerate() {
        if let Some(filter) = &config.interfaces {
            if !filter.iter().any(|candidate| candidate == &iface.name) {
                continue;
            }
        }

        if !config.include_non_physical && !iface.has_device {
            continue;
        }

        if !matches!(iface.operstate, ProbeResult::Ok { value: ref s } if s == "up") {
            results.push(E2eInterfaceResult {
                interface: iface.name.clone(),
                status: E2eStatus::Skip,
                reason: "interface is not up".to_string(),
                packets_sent: 0,
                packets_received: 0,
                attempts: 0,
            });
            continue;
        }

        let Some(ipv4_addr) = interface_ipv4_addr(&iface.name) else {
            results.push(E2eInterfaceResult {
                interface: iface.name.clone(),
                status: E2eStatus::Skip,
                reason: "interface has no usable ipv4 address".to_string(),
                packets_sent: 0,
                packets_received: 0,
                attempts: 0,
            });
            continue;
        };

        let base = u32::from(config.port_base);
        let offset = (index as u32).saturating_mul(config.retries + 1);
        let result = run_interface_test(&iface.name, ipv4_addr, base + offset, config);
        results.push(result);
    }

    finalize(results)
}

fn finalize(results: Vec<E2eInterfaceResult>) -> E2eReport {
    let passed = results
        .iter()
        .filter(|r| r.status == E2eStatus::Pass)
        .count();
    let failed = results
        .iter()
        .filter(|r| r.status == E2eStatus::Fail)
        .count();
    let skipped = results
        .iter()
        .filter(|r| r.status == E2eStatus::Skip)
        .count();
    let tested = results.len();

    E2eReport {
        summary: E2eSummary {
            tested,
            passed,
            failed,
            skipped,
        },
        results,
    }
}

fn run_interface_test(
    interface: &str,
    ipv4_addr: Ipv4Addr,
    port_seed: u32,
    config: &E2eConfig,
) -> E2eInterfaceResult {
    let timeout = Duration::from_millis(config.timeout_ms.max(1));

    let mut packets_sent = 0u64;
    let mut packets_received = 0u64;

    for attempt in 1..=config.retries.max(1) {
        let port = (port_seed + attempt).clamp(1024, u16::MAX as u32) as u16;
        let bind_addr = SocketAddrV4::new(ipv4_addr, port);
        let server = match udp_bind(bind_addr) {
            Ok(sock) => sock,
            Err(err) => {
                return E2eInterfaceResult {
                    interface: interface.to_string(),
                    status: E2eStatus::Fail,
                    reason: format!("failed to bind server socket on {bind_addr}: {err}"),
                    packets_sent,
                    packets_received,
                    attempts: attempt,
                };
            }
        };

        if let Err(err) = bind_to_device(&server, interface) {
            return E2eInterfaceResult {
                interface: interface.to_string(),
                status: E2eStatus::Skip,
                reason: format!("failed to bind server socket to interface {interface}: {err}"),
                packets_sent,
                packets_received,
                attempts: attempt,
            };
        }

        if let Err(err) = server.set_read_timeout(Some(timeout)) {
            return E2eInterfaceResult {
                interface: interface.to_string(),
                status: E2eStatus::Fail,
                reason: format!("failed setting server timeout: {err}"),
                packets_sent,
                packets_received,
                attempts: attempt,
            };
        }

        let client = match udp_bind(SocketAddrV4::new(ipv4_addr, 0)) {
            Ok(sock) => sock,
            Err(err) => {
                return E2eInterfaceResult {
                    interface: interface.to_string(),
                    status: E2eStatus::Fail,
                    reason: format!("failed to bind client socket to {ipv4_addr}: {err}"),
                    packets_sent,
                    packets_received,
                    attempts: attempt,
                };
            }
        };

        if let Err(err) = bind_to_device(&client, interface) {
            return E2eInterfaceResult {
                interface: interface.to_string(),
                status: E2eStatus::Skip,
                reason: format!("failed to bind client socket to interface {interface}: {err}"),
                packets_sent,
                packets_received,
                attempts: attempt,
            };
        }

        let payload = format!("xdp-e2e:{interface}:{attempt}:{port}").into_bytes();

        match client.send_to(&payload, bind_addr) {
            Ok(_) => packets_sent += 1,
            Err(err) => {
                return E2eInterfaceResult {
                    interface: interface.to_string(),
                    status: E2eStatus::Fail,
                    reason: format!("client send failed: {err}"),
                    packets_sent,
                    packets_received,
                    attempts: attempt,
                };
            }
        }

        let mut buf = vec![0u8; payload.len().saturating_add(64)];
        match server.recv_from(&mut buf) {
            Ok((n, _)) => {
                packets_received += 1;
                let received = &buf[..n];
                if received == payload.as_slice() {
                    return E2eInterfaceResult {
                        interface: interface.to_string(),
                        status: E2eStatus::Pass,
                        reason: "udp client/server roundtrip succeeded via interface binding"
                            .to_string(),
                        packets_sent,
                        packets_received,
                        attempts: attempt,
                    };
                }
            }
            Err(err)
                if err.kind() == io::ErrorKind::WouldBlock
                    || err.kind() == io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(err) => {
                return E2eInterfaceResult {
                    interface: interface.to_string(),
                    status: E2eStatus::Fail,
                    reason: format!("server receive failed: {err}"),
                    packets_sent,
                    packets_received,
                    attempts: attempt,
                };
            }
        }
    }

    E2eInterfaceResult {
        interface: interface.to_string(),
        status: E2eStatus::Fail,
        reason: "timed out waiting for e2e test payload".to_string(),
        packets_sent,
        packets_received,
        attempts: config.retries.max(1),
    }
}

fn bind_to_device(socket: &UdpSocket, interface: &str) -> io::Result<()> {
    let iface = CString::new(interface).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface name contains interior null byte",
        )
    })?;

    // Safety: setsockopt with valid fd and pointer to a NUL-terminated interface string.
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            iface.as_ptr() as *const libc::c_void,
            iface.as_bytes_with_nul().len() as libc::socklen_t,
        )
    };

    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn interface_ipv4_addr(interface: &str) -> Option<Ipv4Addr> {
    let ifname = CString::new(interface).ok()?;

    // Safety: direct libc call with static params.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return None;
    }

    // Safety: fd returned by socket.
    let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };

    // Safety: zeroed ifreq is valid initial memory.
    let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
    let name = ifname.as_bytes_with_nul();
    let len = name.len().min(libc::IF_NAMESIZE);
    // Safety: destination buffer is valid and bounded.
    unsafe {
        std::ptr::copy_nonoverlapping(
            name.as_ptr() as *const libc::c_char,
            req.ifr_name.as_mut_ptr(),
            len,
        );
    }

    // Safety: valid fd and pointer for ioctl.
    let res = unsafe { libc::ioctl(fd.as_raw_fd(), libc::SIOCGIFADDR, &mut req) };
    if res < 0 {
        return None;
    }

    // Safety: SIOCGIFADDR returned success, addr is populated.
    let addr = unsafe {
        let addr_ptr = &req.ifr_ifru.ifru_addr as *const libc::sockaddr;
        let sin_addr = (*(addr_ptr as *const libc::sockaddr_in)).sin_addr;
        Ipv4Addr::from(sin_addr.s_addr.to_ne_bytes())
    };

    Some(addr)
}

#[allow(clippy::disallowed_methods)]
fn udp_bind(addr: SocketAddrV4) -> io::Result<UdpSocket> {
    UdpSocket::bind(addr)
}
