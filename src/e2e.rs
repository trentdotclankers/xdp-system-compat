use crate::model::{
    E2eInterfaceResult, E2eModeResult, E2eReport, E2eStatus, E2eSummary, HostSnapshot, ProbeResult,
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
            reason: "AF_XDP probe is only supported on linux".to_string(),
            copy_mode: mode_skip("AF_XDP probe is only supported on linux"),
            zerocopy_mode: mode_skip("AF_XDP probe is only supported on linux"),
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
                reason: format!(
                    "AF_XDP probe could not run: interface inventory unavailable: {reason}"
                ),
                copy_mode: mode_skip(&format!(
                    "AF_XDP probe could not run: interface inventory unavailable: {reason}"
                )),
                zerocopy_mode: mode_skip(&format!(
                    "AF_XDP probe could not run: interface inventory unavailable: {reason}"
                )),
                packets_sent: 0,
                packets_received: 0,
                attempts: 0,
            });
            return finalize(results);
        }
    };

    for iface in ifaces {
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
                reason: "AF_XDP probe skipped: interface is not up".to_string(),
                copy_mode: mode_skip("AF_XDP probe skipped: interface is not up"),
                zerocopy_mode: mode_skip("AF_XDP probe skipped: interface is not up"),
                packets_sent: 0,
                packets_received: 0,
                attempts: 0,
            });
            continue;
        }

        if iface.rx_queues == 0 || iface.tx_queues == 0 {
            results.push(E2eInterfaceResult {
                interface: iface.name.clone(),
                status: E2eStatus::Skip,
                reason: "AF_XDP probe skipped: interface has no rx/tx queues".to_string(),
                copy_mode: mode_skip("AF_XDP probe skipped: interface has no rx/tx queues"),
                zerocopy_mode: mode_skip("AF_XDP probe skipped: interface has no rx/tx queues"),
                packets_sent: 0,
                packets_received: 0,
                attempts: 0,
            });
            continue;
        }

        let attempts = config.retries.max(1);
        let mut last_err: Option<String> = None;
        let mut mode_result: Option<(E2eModeResult, E2eModeResult)> = None;

        for _ in 0..attempts {
            match run_af_xdp_probe(&iface.name) {
                Ok(probe) => {
                    let copy = mode_pass(
                        "AF_XDP copy-mode probe passed: socket + UMEM + rings + bind succeeded",
                    );
                    let zerocopy = match probe.zerocopy_error {
                        None => mode_pass(
                            "AF_XDP zerocopy probe passed: socket + UMEM + rings + bind succeeded",
                        ),
                        Some(err) => mode_fail(&format!("AF_XDP zerocopy probe failed: {err}")),
                    };
                    mode_result = Some((copy, zerocopy));
                    break;
                }
                Err(AfXdpProbeError::Permission(err)) => {
                    let blocked =
                        format!("AF_XDP probe blocked by permissions/capabilities: {err}");
                    results.push(E2eInterfaceResult {
                        interface: iface.name.clone(),
                        status: E2eStatus::Skip,
                        reason: blocked.clone(),
                        copy_mode: mode_skip(&blocked),
                        zerocopy_mode: mode_skip(&blocked),
                        packets_sent: 0,
                        packets_received: 0,
                        attempts: 0,
                    });
                    last_err = None;
                    break;
                }
                Err(AfXdpProbeError::Incompatible(err)) => {
                    last_err = Some(err);
                }
                Err(AfXdpProbeError::Transient(err)) => {
                    last_err = Some(err);
                }
            }
        }

        if let Some((copy_mode, zerocopy_mode)) = mode_result {
            results.push(E2eInterfaceResult {
                interface: iface.name.clone(),
                status: E2eStatus::Pass,
                reason: copy_mode.reason.clone(),
                copy_mode,
                zerocopy_mode,
                packets_sent: 0,
                packets_received: 0,
                attempts,
            });
            continue;
        }

        if let Some(reason) = last_err {
            let failed = format!("AF_XDP probe failed: {reason}");
            results.push(E2eInterfaceResult {
                interface: iface.name.clone(),
                status: E2eStatus::Fail,
                reason: failed.clone(),
                copy_mode: mode_fail(&failed),
                zerocopy_mode: mode_fail(&failed),
                packets_sent: 0,
                packets_received: 0,
                attempts,
            });
        }
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

#[derive(Debug)]
enum AfXdpProbeError {
    Permission(String),
    Incompatible(String),
    Transient(String),
}

#[derive(Debug)]
struct AfXdpProbeSuccess {
    zerocopy_error: Option<String>,
}

#[cfg(target_os = "linux")]
fn run_af_xdp_probe(interface: &str) -> Result<AfXdpProbeSuccess, AfXdpProbeError> {
    use {
        caps::{
            CapSet,
            Capability::{CAP_NET_RAW, CAP_SYS_ADMIN},
        },
        std::{
            ffi::CString,
            io, mem,
            os::fd::{AsRawFd, FromRawFd},
            ptr,
        },
    };

    fn is_perm(err: &io::Error) -> bool {
        matches!(err.raw_os_error(), Some(libc::EPERM | libc::EACCES))
    }

    let ifname = CString::new(interface)
        .map_err(|_| AfXdpProbeError::Transient("invalid interface name".to_string()))?;

    // Safety: libc wrapper with valid c string pointer.
    let ifindex = unsafe { libc::if_nametoindex(ifname.as_ptr()) };
    if ifindex == 0 {
        return Err(AfXdpProbeError::Incompatible(format!(
            "interface '{interface}' has no ifindex"
        )));
    }

    let permitted = caps::read(None, CapSet::Permitted)
        .map_err(|e| AfXdpProbeError::Transient(format!("read permitted caps failed: {e}")))?;
    if !permitted.contains(&CAP_NET_RAW) {
        return Err(AfXdpProbeError::Permission(
            "CAP_NET_RAW is not in permitted set".to_string(),
        ));
    }

    let mut raised = Vec::new();
    for cap in [CAP_NET_RAW, CAP_SYS_ADMIN] {
        if permitted.contains(&cap) && caps::raise(None, CapSet::Effective, cap).is_ok() {
            raised.push(cap);
        }
    }

    // Safety: direct syscall wrapper.
    let fd = unsafe { libc::socket(libc::AF_XDP, libc::SOCK_RAW, 0) };
    if fd < 0 {
        let err = io::Error::last_os_error();
        for cap in raised.iter().rev() {
            let _ = caps::drop(None, CapSet::Effective, *cap);
        }
        if is_perm(&err) {
            return Err(AfXdpProbeError::Permission(format!(
                "socket(AF_XDP) denied: {err}"
            )));
        }
        return Err(AfXdpProbeError::Incompatible(format!(
            "socket(AF_XDP) failed: {err}"
        )));
    }

    // Safety: fd is from socket.
    let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };

    let chunk_size = 4096usize;
    let frame_count = 256usize;
    let len = chunk_size * frame_count;

    // Safety: anonymous private mapping.
    let umem_ptr = unsafe {
        libc::mmap(
            ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if std::ptr::eq(umem_ptr, libc::MAP_FAILED) {
        let err = io::Error::last_os_error();
        for cap in raised.iter().rev() {
            let _ = caps::drop(None, CapSet::Effective, *cap);
        }
        return Err(AfXdpProbeError::Transient(format!(
            "umem mmap failed: {err}"
        )));
    }

    // Safety: plain data struct.
    let mut reg: libc::xdp_umem_reg = unsafe { mem::zeroed() };
    reg.addr = umem_ptr as u64;
    reg.len = len as u64;
    reg.chunk_size = chunk_size as u32;
    reg.headroom = 0;
    reg.flags = 0;
    reg.tx_metadata_len = 0;

    // Safety: valid fd and pointer to reg.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_XDP,
            libc::XDP_UMEM_REG,
            &reg as *const _ as *const libc::c_void,
            mem::size_of::<libc::xdp_umem_reg>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        let err = io::Error::last_os_error();
        // Safety: unmap pointer allocated above.
        unsafe {
            libc::munmap(umem_ptr, len);
        }
        for cap in raised.iter().rev() {
            let _ = caps::drop(None, CapSet::Effective, *cap);
        }
        if is_perm(&err) {
            return Err(AfXdpProbeError::Permission(format!(
                "XDP_UMEM_REG denied: {err}"
            )));
        }
        return Err(AfXdpProbeError::Incompatible(format!(
            "XDP_UMEM_REG failed: {err}"
        )));
    }

    let ring_size: u32 = 64;
    for ring in [
        libc::XDP_UMEM_COMPLETION_RING,
        libc::XDP_UMEM_FILL_RING,
        libc::XDP_TX_RING,
        libc::XDP_RX_RING,
    ] {
        // Safety: valid fd and pointer to ring size.
        let rc = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_XDP,
                ring,
                &ring_size as *const _ as *const libc::c_void,
                mem::size_of::<u32>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            let err = io::Error::last_os_error();
            // Safety: unmap pointer allocated above.
            unsafe {
                libc::munmap(umem_ptr, len);
            }
            for cap in raised.iter().rev() {
                let _ = caps::drop(None, CapSet::Effective, *cap);
            }
            if is_perm(&err) {
                return Err(AfXdpProbeError::Permission(format!(
                    "setting XDP ring {ring} denied: {err}"
                )));
            }
            return Err(AfXdpProbeError::Incompatible(format!(
                "setting XDP ring {ring} failed: {err}"
            )));
        }
    }

    let copy_ok = bind_xdp_socket(fd.as_raw_fd(), ifindex, false);
    let zc_ok = bind_xdp_socket(fd.as_raw_fd(), ifindex, true).err();

    // Safety: unmap pointer allocated above.
    unsafe {
        libc::munmap(umem_ptr, len);
    }
    for cap in raised.iter().rev() {
        let _ = caps::drop(None, CapSet::Effective, *cap);
    }

    match copy_ok {
        Ok(()) => Ok(AfXdpProbeSuccess {
            zerocopy_error: zc_ok.map(|err| err.to_string()),
        }),
        Err(err) => {
            if is_perm(&err) {
                Err(AfXdpProbeError::Permission(format!(
                    "AF_XDP bind denied: {err}"
                )))
            } else {
                Err(AfXdpProbeError::Incompatible(format!(
                    "AF_XDP bind failed: {err}"
                )))
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn bind_xdp_socket(fd: std::os::fd::RawFd, ifindex: u32, zero_copy: bool) -> std::io::Result<()> {
    use std::mem;

    let sxdp = libc::sockaddr_xdp {
        sxdp_family: libc::AF_XDP as libc::sa_family_t,
        sxdp_flags: libc::XDP_USE_NEED_WAKEUP
            | if zero_copy {
                libc::XDP_ZEROCOPY
            } else {
                libc::XDP_COPY
            },
        sxdp_ifindex: ifindex,
        sxdp_queue_id: 0,
        sxdp_shared_umem_fd: 0,
    };

    // Safety: valid fd and socket address data.
    let rc = unsafe {
        libc::bind(
            fd,
            &sxdp as *const _ as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_xdp>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn run_af_xdp_probe(_interface: &str) -> Result<AfXdpProbeSuccess, AfXdpProbeError> {
    Err(AfXdpProbeError::Transient(
        "AF_XDP probe is only supported on linux".to_string(),
    ))
}

fn mode_pass(reason: &str) -> E2eModeResult {
    E2eModeResult {
        status: E2eStatus::Pass,
        reason: reason.to_string(),
    }
}

fn mode_fail(reason: &str) -> E2eModeResult {
    E2eModeResult {
        status: E2eStatus::Fail,
        reason: reason.to_string(),
    }
}

fn mode_skip(reason: &str) -> E2eModeResult {
    E2eModeResult {
        status: E2eStatus::Skip,
        reason: reason.to_string(),
    }
}
