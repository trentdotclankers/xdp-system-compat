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
        let queue_count = iface.rx_queues.min(iface.tx_queues).max(1);
        let copy_mode = run_mode_probe_with_retries(&iface.name, queue_count, attempts, false);
        let zerocopy_mode = run_mode_probe_with_retries(&iface.name, queue_count, attempts, true);
        let (status, reason) = derive_interface_status(&copy_mode, &zerocopy_mode);

        results.push(E2eInterfaceResult {
            interface: iface.name.clone(),
            status,
            reason,
            copy_mode,
            zerocopy_mode,
            packets_sent: 0,
            packets_received: 0,
            attempts,
        });
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
    Busy(String),
    Incompatible(String),
    Transient(String),
}

#[cfg(target_os = "linux")]
fn run_af_xdp_probe(
    interface: &str,
    queue_id: u32,
    zero_copy: bool,
) -> Result<(), AfXdpProbeError> {
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

    let bind_result = bind_xdp_socket(fd.as_raw_fd(), ifindex, queue_id, zero_copy);

    // Safety: unmap pointer allocated above.
    unsafe {
        libc::munmap(umem_ptr, len);
    }
    for cap in raised.iter().rev() {
        let _ = caps::drop(None, CapSet::Effective, *cap);
    }

    match bind_result {
        Ok(()) => Ok(()),
        Err(err) => {
            if is_perm(&err) {
                Err(AfXdpProbeError::Permission(format!(
                    "AF_XDP bind denied: {err}"
                )))
            } else if matches!(err.raw_os_error(), Some(libc::EBUSY)) {
                Err(AfXdpProbeError::Busy(format!(
                    "AF_XDP bind queue {queue_id} busy: {err}"
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
fn bind_xdp_socket(
    fd: std::os::fd::RawFd,
    ifindex: u32,
    queue_id: u32,
    zero_copy: bool,
) -> std::io::Result<()> {
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
        sxdp_queue_id: queue_id,
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
fn run_af_xdp_probe(
    _interface: &str,
    _queue_id: u32,
    _zero_copy: bool,
) -> Result<(), AfXdpProbeError> {
    Err(AfXdpProbeError::Transient(
        "AF_XDP probe is only supported on linux".to_string(),
    ))
}

fn run_mode_probe_with_retries(
    interface: &str,
    queue_count: usize,
    attempts: u32,
    zero_copy: bool,
) -> E2eModeResult {
    let mode_name = if zero_copy { "zerocopy" } else { "copy" };
    let mut last_error: Option<String> = None;
    let mut busy_queues = Vec::new();

    for _ in 0..attempts {
        for queue_id in 0..queue_count {
            let queue_id_u32 = match u32::try_from(queue_id) {
                Ok(value) => value,
                Err(_) => {
                    return mode_fail(&format!(
                        "AF_XDP {mode_name} probe failed: queue index {queue_id} exceeds u32 range"
                    ));
                }
            };
            match run_af_xdp_probe(interface, queue_id_u32, zero_copy) {
                Ok(()) => {
                    return mode_pass(&format!(
                        "AF_XDP {mode_name} probe passed: socket + UMEM + rings + bind succeeded on queue {queue_id_u32}"
                    ));
                }
                Err(AfXdpProbeError::Permission(err)) => {
                    return mode_skip(&format!(
                        "AF_XDP {mode_name} probe blocked by permissions/capabilities: {err}"
                    ));
                }
                Err(AfXdpProbeError::Busy(err)) => {
                    if !busy_queues.contains(&queue_id) {
                        busy_queues.push(queue_id);
                    }
                    last_error = Some(err);
                }
                Err(AfXdpProbeError::Incompatible(err)) | Err(AfXdpProbeError::Transient(err)) => {
                    last_error = Some(err);
                }
            }
        }
    }

    if !busy_queues.is_empty() {
        return mode_skip(&format!(
            "AF_XDP {mode_name} probe inconclusive due to queue contention on queues {:?}; last error: {}",
            busy_queues,
            last_error.unwrap_or_else(|| "resource busy".to_string())
        ));
    }

    mode_fail(&format!(
        "AF_XDP {mode_name} probe failed: {}",
        last_error.unwrap_or_else(|| "unknown error".to_string())
    ))
}

fn derive_interface_status(
    copy_mode: &E2eModeResult,
    zerocopy_mode: &E2eModeResult,
) -> (E2eStatus, String) {
    match copy_mode.status {
        E2eStatus::Pass => {
            if zerocopy_mode.status == E2eStatus::Pass {
                (E2eStatus::Pass, copy_mode.reason.clone())
            } else if zerocopy_mode.status == E2eStatus::Fail {
                (
                    E2eStatus::Pass,
                    format!(
                        "{}; zerocopy unavailable: {}",
                        copy_mode.reason, zerocopy_mode.reason
                    ),
                )
            } else {
                (
                    E2eStatus::Pass,
                    format!(
                        "{}; zerocopy inconclusive: {}",
                        copy_mode.reason, zerocopy_mode.reason
                    ),
                )
            }
        }
        E2eStatus::Fail => (E2eStatus::Fail, copy_mode.reason.clone()),
        E2eStatus::Skip => {
            if zerocopy_mode.status == E2eStatus::Fail {
                (
                    E2eStatus::Fail,
                    format!(
                        "{}; zerocopy failed: {}",
                        copy_mode.reason, zerocopy_mode.reason
                    ),
                )
            } else if zerocopy_mode.status == E2eStatus::Pass {
                (
                    E2eStatus::Skip,
                    format!(
                        "{}; zerocopy passed but copy baseline is inconclusive",
                        copy_mode.reason
                    ),
                )
            } else {
                (E2eStatus::Skip, copy_mode.reason.clone())
            }
        }
    }
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
