use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Error,
    Warn,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub id: &'static str,
    pub severity: Severity,
    pub title: &'static str,
    pub details: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ProbeResult<T> {
    Ok { value: T },
    Blocked { reason: String },
    Failed { reason: String },
    Unavailable { reason: String },
}

impl<T> ProbeResult<T> {
    pub fn ok(value: T) -> Self {
        Self::Ok { value }
    }

    pub fn as_ref(&self) -> ProbeResult<&T> {
        match self {
            Self::Ok { value } => ProbeResult::Ok { value },
            Self::Blocked { reason } => ProbeResult::Blocked {
                reason: reason.clone(),
            },
            Self::Failed { reason } => ProbeResult::Failed {
                reason: reason.clone(),
            },
            Self::Unavailable { reason } => ProbeResult::Unavailable {
                reason: reason.clone(),
            },
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct InterfaceInfo {
    pub name: String,
    pub has_device: bool,
    pub is_bond: bool,
    pub rx_queues: usize,
    pub tx_queues: usize,
    pub driver: ProbeResult<Option<String>>,
    pub pci_address: ProbeResult<Option<String>>,
    pub numa_node: ProbeResult<Option<usize>>,
    pub operstate: ProbeResult<String>,
    pub mtu: ProbeResult<u32>,
    pub speed_mbps: ProbeResult<Option<u64>>,
    pub has_ipv4: ProbeResult<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CpuCoreInfo {
    pub core_id: usize,
    pub numa_node: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CpuTopologyInfo {
    pub logical_core_count: usize,
    pub online_cores: Vec<usize>,
    pub core_to_numa: Vec<CpuCoreInfo>,
    pub smt_sibling_sets: Vec<Vec<usize>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NumaNodeInfo {
    pub node_id: usize,
    pub mem_total_kb: Option<u64>,
    pub mem_free_kb: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NumaTopologyInfo {
    pub nodes: Vec<NumaNodeInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OperatorContext {
    pub cpu_topology: ProbeResult<CpuTopologyInfo>,
    pub numa_topology: ProbeResult<NumaTopologyInfo>,
    pub irq_topology: ProbeResult<Vec<InterfaceIrqInfo>>,
    pub queue_cpu_masks: ProbeResult<Vec<InterfaceQueueAffinity>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IrqInfo {
    pub irq: u32,
    pub smp_affinity_list: ProbeResult<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct InterfaceIrqInfo {
    pub interface: String,
    pub irqs: Vec<IrqInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct QueueCpuMaskInfo {
    pub queue: String,
    pub rps_cpus: ProbeResult<String>,
    pub xps_cpus: ProbeResult<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct InterfaceQueueAffinity {
    pub interface: String,
    pub queues: Vec<QueueCpuMaskInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CapabilityState {
    pub cap_net_admin: bool,
    pub cap_net_raw: bool,
    pub cap_bpf: bool,
    pub cap_perfmon: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostSnapshot {
    pub os: String,
    pub kernel_release: Option<String>,
    pub af_xdp_supported: ProbeResult<bool>,
    pub interfaces: ProbeResult<Vec<InterfaceInfo>>,
    pub operator_context: OperatorContext,
    pub default_route_interface: ProbeResult<Option<String>>,
    pub capabilities_permitted: ProbeResult<CapabilityState>,
    pub memlock_bytes: ProbeResult<u64>,
    pub page_size_bytes: u64,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub summary: Summary,
    pub host: HostSnapshot,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Serialize)]
pub struct Summary {
    pub errors: usize,
    pub warnings: usize,
    pub blocked_probes: usize,
    pub failed_probes: usize,
    pub unavailable_probes: usize,
}
