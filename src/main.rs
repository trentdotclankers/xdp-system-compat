use clap::{Parser, Subcommand};
use xdp_system_compat::{
    e2e::{self, E2eConfig},
    model::{
        E2eReport, E2eStatus, HostSnapshot, InterfaceInfo, ProbeResult, Report, Severity, Summary,
    },
    probe, rules,
};

#[derive(Debug, Clone, clap::ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Debug, Clone, clap::ValueEnum, PartialEq, Eq)]
enum OutputLevel {
    Basic,
    Extended,
}

#[derive(Debug, Clone, Parser)]
struct ProbeArgs {
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
    #[arg(long, value_enum, default_value_t = OutputLevel::Basic)]
    output_level: OutputLevel,
    #[arg(long, default_value_t = false)]
    verbose: bool,
}

impl Default for ProbeArgs {
    fn default() -> Self {
        Self {
            format: OutputFormat::Text,
            output_level: OutputLevel::Basic,
            verbose: false,
        }
    }
}

#[derive(Debug, Clone, Parser)]
struct E2eArgs {
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
    #[arg(long, default_value_t = false)]
    verbose: bool,
    #[arg(long, default_value_t = false)]
    include_non_physical: bool,
    #[arg(long)]
    interfaces: Option<String>,
    #[arg(long, default_value_t = 500)]
    timeout_ms: u64,
    #[arg(long, default_value_t = 3)]
    retries: u32,
    #[arg(long, default_value_t = 39000)]
    port_base: u16,
}

#[derive(Debug, Subcommand)]
enum Command {
    E2e(E2eArgs),
}

#[derive(Debug, Parser)]
#[command(name = "xdp-system-compat")]
#[command(about = "Probe host compatibility constraints for Agave XDP retransmit")]
struct Cli {
    #[command(flatten)]
    probe: ProbeArgs,
    #[command(subcommand)]
    command: Option<Command>,
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Some(Command::E2e(args)) => run_e2e(args),
        None => run_probe(cli.probe),
    }
}

fn run_probe(args: ProbeArgs) {
    let snapshot = probe::collect_snapshot();
    let evaluation = rules::evaluate(&snapshot);
    let findings = evaluation.findings;
    let passes = evaluation.passes;

    let errors = findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::Error))
        .count();
    let warnings = findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::Warn))
        .count();
    let (blocked_probes, failed_probes, unavailable_probes) = count_probe_states(&snapshot);

    let report = Report {
        summary: Summary {
            errors,
            warnings,
            passed_checks: passes.len(),
            blocked_probes,
            failed_probes,
            unavailable_probes,
        },
        host: snapshot,
        findings,
        passes,
    };

    match args.format {
        OutputFormat::Json => match serde_json::to_string_pretty(&report) {
            Ok(json) => println!("{json}"),
            Err(err) => {
                eprintln!("failed to serialize JSON report: {err}");
                std::process::exit(3);
            }
        },
        OutputFormat::Text => print_text_report(&report, &args.output_level, args.verbose),
    }

    if report.summary.errors > 0 {
        std::process::exit(2);
    }
    if report.summary.warnings > 0 {
        std::process::exit(1);
    }
}

fn run_e2e(args: E2eArgs) {
    let snapshot = probe::collect_snapshot();
    let interfaces = args
        .interfaces
        .as_ref()
        .map(|v| {
            v.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .filter(|v| !v.is_empty());

    let config = E2eConfig {
        interfaces,
        include_non_physical: args.include_non_physical,
        timeout_ms: args.timeout_ms,
        retries: args.retries,
        port_base: args.port_base,
    };

    let report = e2e::run(&snapshot, &config);

    match args.format {
        OutputFormat::Json => match serde_json::to_string_pretty(&report) {
            Ok(json) => println!("{json}"),
            Err(err) => {
                eprintln!("failed to serialize JSON report: {err}");
                std::process::exit(3);
            }
        },
        OutputFormat::Text => print_e2e_text_report(&report, args.verbose),
    }

    if report.summary.failed > 0 {
        std::process::exit(2);
    }
    if report.summary.skipped > 0 {
        std::process::exit(1);
    }
}

fn print_e2e_text_report(report: &E2eReport, verbose: bool) {
    println!("xdp-system-compat e2e");
    println!(
        "  interfaces tested: {} ({} passed, {} failed, {} skipped)",
        report.summary.tested, report.summary.passed, report.summary.failed, report.summary.skipped
    );

    if report.results.is_empty() {
        println!("\nNo interfaces matched e2e test selection.");
        return;
    }

    println!("\nE2E Results:");
    for result in &report.results {
        if !verbose && matches!(result.status, E2eStatus::Skip) {
            continue;
        }
        let status = match result.status {
            E2eStatus::Pass => "PASS",
            E2eStatus::Fail => "FAIL",
            E2eStatus::Skip => "SKIP",
        };
        println!(
            "- {} [{}] attempts={} sent={} recv={}",
            result.interface, status, result.attempts, result.packets_sent, result.packets_received
        );
        println!("  reason: {}", result.reason);
    }
}

fn print_text_report(report: &Report, output_level: &OutputLevel, verbose: bool) {
    println!("xdp-system-compat");
    println!("  os: {}", report.host.os);
    if let Some(release) = &report.host.kernel_release {
        println!("  kernel: {release}");
    }
    println!(
        "  findings: {} error(s), {} warning(s), {} passed; probes: {} blocked, {} failed, {} unavailable",
        report.summary.errors,
        report.summary.warnings,
        report.summary.passed_checks,
        report.summary.blocked_probes,
        report.summary.failed_probes,
        report.summary.unavailable_probes
    );

    if report.findings.is_empty() {
        println!("\nNo compatibility constraints detected.");
    } else {
        println!("\nFindings:");
        for f in &report.findings {
            let severity = match f.severity {
                Severity::Error => "ERROR",
                Severity::Warn => "WARN",
            };
            println!("- [{}] {} {}", f.id, severity, f.title);
            println!("  details: {}", f.details);
            println!("  remediation: {}", f.remediation);
        }
    }
    if report.passes.is_empty() {
        println!("\nChecks Passed: none");
    } else {
        println!("\nChecks Passed:");
        for pass in &report.passes {
            println!("- [{}] {}", pass.id, pass.title);
            println!("  details: {}", pass.details);
        }
    }

    print_operator_context(report, output_level, verbose);
}

fn print_operator_context(report: &Report, output_level: &OutputLevel, verbose: bool) {
    println!("\nOperator Context:");
    let visible_ifaces = visible_interfaces(report, verbose);

    if let ProbeResult::Ok { value: cpu } = &report.host.operator_context.cpu_topology {
        println!("  cpu: {} logical cores online", cpu.logical_core_count);
        println!(
            "  cpu online indexes: {}",
            format_index_ranges(&cpu.online_cores)
        );
        if *output_level == OutputLevel::Extended {
            println!("  smt sibling sets: {:?}", cpu.smt_sibling_sets);
            for core in &cpu.core_to_numa {
                println!(
                    "  cpu core {} -> numa {}",
                    core.core_id,
                    core.numa_node
                        .map(|n| n.to_string())
                        .unwrap_or_else(|| "none".to_string())
                );
            }
        }
    } else {
        println!("  cpu: topology probe unavailable");
    }

    if let ProbeResult::Ok { value: numa } = &report.host.operator_context.numa_topology {
        println!("  numa nodes:");
        if numa.nodes.is_empty() {
            println!("  - none");
        } else {
            for node in &numa.nodes {
                let size_mb = node.mem_total_kb.map(|kb| kb / 1024);
                match size_mb {
                    Some(size_mb) => println!("  - {}: {}MB", node.node_id, size_mb),
                    None => println!("  - {}: unknown", node.node_id),
                }
            }
        }
        if *output_level == OutputLevel::Extended {
            for node in &numa.nodes {
                println!(
                    "  numa node {} details: mem_total_kb={:?} mem_free_kb={:?}",
                    node.node_id, node.mem_total_kb, node.mem_free_kb
                );
            }
        }
    } else {
        println!("  numa nodes: unavailable");
    }

    match &report.host.interfaces {
        ProbeResult::Ok { value: ifaces } => {
            let hidden = ifaces.len().saturating_sub(visible_ifaces.len());
            if hidden == 0 {
                println!("  interfaces: {} discovered", ifaces.len());
            } else {
                println!(
                    "  interfaces: {} discovered ({} hidden)",
                    ifaces.len(),
                    hidden
                );
            }
            for iface in &visible_ifaces {
                let zerocopy = interface_zerocopy(report, &iface.name)
                    .unwrap_or_else(|| "unknown".to_string());
                let driver = probe_ok_value(&iface.driver)
                    .and_then(|d| d.as_deref())
                    .unwrap_or("unknown");
                let mtu = probe_ok_value(&iface.mtu)
                    .map(|m| m.to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                let speed = probe_ok_value(&iface.speed_mbps)
                    .and_then(|s| *s)
                    .map(|s| format!("{s}Mbps"))
                    .unwrap_or_else(|| "unknown".to_string());
                if *output_level == OutputLevel::Basic {
                    println!(
                        "  - {}: driver={} mtu={} speed={} zerocopy={} rxq={} txq={} device={} bond={}",
                        iface.name,
                        driver,
                        mtu,
                        speed,
                        zerocopy,
                        iface.rx_queues,
                        iface.tx_queues,
                        iface.has_device,
                        iface.is_bond
                    );
                    continue;
                }
                println!(
                    "  - {}: driver={} mtu={} speed={} zerocopy={} rxq={} txq={} device={} bond={} operstate={:?} pci={:?} numa={:?}",
                    iface.name,
                    driver,
                    mtu,
                    speed,
                    zerocopy,
                    iface.rx_queues,
                    iface.tx_queues,
                    iface.has_device,
                    iface.is_bond,
                    probe_ok_value(&iface.operstate),
                    probe_ok_value(&iface.pci_address),
                    probe_ok_value(&iface.numa_node),
                );
            }
        }
        _ => println!("  interfaces: inventory probe unavailable"),
    }

    if let ProbeResult::Ok { value: iface_irqs } = &report.host.operator_context.irq_topology {
        let total_irqs: usize = iface_irqs
            .iter()
            .filter(|iface| visible_ifaces.iter().any(|v| v.name == iface.interface))
            .map(|iface| iface.irqs.len())
            .sum();
        println!("  irqs: {} mapped", total_irqs);
        if *output_level == OutputLevel::Extended {
            for iface in iface_irqs {
                if !visible_ifaces.iter().any(|v| v.name == iface.interface) {
                    continue;
                }
                println!("  irq map for {}:", iface.interface);
                for irq in &iface.irqs {
                    println!(
                        "    irq {} -> affinity {:?}",
                        irq.irq,
                        probe_ok_value(&irq.smp_affinity_list)
                    );
                }
            }
        }
    } else {
        println!("  irqs: topology probe unavailable");
    }

    if let ProbeResult::Ok { value: queue_maps } = &report.host.operator_context.queue_cpu_masks {
        let shown = queue_maps
            .iter()
            .filter(|iface| visible_ifaces.iter().any(|v| v.name == iface.interface))
            .count();
        println!(
            "  queue cpu masks: {} shown ({} interface entries)",
            shown,
            queue_maps.len()
        );
        if *output_level == OutputLevel::Extended {
            for iface in queue_maps {
                if !visible_ifaces.iter().any(|v| v.name == iface.interface) {
                    continue;
                }
                println!("  queue masks for {}:", iface.interface);
                for queue in &iface.queues {
                    println!(
                        "    {} rps={:?} xps={:?}",
                        queue.queue,
                        probe_ok_value(&queue.rps_cpus),
                        probe_ok_value(&queue.xps_cpus)
                    );
                }
            }
        }
    } else {
        println!("  queue cpu masks: probe unavailable");
    }

    if let ProbeResult::Ok {
        value: xdp_statuses,
    } = &report.host.operator_context.xdp_interface_status
    {
        let shown = xdp_statuses
            .iter()
            .filter(|status| visible_ifaces.iter().any(|v| v.name == status.interface))
            .count();
        println!(
            "  xdp interface status: {} shown ({} interface entries)",
            shown,
            xdp_statuses.len()
        );
        if *output_level == OutputLevel::Extended {
            for status in xdp_statuses {
                if !visible_ifaces.iter().any(|v| v.name == status.interface) {
                    continue;
                }
                println!(
                    "  xdp {}: mode={:?} prog_id={:?} zerocopy={:?} evidence={}",
                    status.interface,
                    probe_ok_value(&status.xdp_mode),
                    probe_ok_value(&status.xdp_prog_id),
                    status.zerocopy_feasibility,
                    status.zerocopy_evidence
                );
            }
        }
    } else {
        println!("  xdp interface status: probe unavailable");
    }

    if let ProbeResult::Ok { value: env } = &report.host.operator_context.bpf_environment {
        println!(
            "  bpf environment: {}; {}; {}",
            format_bpffs_mountpoint(&env.bpffs_mounted),
            format_hugepages_value("configured huge pages", &env.hugepages_total),
            format_hugepages_value("free huge pages", &env.hugepages_free),
        );
    } else {
        println!("  bpf environment: probe unavailable");
    }
}

fn visible_interfaces(report: &Report, verbose: bool) -> Vec<&InterfaceInfo> {
    match &report.host.interfaces {
        ProbeResult::Ok { value: ifaces } => ifaces
            .iter()
            .filter(|iface| verbose || iface.has_device)
            .collect(),
        ProbeResult::Blocked { .. }
        | ProbeResult::Failed { .. }
        | ProbeResult::Unavailable { .. } => Vec::new(),
    }
}

fn interface_zerocopy(report: &Report, interface: &str) -> Option<String> {
    let ProbeResult::Ok { value: statuses } = &report.host.operator_context.xdp_interface_status
    else {
        return None;
    };
    statuses
        .iter()
        .find(|s| s.interface == interface)
        .map(|s| format!("{:?}", s.zerocopy_feasibility).to_lowercase())
}

fn probe_ok_value<T>(probe: &ProbeResult<T>) -> Option<&T> {
    match probe {
        ProbeResult::Ok { value } => Some(value),
        ProbeResult::Blocked { .. }
        | ProbeResult::Failed { .. }
        | ProbeResult::Unavailable { .. } => None,
    }
}

fn format_bpffs_mountpoint(bpffs_mounted: &ProbeResult<bool>) -> String {
    match bpffs_mounted {
        ProbeResult::Ok { value: true } => "bpffs mountpoint: /sys/fs/bpf".to_string(),
        ProbeResult::Ok { value: false } => "bpffs mountpoint: unmounted".to_string(),
        ProbeResult::Blocked { .. }
        | ProbeResult::Failed { .. }
        | ProbeResult::Unavailable { .. } => "bpffs mountpoint: unknown".to_string(),
    }
}

fn format_hugepages_value(label: &str, value: &ProbeResult<u64>) -> String {
    match value {
        ProbeResult::Ok { value } => format!("{label}: {value}"),
        ProbeResult::Blocked { .. }
        | ProbeResult::Failed { .. }
        | ProbeResult::Unavailable { .. } => {
            format!("{label}: unknown")
        }
    }
}

fn format_index_ranges(values: &[usize]) -> String {
    if values.is_empty() {
        return "none".to_string();
    }

    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    sorted.dedup();

    let mut parts = Vec::new();
    let mut start = sorted[0];
    let mut prev = sorted[0];

    for &v in sorted.iter().skip(1) {
        if v == prev + 1 {
            prev = v;
            continue;
        }
        if start == prev {
            parts.push(start.to_string());
        } else {
            parts.push(format!("{start}-{prev}"));
        }
        start = v;
        prev = v;
    }

    if start == prev {
        parts.push(start.to_string());
    } else {
        parts.push(format!("{start}-{prev}"));
    }

    parts.join(",")
}

fn count_probe_states(snapshot: &HostSnapshot) -> (usize, usize, usize) {
    let mut blocked = 0usize;
    let mut failed = 0usize;
    let mut unavailable = 0usize;

    accumulate_probe_state(
        &snapshot.af_xdp_supported,
        &mut blocked,
        &mut failed,
        &mut unavailable,
    );
    accumulate_probe_state(
        &snapshot.interfaces,
        &mut blocked,
        &mut failed,
        &mut unavailable,
    );
    accumulate_probe_state(
        &snapshot.default_route_interface,
        &mut blocked,
        &mut failed,
        &mut unavailable,
    );
    accumulate_probe_state(
        &snapshot.capabilities_permitted,
        &mut blocked,
        &mut failed,
        &mut unavailable,
    );
    accumulate_probe_state(
        &snapshot.memlock_bytes,
        &mut blocked,
        &mut failed,
        &mut unavailable,
    );
    accumulate_probe_state(
        &snapshot.operator_context.cpu_topology,
        &mut blocked,
        &mut failed,
        &mut unavailable,
    );
    accumulate_probe_state(
        &snapshot.operator_context.numa_topology,
        &mut blocked,
        &mut failed,
        &mut unavailable,
    );
    accumulate_probe_state(
        &snapshot.operator_context.irq_topology,
        &mut blocked,
        &mut failed,
        &mut unavailable,
    );
    accumulate_probe_state(
        &snapshot.operator_context.queue_cpu_masks,
        &mut blocked,
        &mut failed,
        &mut unavailable,
    );
    accumulate_probe_state(
        &snapshot.operator_context.xdp_interface_status,
        &mut blocked,
        &mut failed,
        &mut unavailable,
    );
    accumulate_probe_state(
        &snapshot.operator_context.bpf_environment,
        &mut blocked,
        &mut failed,
        &mut unavailable,
    );

    if let ProbeResult::Ok { value: interfaces } = &snapshot.interfaces {
        for iface in interfaces {
            accumulate_probe_state(&iface.has_ipv4, &mut blocked, &mut failed, &mut unavailable);
            accumulate_probe_state(&iface.driver, &mut blocked, &mut failed, &mut unavailable);
            accumulate_probe_state(
                &iface.pci_address,
                &mut blocked,
                &mut failed,
                &mut unavailable,
            );
            accumulate_probe_state(
                &iface.numa_node,
                &mut blocked,
                &mut failed,
                &mut unavailable,
            );
            accumulate_probe_state(
                &iface.operstate,
                &mut blocked,
                &mut failed,
                &mut unavailable,
            );
            accumulate_probe_state(&iface.mtu, &mut blocked, &mut failed, &mut unavailable);
            accumulate_probe_state(
                &iface.speed_mbps,
                &mut blocked,
                &mut failed,
                &mut unavailable,
            );
        }
    }

    if let ProbeResult::Ok { value: iface_irqs } = &snapshot.operator_context.irq_topology {
        for iface in iface_irqs {
            for irq in &iface.irqs {
                accumulate_probe_state(
                    &irq.smp_affinity_list,
                    &mut blocked,
                    &mut failed,
                    &mut unavailable,
                );
            }
        }
    }
    if let ProbeResult::Ok { value: queue_maps } = &snapshot.operator_context.queue_cpu_masks {
        for iface in queue_maps {
            for queue in &iface.queues {
                accumulate_probe_state(
                    &queue.rps_cpus,
                    &mut blocked,
                    &mut failed,
                    &mut unavailable,
                );
                accumulate_probe_state(
                    &queue.xps_cpus,
                    &mut blocked,
                    &mut failed,
                    &mut unavailable,
                );
            }
        }
    }
    if let ProbeResult::Ok {
        value: xdp_statuses,
    } = &snapshot.operator_context.xdp_interface_status
    {
        for status in xdp_statuses {
            accumulate_probe_state(
                &status.xdp_mode,
                &mut blocked,
                &mut failed,
                &mut unavailable,
            );
            accumulate_probe_state(
                &status.xdp_prog_id,
                &mut blocked,
                &mut failed,
                &mut unavailable,
            );
        }
    }
    if let ProbeResult::Ok { value: env } = &snapshot.operator_context.bpf_environment {
        accumulate_probe_state(
            &env.bpffs_mounted,
            &mut blocked,
            &mut failed,
            &mut unavailable,
        );
        accumulate_probe_state(
            &env.hugepages_total,
            &mut blocked,
            &mut failed,
            &mut unavailable,
        );
        accumulate_probe_state(
            &env.hugepages_free,
            &mut blocked,
            &mut failed,
            &mut unavailable,
        );
    }

    (blocked, failed, unavailable)
}

fn accumulate_probe_state<T>(
    probe: &ProbeResult<T>,
    blocked: &mut usize,
    failed: &mut usize,
    unavailable: &mut usize,
) {
    match probe {
        ProbeResult::Ok { .. } => {}
        ProbeResult::Blocked { .. } => *blocked += 1,
        ProbeResult::Failed { .. } => *failed += 1,
        ProbeResult::Unavailable { .. } => *unavailable += 1,
    }
}
