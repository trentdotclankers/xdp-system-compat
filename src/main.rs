use clap::Parser;
use xdp_system_compat::{
    model::{HostSnapshot, ProbeResult, Report, Severity, Summary},
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

#[derive(Debug, Parser)]
#[command(name = "xdp-system-compat")]
#[command(about = "Probe host compatibility constraints for Agave XDP retransmit")]
struct Cli {
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
    #[arg(long, value_enum, default_value_t = OutputLevel::Basic)]
    output_level: OutputLevel,
}

fn main() {
    let cli = Cli::parse();
    let snapshot = probe::collect_snapshot();
    let findings = rules::evaluate(&snapshot);

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
            blocked_probes,
            failed_probes,
            unavailable_probes,
        },
        host: snapshot,
        findings,
    };

    match cli.format {
        OutputFormat::Json => match serde_json::to_string_pretty(&report) {
            Ok(json) => println!("{json}"),
            Err(err) => {
                eprintln!("failed to serialize JSON report: {err}");
                std::process::exit(3);
            }
        },
        OutputFormat::Text => print_text_report(&report, &cli.output_level),
    }

    if report.summary.errors > 0 {
        std::process::exit(2);
    }
    if report.summary.warnings > 0 {
        std::process::exit(1);
    }
}

fn print_text_report(report: &Report, output_level: &OutputLevel) {
    println!("xdp-system-compat");
    println!("  os: {}", report.host.os);
    if let Some(release) = &report.host.kernel_release {
        println!("  kernel: {release}");
    }
    println!(
        "  findings: {} error(s), {} warning(s); probes: {} blocked, {} failed, {} unavailable",
        report.summary.errors,
        report.summary.warnings,
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

    print_operator_context(report, output_level);
}

fn print_operator_context(report: &Report, output_level: &OutputLevel) {
    println!("\nOperator Context:");

    if let ProbeResult::Ok { value: cpu } = &report.host.operator_context.cpu_topology {
        println!("  cpu: {} logical cores online", cpu.logical_core_count);
        if *output_level == OutputLevel::Extended {
            println!("  cpu online list: {:?}", cpu.online_cores);
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
        println!("  numa: {} node(s)", numa.nodes.len());
        if *output_level == OutputLevel::Extended {
            for node in &numa.nodes {
                println!(
                    "  numa node {}: mem_total_kb={:?} mem_free_kb={:?}",
                    node.node_id, node.mem_total_kb, node.mem_free_kb
                );
            }
        }
    } else {
        println!("  numa: topology probe unavailable");
    }

    match &report.host.interfaces {
        ProbeResult::Ok { value: ifaces } => {
            println!("  interfaces: {} discovered", ifaces.len());
            for iface in ifaces {
                if *output_level == OutputLevel::Basic {
                    println!(
                        "  - {}: rxq={} txq={} device={} bond={}",
                        iface.name,
                        iface.rx_queues,
                        iface.tx_queues,
                        iface.has_device,
                        iface.is_bond
                    );
                    continue;
                }
                println!(
                    "  - {}: rxq={} txq={} device={} bond={} operstate={:?} mtu={:?} speed_mbps={:?} driver={:?} pci={:?} numa={:?}",
                    iface.name,
                    iface.rx_queues,
                    iface.tx_queues,
                    iface.has_device,
                    iface.is_bond,
                    probe_ok_value(&iface.operstate),
                    probe_ok_value(&iface.mtu),
                    probe_ok_value(&iface.speed_mbps),
                    probe_ok_value(&iface.driver),
                    probe_ok_value(&iface.pci_address),
                    probe_ok_value(&iface.numa_node),
                );
            }
        }
        _ => println!("  interfaces: inventory probe unavailable"),
    }

    if let ProbeResult::Ok { value: iface_irqs } = &report.host.operator_context.irq_topology {
        let total_irqs: usize = iface_irqs.iter().map(|iface| iface.irqs.len()).sum();
        println!("  irqs: {} mapped", total_irqs);
        if *output_level == OutputLevel::Extended {
            for iface in iface_irqs {
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
        println!("  queue cpu masks: {} interface entries", queue_maps.len());
        if *output_level == OutputLevel::Extended {
            for iface in queue_maps {
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
        println!(
            "  xdp interface status: {} interface entries",
            xdp_statuses.len()
        );
        if *output_level == OutputLevel::Extended {
            for status in xdp_statuses {
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
            "  bpf environment: bpffs_mounted={:?} hugepages_total={:?} hugepages_free={:?}",
            probe_ok_value(&env.bpffs_mounted),
            probe_ok_value(&env.hugepages_total),
            probe_ok_value(&env.hugepages_free),
        );
    } else {
        println!("  bpf environment: probe unavailable");
    }
}

fn probe_ok_value<T>(probe: &ProbeResult<T>) -> Option<&T> {
    match probe {
        ProbeResult::Ok { value } => Some(value),
        ProbeResult::Blocked { .. }
        | ProbeResult::Failed { .. }
        | ProbeResult::Unavailable { .. } => None,
    }
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
