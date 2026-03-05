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

#[derive(Debug, Parser)]
#[command(name = "xdp-system-compat")]
#[command(about = "Probe host compatibility constraints for Agave XDP retransmit")]
struct Cli {
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
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
        OutputFormat::Text => print_text_report(&report),
    }

    if report.summary.errors > 0 {
        std::process::exit(2);
    }
    if report.summary.warnings > 0 {
        std::process::exit(1);
    }
}

fn print_text_report(report: &Report) {
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
        return;
    }

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

    if let ProbeResult::Ok { value: interfaces } = &snapshot.interfaces {
        for iface in interfaces {
            accumulate_probe_state(&iface.has_ipv4, &mut blocked, &mut failed, &mut unavailable);
        }
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
