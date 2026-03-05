use clap::Parser;
use xdp_system_compat::{
    model::{Report, Severity, Summary},
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

    let report = Report {
        summary: Summary { errors, warnings },
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
        "  findings: {} error(s), {} warning(s)",
        report.summary.errors, report.summary.warnings
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
