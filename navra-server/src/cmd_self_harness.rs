//! CLI handler for `navra self-harness`.

use navra_flow::event_log::EventLog;
use navra_flow::self_harness::{MiningConfig, ValidationOutcome, run_self_harness};

pub(crate) fn self_harness_command(
    flow_ids: Vec<String>,
    json: bool,
    retry_threshold: u32,
    slow_tool_ms: u64,
) -> anyhow::Result<()> {
    let event_log_path = dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("navra")
        .join("flow_events.db");

    if !event_log_path.exists() {
        anyhow::bail!(
            "No event log found at {}. Run some flows first.",
            event_log_path.display()
        );
    }

    let log = EventLog::open(&event_log_path)?;

    let ids: Vec<&str> = if flow_ids.is_empty() {
        discover_flow_ids(&log)?
    } else {
        flow_ids.iter().map(|s| s.as_str()).collect()
    };

    if ids.is_empty() {
        println!("No flow traces found in event log.");
        return Ok(());
    }

    let config = MiningConfig {
        retry_threshold,
        slow_tool_ms,
        ..Default::default()
    };

    let report = run_self_harness(&log, &ids, &config);

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("Self-Harness Report");
    println!("{}", "=".repeat(60));
    println!(
        "Flows analyzed: {}  |  Weaknesses: {}  |  Proposals: {} ({} safe)\n",
        report.flows_analyzed,
        report.weaknesses_found,
        report.proposals_generated,
        report.proposals_safe
    );

    if !report.findings.is_empty() {
        println!("Weaknesses");
        println!("{}", "-".repeat(60));
        for (i, f) in report.findings.iter().enumerate() {
            println!(
                "  {}. [{:?}] {} (severity: {:.2}, occurrences: {})",
                i + 1,
                f.weakness_type,
                f.description,
                f.severity,
                f.occurrences
            );
        }
        println!();
    }

    if !report.proposals.is_empty() {
        println!("Proposals");
        println!("{}", "-".repeat(60));
        for (p, v) in report.proposals.iter().zip(report.validations.iter()) {
            let status = match v.outcome {
                ValidationOutcome::Safe => "SAFE",
                ValidationOutcome::Regression => "REGRESSION",
                ValidationOutcome::InsufficientData => "NO DATA",
            };
            println!(
                "  {} [{}] {:?}: {}",
                p.id, status, p.kind, p.description
            );
            if v.outcome == ValidationOutcome::Regression {
                println!(
                    "    Regression in {} of {} traces: {}",
                    v.regressions,
                    v.traces_checked,
                    v.affected_flows.join(", ")
                );
            }
        }
        println!();
    }

    if report.proposals_safe > 0 {
        println!(
            "{} proposal(s) validated as safe to apply.",
            report.proposals_safe
        );
    }

    Ok(())
}

fn discover_flow_ids(log: &EventLog) -> anyhow::Result<Vec<&'static str>> {
    let db_path = dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("navra")
        .join("flow_events.db");

    let db = rusqlite::Connection::open(&db_path)?;
    let mut stmt = db.prepare(
        "SELECT DISTINCT flow_id FROM flow_events ORDER BY MAX(seq) DESC LIMIT 20",
    )?;

    let ids: Vec<String> = stmt
        .query_map([], |row| row.get::<_, String>(0))?
        .filter_map(|r| r.ok())
        .collect();

    Ok(ids.into_iter().map(|s| Box::leak(s.into_boxed_str()) as &str).collect())
}
