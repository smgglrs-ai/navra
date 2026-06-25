use serde::Serialize;

/// Summary of detected hardware resources.
#[derive(Debug, Clone, Serialize)]
pub struct HardwareSummary {
    pub gpus: Vec<GpuInfo>,
    pub npus: Vec<NpuInfo>,
    pub system_ram_bytes: u64,
    pub suggested_vram_budget: u64,
    pub desktop_reservation: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct GpuInfo {
    pub kind: String,
    pub index: u32,
    pub name: String,
    pub vram_bytes: Option<u64>,
    pub vram_used_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NpuInfo {
    pub name: String,
    pub device_path: String,
}

/// Detect available hardware and propose resource allocation.
pub fn detect(desktop_reservation: u64) -> HardwareSummary {
    let raw_gpus = navra_model_runtime::detect_gpus();
    let raw_npus = navra_model_runtime::detect_npus();

    let gpus: Vec<GpuInfo> = raw_gpus
        .iter()
        .map(|g| {
            let (vram, used) = match g.kind {
                navra_model_runtime::GpuKind::Nvidia => {
                    let mem = navra_model_runtime::gpu::sample_nvidia_memory();
                    mem.iter()
                        .find(|m| m.index == g.index)
                        .map(|m| (Some(m.total), Some(m.used)))
                        .unwrap_or((None, None))
                }
                _ => (g.vram, None),
            };
            GpuInfo {
                kind: format!("{:?}", g.kind).to_lowercase(),
                index: g.index,
                name: g.name.clone(),
                vram_bytes: vram,
                vram_used_bytes: used,
            }
        })
        .collect();

    let npus: Vec<NpuInfo> = raw_npus
        .iter()
        .map(|n| NpuInfo {
            name: format!("Intel NPU ({})", n.pci_id),
            device_path: n.dev_path.clone(),
        })
        .collect();

    let total_vram: u64 = gpus.iter().filter_map(|g| g.vram_bytes).sum();
    let suggested = total_vram.saturating_sub(desktop_reservation);

    let system_ram = sys_ram_bytes();

    HardwareSummary {
        gpus,
        npus,
        system_ram_bytes: system_ram,
        suggested_vram_budget: suggested,
        desktop_reservation,
    }
}

fn sys_ram_bytes() -> u64 {
    std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("MemTotal:"))
                .and_then(|l| {
                    l.split_whitespace()
                        .nth(1)
                        .and_then(|v| v.parse::<u64>().ok())
                })
        })
        .map(|kb| kb * 1024)
        .unwrap_or(0)
}

/// Print a human-readable hardware summary to stdout.
pub fn print_summary(summary: &HardwareSummary) {
    println!("Detected resources:");
    if summary.gpus.is_empty() {
        println!("  GPU: none detected");
    } else {
        for gpu in &summary.gpus {
            let vram = gpu
                .vram_bytes
                .map(|v| format!("{}GB VRAM", v / (1024 * 1024 * 1024)))
                .unwrap_or_else(|| "unknown VRAM".to_string());
            println!("  GPU: {} ({}) [{}]", gpu.name, vram, gpu.kind);
        }
    }
    if !summary.npus.is_empty() {
        for npu in &summary.npus {
            println!("  NPU: {} ({})", npu.name, npu.device_path);
        }
    }
    let ram_gb = summary.system_ram_bytes / (1024 * 1024 * 1024);
    println!("  RAM: {}GB", ram_gb);
    println!();

    if summary.suggested_vram_budget > 0 {
        let budget_gb = summary.suggested_vram_budget / (1024 * 1024 * 1024);
        let reserved_gb = summary.desktop_reservation / (1024 * 1024 * 1024);
        println!("Proposed allocation:");
        println!(
            "  GPU: {}GB for models ({}GB reserved for desktop)",
            budget_gb, reserved_gb
        );
    } else {
        println!("Proposed allocation:");
        println!("  CPU-only mode (no GPU detected or budget exhausted)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_returns_summary() {
        let summary = detect(2 * 1024 * 1024 * 1024);
        assert!(summary.system_ram_bytes > 0 || cfg!(not(target_os = "linux")));
    }

    #[test]
    fn print_summary_no_panic() {
        let summary = HardwareSummary {
            gpus: vec![],
            npus: vec![],
            system_ram_bytes: 64 * 1024 * 1024 * 1024,
            suggested_vram_budget: 0,
            desktop_reservation: 2 * 1024 * 1024 * 1024,
        };
        print_summary(&summary);
    }
}
