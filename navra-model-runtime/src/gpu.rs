//! GPU detection via sysfs and procfs.
//!
//! Detects NVIDIA, AMD, and Intel GPUs without requiring vendor-specific
//! libraries. Uses `/sys/class/drm/` and `/proc/driver/nvidia/` probing.

use std::fs;
use std::path::Path;

/// GPU hardware vendor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GpuKind {
    Nvidia,
    Amd,
    Intel,
}

/// A detected GPU device.
#[derive(Debug, Clone)]
pub struct GpuDevice {
    /// Vendor type.
    pub kind: GpuKind,
    /// Device index (e.g., 0 for first GPU).
    pub index: u32,
    /// Device name (e.g., "NVIDIA RTX 4090").
    pub name: String,
    /// VRAM in bytes (if detectable).
    pub vram: Option<u64>,
}

/// Detect all available GPUs on the system.
pub fn detect_gpus() -> Vec<GpuDevice> {
    let mut devices = Vec::new();
    detect_nvidia(&mut devices);
    detect_amd(&mut devices);
    detect_intel(&mut devices);
    devices
}

fn detect_nvidia(devices: &mut Vec<GpuDevice>) {
    // Check if NVIDIA driver is loaded
    let proc_nvidia = Path::new("/proc/driver/nvidia/gpus");
    if !proc_nvidia.exists() {
        return;
    }

    let Ok(entries) = fs::read_dir(proc_nvidia) else {
        return;
    };

    for (index, entry) in entries.flatten().enumerate() {
        let info_path = entry.path().join("information");
        let name = if let Ok(info) = fs::read_to_string(&info_path) {
            info.lines()
                .find(|l| l.starts_with("Model:"))
                .map(|l| l.trim_start_matches("Model:").trim().to_string())
                .unwrap_or_else(|| "NVIDIA GPU".to_string())
        } else {
            "NVIDIA GPU".to_string()
        };

        devices.push(GpuDevice {
            kind: GpuKind::Nvidia,
            index: index as u32,
            name,
            vram: None, // Would need NVML for accurate VRAM
        });
    }
}

fn detect_amd(devices: &mut Vec<GpuDevice>) {
    let drm = Path::new("/sys/class/drm");
    if !drm.exists() {
        return;
    }

    let Ok(entries) = fs::read_dir(drm) else {
        return;
    };

    let mut index = 0u32;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Only look at card devices, not render nodes
        if !name_str.starts_with("card") || name_str.contains('-') {
            continue;
        }

        let device_path = entry.path().join("device");

        // Check vendor: 0x1002 = AMD
        let vendor_path = device_path.join("vendor");
        if let Ok(vendor) = fs::read_to_string(&vendor_path) {
            if vendor.trim() != "0x1002" {
                continue;
            }
        } else {
            continue;
        }

        let gpu_name = read_drm_name(&device_path).unwrap_or_else(|| "AMD GPU".to_string());

        let vram = device_path.join("mem_info_vram_total").pipe_read_u64();

        devices.push(GpuDevice {
            kind: GpuKind::Amd,
            index,
            name: gpu_name,
            vram,
        });
        index += 1;
    }
}

fn detect_intel(devices: &mut Vec<GpuDevice>) {
    let drm = Path::new("/sys/class/drm");
    if !drm.exists() {
        return;
    }

    let Ok(entries) = fs::read_dir(drm) else {
        return;
    };

    let mut index = 0u32;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        if !name_str.starts_with("card") || name_str.contains('-') {
            continue;
        }

        let device_path = entry.path().join("device");

        // Check vendor: 0x8086 = Intel
        let vendor_path = device_path.join("vendor");
        if let Ok(vendor) = fs::read_to_string(&vendor_path) {
            if vendor.trim() != "0x8086" {
                continue;
            }
        } else {
            continue;
        }

        let gpu_name = read_drm_name(&device_path).unwrap_or_else(|| "Intel GPU".to_string());

        // Intel integrated GPUs share system memory, no dedicated VRAM file
        let vram = device_path.join("lmem_total_bytes").pipe_read_u64();

        devices.push(GpuDevice {
            kind: GpuKind::Intel,
            index,
            name: gpu_name,
            vram,
        });
        index += 1;
    }
}

fn read_drm_name(device_path: &Path) -> Option<String> {
    // Try product name from uevent
    let uevent = fs::read_to_string(device_path.join("uevent")).ok()?;
    for line in uevent.lines() {
        if let Some(name) = line.strip_prefix("PCI_SLOT_NAME=") {
            return Some(name.to_string());
        }
    }
    None
}

trait PipeReadU64 {
    fn pipe_read_u64(&self) -> Option<u64>;
}

impl PipeReadU64 for std::path::PathBuf {
    fn pipe_read_u64(&self) -> Option<u64> {
        fs::read_to_string(self)
            .ok()
            .and_then(|s| s.trim().parse().ok())
    }
}

/// GPU memory usage snapshot.
#[derive(Debug, Clone)]
pub struct GpuMemoryUsage {
    /// Device index.
    pub index: u32,
    /// Used memory in bytes.
    pub used: u64,
    /// Total memory in bytes.
    pub total: u64,
}

/// Sample NVIDIA GPU memory usage from procfs.
///
/// Reads `/proc/driver/nvidia/gpus/*/fb_memory_usage` which provides
/// free/used memory without requiring NVML bindings.
pub fn sample_nvidia_memory() -> Vec<GpuMemoryUsage> {
    let proc_nvidia = Path::new("/proc/driver/nvidia/gpus");
    if !proc_nvidia.exists() {
        return Vec::new();
    }
    let Ok(entries) = fs::read_dir(proc_nvidia) else {
        return Vec::new();
    };

    let mut results = Vec::new();
    for (index, entry) in entries.flatten().enumerate() {
        let fb_path = entry.path().join("fb_memory_usage");
        let Ok(content) = fs::read_to_string(&fb_path) else {
            continue;
        };

        let mut used_mb = 0u64;
        let mut total_mb = 0u64;
        for line in content.lines() {
            if let Some(val) = line.strip_prefix("Used :") {
                if let Some(num) = val.trim().strip_suffix(" MB") {
                    used_mb = num.trim().parse().unwrap_or(0);
                }
            } else if let Some(val) = line.strip_prefix("Total :")
                && let Some(num) = val.trim().strip_suffix(" MB") {
                    total_mb = num.trim().parse().unwrap_or(0);
                }
        }
        if total_mb > 0 {
            results.push(GpuMemoryUsage {
                index: index as u32,
                used: used_mb * 1024 * 1024,
                total: total_mb * 1024 * 1024,
            });
        }
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_gpus_does_not_panic() {
        // Should work on any system, even without GPUs
        let gpus = detect_gpus();
        for gpu in &gpus {
            assert!(!gpu.name.is_empty());
        }
    }

    #[test]
    fn gpu_kind_equality() {
        assert_eq!(GpuKind::Nvidia, GpuKind::Nvidia);
        assert_ne!(GpuKind::Nvidia, GpuKind::Amd);
    }

    #[test]
    fn sample_nvidia_memory_does_not_panic() {
        let samples = sample_nvidia_memory();
        for s in &samples {
            assert!(s.total > 0);
            assert!(s.used <= s.total);
        }
    }
}
