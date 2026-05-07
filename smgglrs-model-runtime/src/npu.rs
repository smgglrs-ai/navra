//! NPU detection via sysfs.
//!
//! Detects Intel NPUs (AI Boost) via `/sys/class/accel/` and the
//! `intel_vpu` kernel driver.

use std::fs;
use std::path::Path;

/// A detected NPU device.
#[derive(Debug, Clone)]
pub struct NpuDevice {
    /// Device index (e.g., 0 for first NPU).
    pub index: u32,
    /// PCI device ID (e.g., "8086:643E").
    pub pci_id: String,
    /// Device path (e.g., "/dev/accel/accel0").
    pub dev_path: String,
}

/// Detect Intel NPUs via /sys/class/accel/.
pub fn detect_npus() -> Vec<NpuDevice> {
    let accel = Path::new("/sys/class/accel");
    if !accel.exists() {
        return Vec::new();
    }

    let Ok(entries) = fs::read_dir(accel) else {
        return Vec::new();
    };

    let mut devices = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        if !name_str.starts_with("accel") {
            continue;
        }

        let device_path = entry.path().join("device");

        let uevent_path = device_path.join("uevent");
        let Ok(uevent) = fs::read_to_string(&uevent_path) else {
            continue;
        };

        let mut driver = None;
        let mut pci_id = None;

        for line in uevent.lines() {
            if let Some(d) = line.strip_prefix("DRIVER=") {
                driver = Some(d.to_string());
            }
            if let Some(id) = line.strip_prefix("PCI_ID=") {
                pci_id = Some(id.to_string());
            }
        }

        if driver.as_deref() != Some("intel_vpu") {
            continue;
        }

        let dev_path = format!("/dev/accel/{name_str}");
        let index = name_str
            .strip_prefix("accel")
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);

        devices.push(NpuDevice {
            index,
            pci_id: pci_id.unwrap_or_default(),
            dev_path,
        });
    }

    devices
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_npus_does_not_panic() {
        let npus = detect_npus();
        for npu in &npus {
            assert!(!npu.dev_path.is_empty());
        }
    }
}
