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
    detect_npus_from(Path::new("/sys/class/accel"))
}

/// Detect Intel NPUs from a custom sysfs base path.
///
/// This is the testable core of [`detect_npus()`]. Pass a synthetic
/// directory tree to exercise detection logic without real hardware.
pub fn detect_npus_from(accel: &Path) -> Vec<NpuDevice> {
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
    use std::fs;

    #[test]
    fn detect_npus_does_not_panic() {
        let npus = detect_npus();
        for npu in &npus {
            assert!(!npu.dev_path.is_empty());
        }
    }

    // ── detect_npus_from tests with synthetic sysfs ────────────────────

    /// Helper: create a synthetic accel device directory with a uevent file.
    fn create_accel_device(base: &Path, name: &str, uevent_content: &str) {
        let device_dir = base.join(name).join("device");
        fs::create_dir_all(&device_dir).unwrap();
        fs::write(device_dir.join("uevent"), uevent_content).unwrap();
    }

    #[test]
    fn detect_npus_no_accel_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("nonexistent");
        let devices = detect_npus_from(&missing);
        assert!(devices.is_empty());
    }

    #[test]
    fn detect_npus_empty_accel_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let accel = tmp.path().join("accel");
        fs::create_dir_all(&accel).unwrap();
        let devices = detect_npus_from(&accel);
        assert!(devices.is_empty());
    }

    #[test]
    fn detect_npus_non_accel_entries_skipped() {
        let tmp = tempfile::tempdir().unwrap();
        let accel = tmp.path().join("accel");
        // Create entries that don't start with "accel"
        let bogus = accel.join("gpu0").join("device");
        fs::create_dir_all(&bogus).unwrap();
        fs::write(bogus.join("uevent"), "DRIVER=intel_vpu\nPCI_ID=8086:643E\n").unwrap();

        let devices = detect_npus_from(&accel);
        assert!(devices.is_empty());
    }

    #[test]
    fn detect_npus_non_intel_driver_skipped() {
        let tmp = tempfile::tempdir().unwrap();
        let accel = tmp.path().join("accel");
        create_accel_device(&accel, "accel0", "DRIVER=amd_npu\nPCI_ID=1022:ABCD\n");

        let devices = detect_npus_from(&accel);
        assert!(devices.is_empty());
    }

    #[test]
    fn detect_npus_missing_uevent_skipped() {
        let tmp = tempfile::tempdir().unwrap();
        let accel = tmp.path().join("accel");
        // Create accel0 directory but no uevent file
        let device_dir = accel.join("accel0").join("device");
        fs::create_dir_all(&device_dir).unwrap();

        let devices = detect_npus_from(&accel);
        assert!(devices.is_empty());
    }

    #[test]
    fn detect_npus_intel_vpu_detected() {
        let tmp = tempfile::tempdir().unwrap();
        let accel = tmp.path().join("accel");
        create_accel_device(&accel, "accel0", "DRIVER=intel_vpu\nPCI_ID=8086:643E\n");

        let devices = detect_npus_from(&accel);
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].index, 0);
        assert_eq!(devices[0].pci_id, "8086:643E");
        assert_eq!(devices[0].dev_path, "/dev/accel/accel0");
    }

    #[test]
    fn detect_npus_multiple_devices() {
        let tmp = tempfile::tempdir().unwrap();
        let accel = tmp.path().join("accel");
        create_accel_device(&accel, "accel0", "DRIVER=intel_vpu\nPCI_ID=8086:643E\n");
        create_accel_device(&accel, "accel1", "DRIVER=intel_vpu\nPCI_ID=8086:AD1D\n");

        let mut devices = detect_npus_from(&accel);
        assert_eq!(devices.len(), 2);
        // Sort by index for deterministic assertion (readdir order is unspecified)
        devices.sort_by_key(|d| d.index);
        assert_eq!(devices[0].index, 0);
        assert_eq!(devices[1].index, 1);
    }

    #[test]
    fn detect_npus_missing_pci_id_defaults_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let accel = tmp.path().join("accel");
        // uevent with driver but no PCI_ID line
        create_accel_device(&accel, "accel0", "DRIVER=intel_vpu\n");

        let devices = detect_npus_from(&accel);
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].pci_id, "");
    }
}
