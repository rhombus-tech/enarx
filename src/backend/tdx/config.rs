// SPDX-License-Identifier: Apache-2.0

//! TDX Configuration
//!
//! This module provides configuration details for the TDX backend

use crate::backend;
use std::path::Path;

/// Get configuration datums for TDX
pub fn config() -> Vec<backend::Datum> {
    let mut config = vec![
        backend::Datum {
            name: "driver",
            value: "/dev/tdx-guest",
            long: false,
        },
        backend::Datum {
            name: "version",
            value: "TDX 1.0/1.5",
            long: false,
        },
        backend::Datum {
            name: "parameter_handling",
            value: "Robust dual-format (length-prefixed and direct)",
            long: false,
        },
    ];

    // Add driver status
    let driver_exists = Path::new("/dev/tdx-guest").exists();
    config.push(backend::Datum {
        name: "driver_status",
        value: if driver_exists { "present" } else { "missing" },
        long: false,
    });

    // Add CPU information if available
    if let Ok(cpuinfo) = std::fs::read_to_string("/proc/cpuinfo") {
        for line in cpuinfo.lines() {
            if line.starts_with("model name") {
                if let Some(model) = line.split(':').nth(1) {
                    config.push(backend::Datum {
                        name: "cpu_model",
                        value: model.trim(),
                        long: false,
                    });
                    break;
                }
            }
        }
    }

    config
}
