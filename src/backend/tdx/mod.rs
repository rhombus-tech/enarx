// SPDX-License-Identifier: Apache-2.0

//! The TDX backend implementation
//!
//! This module provides support for Intel TDX (Trust Domain Extensions)
//! with robust parameter handling and accelerated attestation.

mod attestation;
mod config;
mod shim;

use crate::backend::{self, ByteSized, Command, Keep, Signatures, Thread};
use anyhow::{anyhow, bail, Context, Error, Result};

use std::mem::MaybeUninit;
use std::path::Path;
use std::sync::Arc;

/// The TDX Backend
pub struct Backend;

impl backend::Backend for Backend {
    /// The name of this backend
    fn name(&self) -> &'static str {
        "tdx"
    }

    /// Retrieve the shim for this backend
    ///
    /// Returns the embedded shim binary
    fn shim(&self) -> &'static [u8] {
        include_bytes!(concat!(env!("OUT_DIR"), "/bin/shim-tdx"))
    }

    /// Report data
    fn data(&self) -> Vec<backend::Datum> {
        vec![
            backend::Datum {
                name: "tid",
                value: "Intel TDX",
                long: false,
            },
            backend::Datum {
                name: "mode",
                value: "TDX Virtual Machine (VM)",
                long: false,
            },
            backend::Datum {
                name: "implementation",
                value: "Hardware-backed TDX with accelerated attestation",
                long: false,
            },
        ]
    }

    /// Report configuration
    fn config(&self) -> Vec<backend::Datum> {
        config::config()
    }

    /// Whether or not the platform has support for TDX
    fn have(&self) -> bool {
        // This will be replaced with actual detection logic
        // Temporarily return true for testing
        cfg!(enarx_with_shim)
    }

    /// Check if TDX is properly configured on this machine
    fn configured(&self) -> bool {
        if !self.have() {
            return false;
        }

        // This will be replaced with actual configuration check logic
        // Temporarily return true for testing
        true
    }

    /// Create a new keep instance on this backend
    #[inline]
    fn keep(
        &self,
        shim: &[u8],
        exec: &[u8],
        signatures: Option<Signatures>,
    ) -> Result<Arc<dyn Keep>> {
        // Ensure platform has TDX support
        if !self.have() {
            bail!("Missing TDX support");
        }

        // Check platform configuration
        if !self.configured() {
            bail!("TDX not properly configured");
        }

        // Create the keep instance
        shim::Keep::create(shim, exec, signatures)
    }

    /// Generate a cryptographic hash for shim+exec combination
    ///
    /// This is used for remote attestation verification
    fn hash(&self, shim: &[u8], exec: &[u8]) -> Result<Vec<u8>> {
        use sha2::Digest;
        
        let mut hasher = sha2::Sha384::new();
        hasher.update(shim);
        hasher.update(exec);
        Ok(hasher.finalize().to_vec())
    }
}
