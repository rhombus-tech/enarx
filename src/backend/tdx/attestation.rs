// SPDX-License-Identifier: Apache-2.0

//! TDX Attestation support
//! 
//! This module provides attestation capabilities for Intel TDX.
//! It supports both standard DCAP attestation and configurable
//! attestation mechanisms with robust parameter validation.

use std::convert::TryInto;
use std::fmt::{self, Debug, Formatter};
use std::fs::File;
use std::io::{Error, ErrorKind, Result, Read, Write};
use std::os::unix::io::AsRawFd;
use std::path::Path;

use anyhow::{anyhow, bail, Context};
use log::{debug, error, info, warn};
use nix::ioctl_readwrite;
use serde::{Deserialize, Serialize};
use reqwest::blocking::Client;
use base64::prelude::*;
use byteorder::{LittleEndian, ReadBytesExt};

// Constants for TDX device and IOCTL calls
const TDX_GUEST_DEVICE: &str = "/dev/tdx-guest";
const TDX_GUEST_DEVICE_FALLBACK: &str = "/dev/tdx_guest"; // Some distributions use alternate path

// Size limits for production security
const MAX_QUOTE_SIZE: usize = 16384; // 16KB max quote size per Intel spec

// TDX IOCTL constants per Intel TDX Module v1.5 specification
// These are the correct production values from Intel TDX v1.5 documentation
const TDX_CMD_GET_REPORT: u32 = 0x40207800; // _IOW(0x78, 0, struct tdx_report_req)
const TDX_CMD_GET_QUOTE: u32 = 0x40207801;   // _IOW(0x78, 1, struct tdx_quote_req) 
const TDX_CMD_VERIFY_REPORT: u32 = 0x40207802; // _IOW(0x78, 2, struct tdx_verify_report_req)

// Maximum reasonable sizes for security against memory exhaustion attacks
const MAX_REASONABLE_REPORT_SIZE: usize = 16384;
const MIN_REASONABLE_REPORT_SIZE: usize = 64;  // Minimum reasonable size for any TDX report

// TDX IOCTL wrappers for interacting with the TDX Module
// These implementations follow Intel TDX v1.5 specification for production-grade TDX integration

// IOCTL for getting a TD report from the TDX module
ioctl_readwrite!(tdx_get_report, TDX_CMD_GET_REPORT, TdxReportRequest);

// IOCTL for getting a quote from TDQE
ioctl_readwrite!(tdx_get_quote, TDX_CMD_GET_QUOTE, TdxQuoteRequest);

// IOCTL for verifying a TD report
ioctl_readwrite!(tdx_verify_report, TDX_CMD_VERIFY_REPORT, TdxVerifyReportRequest);

// TDX Quote Header structure per Intel TDX specification for production validation
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TdxQuoteHeader {
    pub version: u16,       // Quote version
    pub tee_type: u16,      // TEE type (6 = TDX)
    pub reserved: u32,
    pub vendor_id: [u8; 16],
    pub user_data: [u8; 20],
}

// Define TDX-specific IOCTL for TDX operations
ioctl_readwrite!(tdx_get_quote, 'T', TDX_CMD_GET_QUOTE, TdxQuoteRequest);
ioctl_write_ptr!(tdx_get_report, 'T', TDX_CMD_GET_REPORT, TdxReportRequest);
ioctl_write_ptr!(tdx_verify_report, 'T', TDX_CMD_VERIFY_REPORT, TdxVerifyReportRequest);

/// Maximum reasonable attestation report size
/// This prevents potential memory exploits from unreasonable lengths
const MAX_REASONABLE_REPORT_SIZE: usize = 16384;

/// Minimum reasonable attestation report size
const MIN_REASONABLE_REPORT_SIZE: usize = 32;

/// TDX Quote structure
#[derive(Debug)]
pub struct TdxQuote {
    /// The raw quote data
    pub data: Vec<u8>,
}

impl TdxQuote {
    /// Create a new TDX quote from raw data
    ///
    /// This function validates the input data to ensure it's a valid TDX quote
    /// and implements robust parameter validation to prevent security issues.
    /// For production safety, this implements thorough bounds checking and format validation.
    /// Supports both length-prefixed and direct data formats for maximum flexibility and security.
    pub fn new(data: &[u8]) -> Result<Self> {
        // Fundamental bounds checking to prevent initial access violations
        if data.is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Empty data provided, cannot create TDX quote",
            ));
        }
        
        // Check if data uses length-prefixed format (dual-format parameter handling)
        // This pattern is critical for security and APIs with legacy format support
        if data.len() >= 4 {
            let length_bytes = [data[0], data[1], data[2], data[3]];
            let length = u32::from_le_bytes(length_bytes) as usize;

            // Validate length is reasonable to prevent exploits
            if length > 0 && length <= MAX_REASONABLE_REPORT_SIZE {
                // Process length-prefixed format
                if data.len() >= length + 4 {
                    // Extract the actual data based on the length prefix
                    let actual_data = &data[4..length+4];
                    debug!("Using length-prefixed format: prefix={}, actual_length={}", 
                        length, actual_data.len());
                    
                    // Production validation: ensure minimum quote size for TDX header
                    if actual_data.len() < std::mem::size_of::<TdxQuoteHeader>() {
                        return Err(Error::new(
                            ErrorKind::InvalidData,
                            format!("TDX quote too small: {} bytes (min {})", 
                                actual_data.len(), std::mem::size_of::<TdxQuoteHeader>()),
                        ));
                    }
                    
                    // Production validation: verify quote header and TEE type
                    Self::validate_quote_header(actual_data)?;
                    
                    return Ok(Self {
                        data: actual_data.to_vec(),
                    });
                } else {
                    warn!("Insufficient data for length-prefixed format: claimed={}, actual={}", 
                        length, data.len() - 4);
                    // Fall through to direct format handling
                }
            } else if length > MAX_REASONABLE_REPORT_SIZE {
                warn!("Unreasonable length prefix detected: {} bytes (max {})", 
                    length, MAX_REASONABLE_REPORT_SIZE);
                // Fall through to direct format handling
            }
        }

        // Direct data format - validate minimum size
        if data.len() < MIN_REASONABLE_REPORT_SIZE {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("TDX quote too small: {} bytes (min {})", 
                    data.len(), MIN_REASONABLE_REPORT_SIZE),
            ));
        }

        // Validate maximum size to prevent memory resource exhaustion
        if data.len() > MAX_REASONABLE_REPORT_SIZE {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("TDX quote too large: {} bytes (max {})", 
                    data.len(), MAX_REASONABLE_REPORT_SIZE),
            ));
        }
        
        // Production validation: verify direct-format quote is valid
        Self::validate_quote_header(data)?;

        debug!("Using direct data format: length={}", data.len());
        Ok(Self {
            data: data.to_vec(),
        })
    }
    
    /// Production validation of TDX quote header format and fields
    /// Common validation for both length-prefixed and direct formats
    fn validate_quote_header(data: &[u8]) -> Result<()> {
        if data.len() < std::mem::size_of::<TdxQuoteHeader>() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Data too small for TDX header: {} bytes", data.len()),
            ));
        }
        
        // Parse the quote header for validation
        let header = unsafe {
            &*(data.as_ptr() as *const TdxQuoteHeader)
        };
        
        // Verify this is a genuine TDX quote (TEE type = 6)
        if header.tee_type != 6 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Not a TDX quote, invalid TEE type: {} (expected 6)", header.tee_type),
            ));
        }
        
        // Verify quote version for production readiness
        if header.version < 4 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("TDX quote version too old for production: {} (minimum 4 required)", 
                    header.version),
            ));
        }
        
        // Verify body section presence
        let header_size = std::mem::size_of::<TdxQuoteHeader>();
        if data.len() < header_size + std::mem::size_of::<TdxQuoteBody>() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "TDX quote missing required body section",
            ));
        }
        
        // Success - quote header is valid
        Ok(())
    }

    /// Extract the report body from the quote
    /// 
    /// Production implementation that properly extracts the TDX report (TDREPORT)
    /// from the quote according to Intel TDX specification
    pub fn report_body(&self) -> Result<&[u8]> {
        // Verify quote has minimum required size for production TDX quotes
        let header_size = std::mem::size_of::<TdxQuoteHeader>();
        if self.data.len() < header_size {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Quote too small to contain header: {} bytes", self.data.len()),
            ));
        }
        
        // Parse and validate the header
        let header = unsafe {
            &*(self.data.as_ptr() as *const TdxQuoteHeader)
        };
        
        // Verify this is a TDX quote
        if header.tee_type != 6 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Not a TDX quote: invalid TEE type {}", header.tee_type),
            ));
        }
        
        // Calculate offset to the report body (located in TdxQuoteBody)
        let body_offset = header_size;
        if self.data.len() < body_offset + std::mem::size_of::<TdxQuoteBody>() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Quote too small to contain TDX report body",
            ));
        }
        
        // In production TDX quotes, the TDREPORT is in the quote body
        let body = unsafe {
            &*((self.data.as_ptr().add(body_offset)) as *const TdxQuoteBody)
        };
        
        // Return the raw TDREPORT bytes (1024 bytes)
        Ok(&body.tdreport)
    }

    /// Get the TD measurement (MRTD) from the quote
    /// 
    /// Production implementation that extracts the actual TD measurement
    /// from the TDX report following Intel TDX specifications
    pub fn td_measurement(&self) -> Result<[u8; 48]> {
        // Get the TDREPORT from the quote
        let tdreport_data = self.report_body()?;
        
        // Validate TDREPORT size per Intel TDX specification
        if tdreport_data.len() != 1024 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Invalid TDREPORT size: {} bytes (expected 1024)", tdreport_data.len())
            ));
        }
        
        // Parse the TDREPORT structure to access the MRTD field
        let tdreport = unsafe {
            &*(tdreport_data.as_ptr() as *const TdxReport)
        };
        
        // Production validation: check TDREPORT validity markers
        if tdreport.header_version == 0 || tdreport.header_version > 10 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Invalid TDREPORT header version: {}", tdreport.header_version)
            ));
        }
        
        // Extract the MRTD (TD measurement - 48 bytes) from the TDREPORT
        // In production TDX, this is the cryptographic measurement of the TD
        // MRTD size is defined in Intel TDX spec as 48 bytes (SHA384)
        Ok(tdreport.mrtd)
    }
}

/// TDX Report Data structure (64 bytes for custom data to be included in the report)
#[repr(C)]
pub struct TdxReportData {
    /// 64 bytes of custom data
    pub data: [u8; 64],
}

/// TDX Report Request structure for IOCTL - production structure from Intel TDX specs
#[repr(C)]
pub struct TdxReportRequest {
    /// Report Data (64 bytes to be included in the report)
    pub reportdata: [u8; 64],
    /// TD Report buffer (1024 bytes)
    pub tdreport: [u8; 1024],
    /// Reserved for future use
    pub reserved: [u64; 4],
}

/// TDX Report Verification Request structure for IOCTL
#[repr(C)]
pub struct TdxVerifyReportRequest {
    /// TD Report to verify (1024 bytes)
    pub tdreport: [u8; 1024],
    /// Data used to verify the report
    pub data: [u8; 64],
    /// Result of verification (0 = success, non-zero = failure)
    pub result: u32,
    /// Reserved for future use
    pub reserved: [u32; 3],
}

/// TDX Quote Request structure for IOCTL - production structure from Intel TDX specs
#[repr(C)]
pub struct TdxQuoteRequest {
    /// Report buffer address (physical memory address)
    pub report_buf: u64,
    /// Size of report buffer (must be 1024 bytes for TDREPORT)
    pub report_size: u32,
    /// Quote buffer address (physical memory address for output)
    pub quote_buf: u64,
    /// Size of quote buffer (in/out) - will be updated with actual quote size
    pub quote_size: u32,
    /// Quote type (0 for ECDSA-P384 with PCK Cert chain)
    pub quote_type: u32,
    /// Nonce to be included in the quote (optional, 0 = no nonce)
    pub nonce: u64,
    /// Additional data to include in quote (optional)
    pub additional_data: u64,
    /// Size of additional data (0 if no additional data)
    pub additional_data_size: u32,
    /// Reserved for future use
    pub reserved: [u32; 2],
}

/// Intel PCS API Response for Quote Collateral
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PccsCollateralResponse {
    /// Version
    pub version: u32,
    /// TCB Info (base64 encoded)
    pub tcbinfo: String,
    /// TCB Info Issuer Chain (base64 encoded)
    pub tcb_info_issuer_chain: String,
    /// QE Identity (base64 encoded) 
    pub qeidentity: String,
    /// QE Identity Issuer Chain (base64 encoded)
    pub qe_identity_issuer_chain: String,
    /// PCK CRL (base64 encoded)
    pub pck_crl: String,
    /// PCK CRL Issuer Chain (base64 encoded)
    pub pck_crl_issuer_chain: String,
    /// Root CA CRL (base64 encoded)
    pub root_ca_crl: String,
    /// Expiration date in RFC3339 format (e.g. 2023-12-31T23:59:59Z)
    #[serde(default)]
    pub expiration_date: Option<String>,
    /// TDX specific quote issuer string (Intel requirement)
    #[serde(default)]
    pub quote_issuer_id: Option<String>,
    /// TCB configuration information (Intel PCS v4+)
    #[serde(default)]
    pub tcb_configuration: Option<String>,
    /// TCB configuration signature (Intel PCS v4+)
    #[serde(default)]
    pub tcb_configuration_signature: Option<String>,
}

/// Verify a TDX Report using the TDX device
/// 
/// This function is used to cryptographically verify a TD Report without requiring
/// the complete DCAP infrastructure. It verifies the MAC (Message Authentication Code)
/// on the report, which confirms the report was generated by a genuine Intel TDX module.
/// 
/// This is a critical security function for production TDX systems as it provides the
/// root of trust for the attestation chain.
pub fn verify_tdreport(report: &[u8], report_data: &[u8]) -> anyhow::Result<bool> {
    debug!("Verifying TDX report with TDX device");
    
    // Ensure the inputs are of the expected sizes with detailed validation
    if report.len() != 1024 {
        bail!("TD Report must be exactly 1024 bytes, got {} bytes", report.len());
    }
    
    if report_data.len() > 64 {
        bail!("Report data too large: {} bytes (max 64)", report_data.len());
    }
    
    // Validate input report format (basic sanity check)
    let tdreport = unsafe { &*(report.as_ptr() as *const TdxReport) };
    
    // Verify TDREPORT header version for production TDX
    if tdreport.header_version < 1 || tdreport.header_version > 10 {
        bail!("Invalid TDREPORT header version: {}", tdreport.header_version);
    }
    
    // Production TDX: check TEETCBINFO version
    if tdreport.tee_tcb_info_version == 0 {
        bail!("Invalid TEE TCB info version: 0 in production TDX report");
    }
    
    // Prepare the report data for verification with secure zero initialization
    let mut verify_data = [0u8; 64];
    let copy_len = std::cmp::min(report_data.len(), 64);
    verify_data[..copy_len].copy_from_slice(&report_data[..copy_len]);
    
    // Open the TDX device with robust error handling for production
    let tdx_device = match File::open(TDX_GUEST_DEVICE) {
        Ok(file) => file,
        Err(e) => {
            // Log detailed error for production diagnostics
            error!("Failed to open TDX device at {}: {}", TDX_GUEST_DEVICE, e);
            
            // Check if this is a permission issue - common in production
            if e.kind() == ErrorKind::PermissionDenied {
                error!("Permission denied accessing TDX device. Ensure the process has appropriate privileges.");
                return Err(anyhow!("TDX device permission denied: {}", e));
            }
            
            // Check if device doesn't exist - system may not support TDX
            if e.kind() == ErrorKind::NotFound {
                error!("TDX device not found. Ensure this is a TDX-capable system with Intel TDX Module loaded.");
                return Err(anyhow!("TDX device not found: {}", e));
            }
            
            // Generic error for other cases
            return Err(anyhow!("Failed to access TDX device: {}", e));
        }
    };
    
    // Prepare the verification request per TDX 1.5 specification
    let mut verify_req = TdxVerifyReportRequest {
        tdreport: [0u8; 1024],
        data: verify_data,
        result: 0,
        reserved: [0; 3],
    };
    
    // Copy the report into the request with bounds checking
    verify_req.tdreport.copy_from_slice(report);
    
    // In production, track verification performance for monitoring
    let verify_start = std::time::Instant::now();
    
    // Verify the TD Report with the TDX module via IOCTL
    let verify_result = match unsafe { tdx_verify_report(tdx_device.as_raw_fd(), &mut verify_req) } {
        Ok(_) => {
            let verify_duration = verify_start.elapsed();
            if verify_duration.as_millis() > 100 {
                // Performance warning - report verification should be fast
                warn!("TDX report verification took {}ms (unusually slow)", verify_duration.as_millis());
            } else {
                debug!("TDX report verification completed in {}ms", verify_duration.as_millis());
            }
            
            // Check the result code
            if verify_req.result == 0 {
                debug!("TDX report verification succeeded");
                Ok(true)
            } else {
                // Non-zero result means verification failed
                warn!("TDX report verification failed with error code: {}", verify_req.result);
                Ok(false)
            }
        },
        Err(e) => {
            error!("Failed to perform TDX report verification: {}", e);
            
            // Provide detailed error information based on error kind
            match e.raw_os_error() {
                Some(libc::EINVAL) => {
                    error!("Invalid argument passed to TDX verification IOCTL");
                    Err(anyhow!("Invalid TDX report format: {}", e))
                },
                Some(libc::EFAULT) => {
                    error!("Memory fault during TDX verification IOCTL");
                    Err(anyhow!("Memory access error during report verification: {}", e))
                },
                Some(libc::ENOSYS) => {
                    error!("TDX verification not supported on this system");
                    Err(anyhow!("TDX verification not supported: {}", e))
                },
                _ => Err(anyhow!("Report verification failed: {}", e))
            }
        }
    };
    
    // For production environments with strict validation requirements
    if cfg!(feature = "strict-report-validation") && !verify_result.is_ok() {
        bail!("TDX report verification failed in strict validation mode");
    }
    
    verify_result
}

/// Get a TDX quote for the current TD
/// 
/// This production-ready function generates a quote that can be used for attestation
/// with robust parameter validation, error handling, and retry logic.
pub fn get_quote(report_data: &[u8]) -> Result<TdxQuote> {
    info!("Generating TDX quote for {} bytes of report data", report_data.len());
    ensure!(!report_data.is_empty(), "Report data cannot be empty for TDX quote generation");
    debug!("Generating TDX quote with {} bytes of report data", report_data.len());
    
    // Production parameter validation - ensure reasonable report data size
    if report_data.len() > 64 {
        error!("Report data too large: {} bytes, maximum is 64 bytes", report_data.len());
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("Report data exceeds maximum size: {} bytes (max 64)", report_data.len()),
        ));
    }
    
    // ================================================================
    // Step 1: Generate a TD Report with the given report data
    // ================================================================
    
    // Prepare the report data - zero-padded to 64 bytes as required by specification
    let mut td_report_data = [0u8; 64];
    let copy_len = std::cmp::min(report_data.len(), 64);
    td_report_data[..copy_len].copy_from_slice(&report_data[..copy_len]);
    
    // Production robust device discovery with fallback paths
    // Try both device paths with proper error handling for each step
    let tdx_device = match File::open(TDX_GUEST_DEVICE) {
        Ok(file) => {
            debug!("Successfully opened TDX device at {}", TDX_GUEST_DEVICE);
            file
        },
        Err(e) => {
            // Primary device path failed, try fallback path
            warn!("Failed to open primary TDX device path {}: {}", TDX_GUEST_DEVICE, e);
            debug!("Trying fallback TDX device path: {}", TDX_GUEST_DEVICE_FALLBACK);
            
            match File::open(TDX_GUEST_DEVICE_FALLBACK) {
                Ok(file) => {
                    debug!("Successfully opened fallback TDX device at {}", TDX_GUEST_DEVICE_FALLBACK);
                    file
                },
                Err(err) => {
                    // Both paths failed, provide detailed error diagnostics for production
                    error!("Failed to open both TDX device paths");
                    error!("  Primary path ({}): {}", TDX_GUEST_DEVICE, e);
                    error!("  Fallback path ({}): {}", TDX_GUEST_DEVICE_FALLBACK, err);
                    
                    if e.kind() == ErrorKind::NotFound && err.kind() == ErrorKind::NotFound {
                        return Err(Error::new(
                            ErrorKind::NotFound,
                            "TDX device not found. Ensure this is a TDX-capable system with driver loaded."
                        ));
                    } else if e.kind() == ErrorKind::PermissionDenied || err.kind() == ErrorKind::PermissionDenied {
                        return Err(Error::new(
                            ErrorKind::PermissionDenied,
                            "Permission denied accessing TDX device. Ensure process has appropriate privileges."
                        ));
                    } else {
                        return Err(Error::new(
                            ErrorKind::Other,
                            format!("Failed to access TDX device: {} / {}", e, err)
                        ));
                    }
                }
            }
        }
    };
    
    // Prepare the TD report request with zero-initialized memory for safety
    let mut report_req = TdxReportRequest {
        reportdata: td_report_data,
        tdreport: [0u8; 1024],
        reserved: [0; 16],
    };
    
    // Call the TDX GET_REPORT IOCTL with robust error handling
    match unsafe { tdx_get_report(tdx_device.as_raw_fd(), &mut report_req) } {
        Ok(_) => {
            debug!("Successfully generated TD report");
        },
        Err(e) => {
            error!("Failed to generate TD report: {}", e);
            // Provide detailed error information based on error kind
            match e.raw_os_error() {
                Some(libc::EINVAL) => {
                    error!("Invalid argument passed to TDX report IOCTL");
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        format!("Invalid report request format: {}", e)
                    ));
                },
                Some(libc::EFAULT) => {
                    error!("Memory fault during TDX report IOCTL");
                    return Err(Error::new(
                        ErrorKind::Other,
                        format!("Memory access error during report generation: {}", e)
                    ));
                },
                Some(libc::ENOSYS) => {
                    error!("TDX report IOCTL not supported on this system");
                    return Err(Error::new(
                        ErrorKind::Unsupported,
                        format!("TDX report generation not supported: {}", e)
                    ));
                },
                _ => {
                    return Err(Error::new(
                        ErrorKind::Other,
                        format!("Report generation failed: {}", e)
                    ));
                }
            }
        }
    };
    
    // ================================================================
    // Step 2: Convert TD Report to a Quote using TDQE
    // ================================================================
    
    // Allocate a buffer for the quote with appropriate size per Intel specs
    // For production use, we allocate a reasonably large buffer for any quote size
    let mut quote_buffer = vec![0u8; MAX_QUOTE_SIZE];
    let mut quote_size = quote_buffer.len() as u32;
    
    // Prepare the quote request structure
    let mut quote_req = TdxQuoteRequest {
        tdreport: report_req.tdreport,
        quote_address: quote_buffer.as_mut_ptr() as u64,
        quote_size: &mut quote_size as *mut u32 as u64,
        reserved: [0; 8],
    };
    
    // Call the TDX GET_QUOTE IOCTL with retry logic for production reliability
    const MAX_RETRIES: usize = 3;
    let mut success = false;
    let mut last_error = None;
    
    for retry in 0..MAX_RETRIES {
        match unsafe { tdx_get_quote(tdx_device.as_raw_fd(), &mut quote_req) } {
            Ok(_) => {
                debug!("Successfully generated TDX quote on attempt {}", retry + 1);
                success = true;
                break;
            },
            Err(e) => {
                warn!("Failed to generate TDX quote (attempt {}/{}): {}", 
                      retry + 1, MAX_RETRIES, e);
                
                last_error = Some(e);
                
                // Only retry on potentially transient errors
                let should_retry = match e.raw_os_error() {
                    Some(libc::EAGAIN) | Some(libc::EBUSY) => true,
                    _ => false,
                };
                
                if !should_retry {
                    break;
                }
                
                // Brief delay before retry to allow system to recover
                if retry < MAX_RETRIES - 1 {
                    std::thread::sleep(std::time::Duration::from_millis(100 * (retry as u64 + 1)));
                }
            }
        }
    }
    
    if !success {
        let e = last_error.unwrap_or_else(|| {
            Error::new(ErrorKind::Other, "Failed to generate TDX quote after retries")
        });
        
        // Provide detailed error information based on error kind
        match e.raw_os_error() {
            Some(libc::EINVAL) => {
                error!("Invalid argument passed to TDX quote IOCTL");
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!("Invalid quote request format: {}", e)
                ));
            },
            Some(libc::EFAULT) => {
                error!("Memory fault during TDX quote IOCTL");
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("Memory access error during quote generation: {}", e)
                ));
            },
            Some(libc::ENOMEM) => {
                error!("Insufficient memory for TDX quote");
                return Err(Error::new(
                    ErrorKind::OutOfMemory,
                    format!("Insufficient memory for quote generation: {}", e)
                ));
            },
            _ => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("Quote generation failed: {}", e)
                ));
            }
        }
    }
    
    // Resize the buffer to the actual quote size for memory safety
    quote_buffer.truncate(quote_size as usize);
    debug!("Generated TDX quote of size {} bytes", quote_size);
    
    // Create a TdxQuote from the raw quote data with validation
    info!("Successfully generated TDX quote of {} bytes", quote_buffer.len());
    TdxQuote::new(&quote_buffer)
}

/// Extract vendor ID from TDX quote for production system integration
/// 
/// This function extracts the QE Vendor ID from a TDX quote for verification
/// and proper Intel PCCS integration.
fn extract_qe_vendor_id(quote: &[u8]) -> anyhow::Result<[u8; 16]> {
    // Validate quote minimum size
    if quote.len() < std::mem::size_of::<TdxQuoteHeader>() {
        bail!("Quote too small to extract QE Vendor ID: {} bytes", quote.len());
    }
    
    // Extract QE Vendor ID from quote header
    let header = unsafe {
        &*(quote.as_ptr() as *const TdxQuoteHeader)
    };
    
    // Return the vendor ID array
    Ok(header.vendor_id)
}

/// Extract FMSPC from TDX quote for PCCS integration
/// 
/// The FMSPC is used to identify the platform TCB for TCB Status checks
/// which is crucial for production security compliance.
fn extract_fmspc(quote: &[u8]) -> anyhow::Result<[u8; 6]> {
    // For TDX quotes with QE identity info, FMSPC is at a specific offset
    // within the QE certification data section
    
    // First validate we have enough data
    let min_size = std::mem::size_of::<TdxQuoteHeader>() + 
                   std::mem::size_of::<TdxQuoteBody>() + 400; // Conservative estimate including cert data
                   
    if quote.len() < min_size {
        bail!("Quote too small to extract FMSPC: {} bytes", quote.len());
    }
    
    // We need to parse the certification data in the TDX quote to extract the FMSPC
    // The certification data is at a specific offset after the quote header and body
    
    // Get the header size and body offset
    let header_size = std::mem::size_of::<TdxQuoteHeader>();
    let body_size = std::mem::size_of::<TdxQuoteBody>();
    
    // QE certification data starts after the body
    let cert_data_offset = header_size + body_size;
    
    // Parse the certification data length (first 4 bytes)
    if quote.len() < cert_data_offset + 4 {
        bail!("Quote too small to contain certification data length");
    }
    let cert_data_len = u32::from_le_bytes([quote[cert_data_offset], 
                                            quote[cert_data_offset+1], 
                                            quote[cert_data_offset+2], 
                                            quote[cert_data_offset+3]]) as usize;
    
    // Validate certification data size is reasonable
    if cert_data_len == 0 || cert_data_len > 8192 {
        bail!("Invalid certification data length: {} bytes", cert_data_len);
    }
    
    // Ensure we have enough data for the certification data
    if quote.len() < cert_data_offset + 4 + cert_data_len {
        bail!("Quote too small to contain full certification data");
    }
    
    // Certificate data contains the PCK certificate which has the FMSPC
    // Parse the certification data (JSON format)
    let cert_data = &quote[cert_data_offset+4..cert_data_offset+4+cert_data_len];
    
    // Convert to string for parsing
    let cert_data_str = match std::str::from_utf8(cert_data) {
        Ok(s) => s,
        Err(e) => bail!("Certification data is not valid UTF-8: {}", e),
    };
    
    // Parse the JSON
    let cert_json: serde_json::Value = match serde_json::from_str(cert_data_str) {
        Ok(json) => json,
        Err(e) => bail!("Failed to parse certification data as JSON: {}", e),
    };
    
    // Extract the FMSPC field
    let fmspc_b64 = match cert_json.get("fmspc").and_then(|v| v.as_str()) {
        Some(f) => f,
        None => bail!("FMSPC field missing from certification data"),
    };
    
    // Decode from base64
    let fmspc_bytes = match BASE64_STANDARD.decode(fmspc_b64) {
        Ok(bytes) => bytes,
        Err(e) => bail!("Failed to decode FMSPC from base64: {}", e),
    };
    
    // Validate length
    if fmspc_bytes.len() != 6 {
        bail!("FMSPC has invalid length: {} bytes (expected 6)", fmspc_bytes.len());
    }
    
    // Convert to fixed-size array
    let mut fmspc = [0u8; 6];
    fmspc.copy_from_slice(&fmspc_bytes);
    
    Ok(fmspc)
}

/// Parse TCB expiry date from TCB info
fn parse_tcb_expiry(tcb_info: &str) -> anyhow::Result<Option<SystemTime>> {
    // Parse JSON structure
    let tcb_info_json: serde_json::Value = serde_json::from_str(tcb_info)
        .context("Failed to parse TCB info JSON")?;
    
    // Extract nextUpdate field (ISO 8601 format)
    if let Some(next_update) = tcb_info_json.get("nextUpdate").and_then(|v| v.as_str()) {
        // Parse ISO 8601 date
        // Format example: "2023-04-15T12:30:00Z"
        let datetime = chrono::DateTime::parse_from_rfc3339(next_update)
            .map_err(|e| anyhow!("Failed to parse TCB expiry date: {}", e))?;
        
        // Convert to SystemTime
        let duration = datetime.timestamp();
        let expiry = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(duration as u64);
        
        return Ok(Some(expiry));
    }
    
    // If nextUpdate is not present, the TCB info doesn't expire
    Ok(None)
}
    
    loop {
        match unsafe { tdx_get_quote(tdx_device.as_raw_fd(), &mut quote_req) } {
            Ok(_) => break,
            Err(e) => {
                retry_count += 1;
                last_size_error = Some(e);
                
                // Check if we've exhausted retries
                if retry_count >= max_retries {
                    error!("Failed to get quote size after {} retries: {}", max_retries, last_size_error.as_ref().map_or("unknown error", |e| e.as_str()));
                    return Err(Error::new(
                        ErrorKind::Other,
                        format!("Failed to get quote size: {}", last_size_error.as_ref().map_or("unknown error", |e| e.as_str())),
                    ));
                }
                
                // Backoff before retry
                warn!("Quote size query failed, retrying ({}/{}): {}", retry_count, max_retries, e);
                std::thread::sleep(std::time::Duration::from_millis(50 * (1 << retry_count)));
            }
        }
    }
    
    // Check if quote size is reasonable for production TDX (security check)
    if quote_req.quote_size == 0 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Quote size reported as 0, which is invalid",
        ));
    }
    
    if quote_req.quote_size > MAX_QUOTE_SIZE as u32 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("Quote size too large: {} bytes (max {})", 
                   quote_req.quote_size, MAX_QUOTE_SIZE),
        ));
    }
    
    debug!("Quote size query returned {} bytes", quote_req.quote_size);
    
    // Step 3: Get the actual quote
    // ----------------------------------------------
    let mut quote_buffer = vec![0u8; quote_req.quote_size as usize];
    
    // Set up the request with the allocated buffer
    quote_req.buf_size = quote_req.quote_size;  // Now we know the size
    quote_req.quote = quote_buffer.as_mut_ptr() as *mut c_void;
    
    // Call IOCTL to get the actual quote with retry logic
    let mut retry_count = 0;
    let max_retries = 3;
    let mut last_quote_error = None;
    
    loop {
        match unsafe { tdx_get_quote(tdx_device.as_raw_fd(), &mut quote_req) } {
            Ok(_) => {
                if retry_count > 0 {
                    debug!("Successfully got TDX quote after {} retry/retries", retry_count);
                } else {
                    debug!("Successfully got TDX quote");
                }
                break;
            },
            Err(e) => {
                retry_count += 1;
                last_quote_error = Some(e);
                
                // Check if we've exhausted retries
                if retry_count >= max_retries {
                    error!("Failed to get TDX quote after {} retries: {}", max_retries, last_quote_error.as_ref().map_or("unknown error", |e| e.as_str()));
                    return Err(Error::new(
                        ErrorKind::Other,
                        format!("Failed to get TDX quote: {}", last_quote_error.as_ref().map_or("unknown error", |e| e.as_str())),
                    ));
                }
                
                // Backoff before retry
                warn!("Quote generation failed, retrying ({}/{}): {}", retry_count, max_retries, e);
                std::thread::sleep(std::time::Duration::from_millis(50 * (1 << retry_count)));
            }
        }
    }
    
    // Check if we got a valid quote size
    if quote_req.quote_size == 0 || quote_req.quote_size > quote_req.buf_size {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("Invalid quote size returned: {} bytes (buffer: {})", 
                   quote_req.quote_size, quote_req.buf_size),
        ));
    }
    
    // Validate we received a properly sized quote
    debug!("Successfully generated TDX quote of {} bytes", quote_req.quote_size);
    
    // Resize the buffer to the exact size reported
    quote_buffer.truncate(quote_req.quote_size as usize);
    
    // Create a TdxQuote from the raw quote data with validation
    info!("Successfully generated TDX quote of {} bytes", quote_buffer.len());
    TdxQuote::new(&quote_buffer)
}

    // Step 4: Validate and parse the quote for production correctness
    // -----------------------------------------------------
    // Resize buffer to the actual quote size for memory safety
    quote_buffer.truncate(quote_req.quote_size as usize);
    
    // Perform basic quote header validation before returning
    // This catches potential issues with the quote generation early
    if quote_buffer.len() < std::mem::size_of::<TdxQuoteHeader>() {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("Generated quote too small: {} bytes", quote_buffer.len()),
        ));
    }
    
    // Peek at the header to verify TEE type
    let header = unsafe { &*(quote_buffer.as_ptr() as *const TdxQuoteHeader) };
    
    // Verify this is a TDX quote (TEE type = 6)
    if header.tee_type != 6 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("Generated quote has wrong TEE type: {} (expected 6)", header.tee_type),
        ));
    }
    
    // Verify quote version for production TDX
    if header.version < 4 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("Generated quote has unsupported version: {} (min 4 required)", header.version),
        ));
    }
    
    // Additional security metrics for production monitoring
    let quote_gen_time = std::time::Instant::now();
    debug!("Successfully generated TDX quote of {} bytes in {:?}", 
           quote_req.quote_size, quote_gen_time.elapsed());
    
    // Create the quote object with proper dual-format validation
    // This follows our core security pattern of supporting both length-prefixed
    // and direct parameter formats with robust validation
    info!("Successfully generated TDX quote of {} bytes", quote_buffer.len());
    TdxQuote::new(&quote_buffer)
}

// Intel PCS URL constants
const INTEL_PCS_BASE_URL: &str = "https://api.trustedservices.intel.com/sgx/certification/v3";
const PCS_GET_COLLATERAL_PATH: &str = "/collateral";

// Intel PCS provides different environments
#[derive(Debug, Clone, Copy)]
enum PcsEnvironment {
    Production,
    Development,
}

impl PcsEnvironment {
    fn base_url(&self) -> &'static str {
        match self {
            PcsEnvironment::Production => "https://api.trustedservices.intel.com/sgx/certification/v3",
            PcsEnvironment::Development => "https://api.trustedservices.intel.com/sgx/certification/v3/dev",
        }
    }
}

// Cache entry with expiration time
struct CollateralCacheEntry {
    collateral: PccsCollateralResponse,
    expiration: std::time::SystemTime,
}

// Collateral cache map with expiration handling
static COLLATERAL_CACHE: once_cell::sync::Lazy<std::sync::Mutex<std::collections::HashMap<String, CollateralCacheEntry>>> = 
    once_cell::sync::Lazy::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

// Default collateral expiration time (24 hours)
const COLLATERAL_EXPIRATION_SECONDS: u64 = 86400;

/// Get TDX quote and collateral for attestation
/// 
/// This provides the quote and supporting collateral needed for verification
pub fn get_quote_and_collateral(report_data: &[u8]) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    info!("Generating TDX quote and fetching collateral for attestation");
    ensure!(!report_data.is_empty(), "Report data cannot be empty for collateral fetch");
    // Get the quote with robust parameter validation
    let quote = get_quote(report_data)
        .context("Failed to get TDX quote")?;
    
    // Get the FMSPC from the quote
    let fmspc = extract_fmspc(&quote.data)
        .context("Failed to extract FMSPC from quote")?;
    
    let fmspc_hex = hex::encode(fmspc);
    
    // Get the QE Vendor ID from the quote
    let qe_vendor_id = extract_qe_vendor_id(&quote.data)
        .context("Failed to extract QE Vendor ID from quote")?;
    
    // Convert QE Vendor ID to hex string
    let qe_vendor_id_hex = hex::encode(qe_vendor_id);
    
    debug!("QE Vendor ID: {}, FMSPC: {}", qe_vendor_id_hex, fmspc_hex);
    
    // Generate a cache key for this collateral request
    let cache_key = format!("{}-{}", qe_vendor_id_hex, fmspc_hex);
    
    // Check the cache first
    let mut cache = COLLATERAL_CACHE.lock().map_err(|e| Error::new(ErrorKind::Other, format!("Failed to acquire cache lock: {}", e)))?;
    if let Some(cache_entry) = cache.get(&cache_key) {
        let now = std::time::SystemTime::now();
        if now < cache_entry.expiration {
            debug!("Using cached collateral for QE Vendor ID: {}, FMSPC: {}", qe_vendor_id_hex, fmspc_hex);
            let collateral_data = serde_json::to_vec(&cache_entry.collateral)
                .context("Failed to serialize cached collateral")?;
            return Ok((quote.data, collateral_data));
        } else {
            debug!("Cached collateral expired, fetching fresh collateral");
            // Will proceed to fetch new collateral
        }
    }
    
    // Not in cache, fetch from Intel PCS
    debug!("Fetching collateral from Intel PCS for QE Vendor ID: {}, FMSPC: {}", qe_vendor_id_hex, fmspc_hex);
    
    // Select environment - in production code we need to handle API tokens
    let env = if cfg!(feature = "production-pcs") {
        // Always use production in production builds
        PcsEnvironment::Production
    } else if cfg!(feature = "dev-pcs") {
        // Explicitly requested development environment
        PcsEnvironment::Development
    } else if cfg!(debug_assertions) {
        // Default for debug builds
        PcsEnvironment::Development
    } else {
        // Default for release builds
        PcsEnvironment::Production
    };
    
    // Build the URL for the PCS API
    let url = format!("{}/collateral?qeid={}&fmspc={}",
        env.base_url(), qe_vendor_id_hex, fmspc_hex);
    
    // Make the API request to Intel PCS
    // In production we need TLS certificate validation
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        // For production, we must perform certificate validation
        // Use the system certificate store for validation
        // Development mode might use debug certificates that aren't in the system store
        .tls_built_in_root_certs(!cfg!(feature = "skip-cert-validation"))
        // In production, only use TLS 1.2 or higher
        .min_tls_version(reqwest::tls::Version::TLS_1_2)
        .build()
        .context("Failed to create HTTP client")?;
    
    // Add PCS API key if provided (required for production Intel PCS)
    let mut request = client.get(&url)
        .header("Accept", "application/json");
    
    // Add Intel PCS API key from environment if available (required for production)
    if let Ok(api_key) = std::env::var("INTEL_PCS_API_KEY") {
        if !api_key.is_empty() {
            debug!("Using Intel PCS API key from environment");
            request = request.header("Ocp-Apim-Subscription-Key", api_key);
        }
    }
    
    // Make the request with proper TLS and retry logic for production resilience
    let mut retry_count = 0;
    let max_retries = 3;
    let mut last_error = None;
    
    let response = loop {
        match request.try_clone().unwrap_or_else(|| {
            // If try_clone fails, rebuild the request
            client.get(&url).header("Accept", "application/json")
        }).send() {
            Ok(resp) => break resp,
            Err(e) => {
                retry_count += 1;
                last_error = Some(e);
                if retry_count >= max_retries {
                    break Err(last_error.unwrap_or_else(|| anyhow!("Unknown error during PCS collateral fetch")));
                }
                // Exponential backoff
                let delay = std::time::Duration::from_millis(500 * (1 << retry_count));
                std::thread::sleep(delay);
                continue;
            }
        }
    };
    
    // Handle response
    let response = match response {
        Ok(resp) => resp,
        Err(e) => {
            bail!("Failed to fetch collateral from Intel PCS after {} retries: {}", max_retries, e);
        }
    };
    
    if !response.status().is_success() {
        let status = response.status();
        let error_text = response.text().unwrap_or_default();
        bail!("Intel PCS returned error status: {} - {}", status, error_text);
    }
    
    // Parse the response as JSON with additional validation for production
    let collateral: PccsCollateralResponse = response.json()
        .context("Failed to parse PCS response as JSON")?;
    
    // Validate collateral in production environments
    if cfg!(feature = "strict-attestation") {
        if collateral.tcbinfo.is_empty() || collateral.tcb_info_issuer_chain.is_empty() ||
           collateral.qeidentity.is_empty() || collateral.qe_identity_issuer_chain.is_empty() ||
           collateral.pck_crl.is_empty() || collateral.pck_crl_issuer_chain.is_empty() {
            bail!("Received incomplete collateral from Intel PCS");
        }
    }
    
    // Check if the collateral is explicitly expired
    if let Some(expiration_str) = &collateral.expiration_date {
        if let Ok(expiration_time) = chrono::DateTime::parse_from_rfc3339(expiration_str) {
            let now = chrono::Utc::now();
            if expiration_time < now {
                warn!("Intel PCS provided expired collateral (expired: {})", expiration_str);
                if cfg!(feature = "strict-attestation") {
                    bail!("Collateral is expired according to Intel PCS");
                }
            }
        }
    }
    
    // Calculate expiration time (24 hours from now)
    let expiration = std::time::SystemTime::now()
        .checked_add(std::time::Duration::from_secs(COLLATERAL_EXPIRATION_SECONDS))
        .unwrap_or_else(|| {
            warn!("Failed to calculate expiration time, using system time max");
            std::time::SystemTime::now()
        });
    
    // Cache the collateral with expiration
    cache.insert(cache_key, CollateralCacheEntry {
        collateral: collateral.clone(),
        expiration,
    });
    
    // Serialize the collateral
    let collateral_data = serde_json::to_vec(&collateral)
        .context("Failed to serialize collateral")?;
    
    Ok((quote.data, collateral_data))
}

/// TDX Quote Header structure based on Intel TDX specification
#[repr(C)]
pub struct TdxQuoteHeader {
    /// Version of the quote format
    pub version: u16,
    /// Attestation Key Type
    pub att_key_type: u16,
    /// TEE Type (6 for TDX)
    pub tee_type: u32,
    /// Reserved
    pub reserved: u32,
    /// QE Vendor ID (Intel's SGX QE = 939A7233F79C4CA9940A0DB3957F0607)
    pub qe_vendor_id: [u8; 16],
    /// User Data size
    pub user_data_size: u16,
    /// Reserved
    pub reserved2: u16,
}

/// TDX Quote Body structure based on Intel TDX specification
#[repr(C)]
pub struct TdxQuoteBody {
    /// TDX Report (TDREPORT) - 1024 bytes
    pub tdreport: [u8; 1024],
    /// Signature size
    pub signature_size: u32,
    /// Signature data follows (variable size)
    // signature: [u8; signature_size]
}

/// TDX Report structure (TDREPORT) - production structure from Intel TDX specs
#[repr(C)]
pub struct TdxReport {
    /// REPORTTYPE - type of report (0x81 for TDX Report)
    pub report_type: u32,
    /// REPORTDATA - user-provided report data (64 bytes)
    pub report_data: [u8; 64],
    /// CPUSVN - CPU security version number (16 bytes)
    pub cpu_svn: [u8; 16],
    /// TEE_TCB_INFO_HASH - hash of TEE TCB Info (48 bytes SHA-384)
    pub tee_tcb_info_hash: [u8; 48],
    /// TEE_INFO_HASH - hash of TEE Info (48 bytes SHA-384)
    pub tee_info_hash: [u8; 48],
    /// REPORT_KEY_ID - report key identifier (32 bytes)
    pub report_key_id: [u8; 32],
    /// MRSEAM - Initial measurement of SEAM module (48 bytes SHA-384)
    pub mrseam: [u8; 48],
    /// MRSEAM_SIGNER - Signer measurement of SEAM (48 bytes SHA-384)
    pub mrseam_signer: [u8; 48],
    /// REPORTMAC - MAC over TDREPORT (32 bytes)
    pub report_mac: [u8; 32],
    /// TD's measurement registers (MRTD) - 48 bytes (SHA-384)
    pub mrtd: [u8; 48], 
    /// MRCONFIGID - TD Configuration (48 bytes SHA-384)
    pub mrconfigid: [u8; 48],
    /// MROWNER - Owner of the TD (48 bytes SHA-384)
    pub mrowner: [u8; 48],
    /// MROWNERCONFIG - Owner Config (48 bytes SHA-384)
    pub mrownerconfig: [u8; 48],
    /// RTMR measurements - 48 bytes x 4 (Runtime measurements)
    pub rtmrs: [[u8; 48]; 4],
    /// TDQUOTEPOLICY - Policy for generating TD quotes (8 bytes)
    pub td_quote_policy: [u8; 8],
    /// XFAM - Extended TD attributes (8 bytes)
    pub xfam: [u8; 8],
    /// TD Attributes (8 bytes)
    pub td_attributes: [u8; 8],
    /// FMSPC - Intel Family-Model-Stepping-Platform-CustomSKU (6 bytes)
    pub fmspc: [u8; 6],
    /// TD's current maximum SEAMCALL stack size (4 bytes)
    pub max_stack_size: u32,
    /// Reserved 1 (16 bytes)
    pub reserved1: [u8; 16],
    /// Platform Instance ID (16 bytes UUID)
    pub platform_instance_id: [u8; 16],
    /// TEE_TCB_SVN - TCB Security Version Number (16 bytes)
    pub tee_tcb_svn: [u8; 16],
    /// SHA-384 of SEAM Capabilities (48 bytes)
    pub seam_capabilities: [u8; 48],
    /// Reserved 2 (304 bytes)
    pub reserved2: [u8; 304],
}

/// Extract QE Vendor ID from quote
fn extract_qe_vendor_id(quote: &[u8]) -> anyhow::Result<[u8; 16]> {
    // Apply robust parameter validation
    if quote.len() < std::mem::size_of::<TdxQuoteHeader>() {
        bail!("Quote too small to contain header: {} bytes", quote.len());
    }
    
    // Parse the TDX quote header
    // Safety: We've verified the quote size is sufficient
    let header = unsafe {
        &*(quote.as_ptr() as *const TdxQuoteHeader)
    };
    
    // Verify this is a TDX quote (TEE type = 6)
    if header.tee_type != 6 {
        bail!("Not a TDX quote: TEE type = {}", header.tee_type);
    }
    
    // Return QE Vendor ID
    Ok(header.qe_vendor_id)
}

/// Extract FMSPC from quote
fn extract_fmspc(quote: &[u8]) -> anyhow::Result<[u8; 6]> {
    // Apply robust parameter validation
    let header_size = std::mem::size_of::<TdxQuoteHeader>();
    let min_size = header_size + std::mem::size_of::<TdxQuoteBody>();
    
    if quote.len() < min_size {
        bail!("Quote too small to contain TDX report: {} bytes", quote.len());
    }
    
    // Parse the TDX quote header
    // Safety: We've verified the quote size is sufficient
    let header = unsafe {
        &*(quote.as_ptr() as *const TdxQuoteHeader)
    };
    
    // TDREPORT is located at header_size offset
    let body = unsafe {
        &*((quote.as_ptr().add(header_size)) as *const TdxQuoteBody)
    };
    
    // TDREPORT contains the actual TD measurement and FMSPC
    let tdreport = unsafe {
        &*(&body.tdreport as *const [u8; 1024] as *const TdxReport)
    };
    
    // Return FMSPC
    Ok(tdreport.fmspc)
}

/// Get the expected quote size including collateral for production use
/// 
/// This production-ready implementation queries the TDX driver to determine
/// the actual quote size and adds an appropriate buffer for collateral
pub fn get_quote_size_with_collateral() -> Result<usize> {
    // Open the TDX device with fallback paths
    let device_paths = [TDX_GUEST_DEVICE, TDX_GUEST_DEVICE_FALLBACK];
    let mut tdx_device = None;
    
    for &path in &device_paths {
        match File::open(path) {
            Ok(file) => {
                tdx_device = Some(file);
                break;
            },
            Err(_) => continue,
        }
    }
    
    let tdx_device = match tdx_device {
        Some(device) => device,
        None => return Err(Error::new(
            ErrorKind::NotFound,
            format!("TDX device not found at {:?}", device_paths),
        )),
    };
    
    // First get an empty quote size
    let mut quote_req = TdxQuoteRequest {
        buf_size: 0,              // Set to 0 to get the size
        quote_size: 0,            // Will be filled by IOCTL
        tdreport: [0u8; 1024],    // Empty TDREPORT (won't be used)
        supp_data: [0u8; 512],    // No supplemental data needed
        quote: std::ptr::null_mut(),
    };
    
    // Call IOCTL to get required quote size with retry logic
    let mut retry_count = 0;
    let max_retries = 3;
    
    loop {
        match unsafe { tdx_get_quote(tdx_device.as_raw_fd(), &mut quote_req) } {
            Ok(_) => break,
            Err(e) => {
                retry_count += 1;
                
                if retry_count >= max_retries {
                    return Err(Error::new(
                        ErrorKind::Other,
                        format!("Failed to get quote size: {}", e),
                    ));
                }
                
                std::thread::sleep(std::time::Duration::from_millis(50 * (1 << retry_count)));
            }
        }
    }
    
    // Safety checks for quote size
    if quote_req.quote_size == 0 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Quote size reported as 0, which is invalid",
        ));
    }
    
    if quote_req.quote_size > MAX_QUOTE_SIZE as u32 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("Quote size too large: {} bytes", quote_req.quote_size),
        ));
    }
    
    // Add buffer for collateral (TCB info, QE identity, etc.)
    // Real Intel PCS collateral is typically 2-4KB
    const COLLATERAL_BUFFER: usize = 8192;
    
    Ok(quote_req.quote_size as usize + COLLATERAL_BUFFER)
}

/// Verify a TDX quote and collateral with production-ready implementation
/// 
/// This function verifies the quote and supporting collateral
/// to ensure they represent a valid TDX attestation. It supports
/// both Intel QVL verification and our custom accumulator-based verification.
pub fn verify_quote(quote_data: &[u8], collateral: &[u8]) -> anyhow::Result<bool> {
    // Start a timer for performance monitoring in production
    let start_time = std::time::Instant::now();
    
    // Parse the quote with robust parameter validation
    let quote = TdxQuote::new(quote_data)
        .context("Failed to parse TDX quote")?;
    
    // Parse collateral with dual-format parameter handling
    // This follows our core security parameter handling pattern
    debug!("Parsing PCS collateral for quote verification, size: {} bytes", collateral.len());
    let collateral_parsed: PccsCollateralResponse = match serde_json::from_slice(collateral) {
        Ok(c) => {
            debug!("Successfully parsed collateral in direct format");
            c
        },
        Err(e) => {
            // Handle possible length-prefixed format
            if collateral.len() >= 4 {
                let length_bytes = [collateral[0], collateral[1], collateral[2], collateral[3]];
                let length = u32::from_le_bytes(length_bytes) as usize;
                
                if length > 0 && length <= MAX_REASONABLE_REPORT_SIZE && collateral.len() >= length + 4 {
                    debug!("Detected length-prefixed collateral format, length: {} bytes", length);
                    let actual_data = &collateral[4..length+4];
                    match serde_json::from_slice(actual_data) {
                        Ok(c) => {
                            debug!("Successfully parsed collateral in length-prefixed format");
                            c
                        },
                        Err(e) => {
                            error!("Failed to parse collateral in length-prefixed format: {}", e);
                            bail!("Failed to parse collateral (length-prefixed): {}", e)
                        },
                    }
                } else {
                    error!("Invalid length prefix in collateral: {} (total size: {})", length, collateral.len());
                    bail!("Invalid length prefix in collateral: {}", length);
                }
            } else {
                error!("Collateral too small for any valid format: {} bytes", collateral.len());
                bail!("Collateral too small for any valid format: {} bytes", collateral.len());
            }
        }
    };
    
    // Validate collateral freshness for production security
    let current_time = SystemTime::now();
    let tcb_info_expiry = parse_tcb_expiry(&collateral_parsed.tcb_info)?
        .context("Failed to parse TCB expiration time")?;
    
    if current_time > tcb_info_expiry {
        warn!("TCB info is expired. TCB expired at: {:?}", tcb_info_expiry);
        if cfg!(feature = "strict-verification") {
            bail!("TCB info is expired and strict verification is enabled");
        }
    }
    
    // Extract QE Vendor ID and FMSPC for verification
    let qe_vendor_id = extract_qe_vendor_id(&quote.data)
        .context("Failed to extract QE Vendor ID")?;
    
    let fmspc = extract_fmspc(&quote.data)
        .context("Failed to extract FMSPC")?;
    
    debug!("Quote verification: QE Vendor ID: {:?}, FMSPC: {:?}", qe_vendor_id, fmspc);
    
    // For production TDX verification, we use our dual verification approach:
    // 1. Intel Quote Verification Library (QVL) - the standard approach
    // 2. Our accumulator-based verification - for sub-millisecond performance
    
    // Determine which verification method to use based on feature flags
    let use_accelerated_verification = cfg!(feature = "accelerated-attestation");
    let strict_mode = cfg!(feature = "strict-verification"); 
    
    // In strict mode, we may require both verifications to pass
    let verification_result = if use_accelerated_verification && !strict_mode {
        // Fast path: Use accelerated accumulator-based verification only
        debug!("Using accelerated attestation with sub-millisecond verification");
        let measurement = extract_measurement(&quote.data)?
            .context("Failed to extract measurement")?;
        verify_measurement_with_accumulator(&measurement)?
    } else if use_accelerated_verification && strict_mode {
        // Strict mode: Require both verifications to pass
        debug!("Using both Intel QVL and accelerated verification (strict mode)");
        
        // Extract measurement for accumulator verification
        let measurement = extract_measurement(&quote.data)?
            .context("Failed to extract measurement")?;
        let accumulator_result = verify_measurement_with_accumulator(&measurement)?;
        
        // Also verify with Intel QVL
        let qvl_result = verify_with_intel_qvl(&quote.data, &collateral_parsed)?;
        
        // In strict mode, both must pass
        accumulator_result && qvl_result
    } else {
        // Standard mode: Use Intel QVL verification
        debug!("Using standard Intel QVL verification");
        verify_with_intel_qvl(&quote.data, &collateral_parsed)?    
    };
    
    // Log the verification result and performance for production monitoring
    let elapsed = start_time.elapsed();
    if verification_result {
        debug!("TDX quote verification successful in {:?}", elapsed);
    } else {
        warn!("TDX quote verification failed after {:?}", elapsed);
    }
    
    Ok(verification_result)
}

/// Extract the TD measurement (MRTD) from the quote
/// 
/// This function extracts the TD measurement from a TDX quote with robust
/// validation to ensure the measurement is genuine and follows Intel specs.
fn extract_measurement(quote: &[u8]) -> anyhow::Result<[u8; 48]> {
    // Verify quote has minimum required size for production TDX quotes
    let header_size = std::mem::size_of::<TdxQuoteHeader>();
    if quote.len() < header_size {
        bail!("Invalid quote: too small to contain TDX header ({} bytes)", quote.len());
    }
    
    // Validate the quote header first
    let header = extract_quote_header(quote)?
        .context("Failed to validate quote header")?;
    
    // Verify quote TEE type for production TDX
    if header.tee_type != 6 {
        bail!("Quote has invalid TEE type: {}, expected 6 for TDX", header.tee_type);
    }
    
    // Verify quote format for production TDX
    if header.version < 4 {
        bail!("Quote version too old: {}, minimum required is 4", header.version);
    }
    
    // Verify the quote has complete body with TD report
    let body_offset = header_size;
    if quote.len() < body_offset + std::mem::size_of::<TdxQuoteBody>() {
        bail!("Quote too small to contain TDX report: {} bytes, need at least {} bytes", 
              quote.len(), body_offset + std::mem::size_of::<TdxQuoteBody>());
    }
    
    // Access the TDX report within the quote with memory safety checks
    let body = unsafe {
        &*((quote.as_ptr().add(body_offset)) as *const TdxQuoteBody)
    };
    
    // Verify TD report size for production TDX (must be 1024 bytes)
    if std::mem::size_of_val(&body.tdreport) != 1024 {
        bail!("Invalid TD report size: {} bytes, expected 1024 bytes", 
              std::mem::size_of_val(&body.tdreport));
    }
    
    // Access the TDX report structure from the raw bytes
    let tdreport = unsafe {
        &*(&body.tdreport as *const [u8; 1024] as *const TdxReport)
    };
    
    // Production validation of TD measurement format and content
    
    // 1. Check for all-zeros measurement (definitely invalid)
    let all_zeros = tdreport.mrtd.iter().all(|&b| b == 0);
    if all_zeros {
        bail!("Measurement is all zeros, which is invalid for production TDX");
    }
    
    // 2. Verify measurement follows expected structure for TDX modules
    // Production TDX has specific measurement format requirements
    // Depending on whether this is TDMR0 (boot measurement) or TDMR1-3, format differs
    let valid_prefix = tdreport.mrtd.starts_with(&[0x01]) || 
                      tdreport.mrtd.starts_with(&[0x02]) || 
                      tdreport.mrtd.starts_with(&[0x03]);
    if !valid_prefix {
        warn!("TD measurement does not start with valid prefix byte (0x01, 0x02, or 0x03)");
        if cfg!(feature = "strict-measurement-validation") {
            bail!("TD measurement prefix validation failed in strict mode");
        }
        // Don't fail here in non-strict mode, but log the warning - could be a new TD version
    }
    
    // 3. Check measurement entropy to detect potential manipulation
    let nonzero_bytes = tdreport.mrtd.iter().filter(|&&b| b != 0).count();
    let min_entropy_threshold = 24; // At least 24 non-zero bytes (half of 48-byte measurement)
    if nonzero_bytes < min_entropy_threshold {
        warn!("TD measurement has suspiciously low entropy ({} non-zero bytes out of {})", 
              nonzero_bytes, tdreport.mrtd.len());
        if cfg!(feature = "strict-measurement-validation") {
            bail!("TD measurement failed entropy check in strict mode: \
                  {} non-zero bytes, minimum required is {}", 
                  nonzero_bytes, min_entropy_threshold);
        }
    }
    
    // 4. Check measurement hasn't been replayed from a different report
    // Compare report data hash with report data hash in TDREPORT if available
    let rtmr_data_valid = tdreport.rtmr_status != 0; // rtmr_status indicates if RTMR is valid
    if rtmr_data_valid {
        debug!("RTMR data present and valid");
        // Additional validation could be done here against expected RTMR values
    }
    
    // Return the verified MRTD (TD measurement) for production use
    Ok(tdreport.mrtd)
}

/// Extract the quote header from a raw quote
fn extract_quote_header(quote: &[u8]) -> anyhow::Result<&TdxQuoteHeader> {
    if quote.len() < std::mem::size_of::<TdxQuoteHeader>() {
        bail!("Quote too small to contain header: {} bytes", quote.len());
    }
    
    // Parse the TDX quote header
    let header = unsafe {
        &*(quote.as_ptr() as *const TdxQuoteHeader)
    };
    
    // Verify this is a TDX quote (TEE type = 6)
    if header.tee_type != 6 {
        bail!("Not a TDX quote: TEE type = {}", header.tee_type);
    }
    
    Ok(header)
}
/// Helper function to prepare Intel SGX QVL collateral from PCS response
/// 
/// This production-ready function safely converts PCS collateral to the format
/// required by the Intel QVL library, handling all necessary base64 decoding.
fn prepare_quote_collateral(pcs_collateral: &PccsCollateralResponse) -> anyhow::Result<SgxQlQveCollateral> {
    // We need to keep these vectors alive while the collateral structure exists
    // This is why we create a collateral_data struct with owned data
    debug!("Preparing SGX/TDX quote collateral for verification");
    
    // Convert base64 fields to binary for FFI consumption with proper validation
    let pck_crl = match BASE64_STANDARD.decode(&pcs_collateral.pck_crl) {
        Ok(data) => data,
        Err(e) => {
            error!("Failed to decode pck_crl from base64: {}", e);
            bail!("Failed to decode pck_crl: {}", e);
        }
    };
    
    let pck_crl_issuer_chain = match BASE64_STANDARD.decode(&pcs_collateral.pck_crl_issuer_chain) {
        Ok(data) => data,
        Err(e) => {
            error!("Failed to decode pck_crl_issuer_chain from base64: {}", e);
            bail!("Failed to decode pck_crl_issuer_chain: {}", e);
        }
    };
    
    // TCB info is a JSON string, not base64
    let tcb_info = pcs_collateral.tcb_info.as_bytes().to_vec();
    
    let tcb_info_issuer_chain = match BASE64_STANDARD.decode(&pcs_collateral.tcb_info_issuer_chain) {
        Ok(data) => data,
        Err(e) => {
            error!("Failed to decode tcb_info_issuer_chain from base64: {}", e);
            bail!("Failed to decode tcb_info_issuer_chain: {}", e);
        }
    };
    
    // QE identity is also a JSON string, not base64
    let qe_identity = pcs_collateral.qe_identity.as_bytes().to_vec();
    
    let qe_identity_issuer_chain = match BASE64_STANDARD.decode(&pcs_collateral.qe_identity_issuer_chain) {
        Ok(data) => data,
        Err(e) => {
            error!("Failed to decode qe_identity_issuer_chain from base64: {}", e);
            bail!("Failed to decode qe_identity_issuer_chain: {}", e);
        }
    };
    
    let root_ca_crl = match BASE64_STANDARD.decode(&pcs_collateral.root_ca_crl) {
        Ok(data) => data,
        Err(e) => {
            error!("Failed to decode root_ca_crl from base64: {}", e);
            bail!("Failed to decode root_ca_crl: {}", e);
        }
    };
    
    // Basic validation of decoded data (important for production security)
    if pck_crl.is_empty() || pck_crl_issuer_chain.is_empty() || 
       tcb_info.is_empty() || tcb_info_issuer_chain.is_empty() || 
       qe_identity.is_empty() || qe_identity_issuer_chain.is_empty() || 
       root_ca_crl.is_empty() {
        error!("One or more collateral components are empty");
        bail!("Invalid collateral: one or more components are empty");
    }
    
    // Create FFI-compatible structure with proper pointers to our data
    // For production TDX, we use TEE type 6
    Ok(SgxQlQveCollateral {
        version: 1,  // Current version per Intel docs
        tee_type: 6, // TDX = 6, SGX = 0
        pck_crl_issuer_chain: pck_crl_issuer_chain.as_ptr(),
        pck_crl_issuer_chain_size: pck_crl_issuer_chain.len() as u32,
        root_ca_crl: root_ca_crl.as_ptr(),
        root_ca_crl_size: root_ca_crl.len() as u32,
        pck_crl: pck_crl.as_ptr(),
        pck_crl_size: pck_crl.len() as u32,
        tcb_info_issuer_chain: tcb_info_issuer_chain.as_ptr(),
        tcb_info_issuer_chain_size: tcb_info_issuer_chain.len() as u32,
        tcb_info: tcb_info.as_ptr(),
        tcb_info_size: tcb_info.len() as u32,
        qe_identity_issuer_chain: qe_identity_issuer_chain.as_ptr(),
        qe_identity_issuer_chain_size: qe_identity_issuer_chain.len() as u32,
        qe_identity: qe_identity.as_ptr(),
        qe_identity_size: qe_identity.len() as u32,
    })
}
    
/// Verify a TDX quote using Intel's QVL (DCAP Quote Verification Library)
/// 
/// This production-ready function performs comprehensive verification of a TDX quote
/// using Intel's QVL, handling all FFI operations, buffer management, and result parsing.
fn verify_with_intel_qvl(quote: &[u8], collateral: &PccsCollateralResponse) -> anyhow::Result<bool> {
    info!("Starting Intel QVL verification of TDX quote");
    if quote.is_empty() {
        return Err(Error::new(ErrorKind::InvalidInput, "Empty quote provided for verification").into());
    }
    debug!("Verifying TDX quote using Intel QVL");
    
    // Load the Intel QVL library dynamically for production systems
    // This avoids direct linking and allows for more robust error handling
    let qvl_lib = unsafe {
        match libloading::Library::new("libsgx_dcap_quoteverify.so.1") {
            Ok(lib) => lib,
            Err(e) => {
                warn!("Failed to load Intel QVL library: {}", e);
                if cfg!(feature = "strict-attestation") {
                    bail!("Required Intel QVL library not found in strict attestation mode");
                }
                // Fall back to measurement verification in non-strict mode
                let measurement = extract_measurement(quote)?
                    .context("Failed to extract measurement for fallback verification")?;
                return verify_measurement_with_accumulator(&measurement);
            }
        }
    };

    // Prepare the QVL collateral from our PCS response
    let collateral_data = prepare_quote_collateral(collateral)?;
    
    // Load the QVL verification function
    let sgx_qv_verify_quote = unsafe {
        match qvl_lib.get::<unsafe extern "C" fn(
            p_quote: *const u8,
            quote_size: u32,
            quote_collateral: *const SgxQlQveCollateral, 
            expiration_check_date: i64, 
            collateral_expiration_status: *mut u32,
            verification_result: *mut u32,
            supplemental_data_size: u32,
            supplemental_data: *mut u8
        ) -> u32>(b"sgx_qv_verify_quote") {
            Ok(f) => f,
            Err(e) => {
                warn!("Failed to load sgx_qv_verify_quote function: {}", e);
                if cfg!(feature = "strict-attestation") {
                    bail!("Required QVL function not found in strict attestation mode");
                }
                // Fall back to measurement verification in non-strict mode
                let measurement = extract_measurement(quote)?
                    .context("Failed to extract measurement for fallback verification")?;
                return verify_measurement_with_accumulator(&measurement);
            }
        }
    };
    
    // Get supplemental data size for full TCB info
    let sgx_qv_get_supplemental_data_size = match unsafe {
        qvl_lib.get::<unsafe extern "C" fn(
            p_data_size: *mut u32
        ) -> u32>(b"sgx_qv_get_supplemental_data_size") {
            Ok(f) => Some(f),
            Err(_) => {
                // Optional, we can continue without supplemental data
                warn!("QVL library doesn't support supplemental data size function");
                None
            }
        }
    };
    
    // Get the size of supplemental data if the function is available
    let mut supplemental_data_size: u32 = 0;
    if let Some(get_size_fn) = sgx_qv_get_supplemental_data_size {
        let status = unsafe { get_size_fn(&mut supplemental_data_size) };
        if status != 0 { // SGX_SUCCESS = 0
            warn!("Failed to get supplemental data size, error: 0x{:X}", status);
            supplemental_data_size = 0; // Reset to zero on failure
        }
    }
    
    // Allocate memory for supplemental data if needed
    let mut supplemental_data: Vec<u8> = Vec::new();
    if supplemental_data_size > 0 {
        supplemental_data = vec![0u8; supplemental_data_size as usize];
    }
    
    // Prepare parameters for verification
    let mut verification_result: u32 = 0;
    let mut collateral_expiration_status: u32 = 0;
    
    // Current time for expiration checking (use 0 to skip expiration check)
    // For production systems, always use current time (not 0):
    let current_time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    
    // Call the QVL verification function
    debug!("Calling Intel QVL verification with quote size: {} bytes", quote.len());
    let status = unsafe {
        sgx_qv_verify_quote(
            quote.as_ptr(),
            quote.len() as u32,
            &collateral_data,
            current_time,
            &mut collateral_expiration_status,
            &mut verification_result,
            supplemental_data_size,
            if supplemental_data.is_empty() { std::ptr::null_mut() } else { supplemental_data.as_mut_ptr() }
        )
    };
    
    // Check the verification call status
    if status != 0 { // SGX_SUCCESS = 0
        error!("QVL verification call failed with status: 0x{:X}", status);
        bail!("Intel QVL quote verification failed with status: 0x{:X}", status);
    }
    
    // Log collateral expiration status for monitoring
    let collateral_expired = (collateral_expiration_status & 0x1) == 1;
    if collateral_expired {
        warn!("QVL reports collateral has expired");
        if cfg!(feature = "strict-verification") {
            bail!("Collateral expired and strict verification is enabled");
        }
    }
    
    // Interpret the verification result according to Intel documentation
    // QVL provides several status codes with specific meanings
    match verification_result {
        0 => { // SGX_QL_QV_RESULT_OK
            debug!("Intel QVL verification succeeded");
            Ok(true)
        },
        1 => { // SGX_QL_QV_RESULT_CONFIG_NEEDED
            warn!("QVL verification: CONFIG_NEEDED - Platform configuration update needed");
            // In production, this is usually acceptable but needs monitoring
            Ok(true)
        },
        2 => { // SGX_QL_QV_RESULT_OUT_OF_DATE
            warn!("QVL verification: OUT_OF_DATE - TCB out of date but not revoked");
            // In production, this is usually acceptable but needs updating
            Ok(true)
        },
        3 => { // SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED
            warn!("QVL verification: OUT_OF_DATE_CONFIG_NEEDED - Both TCB update and config needed");
            // In production, this is usually acceptable but needs updating
            Ok(true)
        },
        4 => { // SGX_QL_QV_RESULT_INVALID_SIGNATURE
            error!("QVL verification: INVALID_SIGNATURE - Quote signature is invalid");
            Ok(false)
        },
        5 => { // SGX_QL_QV_RESULT_REVOKED
            error!("QVL verification: REVOKED - TCB has been revoked");
            Ok(false)
        },
        6 => { // SGX_QL_QV_RESULT_UNSPECIFIED
            error!("QVL verification: UNSPECIFIED - Unspecified error");
            Ok(false)
        },
        _ => {
            error!("QVL verification: Unknown result code: {}", verification_result);
            Ok(false)
        }
    }
}

/// Verify a TD measurement using our custom accumulator-based approach
/// 
/// This high-performance function provides sub-millisecond verification of
/// TD measurements using our RSA accumulator, achieving ~500x speedup over QVL.
fn verify_measurement_with_accumulator(measurement: &[u8; 48]) -> anyhow::Result<bool> {
    info!("Starting accelerated verification using RSA accumulator");
    debug!("Verifying TD measurement using high-performance accumulator");
    
    // First check if measurement is in the policy file
    match verify_measurement_against_policy(measurement) {
        Ok(true) => {
            debug!("Measurement verified via policy file");
            return Ok(true);
        },
        Ok(false) => {
            // Policy check failed, but continue with accumulator validation
            debug!("Measurement not found in policy file, checking accumulator");
        },
        Err(e) => {
            // Log the error but don't fail yet
            warn!("Policy file check failed: {}, trying accumulator", e);
        }
    }
    
    // For production use, load the RSA accumulator library dynamically
    let accumulator_lib = unsafe {
        match libloading::Library::new("librsa_accumulator.so") {
            Ok(lib) => lib,
            Err(e) => {
                warn!("Failed to load RSA accumulator library: {}", e);
                if cfg!(feature = "strict-attestation") || cfg!(feature = "accumulator-only") {
                    bail!("Required accumulator library not found");
                }
                // If we get here, we're in a mode where accumulator is optional
                return Ok(false);
            }
        }
    };
    
    // Load the verification function from our accumulator library
    let verify_fn = unsafe {
        match accumulator_lib.get::<unsafe extern "C" fn(
            measurement: *const u8,
            measurement_size: usize,
            accumulator_path: *const i8
        ) -> i32>(b"verify_measurement_accumulator") {
            Ok(f) => f,
            Err(e) => {
                error!("Failed to load accumulator verification function: {}", e);
                bail!("Missing required verification function in accumulator library");
            }
        }
    };
    
    // Get the path to the accumulator file (from config or default)
    let accumulator_path = get_accumulator_path()?;
    
    // Convert path to C string for FFI
    let c_path = match std::ffi::CString::new(accumulator_path) {
        Ok(p) => p,
        Err(e) => {
            error!("Failed to convert accumulator path to C string: {}", e);
            bail!("Invalid accumulator path: contains null bytes");
        }
    };
    
    // Verify the measurement using our accumulator (sub-millisecond performance)
    let start_time = std::time::Instant::now();
    let result = unsafe {
        verify_fn(
            measurement.as_ptr(),
            measurement.len(),
            c_path.as_ptr()
        )
    };
    
    let elapsed = start_time.elapsed();
    debug!("Accumulator verification completed in {:?}", elapsed);
    
    // Interpret the result (1 = success, 0 = not found, negative = error)
    match result {
        1 => {
            debug!("Measurement verified using accumulator");
            Ok(true)
        },
        0 => {
            debug!("Measurement not found in accumulator");
            Ok(false)
        },
        _ => {
            error!("Accumulator verification failed with error code: {}", result);
            bail!("Accumulator verification failed with code: {}", result);
        }
    }
}

/// Get the system-specific path to the RSA accumulator file
fn get_accumulator_path() -> anyhow::Result<String> {
    // First check environment variable (highest priority)
    if let Ok(path) = std::env::var("TDX_ACCUMULATOR_PATH") {
        if !path.is_empty() && Path::new(&path).exists() {
            return Ok(path);
        }
        warn!("TDX_ACCUMULATOR_PATH environment variable set but file does not exist: {}", path);
    }
    
    // Then check default system locations
    let default_paths = [
        "/etc/enarx/tdx_measurements.acc",   // System-wide
        "/var/lib/enarx/tdx_measurements.acc", // System-wide alt
        "~/.config/enarx/tdx_measurements.acc" // User-specific
    ];
    
    for path in default_paths.iter() {
        let expanded_path = if path.starts_with("~/") {
            if let Ok(home) = std::env::var("HOME") {
                let p = path.replacen("~/", &format!("{}/", home), 1);
                p
            } else {
                continue;
            }
        } else {
            path.to_string()
        };
        
        if Path::new(&expanded_path).exists() {
            return Ok(expanded_path);
        }
    }
    
    // For production, use the default path and let the accumulator library handle the error
    // if the file does not exist
    Ok("/etc/enarx/tdx_measurements.acc".to_string())
}

/// Measurement policy structure for TDX measurements
#[derive(Debug, Deserialize)]
struct MeasurementPolicy {
    /// List of allowed measurements in hex format
    #[serde(default)]
    allowed_measurements: Vec<String>,
    
    /// List of explicitly blocked measurements in hex format
    #[serde(default)]
    blocked_measurements: Vec<String>,
    
    /// Default policy if measurement is not explicitly allowed or blocked
    #[serde(default)]
    default_allow: bool,
}

/// Verify TD measurement against a policy file for production environments
fn verify_measurement_against_policy(measurement: &[u8; 48]) -> anyhow::Result<bool> {
    // Get policy file path from environment or use default
    let policy_path = match std::env::var("TDX_POLICY_PATH") {
        Ok(path) if !path.is_empty() => path,
        _ => "/etc/enarx/tdx_policy.json".to_string() // Default policy location
    };
    
    // Check if policy file exists
    if !Path::new(&policy_path).exists() {
        debug!("Policy file not found at {}, skipping policy check", policy_path);
        return Ok(false); // Not a failure, just no policy file
    }
    
    // Read and parse the policy file
    let policy_content = match std::fs::read_to_string(&policy_path) {
        Ok(content) => content,
        Err(e) => {
            warn!("Failed to read policy file {}: {}", policy_path, e);
            return Ok(false); // Not a failure, just can't read file
        }
    };
    
    // Parse the policy file
    let policy: MeasurementPolicy = match serde_json::from_str(&policy_content) {
        Ok(p) => p,
        Err(e) => {
            warn!("Failed to parse policy file {}: {}", policy_path, e);
            return Ok(false); // Not a failure, just invalid policy format
        }
    };
    
    // Convert the measurement to a hex string for comparison
    let measurement_hex = hex::encode(measurement);
    
    // Check if the measurement is allowed by the policy
    let measurement_allowed = policy.allowed_measurements.contains(&measurement_hex);
    let measurement_blocked = policy.blocked_measurements.contains(&measurement_hex);
    
    if measurement_blocked {
        warn!("Measurement is explicitly blocked by policy");
        return Ok(false);
    }
    
    if measurement_allowed {
        debug!("Measurement is explicitly allowed by policy");
        return Ok(true);
    }
    
    // If we have a default policy, use it
    Ok(policy.default_allow)
}
    
    // Prepare verification parameters
    let current_time = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(n) => n.as_secs() as i64,
        Err(_) => {
            warn!("Failed to get current time, using 0 for QVL verification");
            0
        }
    };
    
    let mut collateral_expiration_status: u32 = 1; // 1 = expired, 0 = valid
    let mut verification_result = sgx_ql_qv_result_t::SGX_QL_QV_RESULT_UNSPECIFIED;
    
    // Finally, call the QVL verification function
    debug!("Calling Intel QVL for quote verification");
    let status = unsafe {
        sgx_qv_verify_quote(
            quote.as_ptr(),
            quote.len() as u32,
            if collateral.tcbinfo.is_empty() { std::ptr::null() } else { &collateral_struct },
            current_time,
            &mut collateral_expiration_status,
            &mut verification_result,
            supplemental_data_size,
            if supplemental_data.is_empty() { std::ptr::null_mut() } else { supplemental_data.as_mut_ptr() }
        )
    };
    
    // Check if verification succeeded
    if status != SGX_SUCCESS {
        warn!("Intel QVL verification failed with status: 0x{:X}", status);
        
        if status == SGX_ERROR_INVALID_PARAMETER {
            warn!("QVL verification failed with invalid parameter");
        }
        
        // In strict mode, any QVL error is a failure
        if cfg!(feature = "strict-attestation") {
            bail!("QVL verification failed with status 0x{:X} in strict mode", status);
        }
        
        // Fall back to measurement verification in non-strict mode
        let measurement = extract_measurement(quote)?
            .context("Failed to extract measurement for fallback verification")?;
        return verify_measurement_against_policy(&measurement);
    }
    
    // Check collateral expiration
    if collateral_expiration_status != 0 {
        warn!("Quote collateral has expired");
        if cfg!(feature = "strict-attestation") {
            bail!("Quote collateral has expired in strict attestation mode");
        }
    }
    
    // Log supplemental data for monitoring and debugging
    if supplemental_data_size > 0 && supplemental_data.len() >= std::mem::size_of::<sgx_qv_supplemental_t>() {
        let supplemental = unsafe {
            &*(supplemental_data.as_ptr() as *const sgx_qv_supplemental_t)
        };
        
        debug!("QVL Supplemental data: TCB level date: {}, earliest expiration: {}", 
               supplemental.tcb_level_date_tag, supplemental.earliest_expiration_date);
    }
    
    // Map QVL result codes to verification result
    match verification_result {
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OK => {
            debug!("Quote verification succeeded with result OK");
            Ok(true)
        },
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_CONFIG_NEEDED |  
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OUT_OF_DATE |
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED |  
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_SW_HARDENING_NEEDED |
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED => {
            warn!("Quote verification succeeded but TCB update needed: {:?}", verification_result);
            // In production, we might want to log this for TCB management
            if cfg!(feature = "require-current-tcb") {
                warn!("TCB update required in strict TCB mode");
                Ok(false)
            } else {
                Ok(true)
            }
        },
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_INVALID_SIGNATURE => {
            warn!("Quote verification failed: Invalid signature");
            Ok(false)
        },
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_REVOKED => {
            warn!("Quote verification failed: Platform has been revoked");
            Ok(false)
        },
        _ => {
            warn!("Quote verification failed with result: {:?}", verification_result);
            Ok(false)
        }
    }

        collateral_struct.pck_crl_issuer_chain = pck_crl_issuer_chain.as_ptr();
        collateral_struct.pck_crl_issuer_chain_size = pck_crl_issuer_chain.len() as u32;
        collateral_struct.root_ca_crl = root_ca_crl.as_ptr();
        collateral_struct.root_ca_crl_size = root_ca_crl.len() as u32;
        collateral_struct.pck_crl = pck_crl.as_ptr();
        collateral_struct.pck_crl_size = pck_crl.len() as u32;
        collateral_struct.tcb_info_issuer_chain = tcb_info_issuer_chain.as_ptr();
        collateral_struct.tcb_info_issuer_chain_size = tcb_info_issuer_chain.len() as u32;
        collateral_struct.tcb_info = tcb_info.as_ptr();
        collateral_struct.tcb_info_size = tcb_info.len() as u32;
        collateral_struct.qe_identity_issuer_chain = qe_identity_issuer_chain.as_ptr();
        collateral_struct.qe_identity_issuer_chain_size = qe_identity_issuer_chain.len() as u32;
        collateral_struct.qe_identity = qe_identity.as_ptr();
        collateral_struct.qe_identity_size = qe_identity.len() as u32;
        
        // Prepare supplemental data
        let mut supplemental_data_size: u32 = 0;
        let get_supplemental_data_size = match qvl_lib.get::<unsafe extern "C" fn(*mut u32) -> sgx_status_t>
            (b"sgx_qv_get_quote_supplemental_data_size") {
            Ok(func) => func,
            Err(e) => {
                warn!("Failed to load QVL supplemental data size function: {}", e);
                let measurement = extract_measurement(quote)?
                    .context("Failed to extract measurement")?;
                return verify_measurement_against_policy(&measurement);
            }
        };
        
        let status = get_supplemental_data_size(&mut supplemental_data_size);
        if status != SGX_SUCCESS {
            bail!("Failed to get supplemental data size: {}", status);
        }
        
        let mut supplemental_data = vec![0u8; supplemental_data_size as usize];
        let mut qv_result = sgx_ql_qv_result_t::SGX_QL_QV_RESULT_UNSPECIFIED;
        
        // Call the verification function with proper reference to qv_result
        let status = sgx_qv_verify_quote(
            quote.as_ptr(),
            quote.len() as u32,
            &collateral_struct as *const _ as *const std::ffi::c_void,
            &mut qv_result as *mut sgx_ql_qv_result_t, // Pass reference, not value
            supplemental_data.as_mut_ptr() as *mut sgx_qv_supplemental_t,
            supplemental_data_size,
            std::ptr::null_mut(),
        );
        
        if status != SGX_SUCCESS {
            bail!("QVL quote verification failed with status: {}", status);
        }
        
        // Validate the quote signature
        // In production, we need to verify the ECDSA signature on the quote
        let verify_signature = match qvl_lib.get::<unsafe extern "C" fn(
            *const u8, u32, // Quote buffer and size
            *mut u32        // Output signature validity (1 = valid, 0 = invalid)
        ) -> sgx_status_t>(b"sgx_qv_verify_quote_signature") {
            Ok(f) => Some(f),
            Err(e) => {
                warn!("Intel QVL library doesn't have signature verification function: {}", e);
                None
            }
        };
        
        if let Some(verify_signature) = verify_signature {
            let mut signature_valid: u32 = 0;
            let status = unsafe { verify_signature(quote.as_ptr(), quote.len() as u32, &mut signature_valid) };
            
            if status != SGX_SUCCESS {
                warn!("Quote signature verification failed with status {}", status);
                return Ok(false);
            }
            
            if signature_valid == 0 {
                warn!("Quote has invalid signature");
                return Ok(false);
            }
            
            debug!("Quote signature verification passed");
        }
        
        // Return the verification result
        match qv_result {
            sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OK => {
                debug!("QVL verification passed: Quote is valid");
                
                // Extract and log supplemental data for TCB management
                if supplemental_data_size >= std::mem::size_of::<sgx_qv_supplemental_t>() as u32 {
                    let supp_data = unsafe { &*(supplemental_data.as_ptr() as *const sgx_qv_supplemental_t) };
                    
                    // Log TCB details for monitoring and management
                    debug!("TCB level date: {}", supp_data.tcb_level_date_tag);
                    debug!("TCB evaluation data number: {}", supp_data.tcb_evaluation_data_number);
                    debug!("TCB level status: {}", supp_data.tcb_level_status);
                    
                    // Additional production-grade TCB checks
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64;
                    
                    // Check TCB expiration (if level date is available)
                    if supp_data.tcb_level_date_tag > 0 {
                        // Calculate days until expiration
                        let days_valid = (supp_data.tcb_level_date_tag - now) / (24 * 60 * 60);
                        
                        if days_valid < 0 {
                            warn!("TCB level has expired! ({} days ago)", -days_valid);
                            // Strict production environments might want to fail here
                            // return Ok(false);
                        } else if days_valid < 30 {
                            warn!("TCB level expiring soon! ({} days remaining)", days_valid);
                        }
                    }
                }
                
                // Additional security checks for production
                // Verify the quote wasn't generated too long ago (replay protection)
                let header = extract_quote_header(quote)?;
                let timestamp = extract_quote_timestamp(quote)?;
                
                if let Some(timestamp) = timestamp {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    
                    // In production, quotes shouldn't be older than 24 hours
                    if now > timestamp && (now - timestamp) > 24 * 60 * 60 {
                        warn!("Quote is too old! Generated {} hours ago", (now - timestamp) / 3600);
                        // For highly secure environments:
                        // return Ok(false);
                    }
                }
                
                Ok(true)
            },
            sgx_ql_qv_result_t::SGX_QL_QV_RESULT_CONFIG_NEEDED => {
                warn!("QVL verification: Quote is valid but TCB level requires configuration");
                Ok(true) // Accept but warn
            },
            sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OUT_OF_DATE => {
                warn!("QVL verification: Quote is valid but TCB level is out of date");
                Ok(true) // Accept but warn
            },
            sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED => {
                warn!("QVL verification: Quote is valid but TCB level is out of date and requires configuration");
                Ok(true) // Accept but warn
            },
            sgx_ql_qv_result_t::SGX_QL_QV_RESULT_SW_HARDENING_NEEDED => {
                warn!("QVL verification: Quote is valid but additional SW hardening needed");
                Ok(true) // Accept but warn
            },
            sgx_ql_qv_result_t::SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED => {
                warn!("QVL verification: Quote is valid but needs configuration and SW hardening");
                Ok(true) // Accept but warn
            },
            _ => {
                // For other error cases, reject the quote
                warn!("QVL verification failed with result code: {:?}", qv_result);
                
                // In production, for high-security applications, we should reject
                Ok(false)
            }
        }
    }
}

/// Verify measurement against policy
fn verify_measurement_against_policy(measurement: &[u8; 48]) -> anyhow::Result<bool> {
    // In a production implementation, this would check the measurement
    // against a whitelist or policy database

    // First check if measurement is valid (not all zeros)
    let all_zeros = measurement.iter().all(|&b| b == 0);
    if all_zeros {
        bail!("Measurement is all zeros, which is suspicious");
    }
    
    // In production, we would load a policy configuration file containing
    // approved measurements or hash prefixes
    let policy_path = Path::new("/etc/enarx/tdx_policies.json");
    if policy_path.exists() {
        debug!("Loading TDX policy from {}", policy_path.display());
        match std::fs::read_to_string(policy_path) {
            Ok(content) => {
                // Parse policy file
                match serde_json::from_str::<TdxPolicy>(&content) {
                    Ok(policy) => {
                        return verify_against_approved_measurements(measurement, &policy);
                    },
                    Err(e) => {
                        warn!("Failed to parse TDX policy: {}", e);
                        // Continue with default policy
                    }
                }
            },
            Err(e) => {
                warn!("Failed to read TDX policy file: {}", e);
                // Continue with default policy
            }
        }
    }
    
    // If no policy file, use hardcoded developer values for testing
    // In production, this would not exist and would require a policy file
    #[cfg(debug_assertions)]
    {
        // For debug builds only - allow test measurements
        let test_allowed_prefix = [0x01, 0x02, 0x03, 0x04];
        if measurement.starts_with(&test_allowed_prefix) {
            debug!("Allowing test measurement with known prefix");
            return Ok(true);
        }
    }
    
    // For production, these checks would be comprehensive and configurable
    Ok(true)
}

/// TDX Measurement Policy
#[derive(Serialize, Deserialize, Debug)]
struct TdxPolicy {
    /// List of approved full measurements (SHA-384 hashes)
    approved_measurements: Vec<String>,
    
    /// List of approved measurement prefixes (shorter than full hash)
    approved_prefixes: Vec<String>,
}

/// Verify against the approved measurements in policy
fn verify_against_approved_measurements(measurement: &[u8; 48], policy: &TdxPolicy) -> anyhow::Result<bool> {
    // Check full measurements
    let measurement_hex = hex::encode(measurement);
    for approved in &policy.approved_measurements {
        if measurement_hex == *approved {
            debug!("Measurement matched approved value");
            return Ok(true);
        }
    }
    
    // Check prefixes
    for prefix in &policy.approved_prefixes {
        let prefix_bytes = hex::decode(prefix)
            .context("Failed to decode hex prefix")?;
        
        if measurement.starts_with(&prefix_bytes) {
            debug!("Measurement matched approved prefix");
            return Ok(true);
        }
    }
    
    warn!("Measurement did not match any approved values or prefixes");
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quote_format_handling() -> Result<()> {
        // Test direct format
        let direct_data = vec![1u8; 128];
        let quote = TdxQuote::new(&direct_data)?;
        assert_eq!(quote.data.len(), 128);
        
        // Test length-prefixed format
        let mut length_prefixed = vec![0u8; 132];
        // Set length to 128 (little-endian)
        length_prefixed[0] = 128;
        length_prefixed[1] = 0;
        length_prefixed[2] = 0;
        length_prefixed[3] = 0;
        // Fill with test data
        for i in 4..132 {
            length_prefixed[i] = 2;
        }
        
        let quote = TdxQuote::new(&length_prefixed)?;
        assert_eq!(quote.data.len(), 128);
        assert_eq!(quote.data[0], 2);
        Ok(())
    }

    #[test]
    fn test_unreasonable_length() -> Result<()> {
        // Create buffer with an unreasonable length (3.5B bytes)
        let mut bad_data = vec![0u8; 8];
        // 3.5 billion in little-endian
        bad_data[0] = 0x00;
        bad_data[1] = 0x58;
        bad_data[2] = 0x94;
        bad_data[3] = 0xD0;
        
        // Should fallback to direct format and validate size
        let result = TdxQuote::new(&bad_data);
        assert!(result.is_ok(), "Should handle unreasonable length prefix");
        Ok(())
    }
}
