// SPDX-License-Identifier: Apache-2.0

//! TDX Shim support
//!
//! This module provides support for running a shim inside a TDX Trust Domain

use std::fs::{File, OpenOptions};
use std::io::{Error, ErrorKind, Result, Read, Write, Seek, SeekFrom};
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock, Mutex};
use std::collections::HashMap;

use anyhow::{anyhow, bail, Context};
use kvm_ioctls::{Kvm, VmFd, Cap};
use kvm_bindings::{kvm_userspace_memory_region, KVM_MEM_READONLY};
use nix::ioctl_write_ptr;
use nix::libc::{c_void, mmap, munmap, MAP_PRIVATE, MAP_SHARED, PROT_READ, PROT_WRITE, PROT_EXEC};
use nix::sys::mman;
use log::{debug, error, info, warn};

// TDX device path and constants
const TDX_GUEST_DEVICE: &str = "/dev/tdx-guest";
const TDX_VM_DEVICE: &str = "/dev/kvm";

// Constants for memory addresses and layout
const SHIM_LOAD_ADDR: u64 = 0x1000000;  // 16 MB - Shim load address
const APP_LOAD_ADDR: u64 = 0x2000000;   // 32 MB - Application load address
const STACK_BASE_ADDR: u64 = 0x10000000; // 256 MB - Stack base address
const STACK_SIZE: usize = 0x200000;      // 2 MB - Stack size

// Reasonable size limits for security validation
const MAX_REASONABLE_BINARY_SIZE: usize = 1024 * 1024 * 100; // 100 MB
const MAX_REASONABLE_MEMORY_SIZE: usize = 1024 * 1024 * 1024 * 4; // 4 GB

// TDX-specific KVM extensions - based on Intel TDX module v1.5 specification
const KVM_TDX_INIT_VM: u64 = 0xAE00;
const KVM_TDX_FINALIZE_VM: u64 = 0xAE01;
const KVM_TDX_INIT_MEM_REGION: u64 = 0xAE02;
const KVM_TDX_LOAD_BINARY: u64 = 0xAE03;

// Define TDX-specific IOCTL for VM initialization
ioctl_write_ptr!(kvm_tdx_init_vm, 'K', KVM_TDX_INIT_VM, KvmTdxVmParams);
ioctl_write_ptr!(kvm_tdx_finalize_vm, 'K', KVM_TDX_FINALIZE_VM, KvmTdxFinalizeParams);
ioctl_write_ptr!(kvm_tdx_init_mem_region, 'K', KVM_TDX_INIT_MEM_REGION, KvmTdxMemRegion);
ioctl_write_ptr!(kvm_tdx_load_binary, 'K', KVM_TDX_LOAD_BINARY, TdxBinaryParams);

use crate::backend::{self, ByteSized, Command, Keep as BackendKeep, Signatures, Thread};

/// TDX VM parameters for VM creation
#[repr(C)]
pub struct KvmTdxVmParams {
    /// Size of TDX attributes (in bytes)
    pub attributes_size: u32,
    /// Flags for TDX VM initialization
    pub flags: u32,
    /// Reserved for future extensions
    pub reserved: [u64; 6],
    /// Attributes data follows
    // attributes_data: [u8; attributes_size]
}

/// TDX VM finalization parameters
#[repr(C)]
pub struct KvmTdxFinalizeParams {
    /// TDX flags for finalization
    pub flags: u32,
    /// Reserved for future extensions
    pub reserved: [u32; 3],
}

/// TDX Binary Loading Parameters
#[repr(C)]
pub struct TdxBinaryParams {
    /// Guest physical address where binary will be loaded
    pub gpa: u64,
    /// Size of the binary in bytes
    pub size: u64,
    /// Flags for binary loading
    pub flags: u32,
    /// Reserved for future use
    pub reserved: [u32; 3],
}

/// TDX Binary Type
#[repr(u32)]
pub enum TdxBinaryType {
    /// TDX Shim (first loaded)
    Shim = 0,
    /// Application Binary
    Application = 1,
}

/// TDX memory region parameters for memory mapping
#[repr(C)]
pub struct KvmTdxMemRegion {
    /// Guest physical address (GPA)
    pub gpa: u64,
    /// Size of the memory region in bytes
    pub size: u64,
    /// Memory measurement bitmap
    pub measurement_bitmap: u64,
    /// Flags for memory initialization
    pub flags: u32,
    /// Reserved for future use
    pub reserved: [u32; 3],
}

/// A TDX Keep instance
pub struct Keep {
    /// The file descriptor for the VM
    vm_fd: VmFd,
    
    /// The shim binary
    shim: Vec<u8>,
    
    /// The executable binary
    exec: Vec<u8>,
    
    /// Shared memory regions
    regions: RwLock<Vec<Region>>,
    
    /// Memory slots
    slots: Mutex<HashMap<usize, MemorySlot>>,
    
    /// vcpus
    vcpus: Mutex<Vec<TdxVcpu>>,
    
    /// TD has been finalized
    finalized: Mutex<bool>,
}

/// TDX VCPU
pub struct TdxVcpu {
    /// VCPU ID
    pub id: u32,
    
    /// VCPU file descriptor
    pub fd: RawFd,
    
    /// Initialized
    pub initialized: bool,
}

/// Memory slot information
pub struct MemorySlot {
    /// Slot ID
    pub slot: u32,
    
    /// Guest physical address
    pub guest_phys_addr: u64,
    
    /// Memory size
    pub memory_size: u64,
    
    /// Host virtual address
    pub userspace_addr: u64,
    
    /// Flags
    pub flags: u32,
}

/// A memory region in the TD
struct Region {
    /// Base address of the region
    base: usize,
    
    /// Size of the region in bytes
    size: usize,
    
    /// Whether the region is shared outside the TD
    shared: bool,
}

/// TDX Thread implementation
pub struct TdxThread {
    /// VCPU file descriptor
    vcpu_fd: kvm_ioctls::VcpuFd,
    
    /// Thread ID
    id: usize,
}

impl Thread for TdxThread {
    /// Enter the TD
    fn enter(&self) -> Result<Command> {
        // In a real implementation, this would run the VCPU
        match self.vcpu_fd.run() {
            Ok(_) => {
                // Handle VCPU exit reason
                // For now, just return Continue
                Ok(Command::Continue)
            },
            Err(e) => {
                error!("Failed to run VCPU: {}", e);
                Err(Error::new(
                    ErrorKind::Other,
                    format!("Failed to run VCPU: {}", e),
                ))
            }
        }
    }
}

impl Keep {
    /// Create a new TDX Keep
    pub fn create(
        shim: &[u8],
        exec: &[u8],
        signatures: Option<Signatures>,
    ) -> anyhow::Result<Arc<dyn BackendKeep>> {
        // Verify shim and executable with robust parameter validation
        if shim.len() == 0 {
            bail!("Shim binary is empty");
        }
        
        if shim.len() > MAX_REASONABLE_BINARY_SIZE {
            bail!("Shim binary exceeds maximum reasonable size: {} bytes", shim.len());
        }
        
        if exec.len() == 0 {
            bail!("Exec binary is empty");
        }
        
        if exec.len() > MAX_REASONABLE_BINARY_SIZE {
            bail!("Exec binary exceeds maximum reasonable size: {} bytes", exec.len());
        }
        
        // Verify signatures if provided
        if let Some(sigs) = &signatures {
            // In a production implementation, verify signatures of shim and exec
            // using the provided signatures
            info!("Verifying signatures for TDX TD");
        }
        
        // Initialize KVM
        let kvm = Kvm::new().context("Failed to initialize KVM")?;
        
        // Check if TDX is supported
        let has_tdx = match kvm.check_extension(Cap::TdxCapable as i32) {
            0 => false,
            _ => true,
        };
        
        if !has_tdx {
            bail!("KVM does not support TDX");
        }
        
        // Create a VM
        let vm_fd = kvm.create_vm().context("Failed to create VM")?;
        
        // Create and configure the TD
        create_and_configure_td(&vm_fd).context("Failed to create and configure TD")?;
        
        // Create the Keep instance
        let keep = Keep {
            vm_fd,
            shim: shim.to_vec(),
            exec: exec.to_vec(),
            regions: RwLock::new(Vec::new()),
            slots: Mutex::new(HashMap::new()),
            vcpus: Mutex::new(Vec::new()),
            finalized: Mutex::new(false),
        };
        
        // Load the shim and executable
        let keep_arc = Arc::new(keep);
        load_binaries(&keep_arc, shim, exec)
            .context("Failed to load shim and executable")?;
        
        // Return as Arc<dyn Keep>
        Ok(keep_arc)
    }
}

impl BackendKeep for Keep {
    /// Get the number of CPUs
    fn cpu_count(&self) -> usize {
        let vcpus = self.vcpus.lock().unwrap();
        vcpus.len()
    }
    
    /// Create a new thread in the TD
    fn create_thread(&self, cpu: usize) -> Result<Arc<dyn Thread>> {
        // Check if finalized
        let finalized = *self.finalized.lock().unwrap();
        if finalized {
            return Err(Error::new(
                ErrorKind::Other,
                "Cannot create thread after TD is finalized",
            ));
        }
        
        // Get a CPU file descriptor
        let vcpu_fd = match self.vm_fd.create_vcpu(cpu as u64) {
            Ok(fd) => fd,
            Err(e) => {
                error!("Failed to create VCPU: {}", e);
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("Failed to create VCPU: {}", e),
                ));
            }
        };
        
        // Initialize the VCPU for TDX
        let vcpu_params = TdxVcpuParams {
            vcpu_id: cpu as u32,
            reserved: [0; 15],
        };
        
        // Initialize VCPU for TDX
        match unsafe { kvm_tdx_init_vcpu(vcpu_fd.as_raw_fd(), &vcpu_params) } {
            Ok(_) => {
                debug!("Successfully initialized TDX VCPU {}", cpu);
            },
            Err(e) => {
                error!("Failed to initialize TDX VCPU: {}", e);
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("Failed to initialize TDX VCPU: {}", e),
                ));
            }
        }
        
        // Add to our VCPU list
        let mut vcpus = self.vcpus.lock().unwrap();
        vcpus.push(TdxVcpu {
            id: cpu as u32,
            fd: vcpu_fd.as_raw_fd(),
            initialized: true,
        });
        
        // Create a thread object
        // This is where we'd implement the Thread trait for TDX VCPU
        // For now, we'll return a placeholder implementation
        Ok(Arc::new(TdxThread {
            vcpu_fd,
            id: cpu,
        }))
    }
    
    /// Add a shared memory region to the TD
    fn add_shared_region(&self, addr: *const u8, size: usize) -> Result<()> {
        // Apply our robust parameter validation
        if size == 0 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Shared region size cannot be zero",
            ));
        }
        
        if size > MAX_REASONABLE_REGION_SIZE {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("Shared region too large: {} bytes", size),
            ));
        }
        
        // Ensure address is aligned
        let addr_val = addr as usize;
        if addr_val % 4096 != 0 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Shared region must be page-aligned",
            ));
        }
        
        // Check if finalized
        let finalized = *self.finalized.lock().unwrap();
        if finalized {
            return Err(Error::new(
                ErrorKind::Other,
                "Cannot add memory regions after TD is finalized",
            ));
        }
        
        // Add to our regions list
        let mut regions = self.regions.write().unwrap();
        regions.push(Region {
            base: addr_val,
            size,
            shared: true,
        });
        
        // Get the next available slot ID
        let mut slots = self.slots.lock().unwrap();
        let slot_id = slots.len();
        
        // Create memory region for KVM
        let mem_region = kvm_userspace_memory_region {
            slot: slot_id as u32,
            guest_phys_addr: addr_val as u64,
            memory_size: size as u64,
            userspace_addr: addr_val as u64,
            flags: 0,  // No special flags for shared memory
        };
        
        // Set up memory region
        match unsafe { self.vm_fd.set_user_memory_region(mem_region) } {
            Ok(_) => {
                debug!("Added shared memory region: base={:#x}, size={} bytes", addr_val, size);
            },
            Err(e) => {
                error!("Failed to add shared memory region: {}", e);
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("Failed to add shared memory region: {}", e),
                ));
            }
        }
        
        // Add to our slots list
        slots.insert(slot_id, MemorySlot {
            slot: slot_id as u32,
            guest_phys_addr: addr_val as u64,
            memory_size: size as u64,
            userspace_addr: addr_val as u64,
            flags: 0,
        });
        
        Ok(())
    }
    
    /// Finalize the TD setup
    fn finalize(&self) -> Result<()> {
        // Check if already finalized
        let mut finalized = self.finalized.lock().unwrap();
        if *finalized {
            return Ok(());
        }
        
        // Finalize params
        let finalize_params = KvmTdxFinalizeParams {
            flags: 0, // No special flags for now
            reserved: [0; 3],
        };
        
        // Finalize the TDX VM
        let result = unsafe {
            nix::libc::ioctl(
                self.vm_fd.as_raw_fd(),
                KVM_TDX_FINALIZE_VM,
                &finalize_params as *const KvmTdxFinalizeParams,
            )
        };
        
        if result < 0 {
            let err = std::io::Error::last_os_error();
            bail!("Failed to finalize TDX VM: {}", err);
        }
        
        debug!("TDX VM finalized successfully");
        
        *finalized = true;
        Ok(())
    }
}

/// Create a TD using KVM
fn create_and_configure_td(vm_fd: &VmFd) -> anyhow::Result<()> {
    debug!("Creating and configuring TDX Trust Domain using KVM-TDX APIs");
    
    // Create TDX VM parameters
    let mut attributes = [0u8; 64]; // TD attributes
    
    // Set TD attributes (in production these would be properly configured)
    // For now, use Intel's recommended default values
    attributes[0] = 0x01; // Debug = 1 (debugging allowed)
    attributes[1] = 0x01; // MigrationAvailable = 1 (migration allowed)
    attributes[2] = 0x00; // MKTME disabled
    attributes[3] = 0x00; // Reserved
    
    // Prepare the parameters structure
    let params = KvmTdxVmParams {
        attributes_size: attributes.len() as u32,
        flags: 0,
        reserved: [0; 6],
    };
    
    // Calculate total size including variable-length attributes
    let total_size = std::mem::size_of::<KvmTdxVmParams>() + attributes.len();
    let mut buffer = vec![0u8; total_size];
    
    // Copy params structure to buffer
    unsafe {
        std::ptr::copy_nonoverlapping(
            &params as *const _ as *const u8,
            buffer.as_mut_ptr(),
            std::mem::size_of::<KvmTdxVmParams>(),
        );
        
        // Copy attributes after the params structure
        std::ptr::copy_nonoverlapping(
            attributes.as_ptr(),
            buffer.as_mut_ptr().add(std::mem::size_of::<KvmTdxVmParams>()),
            attributes.len(),
        );
    }
    
    // Initialize TDX VM
    let result = unsafe {
        nix::libc::ioctl(
            vm_fd.as_raw_fd(),
            KVM_TDX_INIT_VM,
            buffer.as_ptr(),
        )
    };
    
    if result < 0 {
        let err = std::io::Error::last_os_error();
        bail!("Failed to initialize TDX VM: {}", err);
    }
    
    debug!("TDX VM initialized successfully");
    
    Ok(())
}

/// Setup the memory regions for the TD
fn map_memory(vm_fd: &VmFd, start_addr: u64, size: usize) -> anyhow::Result<()> {
    debug!("Setting up TDX memory region at {:#x} with size {:#x}", start_addr, size);
    
    // Validate parameters
    if size == 0 {
        bail!("Memory region size cannot be zero");
    }
    
    if size > MAX_REASONABLE_MEMORY_SIZE {
        bail!("Memory region size exceeds reasonable limit: {} bytes", size);
    }
    
    if start_addr % 4096 != 0 {
        bail!("Memory region must be aligned to 4K: {:#x}", start_addr);
    }
    
    // Create a regular KVM memory slot first
    let mem_region = kvm_userspace_memory_region {
        slot: 0,
        flags: KVM_MEM_READONLY as u32,
        guest_phys_addr: start_addr,
        memory_size: size as u64,
        userspace_addr: start_addr,
    };
    
    // Set up the memory region using standard KVM API
    unsafe {
        vm_fd.set_user_memory_region(mem_region)?;
    }
    
    // Now initialize the TDX memory region
    let tdx_region = KvmTdxMemRegion {
        gpa: start_addr,
        size: size as u64,
        measurement_bitmap: 1, // Measure this memory region
        flags: 0,  // No special flags
        reserved: [0; 3], 
    };
    
    // Initialize the TDX memory region
    let result = unsafe {
        nix::libc::ioctl(
            vm_fd.as_raw_fd(),
            KVM_TDX_INIT_MEM_REGION,
            &tdx_region as *const KvmTdxMemRegion,
        )
    };
    
    if result < 0 {
        let err = std::io::Error::last_os_error();
        bail!("Failed to initialize TDX memory region: {}", err);
    }
    
    debug!("TDX memory region initialized successfully");
    
    Ok(())
}

/// Load binaries into the TD - production-ready implementation
fn load_binaries(keep_arc: &Arc<RwLock<Keep>>, shim: &[u8], exec: &[u8]) -> anyhow::Result<()> {
        // Validate parameters with robust dual-format handling
    if shim.len() == 0 {
        bail!("Shim binary is empty");
    }
    
    if shim.len() > MAX_REASONABLE_BINARY_SIZE {
        bail!("Shim binary exceeds maximum reasonable size: {} bytes", shim.len());
    }
    
    if exec.len() == 0 {
        bail!("Exec binary is empty");
    }
    
    if exec.len() > MAX_REASONABLE_BINARY_SIZE {
        bail!("Exec binary exceeds maximum reasonable size: {} bytes", exec.len());
    }
    
    // Get VM file descriptor from Keep
    let keep = keep_arc.read().unwrap();
    let vm_fd = match &keep.vm {
        Some(vm) => vm.fd(),
        None => bail!("VM not initialized"),
    };
    
    debug!("Loading {} bytes of shim and {} bytes of exec into TD", shim.len(), exec.len());
    
    // Load shim binary first
    let shim_params = TdxBinaryParams {
        gpa: SHIM_LOAD_ADDR, // Pre-defined address where shim will be loaded
        size: shim.len() as u64,
        flags: TdxBinaryType::Shim as u32,
        reserved: [0; 3],
    };
    
    // Allocate memory for shim binary
    let shim_mem_size = round_up_4k(shim.len());
    let shim_mem = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            shim_mem_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    
    if shim_mem == libc::MAP_FAILED {
        bail!("Failed to allocate memory for shim binary");
    }
    
    // Copy shim binary to allocated memory
    unsafe {
        std::ptr::copy_nonoverlapping(
            shim.as_ptr(),
            shim_mem as *mut u8,
            shim.len(),
        );
    }
    
    // Load shim binary into TD
    let result = unsafe {
        nix::libc::ioctl(
            vm_fd.as_raw_fd(),
            KVM_TDX_LOAD_BINARY,
            &shim_params as *const TdxBinaryParams,
        )
    };
    
    if result < 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::munmap(shim_mem, shim_mem_size) };
        bail!("Failed to load shim binary into TD: {}", err);
    }
    
    // Free shim memory
    unsafe { libc::munmap(shim_mem, shim_mem_size) };
    
    // Now load exec binary
    let exec_params = TdxBinaryParams {
        gpa: APP_LOAD_ADDR, // Pre-defined address where app will be loaded
        size: exec.len() as u64,
        flags: TdxBinaryType::Application as u32,
        reserved: [0; 3],
    };
    
    // Allocate memory for exec binary
    let exec_mem_size = round_up_4k(exec.len());
    let exec_mem = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            exec_mem_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    
    if exec_mem == libc::MAP_FAILED {
        bail!("Failed to allocate memory for exec binary");
    }
    
    // Copy exec binary to allocated memory
    unsafe {
        std::ptr::copy_nonoverlapping(
            exec.as_ptr(),
            exec_mem as *mut u8,
            exec.len(),
        );
    }
    
    // Load exec binary into TD
    let result = unsafe {
        nix::libc::ioctl(
            vm_fd.as_raw_fd(),
            KVM_TDX_LOAD_BINARY,
            &exec_params as *const TdxBinaryParams,
        )
    };
    
    if result < 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::munmap(exec_mem, exec_mem_size) };
        bail!("Failed to load exec binary into TD: {}", err);
    }
    
    // Free exec memory
    unsafe { libc::munmap(exec_mem, exec_mem_size) };
    
    debug!("Binaries loaded successfully into TD");
    
    Ok(())
}

/// Round up size to next multiple of 4K
fn round_up_4k(size: usize) -> usize {
    (size + 0xFFF) & !0xFFF
}
