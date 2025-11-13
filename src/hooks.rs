use core::fmt::Debug;

use libafl::inputs::HasTargetBytes;
use libafl_bolts::HasLen;
use libafl_qemu::{
    arch::Regs,
    modules::{EmulatorModule, EmulatorModuleTuple},
    qemu::{Hook, SyscallHookResult},
    ArchExtras, GuestAddr, GuestReg, MmapPerms, Qemu,
};

use syscall_numbers::aarch64::{SYS_read, SYS_mmap, SYS_munmap, SYS_exit, SYS_exit_group};

use crate::harness::MAX_INPUT_SIZE;

/// Generic hooks module for intercepting syscalls
#[derive(Debug)]
pub struct HooksModule {
    /// Pre-allocated guest memory address for the mmap region
    mmap_addr: GuestAddr,
    /// Size of the allocated mmap region
    mmap_size: usize,
    /// Size of the current input data (<= mmap_size)
    input_size: usize,
    /// Current read offset into the input data
    read_offset: usize,
    /// Persistent address to reset to (for exit hook)
    persistent_addr: GuestAddr,
    /// Saved state of all registers
    register_state: Vec<u64>,
}

impl HooksModule {
    #[must_use]
    pub fn new() -> Self {
        Self {
            mmap_addr: 0,
            mmap_size: MAX_INPUT_SIZE,
            input_size: 0,
            read_offset: 0,
            persistent_addr: 0,
            register_state: Vec::new(),
        }
    }

    /// Get the mmap address (for use in harness)
    pub fn mmap_addr(&self) -> GuestAddr {
        self.mmap_addr
    }

    /// Get the mmap size
    pub fn mmap_size(&self) -> usize {
        self.mmap_size
    }

    /// Set the persistent state (called from Harness::init)
    pub fn set_persistent_state(
        &mut self,
        persistent_addr: GuestAddr,
        register_state: Vec<u64>,
    ) {
        self.persistent_addr = persistent_addr;
        self.register_state = register_state;
    }

    /// Restore registers to the persistent state
    fn restore_registers(&self, qemu: Qemu) -> Result<(), String> {
        if self.register_state.is_empty() {
            return Err("No register state saved".to_string());
        }

        // Restore all registers
        for (reg_idx, saved_val) in self.register_state.iter().enumerate() {
            if reg_idx >= qemu.num_regs() as usize {
                break;
            }
            qemu.write_reg(reg_idx as i32, *saved_val)
                .map_err(|e| format!("Failed to restore register {}: {:?}", reg_idx, e))?;
        }
        qemu.flush_jit();
        Ok(())
    }
}

impl<I, S> EmulatorModule<I, S> for HooksModule
where
    I: Unpin + Debug + HasTargetBytes + HasLen,
    S: Unpin,
{
    fn post_qemu_init<ET>(
        &mut self,
        qemu: Qemu,
        _emulator_modules: &mut libafl_qemu::emu::EmulatorModules<ET, I, S>,
    ) where
        ET: EmulatorModuleTuple<I, S>,
    {
        // Allocate the mmap region once after QEMU is initialized
        // This region will persist across fuzzing iterations
        match qemu.map_private(0, self.mmap_size, MmapPerms::ReadWrite) {
            Ok(addr) => {
                self.mmap_addr = addr;
                
                // Write dummy data so initial run has something to read
                let dummy_data = b"dummy";
                if qemu.write_mem(addr, dummy_data).is_ok() {
                    self.input_size = dummy_data.len();
                }
            }
            Err(e) => {
                panic!("Failed to allocate mmap region for fuzzer input: {:?}", e);
            }
        }
    }

    fn first_exec<ET>(
        &mut self,
        _qemu: Qemu,
        emulator_modules: &mut libafl_qemu::emu::EmulatorModules<ET, I, S>,
        _state: &mut S,
    ) where
        ET: EmulatorModuleTuple<I, S>,
    {
        // Register our hook to be called before syscalls
        emulator_modules.pre_syscalls(Hook::Function(syscall_hook::<ET, I, S>));
    }

    fn pre_exec<ET>(
        &mut self,
        qemu: Qemu,
        _emulator_modules: &mut libafl_qemu::emu::EmulatorModules<ET, I, S>,
        _state: &mut S,
        input: &I,
    ) where
        ET: EmulatorModuleTuple<I, S>,
    {
        // Restore registers if we have saved state
        if !self.register_state.is_empty() {
            if let Err(e) = self.restore_registers(qemu) {
                log::error!("[HooksModule] Failed to restore registers: {}", e);
            }
        }
    
        // Copy fuzzer input into mmap region
        let mut len = input.len().min(self.mmap_size);
        if len > 0 && self.mmap_addr != 0 {
            let input_bytes = input.target_bytes();
            if qemu.write_mem(self.mmap_addr, &input_bytes[..len]).is_err() {
                len = 0;
            }
        }
    
        self.input_size = len;
        self.read_offset = 0;
    }
}

/// Hook function that gets called before each syscall
/// This is where we can intercept and modify syscall behavior
#[expect(clippy::too_many_arguments)]
fn syscall_hook<ET, I, S>(
    qemu: Qemu,
    emulator_modules: &mut libafl_qemu::emu::EmulatorModules<ET, I, S>,
    _state: Option<&mut S>,
    syscall: i32,
    x0: GuestAddr,  // addr for mmap/munmap, fd for read
    x1: GuestAddr,  // length for mmap/munmap, buf for read
    x2: GuestAddr,  // prot for mmap, count for read
    _x3: GuestAddr, // flags for mmap
    _x4: GuestAddr, // fd for mmap
    _x5: GuestAddr,
    _x6: GuestAddr,
    _x7: GuestAddr,
) -> SyscallHookResult
where
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin + Debug + HasTargetBytes + HasLen,
    S: Unpin,
{
    // Get the hooks module to access state
    let hooks_module = match emulator_modules.get_mut::<HooksModule>() {
        Some(m) => m,
        None => return SyscallHookResult::Run,
    };

    if syscall == SYS_mmap {
        // mmap syscall: return our pre-allocated region address
        // void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
        // We ignore the parameters and just return our pre-allocated address
        eprintln!("[HooksModule] mmap syscall intercepted, returning {:#x}", hooks_module.mmap_addr);
        return SyscallHookResult::Skip(hooks_module.mmap_addr);
    } else if syscall == SYS_munmap {
        // munmap syscall: ignore if it's our region, otherwise let it execute
        // int munmap(void *addr, size_t length);
        if x0 == hooks_module.mmap_addr {
            // It's our region, return success but don't actually unmap
            eprintln!("[HooksModule] munmap syscall intercepted for our region, returning success");
            return SyscallHookResult::Skip(0);
        } else {
            // Not our region, let it execute normally
            return SyscallHookResult::Run;
        }
    } else if syscall == SYS_read {
        // read syscall: read from our mmapped region
        // ssize_t read(int fd, void *buf, size_t count);
        return handle_read_syscall(qemu, hooks_module, x1, x2);
    } else if syscall == SYS_exit || syscall == SYS_exit_group {
        // Restore registers to jump back to persistent_addr
        // Memory will be restored by SnapshotModule::pre_exec() on next iteration
        if hooks_module.restore_registers(qemu).is_err() {
            log::error!("[HooksModule] Failed to restore registers on exit");
        }
        return SyscallHookResult::Skip(0);
    }

    // For other syscalls, let them execute normally
    SyscallHookResult::Run
}

/// Handle read syscall
/// Reads data from the pre-allocated mmap region and copies it to the guest buffer
fn handle_read_syscall(
    qemu: Qemu,
    hooks_module: &mut HooksModule,
    buf: GuestAddr,
    count: GuestAddr,
) -> SyscallHookResult {
    let remaining = hooks_module.input_size.saturating_sub(hooks_module.read_offset);
    let bytes_to_read = if count == 0 {
        0
    } else {
        count.min(remaining as GuestAddr) as usize
    };

    if bytes_to_read == 0 {
        return SyscallHookResult::Skip(0);
    }

    let source_addr = hooks_module.mmap_addr + hooks_module.read_offset as u64;
    let mut read_buffer = vec![0u8; bytes_to_read];

    if qemu.read_mem(source_addr, &mut read_buffer).is_ok()
        && qemu.write_mem(buf, &read_buffer).is_ok()
    {
        hooks_module.read_offset += bytes_to_read;
        SyscallHookResult::Skip(bytes_to_read as u64)
    } else {
        SyscallHookResult::Run
    }
}
