use libafl::{executors::ExitKind, inputs::BytesInput, Error};
use libafl_qemu::{elf::EasyElf, GuestAddr, Qemu, Regs};

pub struct Harness {
    qemu: Qemu,
    pub persistent_addr: GuestAddr, // Address to reset to (main + 0x18C, after getopt)
    pub breakpoint_addr: GuestAddr, // Address to break at in persistent loop (main + 0x160)
    pub register_state: Vec<u64>,   // Saved state of all registers
}

pub const MAX_INPUT_SIZE: usize = 1_048_576; // 1MB

impl Harness {
    /// Change environment
    #[inline]
    #[expect(clippy::ptr_arg)]
    pub fn edit_env(_env: &mut Vec<(String, String)>) {}

    /// Change arguments
    #[inline]
    #[expect(clippy::ptr_arg)]
    pub fn edit_args(_args: &mut Vec<String>) {}

    /// Helper function to find main function
    fn find_main(qemu: Qemu) -> Result<GuestAddr, Error> {
        let mut elf_buffer = Vec::new();
        let elf = EasyElf::from_file(qemu.binary_path(), &mut elf_buffer)?;

        let main_addr = elf
            .resolve_symbol("main", qemu.load_addr())
            .ok_or_else(|| Error::empty_optional("Symbol main not found"))?;
        Ok(main_addr)
    }

    /// Initialize the emulator, run to the persistent address (main + 0x18C) and return the [`Harness`] struct
    /// `input_addr` should be set after initialization by retrieving it from HooksModule
    pub fn init(qemu: Qemu) -> Result<Harness, Error> {
        let main_addr = Self::find_main(qemu)?;
        let persistent_addr = main_addr + 0x18C; // After getopt parsing
        let breakpoint_addr = main_addr + 0x160; // Loop breakpoint

        // Run until we reach the persistent address
        qemu.entry_break(persistent_addr);
        qemu.set_breakpoint(breakpoint_addr);

        // Save all registers
        let num_regs = qemu.num_regs();
        let register_state: Vec<u64> = (0..num_regs)
            .map(|reg_idx| qemu.read_reg(reg_idx).unwrap_or(0))
            .collect();

        // Initialize the harness
        Ok(Harness {
            qemu,
            persistent_addr,
            breakpoint_addr,
            register_state,
        })
    }

    /// If we need to do extra work after forking, we can do that here.
    #[inline]
    #[expect(clippy::unused_self)]
    pub fn post_fork(&self) {}


    /// Run the harness
    pub fn run(&self, _input: &BytesInput) -> ExitKind {
        // State restoration (memory + registers) is now handled in HooksModule::pre_exec
        // to ensure they're restored atomically. We just need to ensure the breakpoint is set and run.
        let result = unsafe { self.qemu.run() };
        
        match result {
            Ok(libafl_qemu::QemuExitReason::Breakpoint(addr)) => {
                if addr == self.breakpoint_addr {
                    ExitKind::Ok
                } else {
                    ExitKind::Ok
                }
            }
            Ok(_reason) => {
                ExitKind::Ok
            }
            Err(_e) => {
                ExitKind::Crash
            }
        }
    }
}
