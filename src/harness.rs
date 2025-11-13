use libafl::{executors::ExitKind, inputs::BytesInput, Error};
use libafl_qemu::{elf::EasyElf, ArchExtras, GuestAddr, GuestReg, Qemu, Regs};

pub struct Harness {
    qemu: Qemu,
    pub persistent_addr: GuestAddr, // Address to reset to (main + 0x18C, after getopt)
    pub breakpoint_addr: GuestAddr, // Address to break at in persistent loop (main + 0x160)
    _input_addr: GuestAddr,         // Pre-allocated mmap region for fuzzer input
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
    pub fn init(qemu: Qemu, input_addr: GuestAddr) -> Result<Harness, Error> {
        let main_addr = Self::find_main(qemu)?;
        let persistent_addr = main_addr + 0x18C; // After getopt parsing
        let breakpoint_addr = main_addr + 0x160; // Loop breakpoint

        eprintln!("main @ {main_addr:#x}, persistent @ {persistent_addr:#x}, breakpoint @ {breakpoint_addr:#x}");

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
            _input_addr: input_addr,
            register_state,
        })
    }

    /// If we need to do extra work after forking, we can do that here.
    #[inline]
    #[expect(clippy::unused_self)]
    pub fn post_fork(&self) {}


    /// Run the harness
    pub fn run(&self, _input: &BytesInput) -> ExitKind {
        eprintln!(
            "[Harness::run] ===== RUN CALLED ====="
        );
        
        // State restoration (memory + registers) is now handled in HooksModule::pre_exec
        // to ensure they're restored atomically. We just need to ensure the breakpoint is set and run.
        let pc_before = self.qemu.read_reg(Regs::Pc).unwrap_or(0);
        let sp_before = self.qemu.read_reg(Regs::Sp).unwrap_or(0);
      
        eprintln!(
            "[Harness::run] PC before run: {:#x}, SP before run: {:#x}, persistent_addr: {:#x}, breakpoint_addr: {:#x}",
            pc_before,
            sp_before,
            self.persistent_addr,
            self.breakpoint_addr
        );

        eprintln!("[Harness::run] About to call qemu.run()...");
        std::io::Write::flush(&mut std::io::stderr()).ok();
        
        let result = unsafe { self.qemu.run() };
        let pc_after_run = self.qemu.read_reg(Regs::Pc).unwrap_or(0);
        let sp_after_run = self.qemu.read_reg(Regs::Sp).unwrap_or(0);
        eprintln!("[Harness::run] qemu.run() returned after {:?}: {:?}", run_elapsed, result);
        eprintln!("[Harness::run] PC after run: {:#x}, SP after run: {:#x}", pc_after_run, sp_after_run);
        std::io::Write::flush(&mut std::io::stderr()).ok();
        
        match result {
            Ok(libafl_qemu::QemuExitReason::Breakpoint(addr)) => {
                if addr == self.breakpoint_addr {
                    eprintln!("[Harness::run] Hit expected breakpoint at {:#x}", addr);
                    ExitKind::Ok
                } else {
                    eprintln!(
                        "[Harness::run] WARNING: Hit unexpected breakpoint: {:#x} (expected {:#x})",
                        addr,
                        self.breakpoint_addr
                    );
                    ExitKind::Ok
                }
            }
            Ok(reason) => {
                eprintln!("[Harness::run] WARNING: Unexpected exit reason: {:?}", reason);
                ExitKind::Ok
            }
            Err(e) => {
                eprintln!("[Harness::run] ERROR: QEMU error: {:?}", e);
                ExitKind::Crash
            }
        }
    }
}
