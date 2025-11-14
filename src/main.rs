//! A libfuzzer-like fuzzer using qemu for binary-only coverage
#[cfg(target_os = "linux")]
mod client;
#[cfg(target_os = "linux")]
mod fuzzer;
#[cfg(target_os = "linux")]
mod harness;
#[cfg(target_os = "linux")]
mod hooks;
#[cfg(target_os = "linux")]
mod instance;
#[cfg(target_os = "linux")]
mod options;
#[cfg(target_os = "linux")]
mod version;

#[cfg(target_os = "linux")]
use crate::fuzzer::Fuzzer;

#[cfg(target_os = "linux")]
pub fn main() {
    if let Err(e) = Fuzzer::new().fuzz() {
        eprintln!("[FATAL] Fuzzer error: {:?}", e);
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
pub fn main() {
    panic!("qemu-user and libafl_qemu is only supported on linux!");
}
