// Licensed under the Apache-2.0 license

//! A very simple program to test the behavior of the CPU when trying to write to ROM.

#![no_main]
#![no_std]

// Needed to bring in startup code
#[allow(unused)]
use caliptra_test_harness::println;

use caliptra_registers::{self, mbox::MboxCsr, soc_ifc::SocIfcReg};

pub const MBOX_ORG: u32 = 0x30000000;
pub const MBOX_SIZE: u32 = 128 * 1024;
pub const MANIFEST_MARKER: u32 = 0x4E414D43;

#[panic_handler]
pub fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
extern "C" fn main() {
    let mut soc_ifc = unsafe { SocIfcReg::new() };
    let mut mbox = unsafe { MboxCsr::new() };
    let mbox = mbox.regs_mut();

    soc_ifc
        .regs_mut()
        .cptra_flow_status()
        .write(|w| w.ready_for_fw(true));

    let mailbox_sram = unsafe { create_slice(MBOX_ORG, MBOX_SIZE as usize) };

    loop {
        while !mbox.status().read().mbox_fsm_ps().mbox_execute_uc() {
            // Wait for a request from the SoC.
        }
        let cmd = mbox.cmd().read();
        // Returns a success response; doesn't consume input.
        if cmd == 0x2000_0000 {
            if mailbox_sram[0] == MANIFEST_MARKER {
                mbox.status().write(|w| w.status(|w| w.cmd_complete()));
            } else {
                soc_ifc
                    .regs_mut()
                    .cptra_fw_error_non_fatal()
                    .write(|_| 0x42);
                mbox.status().write(|w| w.status(|w| w.cmd_failure()));
            }
        }
    }
}

unsafe fn create_slice(org: u32, size: usize) -> &'static mut [u32] {
    let ptr = org as *mut u32;
    core::slice::from_raw_parts_mut(ptr, size)
}
