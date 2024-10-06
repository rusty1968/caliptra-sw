// Licensed under the Apache-2.0 license

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), no_main)]
use core::hint::black_box;

#[cfg(not(feature = "std"))]
core::arch::global_asm!(include_str!("start.S"));

#[cfg(feature = "std")]
pub fn main() {}

#[panic_handler]
#[cfg(not(feature = "std"))]
fn panic(_: &core::panic::PanicInfo) -> ! {
    panic_is_possible();
    loop {}
}

#[no_mangle]
#[cfg(not(feature = "std"))]
pub extern "C" fn entry_point() -> ! {
    loop {}
}

#[no_mangle]
#[inline(never)]
fn panic_is_possible() {
    black_box(());
    // The existence of this symbol is used to inform test_panic_missing
    // that panics are possible. Do not remove or rename this symbol.
}
