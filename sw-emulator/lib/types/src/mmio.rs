// Licensed under the Apache-2.0 license

use core::cell::RefCell;

use crate::RvSize;

use crate::bus::Bus;

const fn rvsize<T>() -> RvSize {
    match core::mem::size_of::<T>() {
        1 => RvSize::Byte,
        2 => RvSize::HalfWord,
        4 => RvSize::Word,
        _other => panic!("Unsupported RvSize"),
    }
}

unsafe fn transmute_to_u32<T>(src: &T) -> u32 {
    match core::mem::size_of::<T>() {
        1 => core::mem::transmute_copy::<T, u8>(src).into(),
        2 => core::mem::transmute_copy::<T, u16>(src).into(),
        4 => core::mem::transmute_copy::<T, u32>(src),
        _ => panic!("Unsupported write size"),
    }
}

/// An MMIO implementation that reads and writes to a `caliptra_emu_bus::Bus`.
pub struct BusMmio<TBus: Bus> {
    bus: RefCell<TBus>,
}
impl<TBus: Bus> BusMmio<TBus> {
    pub fn new(bus: TBus) -> Self {
        Self {
            bus: RefCell::new(bus),
        }
    }
    pub fn into_inner(self) -> TBus {
        self.bus.into_inner()
    }
}
impl<TBus: Bus> ureg::Mmio for BusMmio<TBus> {
    /// Loads from address `src` on the bus and returns the value.
    ///
    /// # Panics
    ///
    /// This function panics if the bus faults.
    ///
    /// # Safety
    ///
    /// As the pointer isn't read from, this Mmio implementation isn't actually
    /// unsafe for POD types like u8/u16/u32.
    unsafe fn read_volatile<T: Clone + Copy + Sized>(&self, src: *const T) -> T {
        let val_u32 = self
            .bus
            .borrow_mut()
            .read(rvsize::<T>(), src as usize as u32)
            .unwrap();
        match core::mem::size_of::<T>() {
            1 => core::mem::transmute_copy::<u8, T>(&(val_u32 as u8)),
            2 => core::mem::transmute_copy::<u16, T>(&(val_u32 as u16)),
            4 => core::mem::transmute_copy::<u32, T>(&val_u32),
            _ => panic!("Unsupported read size"),
        }
    }
}

impl<TBus: Bus> ureg::MmioMut for BusMmio<TBus> {
    /// Stores `src` to address `dst` on the bus.
    ///
    /// # Panics
    ///
    /// This function panics if the bus faults.
    ///
    /// # Safety
    ///
    /// As the pointer isn't written to, this Mmio implementation isn't actually
    /// unsafe for POD types like u8/u16/u32.
    unsafe fn write_volatile<T: Clone + Copy>(&self, dst: *mut T, src: T) {
        self.bus
            .borrow_mut()
            .write(rvsize::<T>(), dst as usize as u32, transmute_to_u32(&src))
            .unwrap()
    }
}
