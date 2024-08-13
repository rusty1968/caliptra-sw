// Licensed under the Apache-2.0 license

#![cfg_attr(not(test), no_std)]

mod capabilities;
mod checksum;
pub mod mailbox;

use caliptra_api_types::Fuses;
use caliptra_emu_types::bus::Bus;
use caliptra_emu_types::mmio::BusMmio;
pub use caliptra_error as error;
pub use capabilities::Capabilities;
pub use checksum::{calc_checksum, verify_checksum};

use crate::mailbox::mbox_write_fifo;

pub trait SocManager {
    type TBus<'a>: Bus
    where
        Self: 'a;

    const SOC_IFC_ADDR: u32;
    const SOC_MBOX_ADDR: u32;
    const SOC_SHA512_ACC_ADDR: u32;
    const SOC_IFC_TRNG_ADDR: u32;

    const MAX_WAIT_CYCLES: u32;

    /// The APB bus from the SoC to Caliptra
    ///
    /// WARNING: Reading or writing to this bus may involve the Caliptra
    /// microcontroller executing a few instructions
    fn apb_bus(&mut self) -> Self::TBus<'_>;

    /// Initializes the fuse values and locks them in until the next reset. This
    /// function can only be called during early boot, shortly after the model
    /// is created with `new_unbooted()`.
    ///
    /// # Panics
    ///
    /// If the cptra_fuse_wr_done has already been written, or the
    /// hardware prevents cptra_fuse_wr_done from being set.
    fn init_fuses(&mut self, fuses: &Fuses) {
        if !self.soc_ifc().cptra_reset_reason().read().warm_reset() {
            assert!(
                !self.soc_ifc().cptra_fuse_wr_done().read().done(),
                "Fuses are already locked in place (according to cptra_fuse_wr_done)"
            );
        }
        //        println!("Initializing fuses: {:#x?}", fuses);

        self.soc_ifc().fuse_uds_seed().write(&fuses.uds_seed);
        self.soc_ifc()
            .fuse_field_entropy()
            .write(&fuses.field_entropy);
        self.soc_ifc()
            .fuse_key_manifest_pk_hash()
            .write(&fuses.key_manifest_pk_hash);
        self.soc_ifc()
            .fuse_key_manifest_pk_hash_mask()
            .write(|w| w.mask(fuses.key_manifest_pk_hash_mask.into()));
        self.soc_ifc()
            .fuse_owner_pk_hash()
            .write(&fuses.owner_pk_hash);
        self.soc_ifc()
            .fuse_fmc_key_manifest_svn()
            .write(|_| fuses.fmc_key_manifest_svn);
        self.soc_ifc().fuse_runtime_svn().write(&fuses.runtime_svn);
        self.soc_ifc()
            .fuse_anti_rollback_disable()
            .write(|w| w.dis(fuses.anti_rollback_disable));
        self.soc_ifc()
            .fuse_idevid_cert_attr()
            .write(&fuses.idevid_cert_attr);
        self.soc_ifc()
            .fuse_idevid_manuf_hsm_id()
            .write(&fuses.idevid_manuf_hsm_id);
        self.soc_ifc()
            .fuse_life_cycle()
            .write(|w| w.life_cycle(fuses.life_cycle.into()));
        self.soc_ifc()
            .fuse_lms_verify()
            .write(|w| w.lms_verify(fuses.lms_verify));
        self.soc_ifc()
            .fuse_lms_revocation()
            .write(|_| fuses.fuse_lms_revocation);
        self.soc_ifc()
            .fuse_soc_stepping_id()
            .write(|w| w.soc_stepping_id(fuses.soc_stepping_id.into()));

        self.soc_ifc().cptra_fuse_wr_done().write(|w| w.done(true));
        assert!(self.soc_ifc().cptra_fuse_wr_done().read().done());
    }

    /// A register block that can be used to manipulate the soc_ifc peripheral
    /// over the simulated SoC->Caliptra APB bus.
    fn soc_ifc(&mut self) -> caliptra_registers::soc_ifc::RegisterBlock<BusMmio<Self::TBus<'_>>> {
        unsafe {
            caliptra_registers::soc_ifc::RegisterBlock::new_with_mmio(
                Self::SOC_IFC_ADDR as *mut u32,
                BusMmio::new(self.apb_bus()),
            )
        }
    }

    /// A register block that can be used to manipulate the soc_ifc peripheral TRNG registers
    /// over the simulated SoC->Caliptra APB bus.
    fn soc_ifc_trng(
        &mut self,
    ) -> caliptra_registers::soc_ifc_trng::RegisterBlock<BusMmio<Self::TBus<'_>>> {
        unsafe {
            caliptra_registers::soc_ifc_trng::RegisterBlock::new_with_mmio(
                Self::SOC_IFC_TRNG_ADDR as *mut u32,
                BusMmio::new(self.apb_bus()),
            )
        }
    }

    /// A register block that can be used to manipulate the mbox peripheral
    /// over the simulated SoC->Caliptra APB bus.
    fn soc_mbox(&mut self) -> caliptra_registers::mbox::RegisterBlock<BusMmio<Self::TBus<'_>>> {
        unsafe {
            caliptra_registers::mbox::RegisterBlock::new_with_mmio(
                Self::SOC_MBOX_ADDR as *mut u32,
                BusMmio::new(self.apb_bus()),
            )
        }
    }

    /// A register block that can be used to manipulate the sha512_acc peripheral
    /// over the simulated SoC->Caliptra APB bus.
    fn soc_sha512_acc(
        &mut self,
    ) -> caliptra_registers::sha512_acc::RegisterBlock<BusMmio<Self::TBus<'_>>> {
        unsafe {
            caliptra_registers::sha512_acc::RegisterBlock::new_with_mmio(
                Self::SOC_SHA512_ACC_ADDR as *mut u32,
                BusMmio::new(self.apb_bus()),
            )
        }
    }


    /// Send a command to the mailbox but don't wait for the response
    fn start_mailbox_execute(
        &mut self,
        cmd: u32,
        buf: &[u8],
    ) -> core::result::Result<(), CaliptraApiError> {
        // Read a 0 to get the lock
        if self.soc_mbox().lock().read().lock() {
            return Err(CaliptraApiError::UnableToLockMailbox);
        }

        // Mailbox lock value should read 1 now
        // If not, the reads are likely being blocked by the PAUSER check or some other issue
        if !(self.soc_mbox().lock().read().lock()) {
            return Err(CaliptraApiError::UnableToReadMailbox);
        }


        self.soc_mbox().cmd().write(|_| cmd);
        mbox_write_fifo(&self.soc_mbox(), buf)?;

        // Ask the microcontroller to execute this command
        self.soc_mbox().execute().write(|w| w.execute(true));

        Ok(())
    }

}
#[derive(Debug, Eq, PartialEq)]
pub enum CaliptraApiError {
    UnableToLockMailbox,
    UnableToReadMailbox,
    BufferTooLargeForMailbox,
}