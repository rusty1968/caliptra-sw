// Licensed under the Apache-2.0 license
use crate::CaliptraApiError;
use caliptra_api_types::Fuses;
use ureg::MmioMut;


/// Implementation of the `SocManager` trait for a `RealSocManager`.
///
/// # Example
///
/// ```rust
/// struct RealSocManager;
/// impl SocManager for RealSocManager {
///     /// Address of the mailbox, remapped for the SoC.
///     const SOC_MBOX_ADDR: u32 = caliptra_address_remap(CPTRA_MBOX_ADDR);
///     
///     /// Address of the SoC interface, remapped for the SoC.
///     const SOC_IFC_ADDR: u32 = caliptra_address_remap(CPTRA_SOC_IFC_ADDR);
///     
///     /// Address of the SoC TRNG interface, remapped for the SoC.
///     const SOC_IFC_TRNG_ADDR: u32 = caliptra_address_remap(CPTRA_SOC_IFC_TRNG_ADDR);
///     
///     /// Address of the SHA-512 accelerator, remapped for the SoC.
///     const SOC_SHA512_ACC_ADDR: u32 = caliptra_address_remap(CPTRA_SHA512_ADDR);
///
///     /// Maximum number of wait cycles.
///     const MAX_WAIT_CYCLES: u32 = 400000;
///
///     /// Type alias for mutable memory-mapped I/O.
///     type TMmio<'a> = RealMmioMut<'a>;
///
///     /// Returns a mutable reference to the memory-mapped I/O.
///     fn mmio_mut(&mut self) -> Self::TMmio<'_> {
///         ureg::RealMmioMut::default()
///     }
///
///     /// Provides a delay function to be invoked when polling mailbox status.
///     fn delay(&mut self) {
///         real_soc_delay_fn(1);
///     }
/// }
/// ```
pub trait SocManager {
    const SOC_IFC_ADDR: u32;
    const SOC_MBOX_ADDR: u32;
    const SOC_SHA512_ACC_ADDR: u32;
    const SOC_IFC_TRNG_ADDR: u32;

    const MAX_WAIT_CYCLES: u32;

    type TMmio<'a>: MmioMut
    where
        Self: 'a;

    fn mmio_mut(&mut self) -> Self::TMmio<'_>;

    // Provide a time base for mailbox status polling loop.
    fn delay(&mut self);

    /// Set up valid PAUSERs for mailbox access.
    fn setup_mailbox_users(&mut self, apb_pausers: &[u32]) {
        for (idx, apb_pauser) in apb_pausers.iter().enumerate() {
            self.soc_ifc()
                .cptra_mbox_valid_pauser()
                .at(idx)
                .write(|_| *apb_pauser);
            self.soc_ifc()
                .cptra_mbox_pauser_lock()
                .at(idx)
                .write(|w| w.lock(true));
        }
    }

    /// Initializes the fuse values and locks them in until the next reset.
    ///
    /// # Errors
    ///
    /// If the cptra_fuse_wr_done has already been written, or the
    /// hardware prevents cptra_fuse_wr_done from being set.
    fn init_fuses(&mut self, fuses: &Fuses) -> Result<(), CaliptraApiError> {
        if !self.soc_ifc().cptra_reset_reason().read().warm_reset()
            && self.soc_ifc().cptra_fuse_wr_done().read().done()
        {
            return Err(CaliptraApiError::FusesAlreadyIniitalized);
        }

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

        if !self.soc_ifc().cptra_fuse_wr_done().read().done() {
            return Err(CaliptraApiError::FuseDoneNotSet);
        }
        Ok(())
    }

    /// A register block that can be used to manipulate the soc_ifc peripheral
    /// over the simulated SoC->Caliptra APB bus.
    fn soc_ifc(&mut self) -> caliptra_registers::soc_ifc::RegisterBlock<Self::TMmio<'_>> {
        unsafe {
            caliptra_registers::soc_ifc::RegisterBlock::new_with_mmio(
                Self::SOC_IFC_ADDR as *mut u32,
                self.mmio_mut(),
            )
        }
    }

    /// A register block that can be used to manipulate the soc_ifc peripheral TRNG registers
    /// over the simulated SoC->Caliptra APB bus.
    fn soc_ifc_trng(&mut self) -> caliptra_registers::soc_ifc_trng::RegisterBlock<Self::TMmio<'_>> {
        unsafe {
            caliptra_registers::soc_ifc_trng::RegisterBlock::new_with_mmio(
                Self::SOC_IFC_TRNG_ADDR as *mut u32,
                self.mmio_mut(),
            )
        }
    }

    /// A register block that can be used to manipulate the mbox peripheral
    /// over the simulated SoC->Caliptra APB bus.
    fn soc_mbox(&mut self) -> caliptra_registers::mbox::RegisterBlock<Self::TMmio<'_>> {
        unsafe {
            caliptra_registers::mbox::RegisterBlock::new_with_mmio(
                Self::SOC_MBOX_ADDR as *mut u32,
                self.mmio_mut(),
            )
        }
    }

    /// A register block that can be used to manipulate the sha512_acc peripheral
    /// over the simulated SoC->Caliptra APB bus.
    fn soc_sha512_acc(&mut self) -> caliptra_registers::sha512_acc::RegisterBlock<Self::TMmio<'_>> {
        unsafe {
            caliptra_registers::sha512_acc::RegisterBlock::new_with_mmio(
                Self::SOC_SHA512_ACC_ADDR as *mut u32,
                self.mmio_mut(),
            )
        }
    }
}
