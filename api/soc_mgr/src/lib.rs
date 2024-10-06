// Licensed under the Apache-2.0 license

#![no_std]
use caliptra_api::SocManager;

const REAL_SOC_IFC_ADDR: u32 = 0x3003_0000;
const REAL_MBOX_ADDR: u32 = 0x3002_0000;
const REAL_SOC_IFC_TRNG_ADDR: u32 = 0x3003_0000;
const REAL_SHA512_ADDR: u32 = 0x3002_1000;

pub struct RealSocManager;

impl RealSocManager {
    pub fn setup_mailbox_access1(&mut self, apb_pausers: [u32; 5]) {
        for (idx, apb_pauser) in apb_pausers.iter().enumerate() {
            // Set up the PAUSER as valid for the mailbox (using index 0)
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
}
impl SocManager for RealSocManager {
    const SOC_MBOX_ADDR: u32 = REAL_MBOX_ADDR;
    const SOC_IFC_ADDR: u32 = REAL_SOC_IFC_ADDR;
    const SOC_IFC_TRNG_ADDR: u32 = REAL_SOC_IFC_TRNG_ADDR;
    const SOC_SHA512_ACC_ADDR: u32 = REAL_SHA512_ADDR;

    const MAX_WAIT_CYCLES: u32 = 400000;

    type TMmio<'a> = ureg::RealMmioMut<'a>;

    fn mmio_mut(&mut self) -> Self::TMmio<'_> {
        ureg::RealMmioMut::default()
    }

    /// Provides a delay function to be invoked when polling mailbox status.
    fn delay(&mut self) {}
}
