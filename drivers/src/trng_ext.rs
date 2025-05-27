// Licensed under the Apache-2.0 license

use core::num::NonZeroU32;

use caliptra_error::{CaliptraError, CaliptraResult};
use caliptra_registers::soc_ifc_trng::SocIfcTrngReg;
use zerocopy::AsBytes;

use crate::Array4x12;
use rand_core::Error as RandCoreError;

pub struct TrngExt {
    soc_ifc_trng: SocIfcTrngReg,
}

impl TrngExt {
    pub fn new(soc_ifc_trng: SocIfcTrngReg) -> Self {
        Self { soc_ifc_trng }
    }

    pub fn generate(&mut self) -> CaliptraResult<Array4x12> {
        const MAX_CYCLES_TO_WAIT: u32 = 250000;

        let regs = self.soc_ifc_trng.regs_mut();
        regs.cptra_trng_status().write(|w| w.data_req(true));
        let mut cycles = 0;
        while !regs.cptra_trng_status().read().data_wr_done() {
            cycles += 1;
            if cycles >= MAX_CYCLES_TO_WAIT {
                return Err(CaliptraError::DRIVER_TRNG_EXT_TIMEOUT);
            }
        }
        let result = Array4x12::read_from_reg(regs.cptra_trng_data());
        regs.cptra_trng_status().write(|w| w.data_req(false));
        Ok(result)
    }
}

fn convert_to_u32(byte_slice: &[u8]) -> u32 {
    let array: [u8; 4] = match byte_slice.get(..4) {
        Some(subslice) => subslice.try_into().unwrap_or([0; 4]),
        None => [0; 4],
    };
    u32::from_ne_bytes(array)
}

fn convert_to_u64(byte_slice: &[u8]) -> u64 {
    let array: [u8; 8] = match byte_slice.get(..8) {
        Some(subslice) => subslice.try_into().unwrap_or([0; 8]),
        None => [0; 8],
    };
    u64::from_ne_bytes(array)
}

impl rand_core::RngCore for TrngExt {
    fn next_u32(&mut self) -> u32 {
        match self.generate() {
            Ok(array) => convert_to_u32(array.as_bytes()),
            Err(_) => 0,
        }
    }

    fn next_u64(&mut self) -> u64 {
        match self.generate() {
            Ok(array) => convert_to_u64(array.as_bytes()),
            Err(_) => 0,
        }
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        if self.try_fill_bytes(dest).is_err() {
            dest.fill(0);
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RandCoreError> {
        match self.generate() {
            Ok(array) => {
                let src = array.as_bytes();
                let len = core::cmp::min(src.len(), dest.len());
                dest[..len].copy_from_slice(&src[..len]);
                Ok(())
            }
            Err(e) => {
                let code: NonZeroU32 = e.into();
                let err = RandCoreError::from(code);
                Err(err)
            }
        }
    }
}
