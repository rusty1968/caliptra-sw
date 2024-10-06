// Licensed under the Apache-2.0 license
use crate::mailbox::mbox_read_fifo;
use crate::mailbox::mbox_write_fifo;
use crate::CaliptraApiError;
use ureg::MmioMut;

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

    fn delay(&mut self);

    /// Send a command to the mailbox but don't wait for the response
    fn start_mailbox_exec(
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

    fn finish_mailbox_exec<'r>(
        &mut self,
        resp_data: &'r mut [u8],
    ) -> core::result::Result<Option<&'r [u8]>, CaliptraApiError> {
        // Wait for the microcontroller to finish executing
        let mut timeout_cycles = Self::MAX_WAIT_CYCLES; // 100ms @400MHz
        while self.soc_mbox().status().read().status().cmd_busy() {
            self.delay();
            timeout_cycles -= 1;
            if timeout_cycles == 0 {
                return Err(CaliptraApiError::MailboxTimeout);
            }
        }
        let status = self.soc_mbox().status().read().status();
        if status.cmd_failure() {
            self.soc_mbox().execute().write(|w| w.execute(false));
            let soc_ifc = self.soc_ifc();
            return Err(CaliptraApiError::MailboxCmdFailed(
                if soc_ifc.cptra_fw_error_fatal().read() != 0 {
                    soc_ifc.cptra_fw_error_fatal().read()
                } else {
                    soc_ifc.cptra_fw_error_non_fatal().read()
                },
            ));
        }
        if status.cmd_complete() {
            self.soc_mbox().execute().write(|w| w.execute(false));
            return Ok(None);
        }
        if !status.data_ready() {
            return Err(CaliptraApiError::UnknownCommandStatus(status as u32));
        }

        let res = mbox_read_fifo(self.soc_mbox(), resp_data);

        self.soc_mbox().execute().write(|w| w.execute(false));

        res?;

        Ok(Some(resp_data))
    }

    /// Executes `cmd` with request data `buf`. Returns `Ok(Some(_))` if
    /// the uC responded with data, `Ok(None)` if the uC indicated success
    /// without data, Err(CaliptraApiError::MailboxCmdFailed) if the microcontroller
    /// responded with an error, or other model errors if there was a problem
    /// communicating with the mailbox.
    fn mailbox_exec<'r>(
        &mut self,
        cmd: u32,
        buf: &[u8],
        resp_data: &'r mut [u8],
    ) -> core::result::Result<Option<&'r [u8]>, CaliptraApiError> {
        self.start_mailbox_exec(cmd, buf)?;
        self.finish_mailbox_exec(resp_data)
    }

    /// Upload firmware to the mailbox.
    fn upload_fw(&mut self, firmware: &[u8]) -> Result<(), CaliptraApiError> {
        let response = SocManager::mailbox_exec(
            self,
            crate::mailbox::CommandId::FIRMWARE_LOAD.into(),
            firmware,
            &mut [],
        )?;
        if response.is_some() {
            return Err(CaliptraApiError::UploadFirmwareUnexpectedResponse);
        }
        Ok(())
    }
    fn setup_mailbox_access(&mut self, apb_pausers: [u32; 5]) {
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
