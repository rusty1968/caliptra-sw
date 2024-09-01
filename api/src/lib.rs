// Licensed under the Apache-2.0 license

#![cfg_attr(not(test), no_std)]
use core::mem;

mod capabilities;
mod checksum;
pub mod mailbox;

use zerocopy::{AsBytes, FromBytes};

pub use crate::mailbox::MboxBuffer;
use crate::mailbox::{MailboxReqHeader, MailboxRespHeader, Request, Response};
use caliptra_api_types::Fuses;
use caliptra_emu_types::bus::Bus;
use caliptra_emu_types::mmio::BusMmio;
pub use caliptra_error as error;
pub use capabilities::Capabilities;
pub use checksum::{calc_checksum, verify_checksum};

pub use crate::mailbox::{mbox_read_fifo, mbox_write_fifo};

use caliptra_registers::mbox::enums::{MboxFsmE, MboxStatusE};

pub struct MailboxRequest<'a> {
    pub cmd: u32,
    pub data: &'a MboxBuffer,
}

pub struct MailboxRecvTxn<'m, 'r, TSocManager: SocManager> {
    pub soc_mgr: &'m mut TSocManager,
    pub req: MailboxRequest<'r>,
}

impl<'m, 'r, TSocManager: SocManager> MailboxRecvTxn<'m, 'r, TSocManager> {
    pub fn new(soc_mgr: &'m mut TSocManager, req: MailboxRequest<'r>) -> Self {
        crate::MailboxRecvTxn { soc_mgr, req }
    }
}

impl<'m, 'r, TSocManager: SocManager> MailboxRecvTxn<'m, 'r, TSocManager> {
    pub fn respond_success(self) {
        self.complete(MboxStatusE::CmdComplete);
    }
    pub fn respond_failure(self) {
        self.complete(MboxStatusE::CmdFailure);
    }
    pub fn respond_with_data(self, data: &[u8]) -> Result<(), CaliptraApiError> {
        let mbox = self.soc_mgr.soc_mbox();
        let mbox_fsm_ps = mbox.status().read().mbox_fsm_ps();
        if !mbox_fsm_ps.mbox_execute_soc() {
            return Err(CaliptraApiError::UnexpectedMailboxFsmStatus {
                expected: MboxFsmE::MboxExecuteSoc as u32,
                actual: mbox_fsm_ps as u32,
            });
        }
        mbox_write_fifo(&mbox, data)?;
        drop(mbox);
        self.complete(MboxStatusE::DataReady);
        Ok(())
    }

    fn complete(self, status: MboxStatusE) {
        self.soc_mgr
            .soc_mbox()
            .status()
            .write(|w| w.status(|_| status));
        // mbox_fsm_ps isn't updated immediately after execute is cleared (!?),
        // so step an extra clock cycle to wait for fm_ps to update
        self.soc_mgr.wait_for_one_cycle();
    }
}

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

    fn wait_for_one_cycle(&mut self);

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

    /// Wait for the response to a previous call to `start_mailbox_execute()`.
    fn finish_mailbox_exec<'r>(
        &mut self,
        resp_data: &'r mut MboxBuffer,
    ) -> core::result::Result<Option<&'r MboxBuffer>, CaliptraApiError> {
        // Wait for the microcontroller to finish executing
        let mut timeout_cycles = 40000000; // 100ms @400MHz
        while self.soc_mbox().status().read().status().cmd_busy() {
            self.wait_for_one_cycle();
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

        mbox_read_fifo(self.soc_mbox(), resp_data)?;

        self.soc_mbox().execute().write(|w| w.execute(false));

        Ok(Some(resp_data))
    }

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

    /// Executes a typed request and (if success), returns the typed response.
    /// The checksum field of the request is calculated, and the checksum of the
    /// response is validated.
    fn mailbox_exec_req<'a, R: crate::Request>(
        &mut self,
        mut req: R,
        response: &'a mut R::Resp,
    ) -> core::result::Result<&'a R::Resp, CaliptraApiError> {
        if mem::size_of::<R>() < mem::size_of::<MailboxReqHeader>() {
            return Err(CaliptraApiError::MailboxReqTypeTooSmall);
        }
        if mem::size_of::<R::Resp>() < mem::size_of::<MailboxRespHeader>() {
            return Err(CaliptraApiError::MailboxRespTypeTooSmall);
        }
        if R::Resp::MIN_SIZE < mem::size_of::<MailboxRespHeader>() {
            return Err(CaliptraApiError::MailboxRespTypeTooSmall);
        }
        let (header_bytes, payload_bytes) = req
            .as_bytes_mut()
            .split_at_mut(mem::size_of::<MailboxReqHeader>());

        let mut header = MailboxReqHeader::read_from(header_bytes as &[u8]).unwrap();
        header.chksum = calc_checksum(R::ID.into(), payload_bytes);
        header_bytes.copy_from_slice(header.as_bytes());

        let mut response_bytes = MboxBuffer::default();
        let res = SocManager::mailbox_exec(self, R::ID.into(), req.as_bytes(), &mut response_bytes)
            .map_err(CaliptraApiError::from)?;
        if res.is_none() {
            return Err(CaliptraApiError::MailboxNoResponseData);
        }

        if response_bytes.data.len() < R::Resp::MIN_SIZE
            || response_bytes.data.len() > mem::size_of::<R::Resp>()
        {
            return Err(CaliptraApiError::MailboxUnexpectedResponseLen {
                expected_min: R::Resp::MIN_SIZE as u32,
                expected_max: mem::size_of::<R::Resp>() as u32,
                actual: response_bytes.data.len() as u32,
            });
        }

        response.as_bytes_mut()[..response_bytes.data.len()].copy_from_slice(&response_bytes.data);

        let response_header =
            MailboxRespHeader::read_from_prefix(response_bytes.data.as_slice()).unwrap();
        let actual_checksum = calc_checksum(0, &response_bytes.data[4..]);
        if actual_checksum != response_header.chksum {
            return Err(CaliptraApiError::MailboxRespInvalidChecksum {
                expected: response_header.chksum,
                actual: actual_checksum,
            });
        }
        if response_header.fips_status != MailboxRespHeader::FIPS_STATUS_APPROVED {
            return Err(CaliptraApiError::MailboxRespInvalidFipsStatus(
                response_header.fips_status,
            ));
        }
        Ok(response)
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
        resp_data: &'r mut MboxBuffer,
    ) -> core::result::Result<Option<&'r MboxBuffer>, CaliptraApiError> {
        self.start_mailbox_exec(cmd, buf)?;
        self.finish_mailbox_exec(resp_data)
    }

    fn wait_for_mailbox_rcv<'a, 'b>(
        &'a mut self,
        buffer: &'b mut MboxBuffer,
    ) -> Result<MailboxRecvTxn<'a, 'b, Self>, CaliptraApiError>
    where
        Self: Sized,
    {
        loop {
            match self.try_mailbox_rcv(buffer) {
                Ok(cmd) => {
                    return Ok(MailboxRecvTxn {
                        soc_mgr: self,
                        req: MailboxRequest { cmd, data: buffer },
                    })
                }
                Err(CaliptraApiError::NoRequestsAvail) => continue,
                Err(e) => break Err(e),
            }
        }
    }

    fn try_mailbox_rcv(&mut self, buffer: &mut MboxBuffer) -> Result<u32, CaliptraApiError>
    where
        Self: Sized,
    {
        if !self
            .soc_mbox()
            .status()
            .read()
            .mbox_fsm_ps()
            .mbox_execute_soc()
        {
            self.wait_for_one_cycle();
            return Err(CaliptraApiError::NoRequestsAvail);
        }
        let cmd = self.soc_mbox().cmd().read();
        mbox_read_fifo(self.soc_mbox(), buffer)?;
        Ok(cmd)
    }
}
#[derive(Debug, Eq, PartialEq)]
pub enum CaliptraApiError {
    UnableToLockMailbox,
    UnableToReadMailbox,
    NoRequestsAvail,
    BufferTooLargeForMailbox,
    UnknownCommandStatus(u32),
    MailboxTimeout,
    MailboxCmdFailed(u32),
    UnexpectedMailboxFsmStatus {
        expected: u32,
        actual: u32,
    },
    MailboxRespInvalidFipsStatus(u32),
    MailboxRespInvalidChecksum {
        expected: u32,
        actual: u32,
    },
    MailboxRespTypeTooSmall,
    MailboxReqTypeTooSmall,
    MailboxNoResponseData,
    MailboxUnexpectedResponseLen {
        expected_min: u32,
        expected_max: u32,
        actual: u32,
    },
}
