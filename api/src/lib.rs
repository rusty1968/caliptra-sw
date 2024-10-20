// Licensed under the Apache-2.0 license
#![cfg_attr(not(test), no_std)]

mod capabilities;
mod checksum;
pub mod mailbox;
pub mod soc_mgr;

use crate::mailbox::mbox_write_fifo;
use crate::mailbox::MboxRequest;
pub use caliptra_error as error;
use caliptra_registers::mbox::enums::{MboxFsmE, MboxStatusE};
pub use capabilities::Capabilities;
pub use checksum::{calc_checksum, verify_checksum};
pub use soc_mgr::SocManager;

#[derive(Debug, Eq, PartialEq)]
pub enum CaliptraApiError {
    UnableToLockMailbox,
    UnableToReadMailbox,
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
    UploadFirmwareUnexpectedResponse,
    UploadMeasurementResponseError,
    ReadBuffTooSmall,
    FusesAlreadyIniitalized,
    FuseDoneNotSet,
    StashMeasurementFailed,
}

pub struct MailboxRecvTxn<'m, 'r, TSocMgr: SocManager> {
    mgr: &'m mut TSocMgr,
    pub req: MboxRequest<'r>,
}
impl<'m, 'r, TSocMgr: SocManager> MailboxRecvTxn<'m, 'r, TSocMgr> {
    pub fn respond_success(self) {
        self.complete(MboxStatusE::CmdComplete);
    }
    pub fn respond_failure(self) {
        self.complete(MboxStatusE::CmdFailure);
    }
    pub fn respond_with_data(self, data: &[u8]) -> Result<(), CaliptraApiError> {
        let mbox = self.mgr.soc_mbox();
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
        self.mgr.soc_mbox().status().write(|w| w.status(|_| status));
        // mbox_fsm_ps isn't updated immediately after execute is cleared (!?),
        // so step an extra clock cycle to wait for fm_ps to update
        self.mgr.delay();
    }
}
