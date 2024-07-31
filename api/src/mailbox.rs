use core::mem::size_of;

use caliptra_registers::{mbox, soc_ifc};
use ureg::RealMmioMut;
use zerocopy::{AsBytes, FromBytes, LayoutVerified, Unalign};
use crate::{calc_checksum, messages::{MailboxReqHeader, MailboxRespHeader, Response}};

#[derive(Debug, Eq, PartialEq)]
pub enum MailboxError {
    /// The mailbox is already locked
    UnableToLockMailbox,
    UnableToReadMailbox,
    /// The buffer is too large to fit in the mailbox
    BufferTooLargeForMailbox,
    /// The request type is too small to contain the mailbox request header
    MailboxReqTypeTooSmall,
    /// The response type is too small to contain the mailbox response header
    MailboxRespTypeTooSmall,

    MailboxRespInvalidFipsStatus(u32),
    /// The response checksum is invalid
    MailboxRespInvalidChecksum {
        expected: u32,
        actual: u32,
    },

    MailboxNoResponseData,

    MailboxUnexpectedResponseLen {
        expected_min: u32,
        expected_max: u32,
        actual: u32,
    },
    MailboxCmdFailed(u32),
    UnknownCommandStatus(u32),

    MailboxTimeout,
}

// SoC to caliptra mailbox requester.
pub struct SocToCaliptra {
    mbox_addr : u32,
    soc_ifc_addr  : u32,
}

impl<'a> SocToCaliptra {
    pub fn new(mbox_addr: u32, soc_ifc_addr : u32) -> Self {
        Self {
            mbox_addr,
            soc_ifc_addr,
        }
    }

     /// Return a register block that can be used to read and
    /// write this peripheral's registers.
    #[inline(always)]
    pub  fn soc_ifc(&mut self) -> caliptra_registers::soc_ifc::RegisterBlock<ureg::RealMmioMut> {
        unsafe { caliptra_registers::soc_ifc::RegisterBlock::new(self.soc_ifc_addr as *mut u32) }
    }
   
     /// Return a register block that can be used to read and
    /// write this peripheral's registers.
    #[inline(always)]
    pub  fn mbox(&mut self) -> caliptra_registers::mbox::RegisterBlock<ureg::RealMmioMut> {
        unsafe { caliptra_registers::mbox::RegisterBlock::new(self.mbox_addr as *mut u32) }
    }


}

impl SocToCaliptra {
    pub fn execute_req<R: crate::messages::Request>(
        &mut self,
        mut req: R,
        delay_one_cycle: impl FnMut(),
    ) -> core::result::Result<R::Resp, MailboxError> {
    
        if core::mem::size_of::<R>() < core::mem::size_of::<MailboxReqHeader>() {
            return Err(MailboxError::MailboxReqTypeTooSmall);
        }
        if core::mem::size_of::<R::Resp>() < core::mem::size_of::<MailboxRespHeader>() {
            return Err(MailboxError::MailboxRespTypeTooSmall);
        }
        if R::Resp::MIN_SIZE < core::mem::size_of::<MailboxRespHeader>() {
            return Err(MailboxError::MailboxRespTypeTooSmall);
        }
        let (header_bytes, payload_bytes) = req
            .as_bytes_mut()
            .split_at_mut(core::mem::size_of::<MailboxReqHeader>());
    
        let mut header = MailboxReqHeader::read_from(header_bytes as &[u8]).unwrap();
        header.chksum = calc_checksum(R::ID.into(), payload_bytes);
        header_bytes.copy_from_slice(header.as_bytes());
    
        let mut response = R::Resp::new_zeroed();
    
        self.mailbox_execute(R::ID.into(), req.as_bytes(), response.as_bytes_mut(), delay_one_cycle)?;
        
        Ok(response)              
    }

    /// Send a command to the mailbox but don't wait for the response
    fn start_mailbox_execute(
        &mut self,
        cmd: u32,
        buf: &[u8],
    ) -> core::result::Result<(), MailboxError> {
        // Read a 0 to get the lock
        if self.mbox().lock().read().lock() {
            return Err(MailboxError::UnableToLockMailbox);
        }

        // Mailbox lock value should read 1 now
        // If not, the reads are likely being blocked by the PAUSER check or some other issue
        if !(self.mbox().lock().read().lock()) {
            return Err(MailboxError::UnableToReadMailbox);
        }

        self.mbox().cmd().write(|_| cmd);
        mbox_write_fifo(&self.mbox(), buf)?;

        // Ask the microcontroller to execute this command
        self.mbox().execute().write(|w| w.execute(true));

        Ok(())
    }

    /// Wait for the response to a previous call to `start_mailbox_execute()`.
    fn finish_mailbox_execute(
        &mut self,
        mut delay_one_cycle: impl FnMut(),
        buf: &mut [u8],
    ) -> core::result::Result<(), MailboxError> {
        // Wait for the microcontroller to finish executing
        let mut timeout_cycles = 40000000; // 100ms @400MHz
        while self.mbox().status().read().status().cmd_busy() {
            if timeout_cycles <= 0 {
                return Err(MailboxError::MailboxTimeout);
            }
            delay_one_cycle();
            timeout_cycles -= 1;
        }
        let status = self.mbox().status().read().status();
        if status.cmd_failure() {
            self.mbox().execute().write(|w| w.execute(false));
            return Err(MailboxError::MailboxCmdFailed(
                if self.soc_ifc().cptra_fw_error_fatal().read() != 0 {
                    self.soc_ifc().cptra_fw_error_fatal().read()
                } else {
                    self.soc_ifc().cptra_fw_error_non_fatal().read()
                },
            ));
        }
        if status.cmd_complete() {
            self.mbox().execute().write(|w| w.execute(false));
            return Ok(());
        }
        if !status.data_ready() {
            return Err(MailboxError::UnknownCommandStatus(status as u32));
        }

        let dlen = self.mbox().dlen().read();
        mbox_read_fifo(&self.mbox(), &mut buf[..dlen as usize]);

        self.mbox().execute().write(|w| w.execute(false));

        Ok(())
    }

    /// Executes `cmd` with request data `buf`. Returns `Ok(Some(_))` if
    /// the uC responded with data, `Ok(None)` if the uC indicated success
    /// without data, Err(ModelError::MailboxCmdFailed) if the microcontroller
    /// responded with an error, or other model errors if there was a problem
    /// communicating with the mailbox.
    pub fn mailbox_execute(
        &mut self,
        cmd: u32,
        req_buf: &[u8],
        resp_buf: &mut [u8],
        delay_one_cycle: impl FnMut(),
    ) -> core::result::Result<(), MailboxError> {
        self.start_mailbox_execute(cmd, req_buf)?;
        self.finish_mailbox_execute(delay_one_cycle, resp_buf)
    }    
}


fn dequeue_words(mbox: &mbox::RegisterBlock<RealMmioMut>, buf: &mut [Unalign<u32>]) {
    for word in buf.iter_mut() {
        *word = Unalign::new(mbox.dataout().read());
    }
}

pub fn mbox_read_fifo(mbox: &mbox::RegisterBlock<RealMmioMut>, mut buf: &mut [u8]) {
    let dlen_bytes = mbox.dlen().read() as usize;
    if dlen_bytes < buf.len() {
        buf = &mut buf[..dlen_bytes];
    }
    let len_words = buf.len() / size_of::<u32>();
    let (mut buf_words, suffix) =
        LayoutVerified::new_slice_unaligned_from_prefix(buf, len_words).unwrap();

    dequeue_words(mbox, &mut buf_words);
    if !suffix.is_empty() {
        let last_word = &mbox.dataout().read();
        let suffix_len = suffix.len();
        suffix
            .as_bytes_mut()
            .copy_from_slice(&last_word.as_bytes()[..suffix_len]);
    }
}

pub fn mbox_write_fifo(
    mbox: &mbox::RegisterBlock<RealMmioMut>,
    buf: &[u8],
) -> Result<(), MailboxError> {
    const MAILBOX_SIZE: u32 = 128 * 1024;

    let Ok(input_len) = u32::try_from(buf.len()) else {
        return Err(MailboxError::BufferTooLargeForMailbox);
    };
    if input_len > MAILBOX_SIZE {
        return Err(MailboxError::BufferTooLargeForMailbox);
    }
    mbox.dlen().write(|_| input_len);

    let mut remaining = buf;
    while remaining.len() >= 4 {
        // Panic is impossible because the subslice is always 4 bytes
        let word = u32::from_le_bytes(remaining[..4].try_into().unwrap());
        mbox.datain().write(|_| word);
        remaining = &remaining[4..];
    }
    if !remaining.is_empty() {
        let mut word_bytes = [0u8; 4];
        word_bytes[..remaining.len()].copy_from_slice(remaining);
        let word = u32::from_le_bytes(word_bytes);
        mbox.datain().write(|_| word);
    }
    Ok(())
}



mod tests {
    use super::*;
    /// A register block that can be used to manipulate the soc_ifc peripheral
    /// over the simulated SoC->Caliptra APB bus.
    #[test]
    fn soc_ifc()  {
        
    }
    
}


