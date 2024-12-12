// Licensed under the Apache-2.0 license

use caliptra_api::SocManager;
use caliptra_builder::{get_ci_rom_version, CiRomVersion};
use caliptra_common::mailbox_api::GetFmcAliasCsrResp;
use caliptra_common::mailbox_api::{CommandId, MailboxReqHeader};
use caliptra_drivers::FmcAliasCsr;
use caliptra_error::CaliptraError;
use caliptra_hw_model::{HwModel, ModelError};
use caliptra_runtime::RtBootStatus;
use openssl::x509::X509Req;
use zerocopy::{AsBytes, FromBytes};

use crate::common::{run_rt_test, RuntimeTestArgs};

#[test]
fn test_get_fmc_alias_csr() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::GET_FMC_ALIAS_CSR),
            &[],
        ),
    };

    let result = model.mailbox_execute(CommandId::GET_FMC_ALIAS_CSR.into(), payload.as_bytes());

    let response = result.unwrap().unwrap();

    let get_fmc_alias_csr_resp = GetFmcAliasCsrResp::read_from(response.as_bytes()).unwrap();

    assert_ne!(
        FmcAliasCsr::UNPROVISIONED_CSR,
        get_fmc_alias_csr_resp.data_size
    );
    assert_ne!(0, get_fmc_alias_csr_resp.data_size);

    let csr_der = &get_fmc_alias_csr_resp.data[..get_fmc_alias_csr_resp.data_size as usize];
    assert_ne!([0; 512], csr_der);


    let csr = openssl::x509::X509Req::from_der(&csr_der).unwrap();
    let csr_txt = String::from_utf8(csr.to_text().unwrap()).unwrap();    

  // To update the CSR testdata:
    std::fs::write("tests/runtime_integration_tests/test_data/fmc_alias_csr.txt", &csr_txt).unwrap();
    std::fs::write("tests/runtime_integration_tests/test_data/fmc_alias_csr.der", &csr_der).unwrap();

}

#[test]
fn test_missing_csr() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::GET_IDEV_CSR), &[]),
    };

    let response = model
        .mailbox_execute(CommandId::GET_IDEV_CSR.into(), payload.as_bytes())
        .unwrap_err();

    match get_ci_rom_version() {
        // 1.0 and 1.1 ROM do not support this feature
        CiRomVersion::Rom1_0 | CiRomVersion::Rom1_1 => assert_eq!(
            response,
            ModelError::MailboxCmdFailed(CaliptraError::RUNTIME_GET_IDEV_ID_UNSUPPORTED_ROM.into())
        ),
        _ => assert_eq!(
            response,
            ModelError::MailboxCmdFailed(CaliptraError::RUNTIME_GET_IDEV_ID_UNPROVISIONED.into())
        ),
    };
}
