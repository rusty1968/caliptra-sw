// Licensed under the Apache-2.0 license

use caliptra_builder::{
    build_firmware_elf,
    firmware::{APP_WITH_UART, FMC_WITH_UART},
    ImageOptions,
};
use caliptra_common::mailbox_api::{
    CertifyKeyExtendedFlags, CertifyKeyExtendedReq, CommandId, MailboxReq, MailboxReqHeader,
    PopulateIdevCertReq, StashMeasurementReq,
};
use caliptra_error::CaliptraError;
use caliptra_hw_model::{BootParams, DefaultHwModel, Fuses, HwModel, InitParams, SecurityState};
use caliptra_image_crypto::OsslCrypto as Crypto;
use caliptra_image_elf::ElfExecutable;
use caliptra_image_gen::{ImageGenerator, ImageGeneratorConfig};
use caliptra_runtime::{
    RtBootStatus, PL0_DPE_ACTIVE_CONTEXT_THRESHOLD, PL1_DPE_ACTIVE_CONTEXT_THRESHOLD,
};

use dpe::{
    commands::{
        CertifyKeyCmd, CertifyKeyFlags, Command, DeriveContextCmd, DeriveContextFlags, InitCtxCmd,
        RotateCtxCmd, RotateCtxFlags,
    },
    context::ContextHandle,
    response::Response,
    DPE_PROFILE,
};
use zerocopy::AsBytes;

use crate::common::{assert_error, execute_dpe_cmd, run_rt_test, DpeResult, TEST_LABEL};

const DATA: [u8; DPE_PROFILE.get_hash_size()] = [0u8; 48];

#[test]
fn test_pl0_derive_context_dpe_context_thresholds() {
    let mut model = run_rt_test(None, None, None);

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    // First rotate the default context so that we don't run into an error
    // when trying to retain the default context in derive child.
    let rotate_ctx_cmd = RotateCtxCmd {
        handle: ContextHandle::default(),
        flags: RotateCtxFlags::empty(),
    };
    let resp = execute_dpe_cmd(
        &mut model,
        &mut Command::RotateCtx(rotate_ctx_cmd),
        DpeResult::Success,
    );
    let Some(Response::RotateCtx(rotate_ctx_resp)) = resp else {
        panic!("Wrong response type!");
    };
    let mut handle = rotate_ctx_resp.handle;

    // Call DeriveContext with PL0 enough times to breach the threshold on the last iteration.
    // Note that this loop runs exactly PL0_DPE_ACTIVE_CONTEXT_THRESHOLD times. When we initialize
    // DPE, we measure mailbox valid pausers in pl0_pauser's locality. Thus, we can call derive child
    // from PL0 exactly 7 times, and the last iteration of this loop, is expected to throw a threshold breached error.
    let num_iterations = PL0_DPE_ACTIVE_CONTEXT_THRESHOLD;
    for i in 0..num_iterations {
        let derive_context_cmd = DeriveContextCmd {
            handle,
            data: DATA,
            flags: DeriveContextFlags::RETAIN_PARENT_CONTEXT,
            tci_type: 0,
            target_locality: 0,
        };

        // If we are on the last call to DeriveContext, expect that we get a PL0_USED_DPE_CONTEXT_THRESHOLD_EXCEEDED error.
        if i == num_iterations - 1 {
            let resp = execute_dpe_cmd(
                &mut model,
                &mut Command::DeriveContext(derive_context_cmd),
                DpeResult::MboxCmdFailure(
                    caliptra_drivers::CaliptraError::RUNTIME_PL0_USED_DPE_CONTEXT_THRESHOLD_REACHED,
                ),
            );
            assert!(resp.is_none());
            break;
        }

        let resp = execute_dpe_cmd(
            &mut model,
            &mut Command::DeriveContext(derive_context_cmd),
            DpeResult::Success,
        );
        let Some(Response::DeriveContext(derive_context_resp)) = resp else {
            panic!("Wrong response type!");
        };
        handle = derive_context_resp.handle;
    }
}

#[test]
fn test_pl1_derive_context_dpe_context_thresholds() {
    let mut image_opts = ImageOptions::default();
    image_opts.vendor_config.pl0_pauser = None;

    let mut model = run_rt_test(None, Some(image_opts), None);

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    // First initialize a simulation context in locality 1
    // so that we get a non-default handle which we can use
    // when calling DeriveContext with the RETAIN_PARENT_CONTEXT flag
    let init_ctx_cmd = InitCtxCmd::new_simulation();
    let resp = execute_dpe_cmd(
        &mut model,
        &mut Command::InitCtx(init_ctx_cmd),
        DpeResult::Success,
    );
    let Some(Response::InitCtx(init_ctx_resp)) = resp else {
        panic!("Wrong response type!");
    };
    let mut handle = init_ctx_resp.handle;

    // Call DeriveContext with PL1 enough times to breach the threshold on the last iteration.
    // Note that this loop runs exactly PL1_DPE_ACTIVE_CONTEXT_THRESHOLD - 1 times. When we initialize
    // DPE, we measure the RT journey PCR in Caliptra's locality: 0xFFFFFFFF, which counts as a PL1 locality.
    // Then, we initialize a simulation context in locality 1. Thus, we can call derive child
    // from PL1 exactly 16 - 2 = 14 times, and the last iteration of this loop, is expected to throw a threshold breached error.
    let num_iterations = PL1_DPE_ACTIVE_CONTEXT_THRESHOLD - 1;
    for i in 0..num_iterations {
        let derive_context_cmd = DeriveContextCmd {
            handle,
            data: DATA,
            flags: DeriveContextFlags::RETAIN_PARENT_CONTEXT,
            tci_type: 0,
            target_locality: 0,
        };

        // If we are on the last call to DeriveContext, expect that we get a PL1_USED_DPE_CONTEXT_THRESHOLD_EXCEEDED error.
        if i == num_iterations - 1 {
            let resp = execute_dpe_cmd(
                &mut model,
                &mut Command::DeriveContext(derive_context_cmd),
                DpeResult::MboxCmdFailure(
                    caliptra_drivers::CaliptraError::RUNTIME_PL1_USED_DPE_CONTEXT_THRESHOLD_REACHED,
                ),
            );
            assert!(resp.is_none());
            break;
        }

        let resp = execute_dpe_cmd(
            &mut model,
            &mut Command::DeriveContext(derive_context_cmd),
            DpeResult::Success,
        );
        let Some(Response::DeriveContext(derive_context_resp)) = resp else {
            panic!("Wrong response type!");
        };
        handle = derive_context_resp.handle;
    }
}

#[test]
fn test_pl0_init_ctx_dpe_context_thresholds() {
    let mut model = run_rt_test(None, None, None);

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    pl0_init_ctx_dpe_context_thresholds(&mut model);
}
fn pl0_init_ctx_dpe_context_thresholds(model: &mut DefaultHwModel) {
    let num_iterations = PL0_DPE_ACTIVE_CONTEXT_THRESHOLD;
    for i in 0..num_iterations {
        let init_ctx_cmd = InitCtxCmd::new_simulation();

        // If we are on the last call to InitializeContext, expect that we get a PL0_USED_DPE_CONTEXT_THRESHOLD_EXCEEDED error.
        if i == num_iterations - 1 {
            let resp = execute_dpe_cmd(
                model,
                &mut Command::InitCtx(init_ctx_cmd),
                DpeResult::MboxCmdFailure(
                    caliptra_drivers::CaliptraError::RUNTIME_PL0_USED_DPE_CONTEXT_THRESHOLD_REACHED,
                ),
            );
            assert!(resp.is_none());
            break;
        }

        let resp = execute_dpe_cmd(
            model,
            &mut Command::InitCtx(init_ctx_cmd),
            DpeResult::Success,
        );
        let Some(Response::InitCtx(_)) = resp else {
            panic!("Wrong response type!");
        };
    }
}


fn pl0_derive_context_dpe_context_thresholds(model : &mut DefaultHwModel) {

    // First rotate the default context so that we don't run into an error
    // when trying to retain the default context in derive child.
    let rotate_ctx_cmd = RotateCtxCmd {
        handle: ContextHandle::default(),
        flags: RotateCtxFlags::empty(),
    };
    let resp = execute_dpe_cmd(
        model,
        &mut Command::RotateCtx(rotate_ctx_cmd),
        DpeResult::Success,
    );
    let Some(Response::RotateCtx(rotate_ctx_resp)) = resp else {
        panic!("Wrong response type!");
    };
    let mut handle = rotate_ctx_resp.handle;

    // Call DeriveContext with PL0 enough times to breach the threshold on the last iteration.
    // Note that this loop runs exactly PL0_DPE_ACTIVE_CONTEXT_THRESHOLD times. When we initialize
    // DPE, we measure mailbox valid pausers in pl0_pauser's locality. Thus, we can call derive child
    // from PL0 exactly 7 times, and the last iteration of this loop, is expected to throw a threshold breached error.
    let num_iterations = PL0_DPE_ACTIVE_CONTEXT_THRESHOLD;
    for i in 0..num_iterations {
        let derive_context_cmd = DeriveContextCmd {
            handle,
            data: DATA,
            flags: DeriveContextFlags::RETAIN_PARENT_CONTEXT,
            tci_type: 0,
            target_locality: 0,
        };

        // If we are on the last call to DeriveContext, expect that we get a PL0_USED_DPE_CONTEXT_THRESHOLD_EXCEEDED error.
        if i == num_iterations - 1 {
            let resp = execute_dpe_cmd(
                model,
                &mut Command::DeriveContext(derive_context_cmd),
                DpeResult::MboxCmdFailure(
                    caliptra_drivers::CaliptraError::RUNTIME_PL0_USED_DPE_CONTEXT_THRESHOLD_REACHED,
                ),
            );
            assert!(resp.is_none());
            break;
        }

        let resp = execute_dpe_cmd(
            model,
            &mut Command::DeriveContext(derive_context_cmd),
            DpeResult::Success,
        );
        let Some(Response::DeriveContext(derive_context_resp)) = resp else {
            panic!("Wrong response type!");
        };
        handle = derive_context_resp.handle;
    }
}

fn derive_context(tci_type: u32, target_locality: u32) -> Option<Response> {
    let derive_context_cmd = DeriveContextCmd {
        handle: ContextHandle::default(),
        data: DATA,
        flags: default::Default(),
        tci_type,
        target_locality,
    };
    execute_dpe_cmd(
        &mut model,
        &mut Command::DeriveContext(derive_context_cmd),
        DpeResult::Success,
    )    
}

#[test]
fn test_dpe_cert_size() {
    let mut image_opts = ImageOptions::default();
    image_opts.vendor_config.pl0_pauser = Some(0x1);


    let mut model = run_rt_test(None, Some(image_opts), None);
    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    for i in 1..16  {
        derive_context(i, 0x01);
        send_certy_key
    }   

    model.set_apb_pauser(0x02);

    for i in 1..16  {
        derive_context(i, 0x02);
    }   

}

#[test]
fn my_test() {
    fn send_certy_key(model : &mut DefaultHwModel) {
        let certify_key_cmd = CertifyKeyCmd {
            handle: ContextHandle::default(),
            label: TEST_LABEL,
            flags: CertifyKeyFlags::empty(),
            format: CertifyKeyCmd::FORMAT_X509,
        };
        let resp = execute_dpe_cmd(
            model,
            &mut Command::CertifyKey(certify_key_cmd),
            DpeResult::Success,
        );
        let Some(Response::CertifyKey(certify_key_resp)) = resp else {
            panic!("Wrong response type!");
        };
        assert!(certify_key_resp.cert_size < 2048);     
    }
  
    let security_state = *SecurityState::default()
        .set_debug_locked(true)
        .set_device_lifecycle(DeviceLifecycle::Production);
    let idevid_pubkey = get_idevid_pubkey();

    let mut image_opts = ImageOptions::default();
    image_opts.vendor_config.pl0_pauser = Some(0x1);
    image_opts.fmc_svn = 9;

    let rom = caliptra_builder::rom_for_fw_integration_tests().unwrap();
    let image = caliptra_builder::build_and_sign_image(
        &firmware::FMC_WITH_UART,
        &firmware::APP_WITH_UART,
        image_opts,
    )
    .unwrap();
    let vendor_pk_hash = sha384(image.manifest.preamble.vendor_pub_keys.as_bytes());
    let owner_pk_hash = sha384(image.manifest.preamble.owner_pub_keys.as_bytes());
    let vendor_pk_hash_words = bytes_to_be_words_48(&vendor_pk_hash);
    let owner_pk_hash_words = bytes_to_be_words_48(&owner_pk_hash);

    let fuses = Fuses {
        key_manifest_pk_hash: vendor_pk_hash_words,
        owner_pk_hash: owner_pk_hash_words,
        fmc_key_manifest_svn: 0b1111111,
        lms_verify: true,
        ..Default::default()
    };
    let mut hw = caliptra_hw_model::new(
        InitParams {
            rom: &rom,
            security_state,
            ..Default::default()
        },
        BootParams {
            fuses,
            fw_image: Some(&image.to_bytes().unwrap()),
            ..Default::default()
        },
    )
    .unwrap();

    if cfg!(feature = "fpga_realtime") {
        assert_eq!(hw.type_name(), "ModelFpgaRealtime");
        hw.set_apb_pauser(0x02);
    } 
}

#[test]
fn test_pl1_init_ctx_dpe_context_thresholds() {
    let mut image_opts = ImageOptions::default();
    image_opts.vendor_config.pl0_pauser = None;

    let mut model = run_rt_test(None, Some(image_opts), None);

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    pl1_init_ctx_dpe_context_thresholds(&mut model);
}

fn pl1_init_ctx_dpe_context_thresholds(model: &mut DefaultHwModel) {
    let num_iterations = PL1_DPE_ACTIVE_CONTEXT_THRESHOLD;
    for i in 0..num_iterations {
        let init_ctx_cmd = InitCtxCmd::new_simulation();

        // InitCtx should fail on the PL1_DPE_ACTIVE_CONTEXT_THRESHOLD - 1st iteration since
        // RT initialization creates the RT journey measurement context in Caliptra's locality,
        // which is PL1.
        if i == num_iterations - 1 {
            let resp = execute_dpe_cmd(
                model,
                &mut Command::InitCtx(init_ctx_cmd),
                DpeResult::MboxCmdFailure(
                    caliptra_drivers::CaliptraError::RUNTIME_PL1_USED_DPE_CONTEXT_THRESHOLD_REACHED,
                ),
            );
            assert!(resp.is_none());
            break;
        }

        let resp = execute_dpe_cmd(
            model,
            &mut Command::InitCtx(init_ctx_cmd),
            DpeResult::Success,
        );
        let Some(Response::InitCtx(_)) = resp else {
            panic!("Wrong response type!");
        };
    }
}

#[test]
fn test_populate_idev_cannot_be_called_from_pl1() {
    let mut image_opts = ImageOptions::default();
    image_opts.vendor_config.pl0_pauser = None;

    let mut image_opts = ImageOptions::default();
    image_opts.vendor_config.pl0_pauser = Some(0x1);


    let mut model = run_rt_test(None, Some(image_opts), None);

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let mut pop_idev_cmd = MailboxReq::PopulateIdevCert(PopulateIdevCertReq::default());
    pop_idev_cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(
            u32::from(CommandId::POPULATE_IDEV_CERT),
            pop_idev_cmd.as_bytes().unwrap(),
        )
        .unwrap_err();
    assert_error(
        &mut model,
        CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL,
        resp,
    );
}

#[test]
fn test_certify_key_x509_cannot_be_called_from_pl1() {
    let mut image_opts = ImageOptions::default();
    image_opts.vendor_config.pl0_pauser = None;

    let mut model = run_rt_test(None, Some(image_opts), None);

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let certify_key_cmd = CertifyKeyCmd {
        handle: ContextHandle::default(),
        label: TEST_LABEL,
        flags: CertifyKeyFlags::empty(),
        format: CertifyKeyCmd::FORMAT_X509,
    };
    let resp = execute_dpe_cmd(
        &mut model,
        &mut Command::CertifyKey(certify_key_cmd),
        DpeResult::MboxCmdFailure(CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL),
    );
    assert!(resp.is_none());
}

#[test]
fn test_certify_key_extended_cannot_be_called_from_pl1() {
    let mut image_opts = ImageOptions::default();
    image_opts.vendor_config.pl0_pauser = None;

    let mut model = run_rt_test(None, Some(image_opts), None);

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let mut certify_key_extended_cmd = MailboxReq::CertifyKeyExtended(CertifyKeyExtendedReq {
        hdr: MailboxReqHeader { chksum: 0 },
        certify_key_req: [0u8; CertifyKeyExtendedReq::CERTIFY_KEY_REQ_SIZE],
        flags: CertifyKeyExtendedFlags::empty(),
    });
    certify_key_extended_cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(
            u32::from(CommandId::CERTIFY_KEY_EXTENDED),
            certify_key_extended_cmd.as_bytes().unwrap(),
        )
        .unwrap_err();
    assert_error(
        &mut model,
        CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL,
        resp,
    );
}

#[test]
fn test_derive_context_cannot_be_called_from_pl1_if_changes_locality_to_pl0() {
    let mut image_opts = ImageOptions::default();
    image_opts.vendor_config.pl0_pauser = None;

    let mut model = run_rt_test(None, Some(image_opts), None);

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    // init ctx since we have currently have no parent handle for pl1
    let init_ctx_cmd = InitCtxCmd::new_simulation();
    let resp = execute_dpe_cmd(
        &mut model,
        &mut Command::InitCtx(init_ctx_cmd),
        DpeResult::Success,
    );
    let Some(Response::InitCtx(init_ctx_resp)) = resp else {
        panic!("Wrong response type!");
    };

    let derive_context_cmd = DeriveContextCmd {
        handle: init_ctx_resp.handle,
        data: DATA,
        flags: DeriveContextFlags::RETAIN_PARENT_CONTEXT | DeriveContextFlags::CHANGE_LOCALITY,
        tci_type: 0,
        target_locality: 0,
    };
    let resp = execute_dpe_cmd(
        &mut model,
        &mut Command::DeriveContext(derive_context_cmd),
        DpeResult::MboxCmdFailure(
            caliptra_drivers::CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL,
        ),
    );
    assert!(resp.is_none());
}

#[test]
fn test_stash_measurement_pl_context_thresholds() {
    let mut model = run_rt_test(None, None, None);

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let num_iterations = PL0_DPE_ACTIVE_CONTEXT_THRESHOLD;
    for i in 0..num_iterations {
        let mut cmd = MailboxReq::StashMeasurement(StashMeasurementReq {
            hdr: MailboxReqHeader { chksum: 0 },
            metadata: [0u8; 4],
            measurement: [0u8; 48],
            context: [0u8; 48],
            svn: 0,
        });
        cmd.populate_chksum().unwrap();

        if i == num_iterations - 1 {
            let resp = model
                .mailbox_execute(
                    u32::from(CommandId::STASH_MEASUREMENT),
                    cmd.as_bytes().unwrap(),
                )
                .unwrap_err();
            assert_error(
                &mut model,
                CaliptraError::RUNTIME_PL0_USED_DPE_CONTEXT_THRESHOLD_REACHED,
                resp,
            );

            break;
        }

        let _ = model
            .mailbox_execute(
                u32::from(CommandId::STASH_MEASUREMENT),
                cmd.as_bytes().unwrap(),
            )
            .unwrap()
            .expect("We should have received a response");
    }
}

#[test]
fn test_measurement_log_pl_context_threshold() {
    let mut model = run_rt_test(None, None, None);

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    // Upload PL0_DPE_ACTIVE_CONTEXT_THRESHOLD measurements to measurement log
    // Since there are some other measurements taken by Caliptra upon startup, this will cause
    // the PL0_DPE_ACTIVE_CONTEXT_THRESHOLD to be breached.
    for idx in 0..PL0_DPE_ACTIVE_CONTEXT_THRESHOLD as u8 {
        let mut measurement = StashMeasurementReq {
            measurement: [0xdeadbeef_u32; 12].as_bytes().try_into().unwrap(),
            hdr: MailboxReqHeader { chksum: 0 },
            metadata: [0u8; 4],
            context: [0u8; 48],
            svn: 0,
        };
        measurement.measurement[0] = idx;
        measurement.context[1] = idx;
        measurement.svn = idx as u32;
        let mut measurement_req = MailboxReq::StashMeasurement(measurement);
        measurement_req.populate_chksum().unwrap();

        if idx == PL0_DPE_ACTIVE_CONTEXT_THRESHOLD as u8 - 1 {
            model
                .upload_measurement(measurement_req.as_bytes().unwrap())
                .unwrap_err();

            break;
        }

        model
            .upload_measurement(measurement_req.as_bytes().unwrap())
            .unwrap();
    }

    model.step_until(|m| {
        m.soc_ifc().cptra_fw_error_non_fatal().read()
            == u32::from(CaliptraError::RUNTIME_PL0_USED_DPE_CONTEXT_THRESHOLD_REACHED)
    });
}

#[test]
fn test_pl0_unset_in_header() {
    let fuses = Fuses::default();
    let rom = caliptra_builder::rom_for_fw_integration_tests().unwrap();
    let mut model = caliptra_hw_model::new(
        InitParams {
            rom: &rom,
            security_state: SecurityState::from(fuses.life_cycle as u32),
            ..Default::default()
        },
        BootParams {
            fuses,
            ..Default::default()
        },
    )
    .unwrap();

    let mut opts = ImageOptions::default();
    opts.vendor_config.pl0_pauser = None;
    let mut image_bundle =
        caliptra_builder::build_and_sign_image(&FMC_WITH_UART, &APP_WITH_UART, opts).unwrap();

    // Change PL0 to 1 so that it matches the real PL0 PAUSER but don't set the
    // flag bit to make it valid. Also need to re-generate and re-sign the image.
    image_bundle.manifest.header.pl0_pauser = 1;

    let opts = ImageOptions::default();
    let ecc_index = opts.vendor_config.ecc_key_idx;
    let lms_index = opts.vendor_config.lms_key_idx;
    let gen = ImageGenerator::new(Crypto::default());
    let header_digest_vendor = gen
        .header_digest_vendor(&image_bundle.manifest.header)
        .unwrap();
    let header_digest_owner = gen
        .header_digest_owner(&image_bundle.manifest.header)
        .unwrap();
    let fmc_elf = build_firmware_elf(&FMC_WITH_UART).unwrap();
    let app_elf = build_firmware_elf(&APP_WITH_UART).unwrap();
    let preamble = gen
        .gen_preamble(
            &ImageGeneratorConfig {
                fmc: ElfExecutable::new(
                    &fmc_elf,
                    opts.fmc_version as u32,
                    opts.fmc_svn,
                    *b"~~~~~NO_GIT_REVISION",
                )
                .unwrap(),
                runtime: ElfExecutable::new(
                    &app_elf,
                    opts.app_version,
                    opts.app_svn,
                    *b"~~~~~NO_GIT_REVISION",
                )
                .unwrap(),
                vendor_config: opts.vendor_config,
                owner_config: opts.owner_config,
            },
            ecc_index,
            lms_index,
            &header_digest_vendor,
            &header_digest_owner,
        )
        .unwrap();
    image_bundle.manifest.preamble = preamble;

    model
        .upload_firmware(&image_bundle.to_bytes().unwrap())
        .unwrap();

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    // If PL0 PAUSER is unset, make sure PL0-only operation fails
    let certify_key_cmd = CertifyKeyCmd {
        handle: ContextHandle::default(),
        label: TEST_LABEL,
        flags: CertifyKeyFlags::empty(),
        format: CertifyKeyCmd::FORMAT_X509,
    };
    let resp = execute_dpe_cmd(
        &mut model,
        &mut Command::CertifyKey(certify_key_cmd),
        DpeResult::MboxCmdFailure(CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL),
    );
    assert!(resp.is_none());
}

#[test]
fn test_user_not_pl0() {
    let fuses = Fuses::default();
    let rom = caliptra_builder::rom_for_fw_integration_tests().unwrap();
    let mut model = caliptra_hw_model::new(
        InitParams {
            rom: &rom,
            security_state: SecurityState::from(fuses.life_cycle as u32),
            ..Default::default()
        },
        BootParams {
            fuses,
            ..Default::default()
        },
    )
    .unwrap();

    let mut opts = ImageOptions::default();
    opts.vendor_config.pl0_pauser = Some(0); // Caller PAUSER is always 1 for current models
    let image_bundle =
        caliptra_builder::build_and_sign_image(&FMC_WITH_UART, &APP_WITH_UART, opts).unwrap();

    model
        .upload_firmware(&image_bundle.to_bytes().unwrap())
        .unwrap();

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    // If PAUSER is not PL0, make sure PL0-only operation fails
    let certify_key_cmd = CertifyKeyCmd {
        handle: ContextHandle::default(),
        label: TEST_LABEL,
        flags: CertifyKeyFlags::empty(),
        format: CertifyKeyCmd::FORMAT_X509,
    };
    let resp = execute_dpe_cmd(
        &mut model,
        &mut Command::CertifyKey(certify_key_cmd),
        DpeResult::MboxCmdFailure(CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL),
    );
    assert!(resp.is_none());
}
