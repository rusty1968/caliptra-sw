// Licensed under the Apache-2.0 license

use std::{fs, io::Write};

use caliptra_builder::firmware;
use caliptra_hw_model::{BootParams, HwModel, InitParams};
use caliptra_hw_model_types::SecurityState;
use caliptra_image_types::ImageManifest;
use zerocopy::{FromBytes, AsBytes};

fn read_file_vec(filepath: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let data = fs::read(filepath)?;
    Ok(data)
}


#[test]
fn release_sanity_test() {
    let security_state = *SecurityState::default().set_debug_locked(true);

    let rom = caliptra_builder::build_firmware_rom(firmware::rom_from_env()).unwrap();

    let image_bytes = include_bytes!("kds_test_data/image-bundle.bin");

    let image = image_bytes.to_vec();

    let manifest = ImageManifest::read_from_prefix(image.as_bytes()).unwrap();
    println!("manifest from release {:?} !", manifest.preamble.vendor_ecc_pub_key_idx);

    let mut hw = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            security_state,
            ..Default::default()
        },
        fw_image: Some(&image),
        ..Default::default()
    })
    .unwrap();

    let mut output = vec![];

    hw.step_until_output_contains("Caliptra RT listening for mailbox commands...\n")
        .unwrap();
    output
        .write_all(hw.output().take(usize::MAX).as_bytes())
        .unwrap();

}


#[test]
fn kds_sanity_test() {
    let security_state = *SecurityState::default().set_debug_locked(true);

    let rom = caliptra_builder::build_firmware_rom(firmware::rom_from_env()).unwrap();

    let image = read_file_vec("image.sbin").expect("Could not read image");

    let manifest = ImageManifest::read_from_prefix(image.as_bytes()).unwrap();
    println!("manifest from KDS {:?} !", manifest.preamble.vendor_ecc_pub_key_idx);

    //let manifest = LayoutVerified::<_, ImageManifest>::new_from_prefix(image.as_slice()).unwrap();
    //println!("KDS signed manifest {:?} will print!", manifest.preamble);

    let mut hw = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            security_state,
            ..Default::default()
        },
        fw_image: Some(&image),
        ..Default::default()
    })
    .unwrap();

    let mut output = vec![];

    hw.step_until_output_contains("Caliptra RT listening for mailbox commands...\n")
        .unwrap();
    output
        .write_all(hw.output().take(usize::MAX).as_bytes())
        .unwrap();
}
