// Licensed under the Apache-2.0 license

use bit_vec::BitVec;
use caliptra_builder::build_firmware_elf;
use caliptra_coverage::calculator;
use caliptra_coverage::collect_instr_pcs;
use caliptra_coverage::get_bitvec_paths;
use caliptra_coverage::CoverageMap;
use caliptra_coverage::CPTRA_COVERAGE_PATH;

use caliptra_builder::firmware::{APP_WITH_UART, FMC_WITH_UART, ROM_WITH_UART};
use caliptra_coverage::get_rom_tag_from_fw_id;
use caliptra_coverage::invoke_objdump;
use caliptra_coverage::uncovered_functions;
use caliptra_image_types::IMAGE_MANIFEST_BYTE_SIZE;

pub fn highlight_covered_instructions_in_objdump_output(
    base_addr: usize,
    bitmap: &BitVec,
    output: String,
) {
    let mut is_disassembly = false;
    let re = regex::Regex::new(r"^\s*(?P<address>[0-9a-f]+):\s*(?P<instruction>[0-9a-f]+\s+.+)")
        .unwrap();

    for line in output.lines() {
        if line.contains("Disassembly of section") {
            is_disassembly = true;
            continue;
        }

        if is_disassembly && re.is_match(line) {
            if let Some(captures) = re.captures(line) {
                let pc = usize::from_str_radix(&captures["address"], 16).unwrap();
                if bitmap.get(pc.wrapping_sub(base_addr)).unwrap_or(false) {
                    let s = format!("[*]{}", line);
                    println!("{s}");
                } else {
                    println!("   {}", line);
                }
            }
        } else {
            println!("   {}", line);
        }
    }
}

fn main() -> std::io::Result<()> {
    println!("Extracting coverage reports now...");
    let cov_path = std::env::var(CPTRA_COVERAGE_PATH).unwrap_or_else(|_| "".into());
    if cov_path.is_empty() {
        println!("Coverage not requested...exiting.");
        return Ok(());
    }

    let paths = get_bitvec_paths(cov_path.as_str()).unwrap();
    if paths.is_empty() {
        println!("{} coverage files found", paths.len());
        return Ok(());
    }

    let tag = get_rom_tag_from_fw_id(&ROM_WITH_UART).unwrap();

    println!("{} coverage files found", paths.len());
    let instr_pcs = collect_instr_pcs(&ROM_WITH_UART).unwrap();
    println!("ROM instruction count = {}", instr_pcs.len());

    let cv = CoverageMap::new(paths);
    let bv = cv
        .map
        .get(&tag)
        .expect("Coverage data  not found for ROM image");

    let elf_bytes = build_firmware_elf(&ROM_WITH_UART)?;

    if let Some(rom_base_addr) = instr_pcs.iter().min() {
        uncovered_functions(*rom_base_addr as u64, &elf_bytes, bv)?;
        println!(
            "Coverage for ROM_WITH_UART is {}%",
            (100 * calculator::coverage_from_bitmap(bv, &instr_pcs)) as f32
                / instr_pcs.len() as f32
        );

        if let Some(fw_dir) = std::env::var_os("CALIPTRA_PREBUILT_FW_DIR") {
            let path = std::path::PathBuf::from(fw_dir).join(ROM_WITH_UART.elf_filename());

            let objdump_output = invoke_objdump(&path.to_string_lossy());
            highlight_covered_instructions_in_objdump_output(
                *rom_base_addr as usize,
                bv,
                objdump_output.unwrap(),
            );
        } else {
            println!("Prebuilt firmware not found");
        }
    }

    let iccm_image_tag = {
        let image = caliptra_builder::build_and_sign_image(
            &FMC_WITH_UART,
            &APP_WITH_UART,
            caliptra_builder::ImageOptions::default(),
        )
        .unwrap();

        let image = image.to_bytes().unwrap();
        let iccm_image = &image.as_slice()[IMAGE_MANIFEST_BYTE_SIZE..];

        caliptra_coverage::get_tag_from_image(iccm_image)
    };

    let iccm_bitmap = cv
        .map
        .get(&iccm_image_tag)
        .expect("Coverage data  not found for Bundle image");

    let executables = vec![&FMC_WITH_UART, &APP_WITH_UART];

    for e in executables {
        println!("////////////////////////////////////");
        println!("Coverage report for {}", e.bin_name);
        println!("////////////////////////////////////");
        let elf_bytes = build_firmware_elf(e)?;
        let instr_pcs = collect_instr_pcs(e).unwrap();
        if let Some(iccm_base_addr) = instr_pcs.iter().min() {
            uncovered_functions(*iccm_base_addr as u64, &elf_bytes, iccm_bitmap)?;

            if let Some(fw_dir) = std::env::var_os("CALIPTRA_PREBUILT_FW_DIR") {
                let path = std::path::PathBuf::from(fw_dir).join(e.elf_filename());

                let objdump_output = invoke_objdump(&path.to_string_lossy());
                highlight_covered_instructions_in_objdump_output(
                    *iccm_base_addr as usize,
                    iccm_bitmap,
                    objdump_output.unwrap(),
                );
            } else {
                println!("Prebuilt firmware not found");
            }
        }
    }

    Ok(())
}
