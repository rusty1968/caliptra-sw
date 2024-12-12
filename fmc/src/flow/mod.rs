/*++

Licensed under the Apache-2.0 license.

File Name:

    mod.rs

Abstract:

    File contains the top level dispatch of various RT Flows.

--*/

mod crypto;
pub mod dice;
mod fmc_alias_csr;
mod pcr;
mod rt_alias;
mod tci;
mod x509;

use crate::flow::rt_alias::RtAliasLayer;

use crate::fmc_env::FmcEnv;
use caliptra_drivers::CaliptraResult;

/// Execute FMC Flows based on reset resason
///
/// # Arguments
///
/// * `env` - FMC Environment
pub fn run(env: &mut FmcEnv) -> CaliptraResult<()> {
    // Generate the Initial DevID Certificate Signing Request (CSR)
    fmc_alias_csr::generate_csr(env)?;

    RtAliasLayer::run(env)
}
