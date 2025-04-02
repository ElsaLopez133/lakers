#![no_std]
#![no_main]

// Reference Manual: file:///C:/Users/elopezpe/OneDrive/Documentos/PhD/micro/stm32eba55cg/rm0493-multiprotocol-wireless-bluetooth-low-energy-and-ieee802154-stm32wba5xxx-arm-based-32-bit-mcus-stmicroelectronics-en.pdf

use stm32wba::stm32wba55;
use {defmt_rtt as _, panic_probe as _};
use cortex_m_rt::entry;
use cortex_m::asm;
use lakers::*;
use lakers_shared::{Crypto as CryptoTrait, *};
use lakers_crypto_rustcrypto_stm::Crypto;
// use defmt::info;

#[entry]
unsafe fn main() -> ! {
    // Access peripherals via PAC
    let p = stm32wba55::Peripherals::take().unwrap();
    let hash = p.HASH;
    
    // call lakers-crypto-rustcrypto-stm private init function

    let crypto = Crypto::new(p, hash);

    crypto.lakers_crypto_rustcrypto_stm_init();

    // call lakers prepare_ead_1
    // call lakers prepare_message_1

    loop {}
}