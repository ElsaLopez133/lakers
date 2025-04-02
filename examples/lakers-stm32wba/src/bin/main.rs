#![no_std]
#![no_main]

// Reference Manual: file:///C:/Users/elopezpe/OneDrive/Documentos/PhD/micro/stm32eba55cg/rm0493-multiprotocol-wireless-bluetooth-low-energy-and-ieee802154-stm32wba5xxx-arm-based-32-bit-mcus-stmicroelectronics-en.pdf

use cortex_m::asm;
use cortex_m_rt::entry;
use stm32wba::stm32wba55;
use {defmt_rtt as _, panic_probe as _};
// use defmt::info;

#[entry]
unsafe fn main() -> ! {
    // Access peripherals via PAC
    let p = stm32wba55::Peripherals::take().unwrap();

    // call lakers-crypto-rustcrypto-stm private init function

    lakers_crypto_rustcrypto_stm_init(p);

    // call lakers prepare_ead_1
    // call lakers prepare_message_1

    loop {}
}
