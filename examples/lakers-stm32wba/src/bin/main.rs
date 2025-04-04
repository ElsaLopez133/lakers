#![no_std]
#![no_main]

// Reference Manual: file:///C:/Users/elopezpe/OneDrive/Documentos/PhD/micro/stm32eba55cg/rm0493-multiprotocol-wireless-bluetooth-low-energy-and-ieee802154-stm32wba5xxx-arm-based-32-bit-mcus-stmicroelectronics-en.pdf

use stm32wba::stm32wba55;
use {defmt_rtt as _, panic_probe as _};
use cortex_m_rt::entry;
use cortex_m::asm;
use lakers::*;
use lakers_shared::{Crypto as CryptoTrait, *};
use lakers_shared::{BASE_POINT_X, BASE_POINT_Y, SCALAR};
use lakers_crypto_rustcrypto_stm::Crypto;
use lakers_crypto_rustcrypto_stm::{u32_to_u8, u8_to_u32};
use defmt::info;

const X_COORDINATE_BYTES: [u8; 32] = [
    0xCB, 0xC9, 0x22, 0x02, 0xD0, 0xF0, 0x99, 0xD7, 
    0xE3, 0x97, 0x30, 0x15, 0xDC, 0xAF, 0xFA, 0x05, 
    0xBA, 0xCF, 0x2A, 0xA9, 0x07, 0x41, 0x52, 0x9A, 
    0x3F, 0xD5, 0x9D, 0xB6, 0xBD, 0x29, 0xB2, 0x4A
];

#[entry]
unsafe fn main() -> ! {
    // Access peripherals via PAC
    let p = &stm32wba55::Peripherals::take().unwrap();
    let hash = &p.HASH;
    let pka = &p.PKA;
    let rng = &p.RNG;
    
    // call lakers-crypto-rustcrypto-stm private init function

    let mut crypto = Crypto::new(&p, hash, pka, rng);

    crypto.lakers_crypto_rustcrypto_stm_init();

    // let (x , y) = crypto.pka_ecc_mult_scalar(u32_to_u8(&BASE_POINT_X), u32_to_u8(&BASE_POINT_Y), &u32_to_u8(&SCALAR) );
    // info!("x: {:#X}, y:{:#X}", u8_to_u32(&x), u8_to_u32(&y));
    
    let (g_x_x, g_x_y) = crypto.bytes_to_point(&X_COORDINATE_BYTES);
    info!("g_x: {:#X}  g_y: {:#X}", g_x_x, g_x_y);

    let (x,y) = crypto.pka_ecc_point_add(u32_to_u8(&BASE_POINT_X), u32_to_u8(&BASE_POINT_Y), u32_to_u8(&BASE_POINT_X), u32_to_u8(&BASE_POINT_Y));
    info!("x: {:#X}   y:{:#X} ", x, y);

    let (x,y) = crypto.pka_ecc_point_add(u32_to_u8(&BASE_POINT_X), u32_to_u8(&BASE_POINT_Y), x, y);
    info!("x: {:#X}   y:{:#X} ", x, y);

    // let proof = crypto.sok_log_eq()

    // call lakers prepare_ead_1


    // call lakers prepare_message_1

    loop {}
}