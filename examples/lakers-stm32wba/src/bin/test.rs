#![no_std]
#![no_main]

// Reference Manual: file:///C:/Users/elopezpe/OneDrive/Documentos/PhD/micro/stm32eba55cg/rm0493-multiprotocol-wireless-bluetooth-low-energy-and-ieee802154-stm32wba5xxx-arm-based-32-bit-mcus-stmicroelectronics-en.pdf

use stm32wba::stm32wba55::{self, GPIOA};
use {defmt_rtt as _, panic_probe as _};
use cortex_m_rt::entry;
use cortex_m::asm;
use lakers::*;
use lakers_shared::{Crypto as CryptoTrait, *};
// use lakers_shared::{GpioPin, SCALAR, BASE_POINT_X, BASE_POINT_Y};
use lakers_crypto_rustcrypto_stm::Crypto;
use lakers_crypto_rustcrypto_stm::{u32_to_u8, u8_to_u32};
use defmt::info;
// use defmt::trace;
use defmt_or_log::trace;
use hexlit::hex;
use stm32_metapac::usart::Usart;
use lakers_stm32wba_like::*; 

pub const X: [u8; 32] = hex!("368ec1f69aeb659ba37d5a8d45b21bdc0299dceaa8ef235f3ca42ce3530f9525");
pub const G_X_X_COORD: [u8; 32] = hex!("8af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b6");
pub const G_X_Y_COORD: [u8; 32] = hex!("51e8af6c6edb781601ad1d9c5fa8bf7aa15716c7c06a5d038503c614ff80c9b3");
pub const CRED_I: &[u8] = &hex!("A2027734322D35302D33312D46462D45462D33372D33322D333908A101A5010202412B2001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8");
pub const I: &[u8] = &hex!("fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b");

pub const SK: [u8; 32] = hex!("5c4172aca8b82b5a62e66f722216f5a10f72aa69f42c1d1cd3ccd7bfd29ca4e9");
pub const MESSAGE_2: [u8; 45] = hex!("582b419701d7f00a26c2dc587a36dd752549f33763c893422c8ea0f955a13a4ff5d59862a1eef9e0e7e1886fcd");
pub const CRED_R: &[u8] = &hex!("A2026008A101A5010202410A2001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072");
pub const R: &[u8] = &hex!("72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac");
pub const G_R_X_COORD: [u8; 32] = hex!("bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f0");
pub const G_R_Y_COORD: [u8; 32] = hex!("4519e257236b2a0ce2023f0931f1f386ca7afda64fcde0108c224c51eabf6072");

pub const BASE_POINT_X: [u8; 32] = hex!("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
pub const BASE_POINT_Y: [u8; 32] = hex!("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");


#[entry]
unsafe fn main() -> ! {

    // Access peripherals via PAC
    let p = &stm32wba55::Peripherals::take().unwrap();
    let hash = &p.HASH;
    let pka = &p.PKA;
    let rng = &p.RNG;
    let rcc = &p.RCC;
    
    // call lakers-crypto-rustcrypto-stm private init function
    let mut crypto = Crypto::new(&p, hash, pka, rng);
    crypto.lakers_crypto_rustcrypto_stm_init();

    let mult = crypto.pka_ecc_point_add(BASE_POINT_X, BASE_POINT_Y, BASE_POINT_X, BASE_POINT_Y);

    loop {}
}