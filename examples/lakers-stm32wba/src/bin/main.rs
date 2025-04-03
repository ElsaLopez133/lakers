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
use defmt::info;

#[entry]
unsafe fn main() -> ! {
    // Access peripherals via PAC
    let p = &stm32wba55::Peripherals::take().unwrap();
    let hash = &p.HASH;
    let pka = &p.PKA;
    
    // call lakers-crypto-rustcrypto-stm private init function

    let mut crypto = Crypto::new(&p, hash, pka);

    crypto.lakers_crypto_rustcrypto_stm_init();

    // Define a test message
    let test_message = b"Hello, Lakers!";  // Example test data
    let message_len = test_message.len();  

    // Convert message to `BytesMaxBuffer`
    let mut message_buffer = [0u8; MAX_BUFFER_LEN];
    message_buffer[..message_len].copy_from_slice(test_message);

    // Call `sha256_digest()`
    let hash_output = crypto.sha256_digest(&message_buffer, message_len);

    // Print the hash (using defmt)
    info!("SHA-256 Digest: {:x}", hash_output);

    // Define a test message
    let test_message = b"abc!";  // Example test data
    let message_len = test_message.len();  

    // Convert message to `BytesMaxBuffer`
    let mut message_buffer = [0u8; MAX_BUFFER_LEN];
    message_buffer[..message_len].copy_from_slice(test_message);

    // Call `sha256_digest()`
    let hash_output = crypto.sha256_digest(&message_buffer, message_len);

    // Print the hash (using defmt)
    info!("SHA-256 Digest: {:x}", hash_output);

    // call lakers prepare_ead_1


    // call lakers prepare_message_1

    loop {}
}