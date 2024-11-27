#![no_std]
#![no_main]

use defmt::info;
use embassy_executor::Spawner;
use embassy_nrf::gpio::{Level, Output, OutputDrive};
use embassy_nrf::radio::ble::Mode;
use embassy_nrf::radio::ble::Radio;
use embassy_nrf::radio::TxPower;
use embassy_nrf::{bind_interrupts, peripherals, radio};
use {defmt_rtt as _, panic_probe as _};
// use nrf52840_hal::pac;
// use nrf52840_hal::prelude::*;
// use embassy_time::{Duration, Timer};

use lakers::*;
use lakers_crypto_cryptocell310::edhoc_rs_crypto_init;

extern crate alloc;

use embedded_alloc::Heap;

use core::ffi::c_char;

#[global_allocator]
static HEAP: Heap = Heap::empty();

extern "C" {
    pub fn mbedtls_memory_buffer_alloc_init(buf: *mut c_char, len: usize);
}

mod common;

bind_interrupts!(struct Irqs {
    RADIO => radio::InterruptHandler<peripherals::RADIO>;
});

// ================================ paint the stack ===============================
const STACK_MAGIC_NUMBER: u32 = 0xDEADDEAD;
use core::arch::asm;
use core::ptr::addr_of;
use cortex_m::register::msp;

extern "C" {
    // marks the end of the stack, see .map file
    static mut __euninit: u8;
}

// using asm because if I use cortex_m::register::msp::read(), it sometimes crashes
fn get_stack_pointer() -> usize {
    let stack_pointer: *const u8;
    unsafe {
        asm!("mov {}, sp", out(reg) stack_pointer);
    }
    stack_pointer as usize
}

fn get_stack_end() -> usize {
    unsafe { addr_of!(__euninit) as *const u8 as usize }
}

fn paint_stack(pattern: u32) {
    let stack_end = get_stack_end();
    let stack_pointer = get_stack_pointer();
    info!("PAINT_STACK stack end: {:#X}", stack_end);
    info!("PAINT_STACK stack pointer is at: {:#X}", stack_pointer);
    let mut addr = stack_pointer;
    info!(
        "PAINT_STACK will paint a total of {} bytes, from {:#X} to {:#X}",
        (addr - stack_end),
        addr,
        stack_end
    );
    while addr > stack_end {
        unsafe {
            core::ptr::write_volatile(addr as *mut u32, pattern);
        }
        addr -= 4;
    }
    info!(
        // do not remove the ==, it is used in the script to parse the output
        "== PAINT_STACK painted a total of {} bytes, from {:#X} to {:#X} ==",
        (stack_pointer - addr),
        stack_pointer,
        addr
    );
}
// ================================================================================

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    paint_stack(STACK_MAGIC_NUMBER);

    let mut config = embassy_nrf::config::Config::default();
    config.hfclk_source = embassy_nrf::config::HfclkSource::ExternalXtal;
    let embassy_peripherals = embassy_nrf::init(config);

    info!("Starting BLE radio");
    let mut radio: Radio<'_, _> = Radio::new(embassy_peripherals.RADIO, Irqs).into();
    unsafe {
        edhoc_rs_crypto_init();
    }
    radio.set_mode(Mode::BLE_1MBIT);
    radio.set_tx_power(TxPower::_0D_BM);
    radio.set_frequency(common::FREQ);

    radio.set_access_address(common::ADV_ADDRESS);
    radio.set_header_expansion(false);
    radio.set_crc_init(common::ADV_CRC_INIT);
    radio.set_crc_poly(common::CRC_POLY);

    info!("init_handshake");

    let cred_i: Credential = Credential::parse_ccs_symmetric(common::CRED_PSK.try_into().unwrap()).unwrap();
    let cred_r: Credential = Credential::parse_ccs_symmetric(common::CRED_PSK.try_into().unwrap()).unwrap();
    
    let mut initiator = EdhocInitiator::new(
        lakers_crypto::default_crypto(),
        EDHOCMethod::PSK1,
        EDHOCSuite::CipherSuite2,
    );

    // Send Message 1 over raw BLE and convert the response to byte
    info!("Prepare message_1");
    let c_i = generate_connection_identifier_cbor(&mut lakers_crypto::default_crypto());
    initiator.set_identity(cred_i);

    let (initiator, message_1) = initiator.prepare_message_1(Some(c_i), &None).unwrap();

    let pckt_1 = common::Packet::new_from_slice(message_1.as_slice(), Some(0xf5))
        .expect("Buffer not long enough");
    info!("Send message_1 and wait message_2");
    let rcvd = common::transmit_and_wait_response(&mut radio, pckt_1, Some(0xf5)).await;


    match rcvd {
        Ok(pckt_2) => {
            info!("Received message_2");
            let message_2: EdhocMessageBuffer =
                pckt_2.pdu[1..pckt_2.len].try_into().expect("wrong length");

            let (initiator, c_r, id_cred_r, ead_2) = initiator.parse_message_2(&message_2).unwrap();

            let valid_cred_r = credential_check_or_fetch(Some(cred_r), id_cred_r.unwrap()).unwrap();

            let initiator = initiator
                .verify_message_2(valid_cred_r)
                .unwrap();

            info!("Prepare message_3");
            let (initiator, message_3, i_prk_out) = initiator
                .prepare_message_3(&None).unwrap();
            info!("Send message_3");
            common::transmit_without_response(
                &mut radio,
                common::Packet::new_from_slice(message_3.as_slice(), Some(c_r.as_slice()[0]))
                    .unwrap(),
            ).await;

            info!("Handshake completed. prk_out = {:X}", i_prk_out);
        }
        Err(_) => panic!("parsing error"),
    }
}
