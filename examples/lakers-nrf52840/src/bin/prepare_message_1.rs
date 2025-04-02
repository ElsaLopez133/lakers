#![no_std]
#![no_main]

use defmt::info;
use embassy_executor::Spawner;
use embassy_nrf::pac::ficr::info;
// use embassy_nrf::radio::ble::Mode;
// use embassy_nrf::radio::ble::Radio;
// use embassy_nrf::radio::TxPower;
use embassy_nrf::{bind_interrupts, peripherals};
use {defmt_rtt as _, panic_probe as _};
use nrf52840_hal::pac;
use nrf52840_hal::prelude::*;
use nrf52840_hal::gpio::{Level, Output, Pin};
use embassy_time::{Duration, Timer};

use lakers::*;

extern crate alloc;

use embedded_alloc::Heap;

use core::ffi::c_char;

use hexlit::hex;

#[global_allocator]
static HEAP: Heap = Heap::empty();

extern "C" {
    pub fn mbedtls_memory_buffer_alloc_init(buf: *mut c_char, len: usize);
}

// mod common;
pub const CRED_PSK: &[u8] =
    &hex!("A202686D79646F74626F7408A101A30104024110205050930FF462A77A3540CF546325DEA214");

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    // let peripherals = pac::Peripherals::take().unwrap();
    // let p0 = nrf52840_hal::gpio::p0::Parts::new(peripherals.P0);
    // let p1 = nrf52840_hal::gpio::p1::Parts::new(peripherals.P1);

    // let mut led_pin_p0_26 = p0.p0_26.into_push_pull_output(nrf52840_hal::gpio::Level::Low);
    // let mut led_pin_p0_8 = p0.p0_08.into_push_pull_output(nrf52840_hal::gpio::Level::Low);
    // let mut led_pin_p0_7 = p0.p0_07.into_push_pull_output(nrf52840_hal::gpio::Level::Low);
    // let mut led_pin_p0_6 = p0.p0_06.into_push_pull_output(nrf52840_hal::gpio::Level::Low);
    // let mut led_pin_p0_5 = p0.p0_05.into_push_pull_output(nrf52840_hal::gpio::Level::Low);

    // let mut led_pin_p1_07 = p1.p1_07.into_push_pull_output(nrf52840_hal::gpio::Level::Low);
    // let mut led_pin_p1_08 = p1.p1_08.into_push_pull_output(nrf52840_hal::gpio::Level::Low);
    // let mut led_pin_p1_06 = p1.p1_06.into_push_pull_output(nrf52840_hal::gpio::Level::Low);

    // let mut config = embassy_nrf::config::Config::default();
    // config.hfclk_source = embassy_nrf::config::HfclkSource::ExternalXtal;
    // let embassy_peripherals = embassy_nrf::init(config);

    info!("Prepare message_1");
    // led_pin_p0_7.set_high();
    let cred_i: Credential = Credential::parse_ccs_symmetric(CRED_PSK.try_into().unwrap()).unwrap();
    let cred_r: Credential = Credential::parse_ccs_symmetric(CRED_PSK.try_into().unwrap()).unwrap();
    // led_pin_p0_7.set_low();
    // info!("cred_r:{:?}", cred_r.bytes.content);
    
    let mut initiator = EdhocInitiator::new(
        lakers_crypto::default_crypto(),
        EDHOCMethod::PSK2,
        EDHOCSuite::CipherSuite2,
    );

    let c_i = generate_connection_identifier_cbor(&mut lakers_crypto::default_crypto());
    initiator.set_identity(cred_i);

    // led_pin_p0_6.set_high();
    let (initiator, message_1) = initiator.prepare_message_1(Some(c_i), &None).unwrap();
    // led_pin_p0_6.set_low();

    info!("Send message_1 and wait message_2");
    // led_pin_p0_26.set_low();

}
