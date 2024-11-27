#![no_std]
#![no_main]

use common::{Packet, PacketError, ADV_ADDRESS, ADV_CRC_INIT, CRC_POLY, FREQ, MAX_PDU};
use defmt::info;
use defmt::unwrap;
use embassy_executor::Spawner;
use embassy_nrf::radio::ble::Mode;
use embassy_nrf::radio::ble::Radio;
use embassy_nrf::radio::TxPower;
use embassy_nrf::{bind_interrupts, peripherals, radio};
use {defmt_rtt as _, panic_probe as _};
use nrf52840_hal::pac;
use nrf52840_hal::prelude::*;
//use nrf52840_hal::gpio::{Level, Output, OutputDrive, Pin};
use embassy_time::{Duration, Timer};

use lakers::*;
use lakers_crypto_cryptocell310::edhoc_rs_crypto_init;

use core::ffi::c_char;

extern crate alloc;

use embedded_alloc::Heap;

#[global_allocator]
static HEAP: Heap = Heap::empty();

extern "C" {
    pub fn mbedtls_memory_buffer_alloc_init(buf: *mut c_char, len: usize);
}

mod common;

bind_interrupts!(struct Irqs {
    RADIO => radio::InterruptHandler<peripherals::RADIO>;
});

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let peripherals = pac::Peripherals::take().unwrap();
    let p0 = nrf52840_hal::gpio::p0::Parts::new(peripherals.P0);
    let p1 = nrf52840_hal::gpio::p1::Parts::new(peripherals.P1);

    let mut led_pin_p0_26 = p0.p0_26.into_push_pull_output(nrf52840_hal::gpio::Level::Low);
    // let mut led_pin_p0_8 = p0.p0_08.into_push_pull_output(nrf52840_hal::gpio::Level::Low);
    // let mut led_pin_p0_7 = p0.p0_07.into_push_pull_output(nrf52840_hal::gpio::Level::Low);
    // let mut led_pin_p0_6 = p0.p0_06.into_push_pull_output(nrf52840_hal::gpio::Level::Low);
    // let mut led_pin_p0_5 = p0.p0_05.into_push_pull_output(nrf52840_hal::gpio::Level::Low);

    let mut led_pin_p1_07 = p1.p1_07.into_push_pull_output(nrf52840_hal::gpio::Level::Low);
    let mut led_pin_p1_08 = p1.p1_08.into_push_pull_output(nrf52840_hal::gpio::Level::Low);
    let mut led_pin_p1_06 = p1.p1_06.into_push_pull_output(nrf52840_hal::gpio::Level::Low);
    let mut led_pin_p1_05 = p1.p1_05.into_push_pull_output(nrf52840_hal::gpio::Level::Low);
    let mut led_pin_p1_04 = p1.p1_04.into_push_pull_output(nrf52840_hal::gpio::Level::Low); // used for the whole message
    let mut led_pin_p1_10 = p1.p1_10.into_push_pull_output(nrf52840_hal::gpio::Level::Low);
    let mut led_pin_p1_14 = p1.p1_14.into_push_pull_output(nrf52840_hal::gpio::Level::Low);

    let mut config = embassy_nrf::config::Config::default();
    config.hfclk_source = embassy_nrf::config::HfclkSource::ExternalXtal;
    let peripherals: embassy_nrf::Peripherals = embassy_nrf::init(config);

    info!("Starting BLE radio");
    let mut radio = Radio::new(peripherals.RADIO, Irqs);
    unsafe {
        edhoc_rs_crypto_init();
    }

    // radio.set_mode(Mode::BLE_1MBIT);
    // radio.set_tx_power(TxPower::_0D_BM);
    // radio.set_frequency(FREQ);

    // radio.set_access_address(ADV_ADDRESS);
    // radio.set_header_expansion(false);
    // radio.set_crc_init(ADV_CRC_INIT);
    // radio.set_crc_poly(CRC_POLY);

    // // Memory buffer for mbedtls
    // #[cfg(feature = "crypto-psa")]
    // let mut buffer: [c_char; 4096 * 2] = [0; 4096 * 2];
    // #[cfg(feature = "crypto-psa")]
    // unsafe {
    //     mbedtls_memory_buffer_alloc_init(buffer.as_mut_ptr(), buffer.len());
    // }

    loop {    
        radio.set_mode(Mode::BLE_1MBIT);
        radio.set_tx_power(TxPower::_0D_BM);
        radio.set_frequency(FREQ);
    
        radio.set_access_address(ADV_ADDRESS);
        radio.set_header_expansion(false);
        radio.set_crc_init(ADV_CRC_INIT);
        radio.set_crc_poly(CRC_POLY);

        let buffer: [u8; MAX_PDU] = [0x00u8; MAX_PDU];
        let mut c_r: Option<ConnId> = None;

        info!("Receiving...");
        let pckt = common::receive_and_filter(&mut radio, Some(0xf5), Some(&mut led_pin_p1_10)) // filter all incoming packets waiting for CBOR TRUE (0xf5)
            .await
            .unwrap();
        info!("Received message_1");
        led_pin_p0_26.set_high();

        led_pin_p1_07.set_high();
        let cred_r: Credential = Credential::parse_ccs_symmetric(common::CRED_PSK.try_into().unwrap()).unwrap();
        led_pin_p1_07.set_low();

        led_pin_p1_07.set_high();
        let responder = EdhocResponder::new(lakers_crypto::default_crypto(), EDHOCMethod::PSK2, None, cred_r);
        led_pin_p1_07.set_low();

        // let message_1: EdhocMessageBuffer = pckt.pdu[1..pckt.len].try_into().expect("wrong length"); // get rid of the TRUE byte
        let Ok(message_1) = 
            pckt.pdu[1..pckt.len].try_into() 
        else {
            info!("Wrong length for EDHOC message_1");
            radio.disable();
            continue;
        };

        led_pin_p1_07.set_high();
        let result = responder.process_message_1(&message_1);
        led_pin_p1_07.set_low();
        led_pin_p0_26.set_low();
        
        if let Ok((responder, _c_i, ead_1)) = result {
            // c_r = Some(generate_connection_identifier_cbor(
            //     &mut lakers_crypto::default_crypto(),
            // ));
            let c_r = Some(ConnId::from_int_raw(5));
            info!("Prepare message_2");
            led_pin_p0_26.set_high();
            led_pin_p1_06.set_high();
            let (responder, message_2) = responder
                .prepare_message_2(CredentialTransfer::ByReference, c_r, &None)
                .unwrap();
            led_pin_p1_06.set_low();
            led_pin_p0_26.set_low();

            // prepend 0xf5 also to message_2 in order to allow the Initiator filter out from other BLE packets
            
            info!("Send message_2 and wait message_3");
            let message_3 = common::transmit_and_wait_response(
                &mut radio,
                Packet::new_from_slice(message_2.as_slice(), Some(0xf5)).expect("wrong length"),
                Some(c_r.unwrap().as_slice()[0]),
                &mut led_pin_p1_14,
            )
            .await;

            match message_3 {
                Ok(message_3) => {
                    info!("Received message_3");
                    led_pin_p0_26.set_high();

                    let rcvd_c_r: ConnId = ConnId::from_int_raw(message_3.pdu[0] as u8);

                    if rcvd_c_r == c_r.unwrap() {
                        led_pin_p1_08.set_high();
                        let message_3: EdhocMessageBuffer = message_3.pdu[1..message_3.len]
                            .try_into()
                            .expect("wrong length");
                        let Ok((responder, id_cred_i, _ead_3)) =
                            responder.parse_message_3(&message_3)
                        else {
                            info!("EDHOC error at parse_message_3");
                            // We don't get another chance, it's popped and can't be used any further
                            // anyway legally
                            radio.disable();
                            continue;
                        };
                        led_pin_p1_08.set_low();
                        
                        led_pin_p1_08.set_high();
                        let cred_i: Credential = 
                            Credential::parse_ccs_symmetric(common::CRED_PSK.try_into().unwrap()).unwrap();
                        led_pin_p1_08.set_low();

                        led_pin_p1_08.set_high();
                        let valid_cred_i =
                            credential_check_or_fetch(Some(cred_i), id_cred_i.unwrap()).unwrap();
                        led_pin_p1_08.set_low();
                        
                        led_pin_p1_08.set_high();
                        let Ok((responder, prk_out)) = responder.verify_message_3(valid_cred_i)
                        else {
                            info!("EDHOC error at verify_message_3");
                            radio.disable();
                            continue;
                        };
                        led_pin_p1_08.set_low();
                        led_pin_p0_26.set_low();
                        info!("Handshake completed. prk_out: {:X}", prk_out);
                        //  change the state of the pin
                        // led_pin_p1_04.toggle();
                         // Manually toggle the LED state (switch between high and low)
                        if led_pin_p1_04.is_set_high().unwrap() {
                            led_pin_p1_04.set_low().unwrap();  // Turn the LED off
                        } else {
                            led_pin_p1_04.set_high().unwrap();  // Turn the LED on
                        }
                        unwrap!(spawner.spawn(example_application_task(prk_out)));
                    } else {
                        info!("Another packet interrupted the handshake.");
                        radio.disable();
                        continue;
                    }
                }
                Err(PacketError::TimeoutError) => {
                    info!("Timeout while waiting for message_3!");
                    radio.disable();
                    continue;
                }
                Err(_) => panic!("Unexpected error"),
            }
        }
    }
}

#[embassy_executor::task]
async fn example_application_task(secret: BytesHashLen) {
    info!(
        "Successfully spawned an application task. EDHOC prk_out: {:X}",
        secret
    );
}
