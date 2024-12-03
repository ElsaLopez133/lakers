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
use nrf52840_hal::pac;
use nrf52840_hal::prelude::*;
//use nrf52840_hal::gpio::{Level, Output, OutputDrive, Pin};
use embassy_time::{Duration, Timer};
use embassy_time::Instant;

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
    let embassy_peripherals = embassy_nrf::init(config);

    info!("Starting BLE radio");
    let mut radio: Radio<'_, _> = Radio::new(embassy_peripherals.RADIO, Irqs).into();
    unsafe {
        edhoc_rs_crypto_init();
    }
    //let mut led = Output::new(embassy_peripherals.P0_13, Level::Low, OutputDrive::Standard);
    //led.set_high();

    // radio.set_mode(Mode::BLE_1MBIT);
    // radio.set_tx_power(TxPower::_0D_BM);
    // radio.set_frequency(common::FREQ);

    // radio.set_access_address(common::ADV_ADDRESS);
    // radio.set_header_expansion(false);
    // radio.set_crc_init(common::ADV_CRC_INIT);
    // radio.set_crc_poly(common::CRC_POLY);

    info!("init_handshake");

    // // Memory buffer for mbedtls
    // #[cfg(feature = "crypto-psa")]
    // let mut buffer: [c_char; 4096 * 2] = [0; 4096 * 2];
    // #[cfg(feature = "crypto-psa")]
    // unsafe {
    //     mbedtls_memory_buffer_alloc_init(buffer.as_mut_ptr(), buffer.len());
    // }
    // let start = Instant::now();
    for iteration in 0..1 {
        info!("iteration {}", iteration);

        radio.set_mode(Mode::BLE_1MBIT);
        radio.set_tx_power(TxPower::_0D_BM);
        radio.set_frequency(common::FREQ);
    
        radio.set_access_address(common::ADV_ADDRESS);
        radio.set_header_expansion(false);
        radio.set_crc_init(common::ADV_CRC_INIT);
        radio.set_crc_poly(common::CRC_POLY);

        info!("Prepare message_1");
        led_pin_p0_26.set_high();
        led_pin_p1_04.set_high();
        led_pin_p1_07.set_high();
        let cred_i: Credential = Credential::parse_ccs_symmetric(common::CRED_PSK.try_into().unwrap()).unwrap();
        let cred_r: Credential = Credential::parse_ccs_symmetric(common::CRED_PSK.try_into().unwrap()).unwrap();
        led_pin_p1_07.set_low();
        //info!("cred_r:{:?}", cred_r.bytes.content);
        
        led_pin_p1_07.set_high();
        let mut initiator = EdhocInitiator::new(
            lakers_crypto::default_crypto(),
            EDHOCMethod::PSK2,
            EDHOCSuite::CipherSuite2,
        );
        led_pin_p1_07.set_low();

        // Send Message 1 over raw BLE and convert the response to byte
        led_pin_p1_07.set_high();
        // let c_i = generate_connection_identifier_cbor(&mut lakers_crypto::default_crypto());
        let c_i = ConnId::from_int_raw(10);
        led_pin_p1_07.set_low();

        led_pin_p1_07.set_high();
        initiator.set_identity(None, cred_i);
        led_pin_p1_07.set_low();

        led_pin_p1_07.set_high();
        let (initiator, message_1) = initiator.prepare_message_1(Some(c_i), &None).unwrap();
        led_pin_p1_07.set_low();

        let pckt_1 = common::Packet::new_from_slice(message_1.as_slice(), Some(0xf5))
            .expect("Buffer not long enough");
        info!("Send message_1 and wait message_2");
        led_pin_p0_26.set_low();
        let rcvd = common::transmit_and_wait_response(&mut radio, pckt_1, Some(0xf5), &mut led_pin_p1_10).await;

        match rcvd {
            Ok(pckt_2) => {
                info!("Received message_2");
                led_pin_p0_26.set_high();
                // let message_2: EdhocMessageBuffer =
                //     pckt_2.pdu[1..pckt_2.len].try_into().expect("wrong length");
                let Ok(message_2) = 
                    pckt_2.pdu[1..pckt_2.len].try_into() 
                else {
                    info!("Wrong length for EDHOC message_2");
                    radio.disable();
                    continue;
                };

                led_pin_p1_06.set_high();
                let Ok((initiator, c_r, id_cred_r, ead_2)) = 
                    initiator.parse_message_2(&message_2)
                else {
                    info!("EDHOC error at parse_message_2");
                    radio.disable();
                    continue;
                };
                // let (initiator, c_r, id_cred_r, ead_2) = initiator.parse_message_2(&message_2).unwrap();
                led_pin_p1_06.set_low();
                
                led_pin_p1_06.set_high();
                let valid_cred_r = credential_check_or_fetch(Some(cred_r), id_cred_r.unwrap()).unwrap();
                led_pin_p1_06.set_low();

                // compute SoK. We need to store g^r. this is in cred_r
                ephemeral_public_key_resp = [u08; P256_ELEM_LEN];
                ephemeral_public_key_resp.copy_from_slice(valid_cred_r.bytes);
                //  What are the message w_I and hash h_I??
                // let sok = initiator.compute_sok(I.try_into(), ephemeral_public_key_resp, w_I, h_I);

                led_pin_p1_06.set_high();
                let Ok(initiator) = 
                    initiator.verify_message_2(valid_cred_r)
                else {
                    info!("EDHOC error at verify_message_2");
                    radio.disable();
                    continue;
                };
                // let initiator = initiator
                //     .verify_message_2(valid_cred_r)
                //     .unwrap();
                led_pin_p1_06.set_low();

                led_pin_p0_26.set_low();

                info!("Prepare message_3");
                led_pin_p0_26.set_high();

                led_pin_p1_08.set_high();
                let (initiator, message_3, i_prk_out) = initiator
                    .prepare_message_3(CredentialTransfer::ByReference, &None).unwrap();
                led_pin_p1_08.set_low();
                info!("Send message_3");
                led_pin_p0_26.set_low();
                common::transmit_without_response(
                    &mut radio,
                    common::Packet::new_from_slice(message_3.as_slice(), Some(c_r.as_slice()[0]))
                        .unwrap(),
                    &mut led_pin_p1_14)
                .await;
                
                info!("Handshake completed. prk_out = {:X}", i_prk_out);
                led_pin_p1_04.set_low();
                Timer::after(Duration::from_secs(1)).await;
            }
            // Err(_) => panic!("parsing error"),
            // Added to measure time. Otherwise revert to up.
            Err(_) => {
                info!("Hanshake failed. Continue to next iteration. Parsing error");
                Timer::after(Duration::from_secs(1)).await; 
                radio.disable();
                led_pin_p1_04.set_low();
                continue;
            }
        }
    }
    // let duration = start.elapsed();
    // info!("start time: {:?} and elapsed time in ms: {:?}", start, duration.as_millis());
    // info!("duration of one handshake in ms: {:?}", duration.as_millis()/100);
}

