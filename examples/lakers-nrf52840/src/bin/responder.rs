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
    // let peripherals = pac::Peripherals::take().unwrap();
    // let p0 = nrf52840_hal::gpio::p0::Parts::new(peripherals.P0);
    // let mut led_pin_p0_26 = p0.p0_26.into_push_pull_output(nrf52840_hal::gpio::Level::Low); // Using nrf52840_hal for GPIO
    // let mut led_pin_p0_14 = p0.p0_14.into_push_pull_output(nrf52840_hal::gpio::Level::Low);
    // let mut led_pin_p0_16 = p0.p0_16.into_push_pull_output(nrf52840_hal::gpio::Level::Low);
    // let mut led_pin_p0_11 = p0.p0_11.into_push_pull_output(nrf52840_hal::gpio::Level::Low);
    // let mut led_pin_p0_24 = p0.p0_24.into_push_pull_output(nrf52840_hal::gpio::Level::Low);
    // let mut led_pin_p0_15 = p0.p0_15.into_push_pull_output(nrf52840_hal::gpio::Level::Low);
    // let mut led_pin_p0_25 = p0.p0_25.into_push_pull_output(nrf52840_hal::gpio::Level::Low);
    // let mut led_pin_p0_19 = p0.p0_19.into_push_pull_output(nrf52840_hal::gpio::Level::Low);

    let mut config = embassy_nrf::config::Config::default();
    config.hfclk_source = embassy_nrf::config::HfclkSource::ExternalXtal;
    let peripherals: embassy_nrf::Peripherals = embassy_nrf::init(config);

    info!("Starting BLE radio");
    let mut radio = Radio::new(peripherals.RADIO, Irqs);

    radio.set_mode(Mode::BLE_1MBIT);
    radio.set_tx_power(TxPower::_0D_BM);
    radio.set_frequency(FREQ);

    radio.set_access_address(ADV_ADDRESS);
    radio.set_header_expansion(false);
    radio.set_crc_init(ADV_CRC_INIT);
    radio.set_crc_poly(CRC_POLY);

    // Memory buffer for mbedtls
    #[cfg(feature = "crypto-psa")]
    let mut buffer: [c_char; 4096 * 2] = [0; 4096 * 2];
    #[cfg(feature = "crypto-psa")]
    unsafe {
        mbedtls_memory_buffer_alloc_init(buffer.as_mut_ptr(), buffer.len());
    }

    loop {
        let buffer: [u8; MAX_PDU] = [0x00u8; MAX_PDU];
        let mut c_r: Option<ConnId> = None;

        info!("Receiving...");
        // led_pin_p0_26.set_high().unwrap();
        //led_pin_p0_25.set_high().unwrap();
        let pckt = common::receive_and_filter(
            &mut radio, 
            Some(0xf5), 
            // Some(&mut led_pin_p0_25)
        ) // filter all incoming packets waiting for CBOR TRUE (0xf5)
            .await
            .unwrap();
        info!("Received message_1");
        //led_pin_p0_25.set_low().unwrap(); 

        let cred_r: Credential = Credential::parse_ccs_symmetric(common::CRED_PSK.try_into().unwrap()).unwrap();
        let responder = EdhocResponder::new(lakers_crypto::default_crypto(), EDHOCMethod::PSK2, None, cred_r);

        let message_1: EdhocMessageBuffer = pckt.pdu[1..pckt.len].try_into().expect("wrong length"); // get rid of the TRUE byte

        // led_pin_p0_14.set_high().unwrap();
        let result = responder.process_message_1(&message_1);
        // led_pin_p0_14.set_low().unwrap();   
        // led_pin_p0_26.set_low().unwrap();
        
        if let Ok((responder, _c_i, ead_1)) = result {
            c_r = Some(generate_connection_identifier_cbor(
                &mut lakers_crypto::default_crypto(),
            ));
            let ead_2 = None;
            info!("Prepare message_2");
            // led_pin_p0_26.set_high().unwrap();
            // led_pin_p0_16.set_high().unwrap();
            let (responder, message_2) = responder
                .prepare_message_2(CredentialTransfer::ByReference, c_r, &ead_2)
                .unwrap();
            // led_pin_p0_16.set_low().unwrap();
            
            // prepend 0xf5 also to message_2 in order to allow the Initiator filter out from other BLE packets
            
            //led_pin_p0_15.set_high().unwrap();
            info!("Send message_2 and wait message_3");
            let message_3 = common::transmit_and_wait_response(
                &mut radio,
                Packet::new_from_slice(message_2.as_slice(), Some(0xf5)).expect("wrong length"),
                Some(c_r.unwrap().as_slice()[0]),
                // &mut led_pin_p0_15,
            )
            .await;
            // led_pin_p0_26.set_low().unwrap();
            //led_pin_p0_15.set_low().unwrap();
            
            match message_3 {
                Ok(message_3) => {
                    info!("Received message_3");
                    // led_pin_p0_26.set_high().unwrap();

                    let rcvd_c_r: ConnId = ConnId::from_int_raw(message_3.pdu[0] as u8);

                    if rcvd_c_r == c_r.unwrap() {
                        let message_3: EdhocMessageBuffer = message_3.pdu[1..message_3.len]
                            .try_into()
                            .expect("wrong length");
                        // led_pin_p0_11.set_high().unwrap();
                        let Ok((responder, id_cred_i, _ead_3)) =
                            responder.parse_message_3(&message_3)
                        else {
                            info!("EDHOC error at parse_message_3");
                            // We don't get another chance, it's popped and can't be used any further
                            // anyway legally
                            continue;
                        };
                        // led_pin_p0_11.set_low().unwrap();

                        let cred_i: Credential = 
                            Credential::parse_ccs_symmetric(common::CRED_PSK.try_into().unwrap()).unwrap();
                        let valid_cred_i =
                            credential_check_or_fetch(Some(cred_i), id_cred_i.unwrap()).unwrap();
                        // led_pin_p0_24.set_high().unwrap();
                        let Ok((responder, prk_out)) = responder.verify_message_3(valid_cred_i)
                        else {
                            info!("EDHOC error at verify_message_3");
                            continue;
                        };
                        // led_pin_p0_24.set_low().unwrap();
                        // led_pin_p0_26.set_low().unwrap();
                        info!("Handshake completed. prk_out: {:X}", prk_out);

                        unwrap!(spawner.spawn(example_application_task(prk_out)));
                    } else {
                        info!("Another packet interrupted the handshake.");
                        continue;
                    }
                }
                Err(PacketError::TimeoutError) => info!("Timeout while waiting for message_3!"),
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
