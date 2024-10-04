#![no_std]
#![no_main]

use common::{Packet, PacketError, ADV_ADDRESS, ADV_CRC_INIT, CRC_POLY, FREQ, MAX_PDU};
use defmt::info;
use embassy_executor::Spawner;
use embassy_nrf::pac::ficr::info;
use embassy_nrf::radio::ble::Mode;
use embassy_nrf::radio::ble::Radio;
use embassy_nrf::radio::TxPower;
use embassy_nrf::{bind_interrupts, peripherals, radio};
use {defmt_rtt as _, panic_probe as _};
use nrf52840_hal::pac;
use nrf52840_hal::prelude::*;
use nrf52840_hal::gpio::{Level, Output, Pin};
use embassy_time::{Duration, Timer};

use lakers::*;

extern crate alloc;

use embedded_alloc::Heap;

use core::ffi::c_char;

#[global_allocator]
static HEAP: Heap = Heap::empty();

extern "C" {
    pub fn mbedtls_memory_buffer_alloc_init(buf: *mut c_char, len: usize);
    static __stack_start__: usize;
    static __stack_end__: usize;
}

mod common;

bind_interrupts!(struct Irqs {
    RADIO => radio::InterruptHandler<peripherals::RADIO>;
});

//  ADDITIONS TO MEMORY MEASUREMENT
use core::sync::atomic::{AtomicUsize, Ordering};
use cortex_m::interrupt;

// static MAX_STACK_USAGE: AtomicUsize = AtomicUsize::new(0);
// static HEAP_USAGE: AtomicUsize = AtomicUsize::new(0);


// #[inline(never)]
// fn update_max_stack_usage() {
//     let current_sp = cortex_m::register::msp::read();
//     let stack_top = 0x2003FFFF; // Top of RAM for nRF52840, adjust if different
//     let used = (stack_top - current_sp) as usize;
//     MAX_STACK_USAGE.fetch_max(used, Ordering::Relaxed);
// }


// Function to initialize stack memory with a known pattern
const STACK_MAGIC_NUMBER: u32 = 0xDEADDEAD;

fn initialize_and_check_stack_memory() {
    unsafe {
        let current_sp: u32 = cortex_m::register::msp::read();
        let stack_top: u32 = 0x2003FFFF; // Top of RAM for nRF52840, adjust if different

        // Initialize stack
        let mut addr: u32 = current_sp;
        while addr < stack_top {
            (addr as *mut u32).write_volatile(STACK_MAGIC_NUMBER);
            addr += 4;
        }

        // Immediate check
        addr = current_sp;
        while addr < stack_top {
            let value = (addr as *const u32).read_volatile();
            if value != STACK_MAGIC_NUMBER {
                info!("Mismatch at 0x{:08X}: expected 0x{:08X}, found 0x{:08X}", 
                      addr, STACK_MAGIC_NUMBER, value);
                break;
            }
            addr += 4;
        }

        info!("Stack initialization and check completed");
    }
}

// Function to measure the stack usage by looking at the remaining known pattern
fn measure_stack_memory() -> usize {
    let mut used_stack = 0;
    let mut count = 0;
    unsafe {
        let current_sp = cortex_m::register::msp::read();
        // info!("current_sp number address (measure): 0x{:08X}", current_sp);
        let stack_top = 0x2003FFFF; // Top of RAM for nRF52840
        let mut addr = current_sp;
        while addr < stack_top {
            // Use `read_volatile` to ensure we're reading the memory directly
            if (addr as *const u32).read_volatile() != STACK_MAGIC_NUMBER {
                if count <= 5{
                    info!("addr value number address: 0x{:08X}", (addr as *const u32).read_volatile());
                }
                count += 1;
                used_stack += 4;
            }
            addr += 4;
        }
    }
    used_stack
}

// Function to measure the stack usage by looking at the remaining known pattern
fn measure_stack_memory_max() -> usize {
    unsafe {
        let current_sp = cortex_m::register::msp::read();
        info!("current_sp number address (measure): 0x{:08X}", current_sp);
        info!("current_sp: {:?}", current_sp);
        let stack_top = 0x2003FFFF; // Top of RAM for nRF52840
        let mut addr = current_sp;
        while addr < stack_top  {
            // Use `read_volatile` to ensure we're reading the memory directly
            if (addr as *const u32).read_volatile() == STACK_MAGIC_NUMBER {
                // info!("current_sp number address (measure): 0x{:08X}", addr);
                return addr as usize;
            }
            addr += 4;
        }
    }
    // if we dont find the magic number, return another setinel value
    0
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    // Step 1: Initialize the stack with a known pattern before doing anything else
    initialize_and_check_stack_memory();
    //  update_max_stack_usage();
    let used_stack = measure_stack_memory();
    info!("Stack memory used: {} bytes", used_stack);
    let max_stack = measure_stack_memory_max();
    info!("Stack memory max: {} bytes", max_stack);

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

    let mut config = embassy_nrf::config::Config::default();
    config.hfclk_source = embassy_nrf::config::HfclkSource::ExternalXtal;
    let embassy_peripherals = embassy_nrf::init(config);

    info!("Starting BLE radio");
    let mut radio: Radio<'_, _> = Radio::new(embassy_peripherals.RADIO, Irqs).into();

    //let mut led = Output::new(embassy_peripherals.P0_13, Level::Low, OutputDrive::Standard);
    //led.set_high();

    radio.set_mode(Mode::BLE_1MBIT);
    radio.set_tx_power(TxPower::_0D_BM);
    radio.set_frequency(common::FREQ);

    radio.set_access_address(common::ADV_ADDRESS);
    radio.set_header_expansion(false);
    radio.set_crc_init(common::ADV_CRC_INIT);
    radio.set_crc_poly(common::CRC_POLY);

    info!("init_handshake");

    // Memory buffer for mbedtls
    #[cfg(feature = "crypto-psa")]
    let mut buffer: [c_char; 4096 * 2] = [0; 4096 * 2];
    #[cfg(feature = "crypto-psa")]
    unsafe {
        mbedtls_memory_buffer_alloc_init(buffer.as_mut_ptr(), buffer.len());
    }
    info!("Prepare message_1");
    // led_pin_p0_26.set_high();
    let cred_i: Credential = Credential::parse_ccs_symmetric(common::CRED_PSK.try_into().unwrap()).unwrap();
    let cred_r: Credential = Credential::parse_ccs_symmetric(common::CRED_PSK.try_into().unwrap()).unwrap();
    //info!("cred_r:{:?}", cred_r.bytes.content);
    
    let mut initiator = EdhocInitiator::new(
        lakers_crypto::default_crypto(),
        EDHOCMethod::PSK2,
        EDHOCSuite::CipherSuite2,
    );

    // Send Message 1 over raw BLE and convert the response to byte
    let c_i = generate_connection_identifier_cbor(&mut lakers_crypto::default_crypto());
    initiator.set_identity(cred_i);

    // led_pin_p0_6.set_high();
    let (initiator, message_1) = initiator.prepare_message_1(Some(c_i), &None).unwrap();
    // led_pin_p0_6.set_low();

    let pckt_1 = common::Packet::new_from_slice(
        message_1.as_slice(), 
        Some(0xf5)
    ).expect("Buffer not long enough");
    info!("Send message_1 and wait message_2");
    // led_pin_p0_26.set_low();
    let rcvd = common::transmit_and_wait_response(
        &mut radio, 
        pckt_1, 
        Some(0xf5),
        // Some(&mut led_pin_p1_07)
    ).await;
    
    match rcvd {
        Ok(pckt_2) => {
            info!("Received message_2");
            // led_pin_p0_26.set_high();
            let message_2: EdhocMessageBuffer =
                pckt_2.pdu[1..pckt_2.len].try_into().expect("wrong length");
            // led_pin_p0_5.set_high();
            let (initiator, c_r, id_cred_r, ead_2) = initiator.parse_message_2(&message_2).unwrap();
            // led_pin_p0_5.set_low();
            let valid_cred_r = credential_check_or_fetch(Some(cred_r), id_cred_r.unwrap()).unwrap();

            // led_pin_p0_8.set_high();
            let initiator = initiator
                .verify_message_2(valid_cred_r)
                .unwrap();
            // led_pin_p0_8.set_low();

            // led_pin_p0_26.set_low();

            info!("Prepare message_3");
            // led_pin_p0_26.set_high();

            // led_pin_p0_7.set_high();
            let (initiator, message_3) = initiator
                .prepare_message_3(CredentialTransfer::ByReference, &None).unwrap();
            // led_pin_p0_7.set_low();

            let pckt_3 = common::Packet::new_from_slice(message_3.as_slice(), Some(c_r.as_slice()[0]))
            .expect("Buffer not long enough");
            info!("Send message_3 and wait message_4");
            // led_pin_p0_26.set_low();
            let rcvd = common::transmit_and_wait_response(
                &mut radio, 
                pckt_3,
                Some(c_r.as_slice()[0]),
                // Some(&mut led_pin_p1_08),
            ).await;
            
            info!("Sent message_3");
            match rcvd {
                Ok(pckt_4) => {
                    info!("Received message_4");
                    // led_pin_p0_26.set_high();
                    let message_4: EdhocMessageBuffer =
                        pckt_4.pdu[1..pckt_4.len].try_into().expect("wrong length");
        
                    // led_pin_p0___.set_high().unwrap();
                    let (initiator, ead_4) = initiator.parse_message_4(&message_4).unwrap();
                    // led_pin_p0___.set_low().unwrap();
                    let (mut initiator, i_prk_out) = initiator.verify_message_4().unwrap();
                    // led_pin_p0_26.set_low();
                    
                    info!("Handshake completed. prk_out = {:X}", i_prk_out);
                }  
                Err(_) => panic!("parsing error"),
            }
        }
        Err(_) => panic!("parsing error"),
    }
    // Step 3: Measure the stack usage after the function has completed
    let used_stack = measure_stack_memory();
    info!("Stack memory used: {} bytes", used_stack);
    let max_stack = measure_stack_memory_max();
    info!("Stack memory max: {} bytes", max_stack);
    // interrupt::free(|_| {
    //     let max_stack = MAX_STACK_USAGE.load(Ordering::Relaxed);
    //     // let heap_usage = HEAP_USAGE.load(Ordering::Relaxed);
    //     info!("Max stack usage: {} bytes", max_stack);
    //     // info!("Current heap usage: {} bytes", heap_usage);
    // });

}
