#![no_std]
#![no_main]

use embassy_executor::Spawner;
use cortex_m_rt::entry;
use nrf52840_hal::gpio::Level;
use nrf52840_hal::{pac, Uarte, Timer};
use {defmt_rtt as _, panic_probe as _};
use defmt::info;
use hexlit::hex;
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


pub const CRED_I: &[u8] = &hex!("A2027734322D35302D33312D46462D45462D33372D33322D333908A101A5010202412B2001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8");
pub const I: &[u8] = &hex!("fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b");
pub const R: &[u8] = &hex!("72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac");
pub const CRED_R: &[u8] = &hex!("A2026008A101A5010202410A2001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072");

// Use a static buffer in RAM
static mut TX_BUFFER: [u8; 64] = [0; 64];
static mut RX_BUFFER: [u8; 64] = [0; 64];

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let peripherals = pac::Peripherals::take().unwrap();
    let p0 = nrf52840_hal::gpio::p0::Parts::new(peripherals.P0);
    let mut timer = Timer::new(peripherals.TIMER0);

    // Disable UART0 before using UARTE0
    peripherals.UART0.enable.write(|w| w.enable().disabled());
    peripherals.UARTE0.enable.write(|w| w.enable().enabled());

    let txd = p0.p0_06.into_push_pull_output(Level::High).degrade();
    let rxd = p0.p0_08.into_floating_input().degrade();


    info!("Starting UART");
    let mut uart = Uarte::new(
        peripherals.UARTE0,
        nrf52840_hal::uarte::Pins {
            txd,
            rxd,
            cts: None,
            rts: None,
        },
        nrf52840_hal::uarte::Parity::EXCLUDED,
        nrf52840_hal::uarte::Baudrate::BAUD9600,
    );

    info!("init_handshake");
    // let message_1 = b"Hello world from nrf52840\n"; 

    info!("Prepare message_1");
    let cred_i = Credential::parse_ccs_symmetric(CRED_I.try_into().unwrap()).unwrap();
    let cred_r = Credential::parse_ccs_symmetric(CRED_R.try_into().unwrap()).unwrap();

    let mut initiator = EdhocInitiator::new(
        lakers_crypto::default_crypto(),
        EDHOCMethod::StatStat,
        EDHOCSuite::CipherSuite2,
    );

    // Prepare Message 1
    let c_i = generate_connection_identifier_cbor(&mut lakers_crypto::default_crypto());
    let (initiator, message_1) = initiator.prepare_message_1(Some(c_i), &None).unwrap();
    info!("message_1: {:?}", message_1.content);

    unsafe {
        TX_BUFFER[..message_1.len].copy_from_slice(message_1.as_slice());
        // TX_BUFFER[..message_1.len()].copy_from_slice(message_1);
        match uart.write(&TX_BUFFER[..message_1.len]) {
            Ok(_) => info!("Message sent successfully"),
            Err(_) => info!("Failed to send message"),
        }

        // Wait to receive response
        RX_BUFFER.fill(0);
        let mut received_bytes = 0;
        while received_bytes < RX_BUFFER.len() {
            match uart.read(&mut RX_BUFFER[received_bytes..received_bytes+1]) {
                Ok(_) => {
                    received_bytes += 1;

                    if RX_BUFFER[received_bytes-1] == b'\n' || RX_BUFFER[received_bytes-1] == b'\r' {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        if received_bytes > 0 {
            info!("Received {} bytes", received_bytes);
            match core::str::from_utf8(&RX_BUFFER[..received_bytes]) {
                Ok(received_msg) => info!("Received response: {}", received_msg),
                Err(_) => info!("Received invalid UTF-8 data"),
            }
        } else {
            info!("Response not received");
        }
    }        
}