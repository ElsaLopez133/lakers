#![no_std]
#![no_main]

use cortex_m_rt::entry;
use defmt::info;
use defmt_rtt as _;
use hexlit::hex;
use lakers::*;
use lakers_crypto_cryptocell310::edhoc_rs_crypto_init;
use nrf52840_hal::gpio::Level;
use nrf52840_hal::{pac, Timer, Uarte};
use {defmt_rtt as _, panic_probe as _};

// Use a static buffer in RAM
static mut TX_BUFFER: [u8; 64] = [0; 64];
static mut RX_BUFFER_2: [u8; 46] = [0; 46];
static mut RX_BUFFER_3: [u8; 1] = [0; 1];
const MAX_MSG_SIZE: usize = 38;

pub const CRED_I: &[u8] = &hex!("A2027734322D35302D33312D46462D45462D33372D33322D333908A101A5010202412B2001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8");
pub const I: &[u8] = &hex!("fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b");
pub const R: &[u8] = &hex!("72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac");
pub const CRED_R: &[u8] = &hex!("A2026008A101A5010202410A2001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072");

#[entry]
fn main() -> ! {
    let peripherals = pac::Peripherals::take().unwrap();
    let p0 = nrf52840_hal::gpio::p0::Parts::new(peripherals.P0);

    // Disable UART0 before using UARTE0
    peripherals.UART0.enable.write(|w| w.enable().disabled());
    peripherals.UARTE0.enable.write(|w| w.enable().enabled());

    let txd = p0.p0_06.into_push_pull_output(Level::High).degrade();
    let rxd = p0.p0_08.into_floating_input().degrade();

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

    unsafe {
        edhoc_rs_crypto_init();
    }

    // EDHOC handshake
    info!("Starting handhsake");
    unsafe {
        let mut initiator = EdhocInitiator::new(
            lakers_crypto::default_crypto(),
            EDHOCMethod::StatStat,
            EDHOCSuite::CipherSuite2,
        );

        let cred_i = Credential::parse_ccs(CRED_I.try_into().unwrap()).unwrap();
        let cred_r = Credential::parse_ccs(CRED_R.try_into().unwrap()).unwrap();
        let i_array: [u8; 32] = I.try_into().expect("Wrong length of I");
        initiator.set_identity(Some(i_array), cred_i);

        // Prepare Message 1
        // let c_i = generate_connection_identifier_cbor(&mut lakers_crypto::default_crypto());
        let c_i = ConnId::from_int_raw(10);
        info!("c_i: {:?}", c_i.as_slice());
        let (initiator, message_1) = initiator.prepare_message_1(Some(c_i), &None).unwrap();

        // EDHOC message_1 when transported over CoAP is prepended with CBOR true
        let mut msg_1_buf: [u8; MAX_MSG_SIZE] = [0; MAX_MSG_SIZE]; // Pre-allocated buffer
        msg_1_buf[0] = 0xF5; // CBOR true
        let msg_1_len = message_1.as_slice().len();
        msg_1_buf[1..msg_1_len + 1].copy_from_slice(message_1.as_slice());

        //  Send message_1 over UART
        TX_BUFFER[..msg_1_buf[0..msg_1_len + 1].len()].copy_from_slice(&msg_1_buf[..msg_1_len + 1]);
        match uart.write(&TX_BUFFER[..msg_1_buf[0..msg_1_len + 1].len()]) {
            Ok(_) => info!(
                "Message_1 (of length {:?}) sent successfully: {}",
                message_1.as_slice().len() + 1,
                &TX_BUFFER[..msg_1_buf[0..msg_1_len + 1].len()]
            ),
            Err(_) => info!("Failed to send message_1"),
        }

        // cortex_m::asm::delay(16_000_000);

        // Wait to receive message_2
        info!("Waiting for message_2");
        RX_BUFFER_2.fill(0);
        let mut received_bytes = 0;
        while received_bytes < RX_BUFFER_2.len() {
            match uart.read(&mut RX_BUFFER_2[received_bytes..received_bytes + 1]) {
                Ok(_) => {
                    received_bytes += 1;
                }
                Err(_) => break,
            }
        }
        if received_bytes > 0 {
            info!("Received {} bytes", received_bytes);
            info!("Received message_2: {:?}", &RX_BUFFER_2[..received_bytes]);

            // Check if the first byte is CBOR true (0xF5)
            if RX_BUFFER_2[0] == 0xF5 {
                info!("CBOR true (0xF5) detected. Valid message_2.");

                let message_2 =
                    EdhocMessageBuffer::new_from_slice(&RX_BUFFER_2[1..received_bytes]).unwrap();

                // info!("id_cred_i: {:?}", cred_i.by_kid().unwrap().bytes.content[..4]);
                // info!("id_cred_r: {:?}",id_cred_r.unwrap().bytes.content[..4]);
                // info!("cred_i: {:?}", cred_i.by_value().unwrap().bytes.content);
                // info!("cred_r: {:?}", cred_r.by_value().unwrap().bytes.content);

                // Parse message_2
                info!("Parse message_2");
                let (mut initiator, c_r, id_cred_r, _ead_2) =
                    initiator.parse_message_2(&message_2).unwrap();

                let valid_cred_r =
                    credential_check_or_fetch(Some(cred_r), id_cred_r.unwrap()).unwrap();
                let initiator = initiator.verify_message_2(valid_cred_r).unwrap();

                // Prepare and send message_3
                let mut msg_3_buf: [u8; MAX_MSG_SIZE] = [0; MAX_MSG_SIZE];
                msg_3_buf[0] = c_r.as_slice()[0];

                let (mut initiator, message_3, prk_out) = initiator
                    .prepare_message_3(CredentialTransfer::ByReference, &None)
                    .unwrap();
                let msg_3_len = message_3.as_slice().len();
                msg_3_buf[1..msg_3_len + 1].copy_from_slice(message_3.as_slice());
                info!("prk_out: {:?}", prk_out);

                // Send message_3 over UART
                //  Send message_1 over UART
                TX_BUFFER[..message_3.as_slice().len() + 1]
                    .copy_from_slice(&msg_3_buf[..msg_3_len + 1]);
                match uart.write(&TX_BUFFER[..message_3.as_slice().len() + 1]) {
                    Ok(_) => info!(
                        "Message_3 (of length {:?}) sent successfully: {}",
                        message_3.as_slice().len() + 1,
                        &TX_BUFFER[..message_3.as_slice().len() + 1]
                    ),
                    Err(_) => info!("Failed to send message_3"),
                }

                // Wait for ack
                info!("Waiting for ack");
                RX_BUFFER_3.fill(0);
                let mut received_bytes = 0;
                while received_bytes < RX_BUFFER_3.len() {
                    match uart.read(&mut RX_BUFFER_3[received_bytes..received_bytes + 1]) {
                        Ok(_) => {
                            received_bytes += 1;
                        }
                        Err(_) => break,
                    }
                }
                if received_bytes > 0 {
                    info!("Received {} bytes", received_bytes);
                    info!("Received ack: {:?}", &RX_BUFFER_3[..received_bytes]);
                }

                // Key derivation example
                let oscore_secret = initiator.edhoc_exporter(0u8, &[], 16);
                let oscore_salt = initiator.edhoc_exporter(1u8, &[], 8);
                info!("oscore_secret: {:?}", oscore_secret[..16]);
                info!("oscore_salt: {:?}", oscore_salt[..8]);
                info!("Handhsake completed");
            } else {
                info!("Error: First byte is not CBOR true (0xF5), invalid message_2!");
            }
        } else {
            info!("message_2 not received. Handshake failed");
        }
    }

    loop {
        cortex_m::asm::wfe();
    }
}
