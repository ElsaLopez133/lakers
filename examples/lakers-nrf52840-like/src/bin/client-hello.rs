#![no_std]
#![no_main]

use cortex_m_rt::entry;
use nrf52840_hal::gpio::Level;
use nrf52840_hal::{pac, Uarte, Timer};
use {defmt_rtt as _, panic_probe as _};
use defmt::info;

// Use a static buffer in RAM
static mut TX_BUFFER: [u8; 64] = [0; 64];
static mut RX_BUFFER: [u8; 64] = [0; 64];

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

    let mut timer = Timer::new(peripherals.TIMER0);
    let message = b"Hello world from nrf52840\n"; 
    let mut counter = 0;
   
    unsafe {
        loop{
            counter +=  1;
            info!("-------Iteration {}--------", counter);

            TX_BUFFER[..message.len()].copy_from_slice(message);
            match uart.write(&TX_BUFFER[..message.len()]) {
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
            info!("-------End iteration {}--------\n", counter);
            timer.delay(4_000_000);
        }
    }
        
}