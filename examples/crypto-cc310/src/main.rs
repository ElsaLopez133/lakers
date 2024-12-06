#![no_std]
#![no_main]

use cortex_m_rt::entry;
use cortex_m_semihosting::debug::{self, EXIT_SUCCESS};
use defmt::info;
use defmt_rtt as _;
use panic_semihosting as _;

pub use nrf52840_pac as pac;
use nrf52840_pac::{cc_pka::{opcode::Opcode, pka_sram_wclear}, ficr::info}; 

// #[no_mangle]
// #[link_section = ".data"]

// Example constants for positions
const TAG_POS: u8 = 0;         // tag of the operan
const REG_R_POS: u8 = 6;       // Result register position (Bits 6:10)
const REG_R_CTRL_POS: u8 = 11; // Result register control position (Bit 11)
const REG_B_POS: u8 = 12;      // Operand B register position (Bits 12:16)
const REG_B_CTRL_POS: u8 = 17; // Operand B register control position (Bit 17)
const REG_A_POS: u8 = 18;      // Operand A register position (Bits 18:22)
const REG_A_CTRL_POS: u8 = 23; // Operand A register control position (Bit 23)
const LEN_POS: u8 = 24;        // Operand length register index (Bits 24:26)
const OPCODE_POS: u8 = 27;     // Operation code position (Bits 27:31)

// Define example values for N and Np 
const N: u32 = 0x12345678;  // Example value for N
const NP: u32 = 0x9ABCDEF0; // Example value for Np

// Example values for a and b
const A: u32 = 0x4;
const B: u32 = 0x2;

static BASE_POINT_G_X_COMPRESSED: [u8; 33] = [
    0x02, // Sign byte indicating positive y-coordinate
    0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0xA2, 0xC4, 0x2F,
    0xF8, 0xBC, 0xBC, 0xED, 0x5C, 0x2D, 0x6B, 0x13,
    0x03, 0xAE, 0xB1, 0xA5, 0xC4, 0xA7, 0xBF, 0xC1,
    0x31, 0x6B, 0x1A, 0x6B, 0x2C, 0x80, 0xF2, 0x0F
];
static BASE_POINT_G_X: [u8; 32] = [
    0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0xA2, 0xC4, 0x2F,
    0xF8, 0xBC, 0xBC, 0xED, 0x5C, 0x2D, 0x6B, 0x13,
    0x03, 0xAE, 0xB1, 0xA5, 0xC4, 0xA7, 0xBF, 0xC1,
    0x31, 0x6B, 0x1A, 0x6B, 0x2C, 0x80, 0xF2, 0x0F
];
static POINT_5_G_COMPRESSED: [u8; 33] = [
    0x02, // Sign byte indicating positive y-coordinate
    0x7B, 0x94, 0x44, 0x3F, 0x16, 0x9D, 0x16, 0x8D,
    0x23, 0xA9, 0xE1, 0xA2, 0xF9, 0xA7, 0xE2, 0x9C,
    0xC6, 0xDB, 0x72, 0x0D, 0x0E, 0x07, 0x8F, 0xF2,
    0x0A, 0x1E, 0x5F, 0x98, 0xFB, 0x02, 0xC9, 0xA7
];
static POINT_5_G: [u8; 32] = [
    0x7B, 0x94, 0x44, 0x3F, 0x16, 0x9D, 0x16, 0x8D,
    0x23, 0xA9, 0xE1, 0xA2, 0xF9, 0xA7, 0xE2, 0x9C,
    0xC6, 0xDB, 0x72, 0x0D, 0x0E, 0x07, 0x8F, 0xF2,
    0x0A, 0x1E, 0x5F, 0x98, 0xFB, 0x02, 0xC9, 0xA7
];

#[entry]
fn main() -> ! {
    info!("Running.");

    // Enable the PKA and CryptoCell clock
    let p = pac::Peripherals::take().unwrap();
    let cc_misc = p.cc_misc;
    let cc_pka = p.cc_pka;

    p.cryptocell.enable().write(|w| w.enable().set_bit());
    cc_misc.pka_clk().write(|w| w.enable().set_bit());

    while cc_misc.clk_status().read().pka_clk().bit_is_clear() {
    // Wait for PKA clock to be ready
    }
    info!("PKA clock ready. PKA engine enabled");

    // Example for 2048-bit operand configurations
    cc_pka.pka_l(1).write(|w| unsafe { w.bits(0x800) });  // 2048 bits


    // Configure memory map
    cc_pka.memory_map(0).write(|w| unsafe { w.bits(0x0) }); // R0
    cc_pka.memory_map(1).write(|w| unsafe { w.bits(0x42) }); // R1
    cc_pka.memory_map(4).write(|w| unsafe { w.bits(0x108) }); // R4
    cc_pka.memory_map(5).write(|w| unsafe { w.bits(0x14A) }); // R5
    cc_pka.memory_map(6).write(|w| unsafe { w.bits(0x18C) }); // R6


    // Load N (R0) and Np (R1) into PKA SRAM
    cc_pka.pka_sram_waddr().write(|w| unsafe { w.bits(cc_pka.memory_map(0).read().bits()) });
    cc_pka.pka_sram_wdata().write(|w| unsafe { w.bits(N) }); 
    cc_pka.pka_sram_waddr().write(|w| unsafe { w.bits(cc_pka.memory_map(1).read().bits()) });
    cc_pka.pka_sram_wdata().write(|w| unsafe { w.bits(NP) }); 

    cc_pka.pka_sram_waddr().write(|w| unsafe { w.bits(cc_pka.memory_map(4).read().bits()) });
    cc_pka.pka_sram_wdata().write(|w| unsafe { w.bits(A) });   

    cc_pka.pka_sram_waddr().write(|w| unsafe { w.bits(cc_pka.memory_map(5).read().bits()) });
    cc_pka.pka_sram_wdata().write(|w| unsafe { w.bits(B) });   

    // Execute the operation you want
    //  5 << 12 bitwise left shift operation. Means shift the binary representation of 5 12 positions to the left
    //  0101 --> 0101 0000 0000 0000
    cc_pka.opcode().write(|w| unsafe {
        w.bits(
            (6 << REG_R_POS as u32)        // Result register (R4)
                | (5 << REG_B_POS as u32) // Operand B register (R5)
                | (4 << REG_A_POS as u32) // Operand A register (R4)
                | (1 << LEN_POS as u32) // Operand length (2048 bits)
                | (((Opcode::AddInc as u8) as u32) << OPCODE_POS as u32)
        )
    });

    // Wait for the operation to complete
    while cc_pka.pka_done().read().bits() == 0 {}

    cc_pka.pka_sram_wclear();
    // Read and log the result
    cc_pka.pka_sram_raddr().write(|w| unsafe { w.bits(cc_pka.memory_map(6).read().bits()) });
    let r6_result = cc_pka.pka_sram_rdata().read().bits();
    info!("R6 result: {:#X}", r6_result);
    
    // exit via semihosting call
    debug::exit(EXIT_SUCCESS);
    loop {}
}
