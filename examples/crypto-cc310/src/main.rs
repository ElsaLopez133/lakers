#![no_std]
#![no_main]

use core::result;

use cortex_m_rt::entry;
use cortex_m_semihosting::debug::{self, EXIT_SUCCESS};
use defmt::info;
use defmt_rtt as _;
use panic_semihosting as _;

pub use nrf52840_pac as pac;
use nrf52840_pac::{cc_pka::{self, opcode::Opcode, pka_sram_wclear}, ficr::info}; 

// #[no_mangle]
// #[link_section = ".data"]

// const A: [u32; 66] = [
//         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//         0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00,
//         0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00,
//         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//         0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00,
//         0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00,
//         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12345678,
//         0x00, 0x00];

// const B: [u32; 66] = [
//         0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//         0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00,
//         0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00,
//         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//         0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00,
//         0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00,
//         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
//         0x00, 0x0];

// Example constants for positions
const TAG_POS: u8 = 0;         // tag of the operand
const REG_R_POS: u8 = 6;       // Result register position (Bits 6:10)
const REG_R_CTRL_POS: u8 = 11; // Result register control position (Bit 11)
const REG_B_POS: u8 = 12;      // Operand B register position (Bits 12:16)
const REG_B_CTRL_POS: u8 = 17; // Operand B register control position (Bit 17)
const REG_A_POS: u8 = 18;      // Operand A register position (Bits 18:22)
const REG_A_CTRL_POS: u8 = 23; // Operand A register control position (Bit 23)
const LEN_POS: u8 = 24;        // Operand length register index (Bits 24:26)
const OPCODE_POS: u8 = 27;     // Operation code position (Bits 27:31)

// All virtual registers must be 64 bits word size aligned, and the size of the virtual 
// registers must be at least the size of the largest operand plus an extra 64 bits 
// for internal PKA calculations. 
// These extra 64 bits must be initialized to zero. 
const OPERAND_SIZE_BITS: usize = 2 * 4 * 8;
const OPERAND_MEMORY_OFFSET: u32 = (OPERAND_SIZE_BITS as u32)/8/4 + 2;
const VIRTUAL_MEMORY_SIZE_BITS: usize = 64 * 4 * 8; // 64-bit word size
const VIRTUAL_MEMORY_OFFSET: u32 = (VIRTUAL_MEMORY_SIZE_BITS as u32)/8/4 + 2;

// Define example values for N and Np 
// const N: [u32; 8] = [0xFFFFFFFF, 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF];
// const NP: [u32; 8] = [0x00000000, 0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF];
// const N: [u32; 8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03];
// const NP: [u32; 8] = [0xAAAAAAAA, 0xAAAAAAAA, 0xAAAAAAAA, 0xAAAAAAAA, 0xAAAAAAAA, 0xAAAAAAAA, 0xAAAAAAAA, 0xAAAAAAAB];
// const N: [u32; 8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05];
// const NP: [u32; 8] = [0xCCCCCCCC, 0xCCCCCCCC, 0xCCCCCCCC, 0xCCCCCCCC, 0xCCCCCCCC, 0xCCCCCCCC, 0xCCCCCCCC, 0xCCCCCCCD];
// const N: [u32; 2] = [0x00, 0x13];
// const NP: [u32; 2] = [0x86BCA1AF, 0x286BCA1B];
const N: [u32; 2] = [0x00, 0x15];
const NP: [u32; 2] = [0xCF3CF3CF, 0x3CF3CF3D];
// const N: [u32; 1] = [0x13];
// const NP: [u32; 1] = [0x286BCA1B];
// const N: [u32; 1] = [0xB];
// const NP: [u32; 1] = [0xBA2E8BA3];
// Example values for a and b
// const A: [u32; 8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05];
const A: [u32; 2] = [0x00, 0x15];
// const A: [u32; 1] = [0x02];
// const A: [u32; 8] = [0xFFFFFFFF, 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF];

// const B: [u32; 8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02];
const B: [u32; 2] = [0x00, 0x04];
// const B: [u32; 1] = [0x07];
// const B: [u32; 8] = [0xFFFFFFFF, 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF];


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

static BASE_POINT_G_Y: [u8; 32] = [
    0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 
    0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16, 
    0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE, 
    0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51,0xF5
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
    cc_pka.pka_l(1).write(|w| unsafe { w.bits(OPERAND_SIZE_BITS as u32) }); 

    // Configure memory map
    cc_pka.memory_map(0).write(|w| unsafe { w.bits(0x0) }); // R0
    cc_pka.memory_map(1).write(|w| unsafe { w.bits(VIRTUAL_MEMORY_OFFSET) }); // R1
    cc_pka.memory_map(4).write(|w| unsafe { w.bits(2 * VIRTUAL_MEMORY_OFFSET) }); // R4
    cc_pka.memory_map(5).write(|w| unsafe { w.bits(3 * VIRTUAL_MEMORY_OFFSET) }); // R5
    cc_pka.memory_map(6).write(|w| unsafe { w.bits(4 * VIRTUAL_MEMORY_OFFSET) }); // R6
    cc_pka.memory_map(30).write(|w| unsafe { w.bits(5 * VIRTUAL_MEMORY_OFFSET) }); // T0
    cc_pka.memory_map(31).write(|w| unsafe { w.bits(6 * VIRTUAL_MEMORY_OFFSET) }); // T1    

    // Load N (R0) and Np (R1) into PKA SRAM
    // Memory is loaded in reverse order
    cc_pka.pka_sram_waddr().write(|w| unsafe { w.bits(cc_pka.memory_map(0).read().bits()) });
    for i in 0..OPERAND_SIZE_BITS/8/4 {
        let reverse_index = OPERAND_SIZE_BITS/8/4 - 1 - i;
        cc_pka.pka_sram_wdata().write(|w| unsafe { w.bits(N[reverse_index]) });
    }
    //  Extra 64 bits (2 words) must be intialized to zero
    for i in 0..2 {
        cc_pka.pka_sram_wdata().write(|w| unsafe { w.bits(0x00) });
    }
    cc_pka.pka_sram_waddr().write(|w| unsafe { w.bits(cc_pka.memory_map(1).read().bits()) });
    for i in 0..OPERAND_SIZE_BITS/8/4 {
        let reverse_index = OPERAND_SIZE_BITS/8/4 - 1 - i;
        cc_pka.pka_sram_wdata().write(|w| unsafe { w.bits(NP[i]) });
    }
    //  Extra 64 bits (2 words) must be intialized to zero
    for i in 0..2 {
        cc_pka.pka_sram_wdata().write(|w| unsafe { w.bits(0x00) });
    }
    cc_pka.pka_sram_waddr().write(|w| unsafe { w.bits(cc_pka.memory_map(4).read().bits()) });
    // FIXME add bound check on A
    for i in 0..OPERAND_SIZE_BITS/8/4 {
        let reverse_index = OPERAND_SIZE_BITS/8/4 - 1 - i;
        cc_pka.pka_sram_wdata().write(|w| unsafe { w.bits(A[reverse_index])}); 
    }
    //  Extra 64 bits (2 words) must be intialized to zero
    for i in 0..2 {
        cc_pka.pka_sram_wdata().write(|w| unsafe { w.bits(0x00) });
    }
    cc_pka.pka_sram_waddr().write(|w| unsafe { w.bits(cc_pka.memory_map(5).read().bits()) });
    // cc_pka.pka_sram_wdata().write(|w| unsafe { w.bits(B[0])}); 
    for i in 0..OPERAND_SIZE_BITS/8/4 {
        let reverse_index = OPERAND_SIZE_BITS/8/4 - 1 - i;
        cc_pka.pka_sram_wdata().write(|w| unsafe { w.bits(B[reverse_index])}); 
    }
    //  Extra 64 bits (2 words) must be intialized to zero
    for i in 0..2 {
        cc_pka.pka_sram_wdata().write(|w| unsafe { w.bits(0x00) });
    }
    cc_pka.pka_sram_waddr().write(|w| unsafe { w.bits(cc_pka.memory_map(6).read().bits()) });
    // cc_pka.pka_sram_wdata().write(|w| unsafe { w.bits(B[0])}); 
    for i in 0..OPERAND_SIZE_BITS/8/4 + 2 {
        cc_pka.pka_sram_wdata().write(|w| unsafe { w.bits(0x00)}); 
    }
    // Verify data is well written
    cc_pka.pka_sram_wclear();
    cc_pka.pka_sram_raddr().write(|w| unsafe { w.bits(cc_pka.memory_map(0).read().bits()) });
    let mut verif_n = [0u32; OPERAND_SIZE_BITS/8/4];
    for i in 0..OPERAND_SIZE_BITS/8/4 {
        verif_n[i] = cc_pka.pka_sram_rdata().read().bits();
    }
    info!("Verification of N: {:#X} = {:?}", verif_n, verif_n);
    
    cc_pka.pka_sram_raddr().write(|w| unsafe { w.bits(cc_pka.memory_map(4).read().bits()) });
    let mut verif_a = [0u32; OPERAND_SIZE_BITS/8/4];
    for i in 0..OPERAND_SIZE_BITS/8/4 {
        verif_a[i] = cc_pka.pka_sram_rdata().read().bits();
    }
    info!("Verification of A: {:#X} = {:?}", verif_a, verif_a);
    
    cc_pka.pka_sram_raddr().write(|w| unsafe { w.bits(cc_pka.memory_map(5).read().bits()) });
    let mut verif_b = [0u32; OPERAND_SIZE_BITS/8/4];
    for i in 0..OPERAND_SIZE_BITS/8/4 {
        verif_b[i] = cc_pka.pka_sram_rdata().read().bits();
    }
    info!("Verification of B: {:#X} = {:?}", verif_b, verif_b);
    
    cc_pka.pka_sram_raddr().write(|w| unsafe { w.bits(cc_pka.memory_map(6).read().bits()) });
    let mut verif_r6 = [0u32; OPERAND_SIZE_BITS/8/4];
    for i in 0..OPERAND_SIZE_BITS/8/4 {
        verif_r6[i] = cc_pka.pka_sram_rdata().read().bits();
    }
    info!("Verification of R6: {:#X} = {:?}", verif_r6, verif_r6);

    // Execute the operation you want
    //  5 << 12 bitwise left shift operation. Means shift the binary representation of 5 12 positions to the left
    //  0101 --> 0101 0000 0000 0000
    cc_pka.opcode().write(|w| unsafe {
        w.bits(
            (6 << REG_R_POS as u32)       // Result register (R6)
                | (5 << REG_B_POS as u32) // Operand B register (R5)
                | (4 << REG_A_POS as u32) // Operand A register (R4)
                | (1 << LEN_POS as u32) 
                | ((Opcode::ModMul as u32) << OPCODE_POS as u32)
        )
    });

    // Wait for the operation to complete
    while cc_pka.pka_done().read().bits() == 0 {}
    // Read status
    let status_bits = cc_pka.pka_status().read().bits();
    // info!("PKA status: {:#021b}", status_bits);
    // info!("A (ALU_MSB_4BITS):    {:04b}", (status_bits >> 0) & 0xF); // 0xF is 1111, so the mask keeps the 4 bits
    // info!("B (ALU_LSB_4BITS):    {:04b}", (status_bits >> 4) & 0xF);
    info!("C (ALU_SIGN_OUT):     {:01b}", (status_bits >> 8) & 0x1);
    info!("D (ALU_CARRY):        {:01b}", (status_bits >> 9) & 0x1);
    info!("E (ALU_CARRY_MOD):    {:01b}", (status_bits >> 10) & 0x1);
    // info!("F (ALU_SUB_IS_ZERO):  {:01b}", (status_bits >> 11) & 0x1);
    // info!("G (ALU_OUT_ZERO):     {:01b}", (status_bits >> 12) & 0x1);
    info!("H (ALU_MODOVRFLW):    {:01b}", (status_bits >> 13) & 0x1);
    // info!("I (DIV_BY_ZERO):      {:01b}", (status_bits >> 14) & 0x1);
    // info!("J (MODINV_OF_ZERO):   {:01b}", (status_bits >> 15) & 0x1);
    // info!("K (OPCODE):           {:05b}", (status_bits >> 16) & 0xFFFF);

    // //  Perform an extra reduction
    // cc_pka.opcode().write(|w| unsafe {
    //     w.bits(
    //         (6 << REG_R_POS as u32)        // Result register (R6)
    //             | (5 << REG_B_POS as u32) // Operand B register (R5)
    //             | (4 << REG_A_POS as u32) // Operand A register (R4)
    //             | (1 << LEN_POS as u32) 
    //             | ((Opcode::ModMul as u32) << OPCODE_POS as u32)
    //     )
    // });

    // // Wait for the operation to complete
    // while cc_pka.pka_done().read().bits() == 0 {}

    cc_pka.pka_sram_wclear();
    // Read and log the result
    let mut result = [0u32; OPERAND_SIZE_BITS/8/4 + 2];
    cc_pka.pka_sram_raddr().write(|w| unsafe { w.bits(cc_pka.memory_map(6).read().bits()) });
    // let result = cc_pka.pka_sram_rdata().read().bits();
    for i in 0..result.len() {
        result[i] = cc_pka.pka_sram_rdata().read().bits(); 
    } 

    info!("Result: {:#X}", result);
    info!("Result: {:?}", result);

    // exit via semihosting call
    debug::exit(EXIT_SUCCESS);
    loop {}
}


/// Struct representing the PKA_STATUS register
#[derive(Debug)]
struct PkaStatus {
    bits: u32,
}

impl PkaStatus {
    /// Create a new instance from the raw register value
    fn new(bits: u32) -> Self {
        PkaStatus { bits }
    }

    /// Most significant 4 bits of the operand after a shift operation
    fn alu_msb_4bits(&self) -> u8 {
        (self.bits & 0b1111) as u8
    }

    /// Least significant 4 bits of the operand after a shift operation
    fn alu_lsb_4bits(&self) -> u8 {
        ((self.bits >> 4) & 0b1111) as u8
    }

    /// MSB sign of the last operation
    fn alu_sign_out(&self) -> bool {
        (self.bits & (1 << 8)) != 0
    }

    /// Carry of the last ALU operation
    fn alu_carry(&self) -> bool {
        (self.bits & (1 << 9)) != 0
    }

    /// Modular overflow flag
    fn alu_mod_overflow(&self) -> bool {
        (self.bits & (1 << 13)) != 0
    }

    /// Division by zero flag
    fn div_by_zero(&self) -> bool {
        (self.bits & (1 << 14)) != 0
    }

    /// Modular inverse of zero flag
    fn modinv_of_zero(&self) -> bool {
        (self.bits & (1 << 15)) != 0
    }
}