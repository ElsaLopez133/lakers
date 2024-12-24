#![no_std]
#![no_main]

use core::result;
use core::cmp::Ordering;
use cortex_m_rt::entry;
use cortex_m_semihosting::debug::{self, EXIT_SUCCESS};
use defmt::info;
use defmt_rtt as _;
use panic_semihosting as _;

pub use nrf52840_pac as pac;
use nrf52840_pac::{cc_pka::{self, opcode::Opcode, pka_sram_wclear}, ficr::info}; 


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
const OPERAND_SIZE_BITS: usize = 8 * 4 * 8;
const OPERAND_SIZE_WORDS: usize = OPERAND_SIZE_BITS/8/4;
const OPERAND_MEMORY_OFFSET: u32 = (OPERAND_SIZE_BITS as u32)/8/4 + 2;
const VIRTUAL_MEMORY_SIZE_BITS: usize = 64 * 4 * 8; // 64-bit word size
const VIRTUAL_MEMORY_OFFSET: u32 = (VIRTUAL_MEMORY_SIZE_BITS as u32)/8/4 + 2;

// Define example values for N and Np 
// 1D examples
// const N: [u32; 1] = [0x15];
// const NP: [u32; 1] = [0xC30C30C3];

// Example values for a and b
// 1D examples
// const A: [u32; 1] = [0x02];
// const B: [u32; 1] = [0x07];


// // P-256 curve parameters
// const N: [u32; 8] = [
//     0xFFFFFFFF, 0x00000001, 0x00000000, 0x00000000,
//     0x00000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
// ];

// const NP: [u32; 8] = [
//     0xFFFFFFFF, 0x00000002, 0x00000000, 0x00000000, 
//     0x00000001, 0x00000000, 0x00000000, 0x00000001
// ];

// const B: [u32; 8] = [
//     0x27D2604B, 0x3BCE3C3E, 0xCC53B0F6, 0x651D06B0,
//     0x769886BC, 0xB3EBBD55, 0xAA3A93E7, 0x5AC635D8
// ];

// const A: [u32; 8] = [
//     0xFFFFFFFC, 0x00000001, 0x00000000, 0x00000000,
//     0x00000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
// ];
// const P_PLUS_1_DIV_4: [u32; 8] = [
//     0x3FFFFFFF, 0x40000000, 0x40000000, 0x40000000,
//     0x40000000, 0x3FFFFFFF, 0xFFFFFFFF, 0x3FFFFFFF
// ];

// const EXP: [u32; 8] = [
//     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03
// ];
// // test vectors: http://point-at-infinity.org/ecc/nisttv
// // k = 1
// // x = 6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
// // y = 4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
// static POINT_X: [u32; 8] = [
//     0x6B17D1F2, 0xE12C4247, 0xF8BCE6E5, 0x63A440F2,
//     0x77037D81, 0x2DEB33A0, 0xF4A13945, 0xD898C296,
// ];

// static POINT_Y: [u32; 8] = [
//     0x4FE342E2, 0xFE1A7F9B, 0x8EE7EB4A, 0x7C0F9E16,
//     0x2BCE3357, 0x6B315ECE, 0xCBB64068, 0x37BF51F5
// ];

//  Easier tests
const N: [u32; 8] = [
    0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000015
];

const LONG_N: [u32; 16] = [
    0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000015
];

const NP: [u32; 8] = [
    0xC30C30C3, 0xC30C30C3, 0xC30C30C3, 0xC30C30C3, 
    0xC30C30C3, 0xC30C30C3, 0xC30C30C3, 0xC30C30C3
];

const B: [u32; 8] = [
    0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000010
];

const A: [u32; 8] = [
    0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000010
];
const P_PLUS_1_DIV_4: [u32; 8] = [
    0x3FFFFFFF, 0x40000000, 0x40000000, 0x40000000,
    0x40000000, 0x3FFFFFFF, 0xFFFFFFFF, 0x3FFFFFFF
];

const EXP: [u32; 8] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3
];
// test vectors: http://point-at-infinity.org/ecc/nisttv
// k = 1
// x = 6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
// y = 4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
static POINT_X: [u32; 8] = [
    0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000100,
];

static POINT_Y: [u32; 8] = [
    0x4FE342E2, 0xFE1A7F9B, 0x8EE7EB4A, 0x7C0F9E16,
    0x2BCE3357, 0x6B315ECE, 0xCBB64068, 0x37BF51F5
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
    cc_pka.pka_l(0).write(|w| unsafe { w.bits(2 * OPERAND_SIZE_BITS as u32) }); 

    // Configure memory map
    configure_memory_map(&cc_pka); 

    // Load curve parameters into PKA SRAM
    load_parameters(&cc_pka);

    // Verify data is well written
    cc_pka.pka_sram_wclear();
    read_word_array(&cc_pka, 0);
    read_word_array(&cc_pka, 1);
    read_word_array(&cc_pka, 4);
    read_word_array(&cc_pka, 5);
    read_word_array(&cc_pka, 6);

    // Execute the operation
    // Calculate y = sqrt(x³ + ax + b mod p)
    // 1. Calculate x³ mod p
    info!("Calculate x^3");
    execute_operation(&cc_pka, cc_pka::opcode::Opcode::ModExp, 5, 4, 5, 1);
    read_word_array(&cc_pka, 5);
    // 2. Calculate ax mod p
    info!("Calculate ax");
    execute_operation(&cc_pka, cc_pka::opcode::Opcode::ModMul, 4, 4, 2, 1);
    read_word_array(&cc_pka, 4);  
    // 3. Add terms and b
    info!("Calculate x^3 + ax + b");
    execute_operation(&cc_pka, cc_pka::opcode::Opcode::ModAddInc, 5, 5, 4, 1);
    execute_operation(&cc_pka, cc_pka::opcode::Opcode::ModAddInc, 6, 5, 3, 1);
    // 4. Calculate sqrt
    // info!("Calculate sqrt");
    // calculate_sqrt(&cc_pka);

    // Read status
    let status_bits = cc_pka.pka_status().read().bits();
    // info!("PKA status: {:#021b}", status_bits);
    // info!("A (ALU_MSB_4BITS):    {:04b}", (status_bits >> 0) & 0xF); // 0xF is 1111, so the mask keeps the 4 bits
    // info!("B (ALU_LSB_4BITS):    {:04b}", (status_bits >> 4) & 0xF);
    // info!("C (ALU_SIGN_OUT):     {:01b}", (status_bits >> 8) & 0x1);
    // info!("D (ALU_CARRY):        {:01b}", (status_bits >> 9) & 0x1);
    // info!("E (ALU_CARRY_MOD):    {:01b}", (status_bits >> 10) & 0x1);
    // info!("F (ALU_SUB_IS_ZERO):  {:01b}", (status_bits >> 11) & 0x1);
    // info!("G (ALU_OUT_ZERO):     {:01b}", (status_bits >> 12) & 0x1);
    // info!("H (ALU_MODOVRFLW):    {:01b}", (status_bits >> 13) & 0x1);
    // info!("I (DIV_BY_ZERO):      {:01b}", (status_bits >> 14) & 0x1);
    // info!("J (MODINV_OF_ZERO):   {:01b}", (status_bits >> 15) & 0x1);
    // info!("K (OPCODE):           {:05b}", (status_bits >> 16) & 0xFFFF);

    cc_pka.pka_sram_wclear();
    read_word_array(&cc_pka, 6);

    // exit via semihosting call
    debug::exit(EXIT_SUCCESS);
    loop {}
}


fn configure_memory_map(cc_pka: &pac::CcPka) {
    cc_pka.pka_l(1).write(|w| unsafe { w.bits(OPERAND_SIZE_BITS as u32) });
    // Map virtual registers
    // R0: modulus (N)
    // R1: Np
    // R2: a parameter
    // R3: b parameter
    // R4: operand A
    // R5: operand B
    // R6: result
    // T0: register 30
    // T1: register 31
    for i in 0..8 {
        cc_pka.memory_map(i).write(|w| unsafe { 
            w.bits(i as u32 * VIRTUAL_MEMORY_OFFSET) 
        });
    }
    cc_pka.memory_map(30).write(|w| unsafe { 
            w.bits(7 as u32 * VIRTUAL_MEMORY_OFFSET) 
        });
    cc_pka.memory_map(31).write(|w| unsafe { 
        w.bits(8 as u32 * VIRTUAL_MEMORY_OFFSET) 
    });
}

fn load_parameters(cc_pka: &pac::CcPka) {
    load_word_array(cc_pka, 0, &N);
    load_word_array(cc_pka, 1, &[0u32; 2 * OPERAND_SIZE_WORDS]);
    load_word_array(cc_pka, 2, &A);
    load_word_array(cc_pka, 3, &B);
    
    // Load operand X into R4
    load_word_array(cc_pka, 4, &POINT_X);
    
    // Load operand EXP into R5
    load_word_array(cc_pka, 5, &EXP);

    // Initialize result R6 to zero
    load_word_array(cc_pka, 6, &[0u32; 2 * OPERAND_SIZE_WORDS]);
    load_word_array(cc_pka, 7, &[0u32; 2 * OPERAND_SIZE_WORDS]);
    load_word_array(cc_pka, 8, &LONG_N);
}

fn load_word_array(cc_pka: &pac::CcPka, reg: usize, data: &[u32]) {
    cc_pka.pka_sram_waddr().write(|w| unsafe { 
        w.bits(cc_pka.memory_map(reg).read().bits()) 
    });
    
    // Load data in reverse order
    for i in 0..data.len() {
        let reverse_index = data.len() - 1 - i;
        cc_pka.pka_sram_wdata().write(|w| unsafe { 
            w.bits(data[reverse_index]) 
        });
    }
    // Add padding zeros
    for _ in 0..2 {
        cc_pka.pka_sram_wdata().write(|w| unsafe { w.bits(0x00) });
    }
}

fn read_word_array(cc_pka: &pac::CcPka, reg: usize) {
    cc_pka.pka_sram_raddr().write(|w| unsafe { 
        w.bits(cc_pka.memory_map(reg).read().bits()) 
    });
    let mut verif = [0u32; OPERAND_SIZE_WORDS];
    for i in 0..OPERAND_SIZE_WORDS {
        verif[7-i] = cc_pka.pka_sram_rdata().read().bits();
    }
    info!("Verification of R{:?}: {:#X}", reg, verif);
}

fn read_word_array_long(cc_pka: &pac::CcPka, reg: usize) {
    cc_pka.pka_sram_raddr().write(|w| unsafe { 
        w.bits(cc_pka.memory_map(reg).read().bits()) 
    });
    let mut verif = [0u32; 2 * OPERAND_SIZE_WORDS];
    for i in 0..2 * OPERAND_SIZE_WORDS {
        verif[15-i] = cc_pka.pka_sram_rdata().read().bits();
    }
    info!("Verification of R{:?}: {:#X}", reg, verif);
}

fn execute_operation(cc_pka: &pac::CcPka, opcode: cc_pka::opcode::Opcode, 
    result_reg: u8, operand_a_reg: u8, operand_b_reg: u8, operand_size_idx: u32) {
    cc_pka.opcode().write(|w| unsafe {
    w.bits(
    ((result_reg as u32) << REG_R_POS)
    | ((operand_b_reg as u32) << REG_B_POS)
    | ((operand_a_reg as u32) << REG_A_POS)
    | (operand_size_idx << LEN_POS)
    | ((opcode as u32) << OPCODE_POS)
    )
    });

    while cc_pka.pka_done().read().bits() == 0 {}

    // // We check if the result is correctly reduced. Otherwise, we apply reduction
    // cc_pka.pka_sram_raddr().write(|w| unsafe { 
    //     w.bits(cc_pka.memory_map(result_reg as usize).read().bits()) 
    // });
    // let mut result = [0u32; OPERAND_SIZE_WORDS];
    // for i in 0..OPERAND_SIZE_WORDS {
    //     result[7-i] = cc_pka.pka_sram_rdata().read().bits();
    // }
    // // Compare with N
    // if let Some(Ordering::Greater) = compare_arrays(&result, &N) {
    //     // Result > N, perform modular reduction
    //     execute_operation(cc_pka, cc_pka::opcode::Opcode::Reduction, 
    //         result_reg, result_reg, 0);
    // }
}

fn compare_arrays(a: &[u32; 8], b: &[u32]) -> Option<Ordering> {
    for i in 0..8 {
        match a[i].cmp(&b[i]) {
            Ordering::Equal => continue,
            other => return Some(other),
        }
    }
    Some(Ordering::Equal)
}


// Koblitz, N A Course In Number Theory And Cryptography (2Ed , Gtm 114, Springer,1994)(600Dpi)(L)(T)(123S) Mtc.djvu
//  page 30. Square roots mod p
fn calculate_sqrt(cc_pka: &pac::CcPka) -> Result<(), &'static str> {
    // Since p ≡ 3 (mod 4) for P-256, we can compute sqrt(a) = a^((p+1)/4) mod p
    // Load (p+1)/4 exponent into R7
    load_word_array(cc_pka, 7, &P_PLUS_1_DIV_4);
    
    // We need to perform modular exponentiation: R6 = R6^((p+1)/4) mod R0
    execute_operation(
        cc_pka, 
        cc_pka::opcode::Opcode::ModExp,
        6,  // Result register (R6)
        6,  // Base register (R6, containing x³ + ax + b)
        7,   // Exponent register (R7, containing (p+1)/4)
        1
    );
    
    // Read status to check for errors
    let status_bits = cc_pka.pka_status().read().bits();
    if ((status_bits >> 14) & 0x1) != 0 {
        return Err("Division by zero error");
    } else if ((status_bits >> 15) & 0x1) != 0 {
        return Err("Modular inverse of zero error");
    } else if ((status_bits >> 13) & 0x1) != 0 {
        return Err("Modular overflow error");
    }
    // R6 contains one square root
    // The other square root is p - R6
    // R7 = -R6 mod p (which is the same as p - R6)
    execute_operation(
        cc_pka,
        cc_pka::opcode::Opcode::ModSubDecNeg,
        7,  // Result register (R7)
        0,  // First operand (R0, containing p)
        6,   // Second operand (R6, containing the first root)
        1
    );

    Ok(())
}

fn read_y_coordinate(cc_pka: &pac::CcPka, positive_root: bool) -> [u32; 8] {
    let mut result = [0u32; 8];
    let reg = if positive_root { 6 } else { 7 };
    
    cc_pka.pka_sram_raddr().write(|w| unsafe {
        w.bits(cc_pka.memory_map(reg).read().bits())
    });
    
    // Read the result (in reverse order)
    for i in 0..8 {
        let word = cc_pka.pka_sram_rdata().read().bits();
        result[7 - i] = word;
    }
    
    result
}


 