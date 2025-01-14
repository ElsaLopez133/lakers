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
use nrf52840_pac::{cc_pka::{self, opcode::Opcode, pka_sram_wclear}, ficr::info, rtc0::cc}; 


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
const MAX_OPERAND_SIZE_BITS: usize = 62 * 4 * 8;
const OPERAND_SIZE_BITS: usize = 8 * 4 * 8;
const NP_OPERAND_SIZE_BITS: usize = 11 * 4 * 8;
const OPERAND_SIZE_WORDS: usize = OPERAND_SIZE_BITS/8/4;
const MAX_OPERAND_SIZE_WORDS: usize = MAX_OPERAND_SIZE_BITS/8/4;
const NP_OPERAND_SIZE_WORDS: usize = NP_OPERAND_SIZE_BITS/8/4;
const OPERAND_MEMORY_OFFSET: u32 = (OPERAND_SIZE_BITS as u32)/8/4 + 2;
const VIRTUAL_MEMORY_SIZE_BITS: usize = 64 * 4 * 8; // 64-bit word size
const VIRTUAL_MEMORY_OFFSET: u32 = (VIRTUAL_MEMORY_SIZE_BITS as u32)/8/4;

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
    0x00000000, 0x00000000, 0x00000000, 0x000000B
];

const NP: [u32; 8] = [
    0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000008, 0x00000000, 0x00000000, 0x00000000
];

const B: [u32; 8] = [
    0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000010
];

const A: [u32; 8] = [
    0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000
];

const P_PLUS_1_DIV_4: [u32; 8] = [
    0x3FFFFFFF, 0x40000000, 0x40000000, 0x40000000,
    0x40000000, 0x3FFFFFFF, 0xFFFFFFFF, 0x3FFFFFFF
];

const EXP: [u32; 8] = [
    0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000009
];
// test vectors: http://point-at-infinity.org/ecc/nisttv
// k = 1
// x = 6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
// y = 4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
static POINT_X: [u32; 8] = [
    0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000005,
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
    // max opernad size
    cc_pka.pka_l(0).write(|w| unsafe { w.bits(MAX_OPERAND_SIZE_BITS as u32) });
    // Operand size
    cc_pka.pka_l(1).write(|w| unsafe { w.bits(OPERAND_SIZE_BITS as u32) }); 
    // NP operand size 
    cc_pka.pka_l(2).write(|w| unsafe { w.bits(NP_OPERAND_SIZE_BITS as u32) }); 

    // Configure memory map
    configure_memory_map(&cc_pka);

    // Clear registers
    clear_pka_registers(&cc_pka);

    // Load N
    load_word_array(&cc_pka, 0, &N);
    
    // Calculate Np
    // calculate_np(&cc_pka);
    // load_word_array(&cc_pka, 1, &NP);

    // Load Curve Parameters
    // load_word_array(&cc_pka, 2, &A);
    // load_word_array(&cc_pka, 3, &B);

    // Load data to compute operations
    load_word_array(&cc_pka, 4, &POINT_X);
    load_word_array(&cc_pka, 5, &EXP);

    // Verify data is well written
    cc_pka.pka_sram_wclear();
    let mut buffer = [0u32; OPERAND_SIZE_WORDS + 3];
    read_word_array(&cc_pka, 0, &mut buffer);
    // read_word_array(&cc_pka, 1, &mut buffer);
    // read_word_array(&cc_pka, 2);
    // read_word_array(&cc_pka, 3);
    read_word_array(&cc_pka, 4, &mut buffer);
    read_word_array(&cc_pka, 5, &mut buffer);
    // read_word_array(&cc_pka, 6, &mut buffer);

    // calcluate y-coordinate
    // let point_y = calculate_y_coordinate(&cc_pka, 7);
    // info!("point_y: {:#X}", point_y);

    // example operation 4 * 5  = 6
    // clear_pka_register(&cc_pka, 6);
    execute_operation(&cc_pka, cc_pka::opcode::Opcode::ModMul, 6, 4, 0, 5, 0, 1);
    // cc_pka.pka_sram_wclear();
    let mut buffer = [0u32; OPERAND_SIZE_WORDS + 3];
    read_word_array(&cc_pka, 6, &mut buffer);

    // exit via semihosting call
    debug::exit(EXIT_SUCCESS);
    loop {}
}


fn configure_memory_map(cc_pka: &pac::CcPka) {
    // Map virtual registers
    // R0: modulus (N)
    // R1: Np
    // R2: a parameter
    // R3: b parameter
    // R4: operand A
    // R5: operand B
    // R6: result
    // R7: temporal
    // R8: temporal
    // T0: register 30
    // T1: register 31
    for i in 0..9 {
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

fn clear_pka_register(cc_pka: &pac::CcPka, reg: usize) {
    cc_pka.pka_sram_waddr().write(|w| unsafe { 
        w.bits(cc_pka.memory_map(reg).read().bits()) 
    });
    
    for _ in 0..MAX_OPERAND_SIZE_WORDS + 2 {
        cc_pka.pka_sram_wdata().write(|w| unsafe { 
            w.bits(0x00) 
        });
    }
}

fn clear_pka_registers(cc_pka: &pac::CcPka) {
    for i in 0..9 {
        cc_pka.pka_sram_waddr().write(|w| unsafe { 
            w.bits(cc_pka.memory_map(i).read().bits()) 
        });
        
        for _ in 0..MAX_OPERAND_SIZE_WORDS + 2 {
            cc_pka.pka_sram_wdata().write(|w| unsafe { 
                w.bits(0x00) 
            });
        }
    }
    for i in 30..32 {
        cc_pka.pka_sram_waddr().write(|w| unsafe { 
            w.bits(cc_pka.memory_map(i).read().bits()) 
        });
        
        for _ in 0..MAX_OPERAND_SIZE_WORDS + 2 {
            cc_pka.pka_sram_wdata().write(|w| unsafe { 
                w.bits(0x00) 
            });
        }
    }
}

fn load_word_array(cc_pka: &pac::CcPka, reg: usize, data: &[u32]) {
    cc_pka.pka_sram_waddr().write(|w| unsafe { 
        w.bits(cc_pka.memory_map(reg).read().bits()) 
    });
    
    // Load data in reverse order (little endian: least significative go first)
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

fn read_word_array(cc_pka: &pac::CcPka, reg: usize, buffer: &mut [u32]) {
    cc_pka.pka_sram_raddr().write(|w| unsafe { 
        w.bits(cc_pka.memory_map(reg).read().bits()) 
    });
    for i in 0..buffer.len() {
        buffer[buffer.len() - 1 - i] = cc_pka.pka_sram_rdata().read().bits();
    }
    info!("Verification of R{:?}: {:#X}", reg, buffer);
}

fn read_word_array_long(cc_pka: &pac::CcPka, reg: usize) {
    cc_pka.pka_sram_raddr().write(|w| unsafe { 
        w.bits(cc_pka.memory_map(reg).read().bits()) 
    });
    let mut verif = [0u32; MAX_OPERAND_SIZE_WORDS];
    for i in 0..MAX_OPERAND_SIZE_WORDS {
        verif[MAX_OPERAND_SIZE_WORDS - 1 -i] = cc_pka.pka_sram_rdata().read().bits();
    }
    info!("Verification of R{:?}: {:#X}", reg, verif);
}

fn read_result_array(cc_pka: &pac::CcPka, reg: usize, array: &mut [u32]) -> [u32; OPERAND_SIZE_WORDS] {
    cc_pka.pka_sram_raddr().write(|w| unsafe { 
        w.bits(cc_pka.memory_map(reg).read().bits()) 
    });
    let mut result = [0u32; OPERAND_SIZE_WORDS];
    for i in 0..OPERAND_SIZE_WORDS {
        result[OPERAND_SIZE_WORDS - 1 - i] = cc_pka.pka_sram_rdata().read().bits();
    }
    result
}

fn write_result_array(cc_pka: &pac::CcPka, reg: usize, result: &mut [u32; OPERAND_SIZE_WORDS]) {
    cc_pka.pka_sram_raddr().write(|w| unsafe { 
        w.bits(cc_pka.memory_map(reg).read().bits()) 
    });
    for i in 0..OPERAND_SIZE_WORDS {
        result[OPERAND_SIZE_WORDS - 1 - i] = cc_pka.pka_sram_rdata().read().bits();
    }
}

fn execute_operation(cc_pka: &pac::CcPka, opcode: cc_pka::opcode::Opcode, 
    result_reg: u8, operand_a_reg: u8, operand_a_ctrl: u8, operand_b_reg: u8, operand_b_ctrl: u8, operand_size_idx: u32) {
    cc_pka.opcode().write(|w| unsafe {
    w.bits(
    ((result_reg as u32) << REG_R_POS)
    | ((operand_b_reg as u32) << REG_B_POS)
    | ((operand_b_ctrl as u32) << REG_B_CTRL_POS)
    | ((operand_a_reg as u32) << REG_A_POS)
    | ((operand_a_ctrl as u32) << REG_A_CTRL_POS)
    | (operand_size_idx << LEN_POS)
    | ((opcode as u32) << OPCODE_POS)
    )
    });

    while cc_pka.pka_done().read().bits() == 0 {}

    // Status
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

    // // Np is greater than N normally
    // if result_reg != 1 {
    //     // We check if the result is correctly reduced. Otherwise, we apply reduction
    //     cc_pka.pka_sram_raddr().write(|w| unsafe { 
    //         w.bits(cc_pka.memory_map(result_reg as usize).read().bits()) 
    //     });
    //     let mut result = [0u32; OPERAND_SIZE_WORDS];
    //     for i in 0..OPERAND_SIZE_WORDS {
    //         result[OPERAND_SIZE_WORDS - 1 - i] = cc_pka.pka_sram_rdata().read().bits();
    //     }
    //     // Compare with N
    //     if let Some(Ordering::Greater) = compare_arrays(&result, &N) {
    //         // Result > N, perform modular reduction
    //         execute_operation(cc_pka, cc_pka::opcode::Opcode::Reduction, 
    //             result_reg, result_reg, 0, 0);
    //     }
    // }
}

fn compare_arrays(a: &[u32], b: &[u32]) -> Option<Ordering> {
    for i in 0..MAX_OPERAND_SIZE_WORDS {
        match a[i].cmp(&b[i]) {
            Ordering::Equal => continue,
            other => return Some(other),
        }
    }
    Some(Ordering::Equal)
}

fn calculate_np(cc_pka: &pac::CcPka) -> () {

    // Clear temporary registers (tempN: 7, tempNp: 8, Np: 1)
    clear_pka_register(cc_pka, 7);
    clear_pka_register(cc_pka, 8);
    clear_pka_register(cc_pka, 1);

    // Copy N into tempN: 7
    // even though N is in R0, when doing the division next the reminder will be stored 
    // in REG_B, which is why we need a temp register for N
    load_word_array(cc_pka, 7, &N);
    // let mut buffer = [0u32; MAX_OPERAND_SIZE_WORDS];
    // read_word_array(cc_pka, 7, &mut buffer);

    // https://github.com/ARM-software/cryptocell-312-runtime/blob/update-cc110-bu-00000-r1p4/codesafe/src/crypto_api/pki/common/pka.c#L580
    // line 580
    let a: usize = 64; // The size of the PKA engine word in bits.
    let x: usize = 8; // The maximal count of extra bits in PKA operations.

    let total_bits = OPERAND_SIZE_BITS + a + x - 1;

    // Create big number representing 2^(N+A+X-1)    
    let word_index = total_bits / 32;
    let bit_index = total_bits % 32;
    let mut numerator = [0u32; MAX_OPERAND_SIZE_WORDS];
    numerator[MAX_OPERAND_SIZE_WORDS - 1 - word_index] = 1 << bit_index;
    // info!("numerator: {:#X}", numerator);

    // Load data in reverse order into a temp register
    load_word_array(&cc_pka, 8, &numerator);
    // Check
    // let mut buffer = [0u32; MAX_OPERAND_SIZE_WORDS];
    // read_word_array(cc_pka, 8, &mut buffer);
 
    // execute division
    execute_operation(
        &cc_pka, 
        cc_pka::opcode::Opcode::Division, 
        1, 
        8,
        0, 
        7, 
        0,
        0
    );
 }


// Guide to Elliptic Curve Cryptography: point addition
fn point_addition_ecc(
    cc_pka: &pac::CcPka,
    p1_x: &[u32; OPERAND_SIZE_WORDS],
    p1_y: &[u32; OPERAND_SIZE_WORDS],
    p2_x: &[u32; OPERAND_SIZE_WORDS],
    p2_y: &[u32; OPERAND_SIZE_WORDS]
) -> Result<([u32; OPERAND_SIZE_WORDS], [u32; OPERAND_SIZE_WORDS]), &'static str> {
    // Register allocation:
    // R4: x1
    // R5: y1
    // R6: x2
    // R7: y2
    // R8: Used for delta and temporary calculations
    // R9: x3 (result)
    // R10: y3 (result)
    
    // Load points into PKA registers
    load_word_array(cc_pka, 4, p1_x);
    load_word_array(cc_pka, 5, p1_y);
    load_word_array(cc_pka, 6, p2_x);
    load_word_array(cc_pka, 7, p2_y);

    // Check if points are equal - if so, should use point doubling instead
    execute_operation(
        cc_pka,
        cc_pka::opcode::Opcode::ModSubDecNeg,
        8,  // Result in R8
        6,  // x2 in R6
        0,
        4,  // x1 in R4
        0,
        1
    );
    
    let mut temp = [0u32; OPERAND_SIZE_WORDS];
    read_result_array(cc_pka, 8, &mut temp);
    if temp.iter().all(|&x| x == 0) {
        return Err("Points are equal - use point doubling instead");
    }

    // Calculate delta = (y2-y1)/(x2-x1)
    // First y2-y1 in R8
    execute_operation(
        cc_pka,
        cc_pka::opcode::Opcode::ModSubDecNeg,
        8,  // Result in R8
        7,  // y2 in R7
        0,
        5,  // y1 in R5
        0,
        1
    );
    
    // Then x2-x1 in R11 (using R11 as additional temp)
    execute_operation(
        cc_pka,
        cc_pka::opcode::Opcode::ModSubDecNeg,
        11,  // Result in R11
        6,   // x2 in R6
        0,
        4,   // x1 in R4
        0,
        1
    );
    
    // Calculate inverse of (x2-x1) in R11
    execute_operation(
        cc_pka,
        cc_pka::opcode::Opcode::ModInv,
        11,  // Result in R11
        11,  // Input in R11
        0,
        0,   // Not used
        0,
        1
    );
    
    // Multiply to get delta = (y2-y1)/(x2-x1) in R8
    execute_operation(
        cc_pka,
        cc_pka::opcode::Opcode::ModMul,
        8,   // Result in R8 (delta)
        8,   // (y2-y1) in R8
        0,
        11,  // 1/(x2-x1) in R11
        0,
        1
    );
    
    // Calculate x3 = delta² - x1 - x2
    // First delta² in R9
    execute_operation(
        cc_pka,
        cc_pka::opcode::Opcode::ModMul,
        9,  // Result in R9
        8,  // delta in R8
        0,
        8,  // delta in R8
        0,
        1
    );
    
    // Subtract x1
    execute_operation(
        cc_pka,
        cc_pka::opcode::Opcode::ModSubDecNeg,
        9,  // Result in R9
        9,  // delta² in R9
        0,
        4,  // x1 in R4
        0,
        1
    );
    
    // Subtract x2
    execute_operation(
        cc_pka,
        cc_pka::opcode::Opcode::ModSubDecNeg,
        9,  // Result in R9
        9,  // (delta² - x1) in R9
        0,
        6,  // x2 in R6
        0,
        1
    );
    
    // Calculate y3 = delta(x1 - x3) - y1
    // First (x1 - x3) in R11
    execute_operation(
        cc_pka,
        cc_pka::opcode::Opcode::ModSubDecNeg,
        11,  // Result in R11
        4,   // x1 in R4
        0,
        9,   // x3 in R9
        0,
        1
    );
    
    // Multiply by delta
    execute_operation(
        cc_pka,
        cc_pka::opcode::Opcode::ModMul,
        10,  // Result in R10
        8,   // delta in R8
        0,
        11,  // (x1 - x3) in R11
        0,
        1
    );
    
    // Subtract y1
    execute_operation(
        cc_pka,
        cc_pka::opcode::Opcode::ModSubDecNeg,
        10,  // Result in R10
        10,  // delta(x1 - x3) in R10
        0,
        5,   // y1 in R5
        0,
        1
    );

    // Read results
    let mut x3 = [0u32; OPERAND_SIZE_WORDS];
    let mut y3 = [0u32; OPERAND_SIZE_WORDS];
    write_result_array(cc_pka, 9, &mut x3);
    write_result_array(cc_pka, 10, &mut y3);

    Ok((x3, y3))
}

// Koblitz, N A Course In Number Theory And Cryptography (2Ed , Gtm 114, Springer,1994)(600Dpi)(L)(T)(123S) Mtc.djvu
//  page 30. Square roots mod p
fn calculate_sqrt(cc_pka: &pac::CcPka, reg: usize) -> Result<[u32; OPERAND_SIZE_WORDS], &'static str> {
    // Since p ≡ 3 (mod 4) for P-256, we can compute sqrt(a) = a^((p+1)/4) mod p
    // Load (p+1)/4 exponent into R7
    load_word_array(cc_pka, 7, &P_PLUS_1_DIV_4);
    
    // We need to perform modular exponentiation: R6 = R6^((p+1)/4) mod R0
    execute_operation(
        cc_pka, 
        cc_pka::opcode::Opcode::ModExp,
        reg as u8,  // Result register (R6)
        reg as u8,  // Base register (R6, containing x³ + ax + b)
        0,
        7,   // Exponent register (R7, containing (p+1)/4)
        0,
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
        0,
        reg as u8,   // Second operand (R6, containing the first root)
        0,
        1
    );

    // Store the result in an array
    cc_pka.pka_sram_raddr().write(|w| unsafe { 
        w.bits(cc_pka.memory_map(reg).read().bits()) 
    });
    let mut sqrt = [0u32; OPERAND_SIZE_WORDS];
    for i in 0..OPERAND_SIZE_WORDS {
        sqrt[OPERAND_SIZE_WORDS - 1 -i] = cc_pka.pka_sram_rdata().read().bits();
    }

    Ok(sqrt)
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

fn calculate_y_coordinate(cc_pka: &pac::CcPka, reg: usize) -> Result<[u32; OPERAND_SIZE_WORDS], &'static str> {
    // Calculate y = sqrt(x³ + ax + b mod p)
    // 1. Calculate x³ mod p
    execute_operation(
        &cc_pka, 
        cc_pka::opcode::Opcode::ModExp, 
        5, 
        4,
        0, 
        3, 
        1, 
        0
    );
    // read_word_array(&cc_pka, 5);

    // 2. Calculate ax mod p
    execute_operation(
        &cc_pka, 
        cc_pka::opcode::Opcode::ModMul, 
        4, 
        4, 
        0,
        2, 
        0,
        0
    );
    // read_word_array(&cc_pka, 4); 

    // 3. Add terms and b
    execute_operation(
        &cc_pka, 
        cc_pka::opcode::Opcode::ModAddInc, 
        5, 
        5, 
        0,
        4, 
        0,
        0
    );
    execute_operation(
        &cc_pka, 
        cc_pka::opcode::Opcode::ModAddInc, 
        6, 
        5, 
        0,
        3, 
        0,
        0
    );
    
    // 4. Calculate sqrt
    calculate_sqrt(&cc_pka, reg)
}
 