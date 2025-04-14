#![no_std]

use lakers_shared::{GpioPin, A, A_SIGN, B, BASE, COEF_A_OFFSET, COEF_A_OFFSET_ADD, COEF_A_SIGN_OFFSET, COEF_A_SIGN_OFFSET_ADD, COEF_B_OFFSET, MODE, MODULUS_LENGTH_OFFSET, MODULUS_LENGTH_OFFSET_ADD, MODULUS_OFFSET, MODULUS_OFFSET_ADD, MODULUS_OFFSET_PTA, MODULUS_REDUC, MODULUS_SUB, MONTGOMERY_PTA, N, OPERAND_A_ARITHEMTIC_MULT, OPERAND_A_REDUC, OPERAND_A_SUB, OPERAND_B_ARITHEMTIC_MULT, OPERAND_B_SUB, OPERAND_LENGTH, OPERAND_LENGTH_MULT, OPERAND_LENGTH_REDUC, OPERAND_LENGTH_SUB, PKA_RAM_OFFSET, POINT_P_X, POINT_P_X_PTA, POINT_P_Y, POINT_P_Y_PTA, POINT_P_Z, POINT_P_Z_PTA, POINT_Q_X, POINT_Q_Y, POINT_Q_Z, POINT_X_OFFSET, POINT_Y_OFFSET, PRIME_LENGTH_OFFSET, PRIME_LENGTH_OFFSET_ADD, PRIME_OFFSET, PRIME_ORDER, R2MODN, RAM_BASE, RAM_NUM_DW, RESULT_ARITHMETIC_MULT, RESULT_ERROR_ADD, RESULT_ERROR_OFFSET, RESULT_ERROR_PTA, RESULT_REDUC, RESULT_SUB, RESULT_X_ADD, RESULT_X_OFFSET, RESULT_X_PTA, RESULT_Y_ADD, RESULT_Y_OFFSET, RESULT_Y_PTA, SCALAR_K_ADD, SCALAR_M_ADD, SCALAR_OFFSET, WORD_LENGTH, Z_COORDINATE 
};
// use lakers::shared{X, G_X_X_COORD, G_X_Y_COORD, I, CRED_I};

use lakers_shared::{
    BufferCiphertext3, BufferPlaintext3, BytesCcmIvLen, BytesCcmKeyLen, BytesHashLen,
    BytesMaxBuffer, BytesMaxInfoBuffer, BytesP256ElemLen, Crypto as CryptoTrait, EDHOCError,
    AES_CCM_TAG_LEN, MAX_BUFFER_LEN, BytesP256AuthPubKey,SokLogProof,SokLogEqProof, P256_ELEM_LEN
};

use core::{
    mem::size_of,
    ptr::{read_volatile, write_volatile},
};

use ccm::AeadInPlace;
use ccm::KeyInit;
use p256::elliptic_curve::point::AffineCoordinates;
use p256::elliptic_curve::point::DecompressPoint;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::elliptic_curve::sec1::FromEncodedPoint;
use p256::elliptic_curve::Field;
use p256::elliptic_curve::PrimeField;
use p256::elliptic_curve::Group;
use p256::{
    PublicKey,
    EncodedPoint,
    AffinePoint,
    ProjectivePoint,
    FieldBytes,
    Scalar,
};
use sha2::Digest;
use cortex_m::asm;
use stm32wba::stm32wba55::{self, GPIOA, USART1};
use stm32wba::stm32wba55::Peripherals as peripherals;
use stm32wba::stm32wba55::PKA as PKA;
use stm32wba::stm32wba55::HASH as HASH;
use stm32wba::stm32wba55::RCC as RCC;
use stm32wba::stm32wba55::RNG as RNG;
use defmt::{info, trace};
use hexlit::hex;

type AesCcm16_64_128 = ccm::Ccm<aes::Aes128, ccm::consts::U8, ccm::consts::U13>;

pub const X: [u8; 32] = hex!("368ec1f69aeb659ba37d5a8d45b21bdc0299dceaa8ef235f3ca42ce3530f9525");
pub const G_X_X_COORD: [u8; 32] = hex!("8af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b6");
pub const G_X_Y_COORD: [u8; 32] = hex!("51e8af6c6edb781601ad1d9c5fa8bf7aa15716c7c06a5d038503c614ff80c9b3");
pub const CRED_I: &[u8] = &hex!("A2027734322D35302D33312D46462D45462D33372D33322D333908A101A5010202412B2001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8");
pub const I: &[u8] = &hex!("fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b");
pub const SK: [u8; 32] = hex!("5c4172aca8b82b5a62e66f722216f5a10f72aa69f42c1d1cd3ccd7bfd29ca4e9");
pub const BASE_POINT_X: [u8; 32] = hex!("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
pub const BASE_POINT_Y: [u8; 32] = hex!("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");


fn bytes_to_point(bytes: &[u8]) -> ([u8; 32], [u8; 32]) {
    // Create an EncodedPoint from the compressed bytes
    let mut compressed_point: [u8; 33] = [0; 33];    
    compressed_point[0] = 0x02;        
    compressed_point[1..].copy_from_slice(bytes);

    let encoded_point = EncodedPoint::from_bytes(&compressed_point).expect("Invalid encoded point");
    
    // Convert to PublicKey
    let public_key = PublicKey::from_encoded_point(&encoded_point)
        .expect("Invalid point encoding");
    
    // Get the point in affine coordinates
    let point = public_key.as_affine();
    
    // Convert to uncompressed EncodedPoint to access coordinates
    let uncompressed = point.to_encoded_point(false);
    
    // Extract the x and y coordinates as byte arrays
    let x_bytes: [u8; 32] = uncompressed.x().unwrap().clone().into();
    let y_bytes: [u8; 32] = uncompressed.y().unwrap().clone().into();
    
    (x_bytes, y_bytes)
}

fn bytes_to_point_odd(bytes: &[u8]) -> ([u8; 32], [u8; 32]) {
    // Create an EncodedPoint from the compressed bytes
    let mut compressed_point: [u8; 33] = [0; 33];    
    compressed_point[0] = 0x03;        
    compressed_point[1..].copy_from_slice(bytes);

    let encoded_point = EncodedPoint::from_bytes(&compressed_point).expect("Invalid encoded point");
    
    // Convert to PublicKey
    let public_key = PublicKey::from_encoded_point(&encoded_point)
        .expect("Invalid point encoding");
    
    // Get the point in affine coordinates
    let point = public_key.as_affine();
    
    // Convert to uncompressed EncodedPoint to access coordinates
    let uncompressed = point.to_encoded_point(false);
    
    // Extract the x and y coordinates as byte arrays
    let x_bytes: [u8; 32] = uncompressed.x().unwrap().clone().into();
    let y_bytes: [u8; 32] = uncompressed.y().unwrap().clone().into();
    
    (x_bytes, y_bytes)
}

fn coordinates_to_projective_point(
    x: BytesP256ElemLen,
    y: BytesP256ElemLen
) -> ProjectivePoint {
    
    // Convert h_x and h_y bytes into an AffinePoint
    let x_scalar = p256::FieldBytes::from_slice(&x);
    let y_scalar = p256::FieldBytes::from_slice(&y);

    // Create an encoded point
    let encoded_point = EncodedPoint::from_affine_coordinates(
        x_scalar, 
        y_scalar, 
        false // Uncompressed form
    );
    // Parse into an actual curve point
    let point = AffinePoint::from_encoded_point(&encoded_point)
    .expect("Invalid curve point");

    // Convert to projective for efficient operations
    let point_proj = ProjectivePoint::from(point);

    point_proj
}

fn projective_to_coordinates(
    h: ProjectivePoint
) -> ([u8; 32], [u8; 32]) {
    let h_affine = h.to_affine();
    let uncompressed = h_affine.to_encoded_point(false);
    let h_x: [u8; 32] = uncompressed.x().unwrap().clone().into();
    let h_y: [u8; 32] = uncompressed.y().unwrap().clone().into();

    (h_x, h_y)
}

fn ecc_generator_mult_projective(
    r: Scalar
) -> ProjectivePoint {

    let g_r = p256::ProjectivePoint::generator() * r;
    g_r
}

fn ecc_generator_mult(
    r: Scalar
) -> ([u8; 32], [u8; 32]) {

    let g_r = p256::ProjectivePoint::generator() * r;
    let g_r_affine = g_r.to_affine();
    let uncompressed = g_r_affine.to_encoded_point(false);
    let g_r_x: [u8; 32] = uncompressed.x().unwrap().clone().into();
    let g_r_y: [u8; 32] = uncompressed.y().unwrap().clone().into();

    (g_r_x, g_r_y)
}

fn ecc_mult_scalar(
    h: BytesP256ElemLen,
    r: Scalar
) -> ([u8; 32], [u8; 32]) {

    let (h_point_x, h_point_y) = bytes_to_point(&h);
    let h_proj_point = coordinates_to_projective_point(h_point_x, h_point_y);
    let h_r = h_proj_point * r;
    let h_r_affine = h_r.to_affine();
    let uncompressed = h_r_affine.to_encoded_point(false);
    let h_r_x: [u8; 32] = uncompressed.x().unwrap().clone().into();
    let h_r_y: [u8; 32] = uncompressed.y().unwrap().clone().into();

    (h_r_x, h_r_y)
}

unsafe fn write_ram(offset: usize, buf: &[u32]) {
    debug_assert_eq!(offset % 4, 0);
    debug_assert!(offset + buf.len() * size_of::<u32>() < 0x520C_33FF);
    buf.iter().rev().enumerate().for_each(|(idx, &dw)| {
        write_volatile((offset + idx * size_of::<u32>()) as *mut u32, dw)
    });
}

unsafe fn read_ram(offset: usize, buf: &mut [u32]) {
    debug_assert_eq!(offset % 4, 0);
    debug_assert!(offset + buf.len() * size_of::<u32>() < 0x520C_33FF);
    buf.iter_mut().rev().enumerate().for_each(|(idx, dw)| {
        *dw = read_volatile((offset + idx * size_of::<u32>()) as *const u32);
    });
}

unsafe fn zero_ram() {
    (0..RAM_NUM_DW)
        .into_iter()
        .for_each(|dw| unsafe { write_volatile((dw * 4 + RAM_BASE) as *mut u32, 0) });
}

// pub fn u32_to_u8(arr: &[u32; 8]) -> [u8; 32] {
//     let mut result = [0u8; 32];
//     for (i, &val) in arr.iter().enumerate() {
//         result[i * 4..(i + 1) * 4].copy_from_slice(&val.to_le_bytes());
//     }
//     result
// }

pub fn u32_to_u8(input: &[u32; 8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, word) in input.iter().enumerate() {
        let bytes = word.to_be_bytes(); // convert u32 to [u8; 4] in big-endian
        out[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
    }
    out
}

pub fn u8_to_u32(bytes: &[u8; 32]) -> [u32; 8] {
    let mut words = [0u32; 8];
    for i in 0..8 {
        words[i] = u32::from_be_bytes([
            bytes[i * 4],
            bytes[i * 4 + 1],
            bytes[i * 4 + 2],
            bytes[i * 4 + 3],
        ]);
    }
    words
}

pub fn int_to_u8_array(r: u32) -> [u8; 32] {
    let mut result = [0u8; 32]; // Create a 32-byte array
    let bytes = r.to_be_bytes(); // Convert the integer to bytes (big-endian)
    
    // Copy the bytes of r into the array starting from the last bytes
    result[32 - bytes.len()..].copy_from_slice(&bytes);

    result
}

pub struct Crypto<'a> {
    p: &'a peripherals,
    hash: &'a HASH,
    pka: &'a PKA,
    rng: &'a RNG,
}

impl<'a> Crypto<'a> {
    pub fn new(p: &'a peripherals, hash: &'a HASH, pka: &'a PKA, rng: &'a RNG) -> Self {
        Self { p, hash, pka, rng }
    }

    // pub unsafe fn stm32wba_init_uart(&self) -> &USART1 {
    //     let p = stm32wba55::Peripherals::take().unwrap();
    //     let rcc = &p.RCC;
    //     let uart = &p.USART1;

    //     // Enable HSI as a stable clock source
    //     rcc.rcc_cr().modify(|_, w| w
    //         .hseon().set_bit()
    //     );
    //     while rcc.rcc_cr().read().hserdy().bit_is_clear() {
    //         asm::nop();
    //     }
    //     // rcc.rcc_ccipr1().modify(|_, w| w.usart1sel().bits(clk as u8));

    //     // let freq: u32 = uart. clock_hz(rcc);
    //     let freq = 1;

    //     // only for oversampling of 16 (default), change for oversampling of 8
    //     let baud = 115_200;
    //     let br: u16 = (freq / baud) as u16;
    //     uart.usart_brr().write(|w| w.brr().bits(br));
    //     uart.usart_cr1().write(|w| w.ue().set_bit().fifoen().set_bit());

    //     &uart
    // }

    pub fn lakers_crypto_rustcrypto_stm_init(&self) {

        let rng = Self::stm32wba_init_rng(self);
        let hash = Self::stm32wba_init_hash(self);
        let pka = Self::stm32wba_init_pka(self);
        
    }

    fn stm32wba_init_rng(&self) -> &RNG {
        let clock = &self.p.RCC;

        // Enable HSE as a stable clock source. HSE when using PKA and HASH
        clock.rcc_cr().modify(|_, w| w
            .hsion().set_bit()
        );
        while clock.rcc_cr().read().hsirdy().bit_is_clear() {
            asm::nop();
        }
    
        // Enable RNG clock. Select the source clock
        clock.rcc_ccipr2().write(|w| w.rngsel().b_0x2());
        // Enable RNG clock. Select the AHB clock
        clock.rcc_ahb2enr().modify(|_, w| w.rngen().set_bit());
        while clock.rcc_ahb2enr().read().rngen().bit_is_clear() {
            asm::nop();
        }
    
        // Configure RNG
        // To configure, CONDRST bit is set to 1 in the same access and CONFIGLOCK remains at 0
        self.rng.rng_cr().write(|w| w
            .rngen().clear_bit()
            .condrst().set_bit()
            .configlock().clear_bit()
            .nistc().clear_bit()   // Hardware default values for NIST compliant RNG
            .ced().clear_bit()     // Clock error detection enabled
        );
    
        // First clear CONDRST while keeping RNGEN disabled
        self.rng.rng_cr().modify(|_, w| w
            .condrst().clear_bit()
        );
    
        // Then enable RNG in a separate step
        self.rng.rng_cr().modify(|_, w| w
            .rngen().set_bit()
            .ie().set_bit()
        );
        
        while self.rng.rng_sr().read().drdy().bit_is_clear() {
            asm::nop();
        }

        &self.rng
    }

    fn stm32wba_init_pka(&self) -> &PKA {
        let clock = &self.p.RCC;

        // Enable PKA peripheral clock via RCC_AHB2ENR register
        clock.rcc_ahb2enr().modify(|_, w| w.pkaen().set_bit());

        // Reset PKA before enabling (sometimes helps with initialization)
        self.pka.pka_cr().modify(|_, w| w.en().clear_bit());
        for _ in 0..10 {
            asm::nop();
        }

        // Enable PKA peripheral
        self.pka.pka_cr().write(|w| w
            .en().set_bit()
        );
    
        // Wait for PKA to initialize
        while self.pka.pka_sr().read().initok().bit_is_clear() {
            asm::nop();
        }
        
        &self.pka
    }

    fn stm32wba_init_hash(&self) -> &HASH {

        // Enable HASH peripheral clock via RCC_AHB2ENR register
        // HASH peripheral is located on AHB2
        let clock = &self.p.RCC;

        clock.rcc_ahb2enr().modify(|_, w| w.hashen().set_bit());

        // Reset HASH peripheral
        self.hash.hash_cr().write(|w| w.init().set_bit());
        while self.hash.hash_cr().read().init().bit_is_set() {
            asm::nop();
        }

        // Configure for SHA-256 mode with byte-swapping
        unsafe {
            self.hash.hash_cr().write(|w| w
                .algo().bits(0b11)      // SHA-256 algorithm
                .mode().bit(false)      // Hash mode (not HMAC)
                .datatype().bits(0b10)  // 8-bit data with byte swapping
                .dmae().clear_bit()     // No DMA
                .init().set_bit()     
            );
        }

        // TODO
        &self.hash
    }

    fn stm32wba_init_rcc(&self) -> &RCC {
        // TODO
        &self.p.RCC
    }
}

impl core::fmt::Debug for Crypto<'_>  {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        f.debug_struct("lakers_crypto_rustcrypto::Crypto")
            // Exclude the rng field from Debug output
            .finish()
    }
}

impl CryptoTrait for Crypto<'_>  {

    unsafe fn pka_ecc_projective_to_affine(
        &mut self, 
        point_a_x: BytesP256ElemLen, 
        point_a_y: BytesP256ElemLen,
        point_a_z: BytesP256ElemLen,
    ) -> (BytesP256ElemLen, BytesP256ElemLen ) {

        // FIXME: It always return zero even though there is no error flag
        
        self.stm32wba_init_pka();

        // Convert points to the right format
        let point_a_x_u32 = u8_to_u32(&point_a_x);
        let point_a_y_u32 = u8_to_u32(&point_a_y);
        let point_a_z_u32 = u8_to_u32(&point_a_z);

        zero_ram();
        // constant values for P-256 curve
        write_ram(MODULUS_LENGTH_OFFSET, &[OPERAND_LENGTH]);
        write_ram(MONTGOMERY_PTA, &R2MODN);
        write_ram(MODULUS_OFFSET_PTA, &N);

        write_ram(POINT_P_X_PTA, &point_a_x_u32);
        write_ram(POINT_P_Y_PTA, &point_a_y_u32);
        write_ram(POINT_P_Z_PTA, &point_a_z_u32);

        // Configure PKA operation mode and start
        self.pka.pka_cr().modify(|_, w| w
            .mode().bits(0x2F)
            .start().set_bit()
        );

        // Wait for processing to complete - PROCENDF is 1 when done
        while self.pka.pka_sr().read().procendf().bit_is_clear() {
            asm::nop();
        }

        // Read the result
        let mut result = [0u32; 1];
        let mut result_x = [0u32; 8];
        let mut result_y = [0u32; 8];
        read_ram(RESULT_ERROR_PTA, &mut result);
        if result[0] == 0xD60D {
            // info!("No errors: {:#X}", result[0]);
            read_ram(RESULT_X_PTA, &mut result_x);
            read_ram(RESULT_Y_PTA, &mut result_y);
            // info!("POINT (X, Y): ({:#X}, {:#X})", result_x, result_y);
        }
        if result[0] == 0xA3B7 {
            // info!("Error in computation: {:#X}", result);
        }
                
        // Clear the completion flag
        self.pka.pka_clrfr().write(|w| w.procendfc().set_bit());

        (u32_to_u8(&result_x), u32_to_u8(&result_y))

    }

    // WORKS 
    unsafe fn pka_ecc_point_add(
        &mut self, 
        point_a_x: BytesP256ElemLen, 
        point_a_y: BytesP256ElemLen, 
        point_b_x: BytesP256ElemLen, 
        point_b_y: BytesP256ElemLen
    ) -> (BytesP256ElemLen, BytesP256ElemLen) {

        self.stm32wba_init_pka();
        //  Perform PQ where P and W are points of the curve (in ECC notation this is P + Q

        // Convert points to the right format
        let point_a_x_u32 = u8_to_u32(&point_a_x);
        let point_a_y_u32 = u8_to_u32(&point_a_y);
        let point_b_x_u32 = u8_to_u32(&point_b_x);
        let point_b_y_u32 = u8_to_u32(&point_b_y);

        zero_ram();
        // constant values for P-256 curve
        write_ram(MODULUS_LENGTH_OFFSET_ADD, &[OPERAND_LENGTH]);
        write_ram(PRIME_LENGTH_OFFSET_ADD, &[OPERAND_LENGTH]);
        write_ram(COEF_A_SIGN_OFFSET_ADD, &[A_SIGN]);
        write_ram(COEF_A_OFFSET_ADD, &A);
        // write_ram(COEF_B_OFFSET, &B);
        write_ram(MODULUS_OFFSET_ADD, &N);

        write_ram(POINT_P_X, &point_a_x_u32);
        write_ram(POINT_P_Y, &point_a_y_u32);
        write_ram(POINT_P_Z, &Z_COORDINATE);

        write_ram(POINT_Q_X, &point_b_x_u32);
        write_ram(POINT_Q_Y, &point_b_y_u32);
        write_ram(POINT_Q_Z, &Z_COORDINATE);

        write_ram(SCALAR_K_ADD, &[1]);
        write_ram(SCALAR_M_ADD, &[1]);

        // Configure PKA operation mode and start
        self.pka.pka_cr().modify(|_, w| w
            .mode().bits(0x27)
            .start().set_bit()
        );

        // Wait for processing to complete - PROCENDF is 1 when done
        while self.pka.pka_sr().read().procendf().bit_is_clear() {
            asm::nop();
        }

        // Read the result
        let mut result_x = [0u32; 8];
        let mut result_y = [0u32; 8];

        read_ram(RESULT_X_ADD, &mut result_x);
        read_ram(RESULT_Y_ADD, &mut result_y);

        // Clear the completion flag
        self.pka.pka_clrfr().write(|w| w.procendfc().set_bit());

        // Check: compare to the value in software
        let point_a = coordinates_to_projective_point(point_a_x, point_a_y);
        let point_b = coordinates_to_projective_point(point_b_x, point_b_y);
        let sum = point_a + point_b;
        let (sum_x, sum_y) = projective_to_coordinates(sum);

        // info!("software a + b : ({:#X}, {:#X})", sum_x, sum_y);
        // info!("hardware a + b : ({:#X}, {:#X})", result_x, result_y);

        
        (u32_to_u8(&result_x), u32_to_u8(&result_y))

    }

    // WORKS
    unsafe fn pka_ecc_mult_scalar(
        &mut self, 
        point_x: BytesP256ElemLen, 
        point_y: BytesP256ElemLen, 
        scalar: BytesP256ElemLen
    ) -> (BytesP256ElemLen, BytesP256ElemLen) {

        self.stm32wba_init_pka();
        //  Perform g^r where g is a point of the curve and r a scalar (in ECC notation this is g * r)
        // Because stm32wba_init_pka has been called before, pka is already initialized in self.pka

        // Convert points to the right format
        let point_x_u32 = u8_to_u32(&point_x);
        let point_y_u32 = u8_to_u32(&point_y);
        let scalar_u32 = u8_to_u32(&scalar);
        
        zero_ram();
        // constant values for P-256 curve
        write_ram(MODULUS_LENGTH_OFFSET, &[OPERAND_LENGTH]);
        write_ram(PRIME_LENGTH_OFFSET, &[OPERAND_LENGTH]);
        write_ram(COEF_A_SIGN_OFFSET, &[A_SIGN]);
        write_ram(COEF_A_OFFSET, &A);
        write_ram(COEF_B_OFFSET, &B);
        write_ram(MODULUS_OFFSET, &N);
        write_ram(PRIME_OFFSET, &PRIME_ORDER);

        write_ram(POINT_X_OFFSET, &point_x_u32);
        write_ram(POINT_Y_OFFSET, &point_y_u32);
        write_ram(SCALAR_OFFSET, &scalar_u32);
    
        
        // Configure PKA operation mode and start
        self.pka.pka_cr().modify(|_, w| w
            .mode().bits(0x20)
            .start().set_bit()
        );

        // Wait for processing to complete - PROCENDF is 1 when done
        while self.pka.pka_sr().read().procendf().bit_is_clear() {
            asm::nop();
        }

        // Read the result
        let mut result = [0u32; 1];
        let mut result_x = [0u32; 8];
        let mut result_y = [0u32; 8];
        read_ram(RESULT_ERROR_OFFSET, &mut result);
        if result[0] == 0xD60D {
            // info!("No errors: {:#X}", result[0]);
            read_ram(RESULT_X_OFFSET, &mut result_x);
            read_ram(RESULT_Y_OFFSET, &mut result_y);
            // info!("POINT (X, Y): ({:#X}, {:#X})", result_x, result_y);
        }
        if result[0] == 0xCBC9 {
            // info!("Error in computation: {:#X}", result);
        }
                
        // Clear the completion flag
        self.pka.pka_clrfr().write(|w| w.procendfc().set_bit());

        // // Check: compare to the value in software
        // let point = coordinates_to_projective_point(point_x, point_y);
        // let r_scalar = Scalar::from_repr(scalar.into()).unwrap();
        // let mult = point * r_scalar;
        // let (mult_x, mult_y) = projective_to_coordinates(mult);

        // info!("software a ^ b : ({:#X}, {:#X})", mult_x, mult_y);
        // info!("hardware a ^ b : ({:#X}, {:#X})", result_x, result_y);

        (u32_to_u8(&result_x), u32_to_u8(&result_y))
    }

    unsafe fn pka_mod_mult(
        &mut self, 
        a: &BytesP256ElemLen, 
        b: &BytesP256ElemLen, 
    ) -> BytesP256ElemLen {

        self.stm32wba_init_pka();

        // Convert points to the right format
        let a_u32 = u8_to_u32(&a);
        let b_u32 = u8_to_u32(&b);
        
        zero_ram();
        // constant values for P-256 curve
        write_ram(OPERAND_LENGTH_MULT, &[OPERAND_LENGTH]);
        write_ram(OPERAND_A_ARITHEMTIC_MULT, &a_u32);
        write_ram(OPERAND_B_ARITHEMTIC_MULT, &b_u32);    
        
        // Configure PKA operation mode and start
        self.pka.pka_cr().modify(|_, w| w
            .mode().bits(0x0B)
            .start().set_bit()
        );

        // Wait for processing to complete - PROCENDF is 1 when done
        while self.pka.pka_sr().read().procendf().bit_is_clear() {
            asm::nop();
        }

        // Read the result
        let mut result = [0u32; 8];
        read_ram(RESULT_ARITHMETIC_MULT, &mut result);
                
        // Clear the completion flag
        self.pka.pka_clrfr().write(|w| w.procendfc().set_bit());

        // We now reduce the value mod n
        // self.stm32wba_init_pka();

        zero_ram();
        write_ram(OPERAND_LENGTH_REDUC, &[OPERAND_LENGTH]);
        write_ram(MODULUS_LENGTH_OFFSET, &[OPERAND_LENGTH]);
        write_ram(OPERAND_A_REDUC, &A);
        write_ram(MODULUS_REDUC, &N);

        // Configure PKA operation mode and start
        self.pka.pka_cr().modify(|_, w| w
            .mode().bits(0x0D)
            .start().set_bit()
        );

        // Wait for processing to complete - PROCENDF is 1 when done
        while self.pka.pka_sr().read().procendf().bit_is_clear() {
            asm::nop();
        }

        // Read the result
        let mut result_reduc = [0u32; 8];
        read_ram(RESULT_REDUC, &mut result_reduc);
                
        // Clear the completion flag
        self.pka.pka_clrfr().write(|w| w.procendfc().set_bit());

        u32_to_u8(&result_reduc)
    }

    unsafe fn pka_mod_sub(
        &mut self, 
        a: &BytesP256ElemLen, 
        b: &BytesP256ElemLen, 
    ) -> BytesP256ElemLen {

        self.stm32wba_init_pka();

        // Convert points to the right format
        let a_u32 = u8_to_u32(&a);
        let b_u32 = u8_to_u32(&b);
        
        zero_ram();
        // constant values for P-256 curve
        write_ram(OPERAND_LENGTH_SUB, &[OPERAND_LENGTH]);
        write_ram(OPERAND_A_SUB, &a_u32);
        write_ram(OPERAND_B_SUB, &b_u32);    
        
        // Configure PKA operation mode and start
        self.pka.pka_cr().modify(|_, w| w
            .mode().bits(0x0f)
            .start().set_bit()
        );

        // Wait for processing to complete - PROCENDF is 1 when done
        while self.pka.pka_sr().read().procendf().bit_is_clear() {
            asm::nop();
        }

        // Read the result
        let mut result = [0u32; 8];
        read_ram(RESULT_SUB, &mut result);
                
        // Clear the completion flag
        self.pka.pka_clrfr().write(|w| w.procendfc().set_bit());

        u32_to_u8(&result)
    }

    unsafe fn pka_mod_add(
        &mut self, 
        a: &BytesP256ElemLen, 
        b: &BytesP256ElemLen, 
    ) -> BytesP256ElemLen {

        self.stm32wba_init_pka();

        // Convert points to the right format
        let a_u32 = u8_to_u32(&a);
        let b_u32 = u8_to_u32(&b);
        
        zero_ram();
        // constant values for P-256 curve
        write_ram(OPERAND_LENGTH_SUB, &[OPERAND_LENGTH]);
        write_ram(OPERAND_A_SUB, &a_u32);
        write_ram(OPERAND_B_SUB, &b_u32);    
        
        // Configure PKA operation mode and start
        self.pka.pka_cr().modify(|_, w| w
            .mode().bits(0x0e)
            .start().set_bit()
        );

        // Wait for processing to complete - PROCENDF is 1 when done
        while self.pka.pka_sr().read().procendf().bit_is_clear() {
            asm::nop();
        }

        // Read the result
        let mut result = [0u32; 8];
        read_ram(RESULT_SUB, &mut result);
                
        // Clear the completion flag
        self.pka.pka_clrfr().write(|w| w.procendfc().set_bit());

        u32_to_u8(&result)
    }
   
    fn sha256_digest(
        &mut self, 
        message: &BytesMaxBuffer, 
        message_len: usize
    ) -> BytesHashLen {
        // Reset HASH peripheral
        self.hash.hash_cr().write(|w| w.init().set_bit());
        while self.hash.hash_cr().read().init().bit_is_set() {
            asm::nop();
        }

        // Configure for SHA-256 mode with byte-swapping
        unsafe {
            self.hash.hash_cr().write(|w| w
                .algo().bits(0b11)      // SHA-256 algorithm
                .mode().bit(false)      // Hash mode (not HMAC)
                .datatype().bits(0b00)  // 8-bit data with byte swapping
                .dmae().clear_bit()     // No DMA
                .init().set_bit()     
            );
        }

        // Feed message data to the peripheral
        // Process in 32-bit chunks
        // info!("message: {:#X}", message[..message_len]);
        let full_words = message_len / 4;
        let remainder_bytes = message_len % 4;
        
        // Write full 32-bit words
        for i in 0..full_words {
            let idx = i * 4;
            let word = (u32::from(message[idx]) << 24) |
                    (u32::from(message[idx+1]) << 16) |
                    (u32::from(message[idx+2]) << 8) |
                    u32::from(message[idx+3]);
            unsafe {
                self.hash.hash_din().write(|w| w.bits(word));
            }
        }
        
        // Handle remaining bytes in the last partial word, if any
        if remainder_bytes > 0 {
            let mut last_word = 0u32;
            let base_idx = full_words * 4;
            
            for i in 0..remainder_bytes {
                last_word |= u32::from(message[base_idx + i]) << (24 - (i * 8));
            }
             unsafe {
                self.hash.hash_din().write(|w| w.bits(last_word));
             }
        }
        
        // Tell the peripheral how many valid bytes are in the last word
        // and start the digest calculation
        unsafe {
            self.hash.hash_str().write(|w| w
            .nblw().bits(remainder_bytes as u8)  // Valid bytes in last word
            .dcal().set_bit()                                       // Start calculation
        );
        }

        // Wait for digest calculation to complete
        while self.hash.hash_sr().read().busy().bit_is_set() {
            asm::nop();
        }
        // Read hash result and convert to bytes
        let mut result = [0u8; 32];
        
        // Read the 8 hash registers (each 32-bits)
        let hr0 = self.hash.hash_hr0().read().bits();
        let hr1 = self.hash.hash_hr1().read().bits();
        let hr2 = self.hash.hash_hr2().read().bits();
        let hr3 = self.hash.hash_hr3().read().bits();
        let hr4 = self.hash.hash_hr4().read().bits();
        let hr5 = self.hash.hash_hr5().read().bits();
        let hr6 = self.hash.hash_hr6().read().bits();
        let hr7 = self.hash.hash_hr7().read().bits();
        
        // Convert to bytes (be careful about endianness)
        result[0..4].copy_from_slice(&hr0.to_be_bytes());
        result[4..8].copy_from_slice(&hr1.to_be_bytes());
        result[8..12].copy_from_slice(&hr2.to_be_bytes());
        result[12..16].copy_from_slice(&hr3.to_be_bytes());
        result[16..20].copy_from_slice(&hr4.to_be_bytes());
        result[20..24].copy_from_slice(&hr5.to_be_bytes());
        result[24..28].copy_from_slice(&hr6.to_be_bytes());
        result[28..32].copy_from_slice(&hr7.to_be_bytes());

        // info!("hash: {:#X}", result);
        
        result

    }

    // fn sha256_digest(&mut self, message: &BytesMaxBuffer, message_len: usize) -> BytesHashLen {
    //     info!("message: {:#X}", message);
    //     let mut hasher = sha2::Sha256::new();
    //     hasher.update(&message[..message_len]);
    //     hasher.finalize().into()
    // }

    fn hkdf_expand(
        &mut self,
        prk: &BytesHashLen,
        info: &BytesMaxInfoBuffer,
        info_len: usize,
        length: usize,
    ) -> BytesMaxBuffer {
        let hkdf =
            hkdf::Hkdf::<sha2::Sha256>::from_prk(prk).expect("Static size was checked at extract");
        let mut output: BytesMaxBuffer = [0; MAX_BUFFER_LEN];
        hkdf.expand(&info[..info_len], &mut output[..length])
            .expect("Static lengths match the algorithm");
        output
    }

    fn hkdf_extract(&mut self, salt: &BytesHashLen, ikm: &BytesP256ElemLen) -> BytesHashLen {
        // While it'd be nice to just pass around an Hkdf, the extract output is not a type generic
        // of this trait (yet?).
        let mut extracted = hkdf::HkdfExtract::<sha2::Sha256>::new(Some(salt));
        extracted.input_ikm(ikm);
        extracted.finalize().0.into()
    }

    fn aes_ccm_encrypt_tag_8(
        &mut self,
        key: &BytesCcmKeyLen,
        iv: &BytesCcmIvLen,
        ad: &[u8],
        plaintext: &BufferPlaintext3,
    ) -> BufferCiphertext3 {
        let key = AesCcm16_64_128::new(key.into());
        let mut outbuffer = BufferCiphertext3::new();
        outbuffer.content[..plaintext.len].copy_from_slice(plaintext.as_slice());
        if let Ok(tag) =
            key.encrypt_in_place_detached(iv.into(), ad, &mut outbuffer.content[..plaintext.len])
        {
            outbuffer.content[plaintext.len..][..AES_CCM_TAG_LEN].copy_from_slice(&tag);
        } else {
            panic!("Preconfigured sizes should not allow encryption to fail")
        }
        outbuffer.len = plaintext.len + AES_CCM_TAG_LEN;
        outbuffer
    }

    fn aes_ccm_decrypt_tag_8(
        &mut self,
        key: &BytesCcmKeyLen,
        iv: &BytesCcmIvLen,
        ad: &[u8],
        ciphertext: &BufferCiphertext3,
    ) -> Result<BufferPlaintext3, EDHOCError> {
        let key = AesCcm16_64_128::new(key.into());
        let mut buffer = BufferPlaintext3::new();
        buffer.len = ciphertext.len - AES_CCM_TAG_LEN;
        buffer.content[..buffer.len].copy_from_slice(&ciphertext.content[..buffer.len]);
        let tag = &ciphertext.content[buffer.len..][..AES_CCM_TAG_LEN];
        key.decrypt_in_place_detached(iv.into(), ad, &mut buffer.content[..buffer.len], tag.into())
            .map_err(|_| EDHOCError::MacVerificationFailed)?;
        Ok(buffer)
    }

    fn p256_ecdh(
        &mut self,
        private_key: &BytesP256ElemLen,
        public_key: &BytesP256ElemLen,
    ) -> BytesP256ElemLen {
        let secret = p256::SecretKey::from_bytes(private_key.as_slice().into())
            .expect("Invalid secret key generated");
        let public = p256::AffinePoint::decompress(
            public_key.into(),
            1.into(), /* Y coordinate choice does not matter for ECDH operation */
        )
        // While this can actually panic so far, the proper fix is in
        // https://github.com/openwsn-berkeley/lakers/issues/93 which will justify this to be a
        // panic (because after that, public key validity will be an invariant of the public key
        // type)
        .expect("Public key is not a good point");

        (*p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), public).raw_secret_bytes()).into()
        // [0u8; BytesP256ElemLen]
    }

    fn get_random_byte(&mut self) -> u8 {
        // self.rng.next_u32() as _
        0u8
    }

    fn p256_generate_key_pair(&mut self) -> (BytesP256ElemLen, BytesP256ElemLen) {
        // let secret = p256::SecretKey::random(&mut self.rng);

        // let public_key = secret.public_key().as_affine().x();
        // let private_key = secret.to_bytes();

        // (private_key.into(), public_key.into())
        (X, G_X_X_COORD)
    }

    unsafe fn precomp(
        &mut self,
        pk_aut: &[BytesP256AuthPubKey],
        id_cred_i: &[u8],
        gpio: GpioPin,
    ) -> (BytesP256ElemLen, BytesHashLen) {
        trace!("Precomputation phase");

        trace!("Verify authorities keys");
        // Verify all authority keys
        gpio.set_high();
        for pk in pk_aut {
            if !self.vok_log(pk.pk1, &pk.pk2, None) {
                panic!("Error: authority keys invalid");
            }
        }
        gpio.set_low();

        // Compute h as the product of all authority public keys
        trace!("Computation of h");
        gpio.set_high();
        // let (mut h_point_x, mut h_point_y) = pk_aut[0].pk1;
        // let mut h = coordinates_to_projective_point(h_point_x, h_point_y);
        // for i in 1..pk_aut.len() {
        //     let (pk_point_x, pk_point_y) = pk_aut[i].pk1;
        //     let pk_proj = coordinates_to_projective_point(pk_point_x, pk_point_y);
        //     h = h + pk_proj;
        // }
        // Compute h as the product of all authority public keys
        let (mut h_point_x, mut h_point_y) = pk_aut[0].pk1;
        for i in 1..pk_aut.len() {
            let (pk_point_x, pk_point_y) = pk_aut[i].pk1;
            (h_point_x, h_point_y) = self.pka_ecc_point_add(h_point_x, h_point_y, pk_point_x, pk_point_y);
        }
        gpio.set_low();
        
        trace!("Computation of w");
        gpio.set_high();
        // Create the tuple for hashing (pk_A, pk_aut[0].pk1, pk_aut[1].pk1, ...)
        let mut hash_input = [0u8; MAX_BUFFER_LEN];
        let mut offset = 0;
    
        // Add id_cred_i
        hash_input[offset..offset + id_cred_i.len()].copy_from_slice(id_cred_i);
        offset += id_cred_i.len();
    
        // Add pk_aut[i].pk1
        for authority in pk_aut {
            let (pk1_x, pk1_y) = authority.pk1;
            hash_input[offset..offset + P256_ELEM_LEN].copy_from_slice(&pk1_x);
            offset += P256_ELEM_LEN;
        }

        let w = self.sha256_digest(&hash_input, offset);
        gpio.set_low();

        // Return (h, w)        
        (h_point_x, w)
    }

    // Authority key generation function
    unsafe fn keygen_a(&mut self, gpio: GpioPin) -> (BytesP256AuthPubKey, BytesP256ElemLen) {
        trace!("KeyAuthGen");
        // Generate random secret key
        // let sk = p256::NonZeroScalar::random(&mut self.rng);
        // For now we replace it with a hard coded constant SK
        // info!("SK: {:#X}", SK);
        let sk_scalar = Scalar::from_repr(SK.into()).unwrap();

        // pk1 = g^sk (g is the generator point in P256)
        gpio.set_high();
        // let (pk1_x, pk1_y) = ecc_generator_mult(sk_scalar);
        let (pk1_x, pk1_y) = self.pka_ecc_mult_scalar(BASE_POINT_X, BASE_POINT_Y, SK);
        // info!("pk1_x: {:#X}   pk1_y: {:#X}", pk1_x, pk1_y);
        gpio.set_low();

        // Create proof of knowledge of sk
        // FIX: Should we pass both coordinates? How to make sure is always the 0x2 for y-coordinate?
        gpio.set_high();
        let pk2 = self.sok_log(SK, (pk1_x, pk1_y), None);
        gpio.set_low();

        // Create the authority public key structure
        gpio.set_high();
        let mut pk = BytesP256AuthPubKey::default();
        pk.pk1 = (pk1_x, pk1_y);
        pk.pk2 = pk2;
        gpio.set_low();

        // Return (pk, sk)
        (pk, SK)
    }

    unsafe fn sok_log(
        &mut self, 
        x: BytesP256ElemLen, 
        h: (BytesP256ElemLen, BytesP256ElemLen), 
        message: Option<&[u8]>
    ) -> SokLogProof {
        trace!("Sok Log");

        let (h_point_x, h_point_y) = h;

        // Generate random value r
        // let r = p256::NonZeroScalar::random(&mut self.rng);
        let r = hex!("d1f3a4c8b66e30f78a53e5b7896ab8a2ffefc0bde45a7a7e13347157956c8e2a");
        let r_scalar = Scalar::from_repr(r.into()).unwrap();

        // Compute R = g^r
        let (g_r_x, g_r_y) = self.pka_ecc_mult_scalar(BASE_POINT_X, BASE_POINT_Y, r);
        // let (g_r_x, g_r_y) = ecc_generator_mult(r_scalar);

        // Create the hash input (R, h, message)
        let mut hash_input = [0u8; MAX_BUFFER_LEN];
        let mut hash_len = 0;

        // Copy sum_x into hash_input
        hash_input[..P256_ELEM_LEN].copy_from_slice(&g_r_x);
        let mut hash_len = hash_len + P256_ELEM_LEN;
        hash_input[P256_ELEM_LEN..P256_ELEM_LEN + P256_ELEM_LEN].copy_from_slice(&h_point_x);
        let mut hash_len = hash_len + P256_ELEM_LEN;

        // Copy message if it exists
        if let Some(message_bytes) = message {
            hash_input[P256_ELEM_LEN + P256_ELEM_LEN ..P256_ELEM_LEN + P256_ELEM_LEN + message_bytes.len()]
                .copy_from_slice(message_bytes);
            hash_len = hash_len + message_bytes.len()
        }       
        
        // Compute c = H(R, h, message)
        let hash = self.sha256_digest(&hash_input, hash_len);
        
        // Compute z = r + x*c
        // let temp = self.pka_mod_mult(&x, &hash);
        // let z = self.pka_mod_add(&r, &temp);

        let x_scalar = Scalar::from_repr(x.into()).unwrap();
        let hash_scalar = Scalar::from_repr(hash.into()).unwrap();

        let temp = x_scalar * hash_scalar; // Modular multiplication 
        let z_scalar = r_scalar + temp;    // Modular addition

        // Store intermediate representations
        let z_repr = z_scalar.to_repr();

        // Then get references for logging or further use
        let z_bytes = z_repr.as_ref();
        // info!("sok_log z: {=[u8]:#X}", z_bytes);

        // Return the proof (R, z)
        let mut proof = SokLogProof::default();
        proof.pi1 = (g_r_x, g_r_y);
        proof.pi2.copy_from_slice(&z_bytes);
        proof

    }

    // FIXME
    unsafe fn vok_log(
        &mut self, 
        h:(BytesP256ElemLen, BytesP256ElemLen), 
        pi: &SokLogProof, 
        message: Option<&[u8]>
    ) -> bool {
        trace!("VoK Log");

        let (h_point_x, h_point_y) = h;

        let (g_r_x, g_r_y) = pi.pi1;
        // let g_r_proj_point = coordinates_to_projective_point(g_r_x, g_r_y);

        let z = pi.pi2;
        let z_scalar = Scalar::from_repr(z.into()).unwrap();

        // Create the hash input (R, h, message)
        let mut hash_input = [0u8; MAX_BUFFER_LEN];
        let mut hash_len = 0;

        // Copy sum_x into hash_input
        hash_input[..P256_ELEM_LEN].copy_from_slice(&g_r_x);
        let mut hash_len = hash_len + P256_ELEM_LEN;
        hash_input[P256_ELEM_LEN..P256_ELEM_LEN + P256_ELEM_LEN].copy_from_slice(&h_point_x);
        let mut hash_len = hash_len + P256_ELEM_LEN;

        // Copy message if it exists
        if let Some(message_bytes) = message {
            hash_input[P256_ELEM_LEN + P256_ELEM_LEN ..P256_ELEM_LEN + P256_ELEM_LEN + message_bytes.len()]
                .copy_from_slice(message_bytes);
            hash_len = hash_len + message_bytes.len()
        }       
        
        // Compute c = H(R, h, message)
        let c = self.sha256_digest(&hash_input, hash_len);
        let c_scalar = Scalar::from_repr(c.into()).unwrap();
        
        // Verify: g^z == R * h^c
        // let (g_z_x, g_z_y) = ecc_generator_mult(z_scalar);
        let (g_z_x, g_z_y) = self.pka_ecc_mult_scalar(BASE_POINT_X, BASE_POINT_Y, z);

        // Convert h_x and h_y bytes into an AffinePoint
        let (h_c_x, h_c_y) = self.pka_ecc_mult_scalar(h_point_x, h_point_y, c);
        let (expected_point_x, expected_point_y) = self.pka_ecc_point_add(h_c_x, h_c_y, g_r_x, g_r_y);
        // let h_point_proj = coordinates_to_projective_point(h_point_x, h_point_y);
        // let h_c = h_point_proj * c_scalar;
        // let expected_point = h_c + g_r_proj_point;

        // let expected_point_affine = expected_point.to_affine();
        // let uncompressed = expected_point_affine.to_encoded_point(false);
        // let expected_point_x: [u8; 32] = uncompressed.x().unwrap().clone().into();
        // let expected_point_y: [u8; 32] = uncompressed.y().unwrap().clone().into();

        // info!("g_z_x: {:#X}   expected_x: {:#X}", g_z_x, expected_point_x);

        g_z_x == expected_point_x
    }

    unsafe fn sok_log_eq(
        &mut self,
        h: BytesP256ElemLen,
        g_r: BytesP256ElemLen, 
        g_x: BytesP256ElemLen, 
        g_y: BytesP256ElemLen, 
        x: BytesP256ElemLen, 
        i: BytesP256ElemLen,
        message: Option<&[u8]>,
    ) -> SokLogEqProof {
        trace!("Sok Log equality");

        // let r= hex!("72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac");
        // let r_scalar = Scalar::from_repr(r.into()).unwrap();
        // let g_r_proj_point = p256::ProjectivePoint::generator() * r_scalar;
        // let (g_r_x, g_r_y) = projective_to_coordinates(g_r_proj_point);
        // info!("g_r_x: {:#X}   g_r_y: {:#X}", g_r_x, g_r_y);
        // let g_r_proj = coordinates_to_projective_point(g_r_x, g_r_y);

        let (h_point_x, h_point_y) = bytes_to_point(&h);
        let h_proj_point = coordinates_to_projective_point(h_point_x, h_point_y);

        let (g_y_point_x, g_y_point_y) = bytes_to_point(&g_y);
        let g_y_proj_point = coordinates_to_projective_point(g_y_point_x, g_y_point_y);

        let (g_r_point_x, g_r_point_y) = bytes_to_point(&g_r);
        let g_r_proj_point = coordinates_to_projective_point(g_r_point_x, g_r_point_y);
        
        let x_scalar = Scalar::from_repr(x.into()).unwrap();

        // Compute H_I^1 = (h_I * g^y)^x
        let (h_i_1_temp_x, h_i_1_temp_y)  = self.pka_ecc_point_add(h_point_x, h_point_y, g_y_point_x, g_y_point_y);
        let (h_i_1_x, h_i_1_y) = self.pka_ecc_mult_scalar(h_i_1_temp_x, h_i_1_temp_y, x); 
        // let h_i_1_temp = h_proj_point + g_y_proj_point;
        // let h_i_1 = h_i_1_temp * x_scalar;

        // Compute H_I^2 = (h_I * g^r)^x
        let (h_i_2_temp_x, h_i_2_temp_y)  = self.pka_ecc_point_add(h_point_x, h_point_y, g_r_point_x, g_r_point_y);
        let (h_i_2_x, h_i_2_y) = self.pka_ecc_mult_scalar(h_i_2_temp_x, h_i_2_temp_y, x); 
        // let h_i_2_temp = h_proj_point + g_r_proj_point;
        // let h_i_1 = h_i_2_temp * x_scalar;

        // Generate proof pi
        // Generate random value r_I, s_I
        let r = hex!("d1f3a4c8b66e30f78a53e5b7896ab8a2ffefc0bde45a7a7e13347157956c8e2a");
        let r_scalar = Scalar::from_repr(r.into()).unwrap();
        let s = hex!("5bfe2d83d8b44059f01b0e6efef7622ab0806e67dfed50d9d48f845e7f4b35a1");
        let s_scalar = Scalar::from_repr(s.into()).unwrap();

        // Compute I_1 = g^r_I
        let (i_1_x, i_1_y) = self.pka_ecc_mult_scalar(BASE_POINT_X, BASE_POINT_Y, r);
        // let i_1 = ecc_generator_mult_projective(r_scalar);
        
        // Compute I_2 = (h_I g^y)^r
        let (i_2_x, i_2_y) = self.pka_ecc_mult_scalar(h_i_1_temp_x, h_i_1_temp_y, r);
        // let i_2 = h_i_1_temp * r_scalar;

        // Compute I_3 = (h_I g^r)^r
        let (i_3_x, i_3_y) = self.pka_ecc_mult_scalar(h_i_2_temp_x, h_i_2_temp_y, r);
        // let i_3 = h_i_2_temp * r_scalar;

        // Compute I_4 = g^s
        let (i_4_x, i_4_y) = self.pka_ecc_mult_scalar(BASE_POINT_X, BASE_POINT_Y, s);
        // let i_4 = ecc_generator_mult_projective(s_scalar);

        // Compute I_5 = (h_I g^y)^s
        let (i_5_x, i_5_y) = self.pka_ecc_mult_scalar(h_i_1_temp_x, h_i_1_temp_y, s);
        // let i_5 = h_i_1_temp * s_scalar;

        // Create the hash input (I_1, I_2, I_3, I_4, I_5, message)
        // we need to add I_1 + I_2 + I_3 + I_4 + I_5
        let (mut sum_x, mut sum_y) = self.pka_ecc_point_add(i_1_x, i_1_y, i_2_x, i_2_y);
        let (mut sum_x, mut sum_y) = self.pka_ecc_point_add(sum_x, sum_y, i_3_x, i_3_y);
        let (mut sum_x, mut sum_y) = self.pka_ecc_point_add(sum_x, sum_y, i_4_x, i_4_y);
        let (mut sum_x, mut sum_y) = self.pka_ecc_point_add(sum_x, sum_y, i_5_x, i_5_y);
        // let sum = i_1 + i_2 + i_3 + i_4 + i_5;
        // let (sum_x, sum_y) = projective_to_coordinates(sum);

        // let inputs = [I_1 + I_2 + I_3 + I_4 + I_5 || message.unwrap_or(&[])];
        let mut hash_input = [0u8; MAX_BUFFER_LEN];

        // Copy sum_x into hash_input
        hash_input[..P256_ELEM_LEN].copy_from_slice(&sum_x);
        let mut hash_len = P256_ELEM_LEN;
        
        // Copy message if it exists
        if let Some(message_bytes) = message {
            hash_input[P256_ELEM_LEN..P256_ELEM_LEN + message_bytes.len()]
                .copy_from_slice(message_bytes);
            hash_len = hash_len + message_bytes.len()
        }        

        // Compute alpha = H(I_1, I_2, I_3, I_4, I_5, message)
        let alpha = self.sha256_digest(&hash_input, hash_len);
        
        // Compute beta = r - x*alpha
        // Convert the bytes to FieldElement values
        let alpha_scalar = Scalar::from_repr(alpha.into()).unwrap();

        let temp = x_scalar * alpha_scalar;
        let beta_scalar = r_scalar + temp;
        let beta_repr  = beta_scalar.to_repr();
        let beta = beta_repr.as_ref();

        // Compute gamma = s - i*alpha
        let i_scalar = Scalar::from_repr(i.into()).unwrap();

        let temp = i_scalar * alpha_scalar;
        let gamma_scalar = s_scalar + temp;
        let gamma_repr= gamma_scalar.to_repr();
        let gamma = gamma_repr.as_ref();
        
        // Return the proof (alpha, beta, gamma)
        let mut proof = SokLogEqProof::default();
        proof.pi1.copy_from_slice(&alpha);
        proof.pi2.copy_from_slice(&beta);
        proof.pi3.copy_from_slice(&gamma);

        proof
    }
    
}

