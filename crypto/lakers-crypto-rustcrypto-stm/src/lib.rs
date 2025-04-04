#![no_std]

use lakers_shared::{MODE, BASE, PKA_RAM_OFFSET, RAM_BASE, RAM_NUM_DW, 
    PRIME_LENGTH_OFFSET, MODULUS_LENGTH_OFFSET, COEF_A_SIGN_OFFSET, COEF_A_OFFSET, COEF_B_OFFSET, MODULUS_OFFSET, SCALAR_OFFSET, POINT_X_OFFSET, POINT_Y_OFFSET, PRIME_OFFSET, RESULT_X_OFFSET, RESULT_Y_OFFSET, RESULT_ERROR_OFFSET, A_SIGN, A, B,
    N, BASE_POINT_X, BASE_POINT_Y, PRIME_ORDER, WORD_LENGTH, OPERAND_LENGTH, 
    MODULUS_OFFSET_ADD, MODULUS_LENGTH_OFFSET_ADD, PRIME_LENGTH_OFFSET_ADD, COEF_A_OFFSET_ADD, COEF_A_SIGN_OFFSET_ADD, Z_COORDINATE, SCALAR_K_ADD, SCALAR_M_ADD, POINT_P_X, POINT_P_Y, POINT_P_Z, POINT_Q_X, POINT_Q_Y, POINT_Q_Z, RESULT_Y_ADD, RESULT_X_ADD, RESULT_ERROR_ADD, R2MODN, 
    MODULUS_OFFSET_PTA, POINT_P_X_PTA, POINT_P_Y_PTA, POINT_P_Z_PTA, MONTGOMERY_PTA, RESULT_ERROR_PTA, RESULT_X_PTA, RESULT_Y_PTA, 
    OPERAND_LENGTH_MULT, OPERAND_A_ARITHEMTIC_MULT, OPERAND_B_ARITHEMTIC_MULT, RESULT_ARITHMETIC_MULT, 
    OPERAND_LENGTH_REDUC, OPERAND_A_REDUC, MODULUS_REDUC, RESULT_REDUC, 
    OPERAND_LENGTH_SUB, OPERAND_A_SUB, OPERAND_B_SUB, MODULUS_SUB, RESULT_SUB 
};

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
use p256::{
    PublicKey,
    EncodedPoint,
    AffinePoint,
    ProjectivePoint,
    FieldBytes,
};
use sha2::Digest;
use cortex_m::asm;
use stm32wba::stm32wba55;
use stm32wba::stm32wba55::Peripherals as peripherals;
use stm32wba::stm32wba55::PKA as PKA;
use stm32wba::stm32wba55::HASH as HASH;
use stm32wba::stm32wba55::RCC as RCC;
use stm32wba::stm32wba55::RNG as RNG;
use defmt::info;

type AesCcm16_64_128 = ccm::Ccm<aes::Aes128, ccm::consts::U8, ccm::consts::U13>;

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

pub fn u32_to_u8(arr: &[u32; 8]) -> [u8; 32] {
    let mut result = [0u8; 32];
    for (i, &val) in arr.iter().enumerate() {
        result[i * 4..(i + 1) * 4].copy_from_slice(&val.to_le_bytes());
    }
    result
}

pub fn u8_to_u32(arr: &[u8; 32]) -> [u32; 8] {
    let mut result = [0u32; 8];
    for i in 0..8 {
        let bytes = &arr[i * 4..(i + 1) * 4];
        result[i] = u32::from_le_bytes(bytes.try_into().unwrap());
    }
    result
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

    pub fn lakers_crypto_rustcrypto_stm_init(&self) {

        let rng = Self::stm32wba_init_rng(self);
        let hash = Self::stm32wba_init_hash(self);
        let pka = Self::stm32wba_init_pka(self);
        
    }

    fn stm32wba_init_rng(&self) -> &RNG {
        let clock = &self.p.RCC;

        // Enable HSI as a stable clock source
        clock.rcc_cr().modify(|_, w| w
            .hseon().set_bit()
        );
        while clock.rcc_cr().read().hserdy().bit_is_clear() {
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

        
        (u32_to_u8(&result_x), u32_to_u8(&result_y))

    }

    unsafe fn pka_ecc_mult_scalar(
        &mut self, 
        point_x: BytesP256ElemLen, 
        point_y: BytesP256ElemLen, 
        scalar: &BytesP256ElemLen
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
        self.stm32wba_init_pka();

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
   
    fn sha256_digest(&mut self, message: &BytesMaxBuffer, message_len: usize) -> BytesHashLen {
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

        // Set NBLW to 24 (original message length)
        unsafe {
            for chunk in message[..message_len].chunks_exact(4) {
                let word = u32::from_le_bytes(chunk.try_into().unwrap());
                self.hash.hash_din().write(|w| w.bits(word));
            }
            self.hash.hash_str().write(|w| w.nblw().bits(message_len as u8));
        }

        // Start padding and digest computation
        self.hash.hash_str().write(|w| w.dcal().set_bit());

        // Wait for digest calculation to complete
        while self.hash.hash_sr().read().busy().bit_is_set() {
            asm::nop();
        }

        // Read final hash
        let hash_result = [
            self.hash.hash_hr0().read().bits(),
            self.hash.hash_hr1().read().bits(),
            self.hash.hash_hr2().read().bits(),
            self.hash.hash_hr3().read().bits(),
            self.hash.hash_hr4().read().bits(),
            self.hash.hash_hr5().read().bits(),
            self.hash.hash_hr6().read().bits(),
            self.hash.hash_hr7().read().bits(),
        ];

         // Convert `[u32; 8]` → `[u8; 32]`
        let mut final_hash: [u8; 32] = [0; 32];
        for (i, word) in hash_result.iter().enumerate() {
            final_hash[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes()); 
        }

        final_hash

    }

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
        ([0u8; P256_ELEM_LEN], [0u8; P256_ELEM_LEN])
    }

    fn bytes_to_point(&self, bytes: &[u8]) -> ([u8; 32], [u8; 32]) {
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

    // fn build_hash_input(inputs: &[&[u8]]) -> Vec<u8> {
    //     let total_len: usize = inputs.iter().map(|x| x.len()).sum();
    //     let mut hash_input = Vec::with_capacity(total_len);
        
    //     for input in inputs {
    //         hash_input.extend_from_slice(input);
    //     }
        
    //     hash_input
    // }

    // fn hash_to_scalar(&self, input: &[u8]) -> p256::NonZeroScalar {
    //     let hash = sha2::Sha256::digest(input);  // Hash the input
    //     let mut scalar_bytes = [0u8; 32];  
    //     scalar_bytes.copy_from_slice(&hash[..32]);  // Copy into fixed-size array
    
    //     // Convert to scalar modulo the curve order
    //     p256::NonZeroScalar::from_repr(scalar_bytes.into()).expect("Hash must be a valid scalar")
    // }

    // // User key generation function
    // fn keygen_u(&mut self) -> (BytesP256ElemLen, BytesP256ElemLen) {
    //     self.p256_generate_key_pair()
    // }

    // // Authority key generation function
    // fn keygen_a(&mut self) -> (BytesP256AuthPubKey, BytesP256ElemLen) {
    //     // Generate random secret key
    //     let sk = p256::NonZeroScalar::random(&mut self.rng);
        
    //     // pk1 = g^sk (g is the generator point in P256)
    //     let pk1_point = p256::ProjectivePoint::generator() * sk;
    //     let pk1_bytes = pk1_point.to_affine().x().to_bytes();
        
    //     // Create proof of knowledge of sk
    //     let pk2 = self.sok_log(sk, &pk1_bytes, None);
        
    //     // Create the authority public key structure
    //     let mut pk = BytesP256AuthPubKey::default();
    //     pk.pk1.copy_from_slice(&pk1_bytes);
    //     pk.pk2 = pk2;
        
    //     // Return (pk, sk)
    //     (pk, sk.to_bytes().into())
    // }

    unsafe fn sok_log_eq(
        &mut self,
        h: &BytesP256ElemLen,
        g_r: &BytesP256ElemLen, 
        g_x: &BytesP256ElemLen, 
        g_y: &BytesP256ElemLen, 
        x: &BytesP256ElemLen, 
        i: &BytesP256ElemLen,
        message: Option<&[u8]>,
    ) -> SokLogEqProof {

        let (h_point_x, h_point_y) = self.bytes_to_point(h);
        let (g_y_point_x, g_y_point_y) = self.bytes_to_point(g_y);
        let (g_r_point_x, g_r_point_y) = self.bytes_to_point(g_r);

        // Compute H_I^1 = (h_I * g^y)^x
        let (h_g_y_point_x, h_g_y_point_y) = self.pka_ecc_point_add(h_point_x, h_point_y, g_y_point_x, g_y_point_y );
        // let (h_g_y_point_x_proj, h_g_y_point_y_proj, h_g_y_point_z_proj) = self.pka_ecc_point_add(h_point_x, h_point_y, g_y_point_x, g_y_point_y );
        // let (h_g_y_point_x, h_g_y_point_y) = self.pka_ecc_projective_to_affine(h_g_y_point_x_proj, h_g_y_point_y_proj, h_g_y_point_z_proj);
        let (h_1_point_x, h_1_point_y) = self.pka_ecc_mult_scalar(h_g_y_point_x, h_g_y_point_y, x);
        // let h_bytes_1 = h_1.to_affine().x().to_bytes();

        // Compute H_I^2 = (h_I * g^r)^x
        let (h_g_r_point_x, h_g_r_point_y) = self.pka_ecc_point_add(h_point_x, h_point_y, g_r_point_x, g_r_point_y );
        // let (h_g_r_point_x_proj, h_g_r_point_y_proj, h_g_r_point_z_proj) = self.pka_ecc_point_add(h_point_x, h_point_y, g_r_point_x, g_r_point_y );
        // let (h_g_r_point_x, h_g_r_point_y) = self.pka_ecc_projective_to_affine(h_g_r_point_x_proj, h_g_r_point_y_proj, h_g_r_point_z_proj);
        let (h_2_point_x, h_2_point_y) = self.pka_ecc_mult_scalar(h_g_r_point_x, h_g_r_point_y, x);
        // let h_bytes_2 = h_2.to_affine().x().to_bytes();

        // // Generate proof pi
        // let h_g_y_bytes = h_g_y.to_affine().x().to_bytes();
        // let h_g_r_bytes = h_g_r.to_affine().x().to_bytes();

        // Generate random value r_I, s_I
        let r = int_to_u8_array(2); //p256::NonZeroScalar::random(&mut self.rng);
        let s = int_to_u8_array(3); //p256::NonZeroScalar::random(&mut self.rng);
        
        // Convert byte arrays to points
        // Maybe this function can handle as well the point addition, so we compute here ECC h + g^y
        // let (h_g_y_point_x, h_g_y_point_y) = self.bytes_to_point(h_g_y);
        // let (h_g_r_point_x, h_g_r_point_y) = self.bytes_to_point(h_g_r);
        
        // Compute I_1 = g^r_I
        let (I_1_x, I_1_y) = self.pka_ecc_mult_scalar(u32_to_u8(&BASE_POINT_X), u32_to_u8(&BASE_POINT_Y), &r);
        
        // Compute I_2 = (h_I g^y)^r
        let (I_2_x, I_2_y) = self.pka_ecc_mult_scalar(h_g_y_point_x, h_g_y_point_y, &r);

        // Compute I_3 = (h_I g^r)^r
        let (I_3_x, I_3_y) = self.pka_ecc_mult_scalar(h_g_r_point_x, h_g_r_point_y, &r);

        // Compute I_4 = g^s
        let (I_4_x, I_4_y) = self.pka_ecc_mult_scalar(u32_to_u8(&BASE_POINT_X), u32_to_u8(&BASE_POINT_Y), &s);

        // Compute I_5 = (h_I g^y)^s
        let (I_5_x, I_5_y) = self.pka_ecc_mult_scalar(h_g_y_point_x, h_g_y_point_y, &s);
        
        // Create the hash input (I_1, I_2, I_3, I_4, I_5, message)
        // we need to add I_1 + I_2 + I_3 + I_4 + I_5
        let (sum_x, sum_y) = self.pka_ecc_point_add(I_1_x, I_1_y, I_2_x, I_2_y);
        let (sum_x, sum_y) = self.pka_ecc_point_add(sum_x, sum_y, I_3_x, I_3_y);
        let (sum_x, sum_y) = self.pka_ecc_point_add(sum_x, sum_y, I_4_x, I_4_y);
        let (sum_x, sum_y) = self.pka_ecc_point_add(sum_x, sum_y, I_5_x, I_5_y);

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
        let mut beta = self.pka_mod_mult(x, &alpha);
        let beta = self.pka_mod_sub(&r, &beta);

        // Compute gamma = s - i*alpha
        let gamma = self.pka_mod_mult(i, &alpha);
        let gamma = self.pka_mod_sub(&s, &gamma);
        
        // Return the proof (alpha, beta, gamma)
        let mut proof = SokLogEqProof::default();
        proof.pi1.copy_from_slice(&alpha);
        proof.pi2.copy_from_slice(&beta);
        proof.pi3.copy_from_slice(&gamma);

        proof
    }
    
}

