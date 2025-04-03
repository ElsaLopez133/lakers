#![no_std]

use lakers_shared::{MODE, BASE, PKA_RAM_OFFSET, RAM_BASE, RAM_NUM_DW, PRIME_LENGTH_OFFSET, MODULUS_LENGTH_OFFSET, COEF_A_SIGN_OFFSET,
COEF_A_OFFSET, COEF_B_OFFSET, MODULUS_OFFSET, SCALAR_OFFSET, POINT_X_OFFSET, POINT_Y_OFFSET, PRIME_OFFSET, RESULT_X_OFFSET, RESULT_Y_OFFSET, RESULT_ERROR_OFFSET, A_SIGN, A, B,
N, BASE_POINT_X, BASE_POINT_Y, PRIME_ORDER, WORD_LENGTH, OPERAND_LENGTH, MODULUS_OFFSET_ADD, POINT_P_X, POINT_P_Y, POINT_P_Z,
POINT_Q_X, POINT_Q_Y, POINT_Q_Z, RESULT_Y, RESULT_Z, RESULT_X, R2MODN, MODULUS_OFFSET_PTA, POINT_P_X_PTA, POINT_P_Y_PTA, POINT_P_Z_PTA, MONTGOMERY_PTA, 
RESULT_ERROR_PTA, RESULT_X_PTA, RESULT_Y_PTA};

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

        // let rng = &self.p.RNG;
        // // Enable HSI as a stable clock source
        // clock.rcc_cr().modify(|_, w| w
        // .hseon().set_bit()
        // );
        // while clock.rcc_cr().read().hserdy().bit_is_clear() {
        //     asm::nop();
        // }

        // // Enable RNG clock. Select the source clock
        // clock.rcc_ccipr2().write(|w| w.rngsel().b_0x2());
        // // Enable RNG clock. Select the AHB clock
        // clock.rcc_ahb2enr().modify(|_, w| w.rngen().set_bit());
        // while clock.rcc_ahb2enr().read().rngen().bit_is_clear() {
        //     asm::nop();
        // }

        // // Configure RNG
        // // To configure, CONDRST bit is set to 1 in the same access and CONFIGLOCK remains at 0
        // rng.rng_cr().write(|w| w
        //     .rngen().clear_bit()
        //     .condrst().set_bit()
        //     .configlock().clear_bit()
        //     .nistc().clear_bit()   // Hardware default values for NIST compliant RNG
        //     .ced().clear_bit()     // Clock error detection enabled
        // );

        // // First clear CONDRST while keeping RNGEN disabled
        // rng.rng_cr().modify(|_, w| w
        //     .condrst().clear_bit()
        // );

        // // Then enable RNG in a separate step
        // rng.rng_cr().modify(|_, w| w
        //     .rngen().set_bit()
        //     .ie().set_bit()
        // );

        // while rng.rng_sr().read().drdy().bit_is_clear() {
        //     asm::nop();
        // }

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
    ) -> (BytesP256ElemLen, BytesP256ElemLen, BytesP256ElemLen ) {

        self.stm32wba_init_pka();
        //  Perform PQ where P and W are points of the curve (in ECC notation this is P + Q

        // Convert points to the right format
        let point_a_x_u32 = u8_to_u32(&point_a_x);
        let point_a_y_u32 = u8_to_u32(&point_a_y);
        let point_b_x_u32 = u8_to_u32(&point_b_x);
        let point_b_y_u32 = u8_to_u32(&point_b_y);

        zero_ram();
        // constant values for P-256 curve
        write_ram(MODULUS_LENGTH_OFFSET, &[OPERAND_LENGTH]);
        write_ram(COEF_A_SIGN_OFFSET, &[A_SIGN]);
        write_ram(COEF_A_OFFSET, &A);
        write_ram(COEF_B_OFFSET, &B);
        write_ram(MODULUS_OFFSET_ADD, &N);

        write_ram(POINT_P_X, &point_a_x_u32);
        write_ram(POINT_P_Y, &point_a_y_u32);
        write_ram(POINT_P_Z, &[1]);

        write_ram(POINT_Q_X, &point_b_x_u32);
        write_ram(POINT_Q_Y, &point_b_y_u32);
        write_ram(POINT_Q_Z, &[1]);

        // Configure PKA operation mode and start
        self.pka.pka_cr().modify(|_, w| w
            .mode().bits(0x23)
            .start().set_bit()
        );

        // Wait for processing to complete - PROCENDF is 1 when done
        while self.pka.pka_sr().read().procendf().bit_is_clear() {
            asm::nop();
        }

        // Read the result
        let mut result_x = [0u32; 8];
        let mut result_y = [0u32; 8];
        let mut result_z = [0u32; 8];
        
        read_ram(RESULT_X, &mut result_x);
        read_ram(RESULT_Y, &mut result_y);
        read_ram(RESULT_Z, &mut result_z);

        // Clear the completion flag
        self.pka.pka_clrfr().write(|w| w.procendfc().set_bit());

        (u32_to_u8(&result_x), u32_to_u8(&result_y), u32_to_u8(&result_z))

    }

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

        (u32_to_u8(&result_x), u32_to_u8(&result_y))
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

    // fn build_hash_input(
    //     r_bytes: &[u8],
    //     h: &[u8],
    //     message: Option<&[u8]>,
    // ) -> Vec<u8> {
    //     let mut hash_input = Vec::with_capacity(r_bytes.len() + h.len() + message.map_or(0, |m| m.len()));
    //     hash_input.extend_from_slice(r_bytes);
    //     hash_input.extend_from_slice(h);
    //     if let Some(msg) = message {
    //         hash_input.extend_from_slice(msg);
    //     }
    //     hash_input
    // }

    // fn bytes_to_scalar(&self, bytes: &[u8]) -> p256::NonZeroScalar {
    //     let scalar = p256::Scalar::from_bytes_reduced(bytes.into());
    //     p256::NonZeroScalar::new(scalar).expect("Invalid scalar: must not be zero")
    // }

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
        x: BytesP256ElemLen,
        i: BytesP256ElemLen,
        g_x: &BytesP256ElemLen,
        h_g_y: &BytesP256ElemLen,
        h_g_r: &BytesP256ElemLen,
        message: Option<&[u8]>,
    ) -> SokLogEqProof {

        // Compute H_I^1 = (h_I * g^y)^x
        // let h_g_y = h_point + g_y_point;
        // let h_1 = h_g_y * x;
        // let h_bytes_1 = h_1.to_affine().x().to_bytes();

        // // Compute H_I^2 = (h_I * g^r)^x
        // let h_point_1 = self.bytes_to_point(h);
        // let g_r_point = self.bytes_to_point(g_r);
        // let h_g_r = h_point + g_r_point;
        // let h_2 = h_g_r * x;
        // let h_bytes_2 = h_2.to_affine().x().to_bytes();

        // // Generate proof pi
        // let h_g_y_bytes = h_g_y.to_affine().x().to_bytes();
        // let h_g_r_bytes = h_g_r.to_affine().x().to_bytes();

        // Generate random value r_I, s_I
        let r = int_to_u8_array(2); //p256::NonZeroScalar::random(&mut self.rng);
        let s = int_to_u8_array(3); //p256::NonZeroScalar::random(&mut self.rng);
        
        // Convert byte arrays to points
        // Maybe this function can handle as well the point addition, so we compute here ECC h + g^y
        let (h_g_y_point_x, h_g_y_point_y) = self.bytes_to_point(h_g_y);
        let (h_g_r_point_x, h_g_r_point_y) = self.bytes_to_point(h_g_r);
        
        // Compute I_1 = g^r_I
        let (I_1, _) = self.pka_ecc_mult_scalar(u32_to_u8(&BASE_POINT_X), u32_to_u8(&BASE_POINT_Y), r);
        
        // Compute I_2 = (h_I g^y)^r
        let (I_2, _) = self.pka_ecc_mult_scalar(h_g_y_point_x, h_g_y_point_y, r);

        // Compute I_3 = (h_I g^r)^r
        let (I_3, _) = self.pka_ecc_mult_scalar(h_g_r_point_x, h_g_r_point_y, r);

        // Compute I_4 = g^s
        let (I_4, _) = self.pka_ecc_mult_scalar(u32_to_u8(&BASE_POINT_X), u32_to_u8(&BASE_POINT_Y), s);

        // Compute I_5 = (h_I g^y)^s
        let (I_5, _) = self.pka_ecc_mult_scalar(h_g_y_point_x, h_g_y_point_y, s);
        
        // Create the hash input (I_1, I_2, I_3, I_4, I_5, message)
        // let inputs = [I_1, I_2, I_3, I_4, I_5, message.unwrap_or(&[])];
        // let hash_input = build_hash_input(&inputs);
        
        // // Compute alpha = H(I_1, I_2, I_3, I_4, I_5, message)
        // let alpha = self.hash_to_scalar(&hash_input);
        
        // // Compute beta = r - x*alpha
        // let beta = r - (x * alpha);

        // // Compute gamma = s - i*alpha
        // let gamma = s - (i * alpha);
        
        // // Return the proof (alpha, beta, gamma)
        // let mut proof = SokLogEqProof::default();
        // proof.pi1.copy_from_slice(&alpha);
        // proof.pi2.copy_from_slice(&beta.to_bytes());
        // proof.pi3.copy_from_slice(&gamma.to_bytes());
        
        // proof

        let mut proof = SokLogEqProof::default();

        proof
    }
    
    // fn vok_log_eq(
    //     &mut self,
    //     g1: &BytesP256ElemLen,
    //     g2: &BytesP256ElemLen,
    //     h1: &BytesP256ElemLen,
    //     h2: &BytesP256ElemLen,
    //     pi: &SokLogEqProof,
    //     message: Option<&[u8]>,
    // ) -> bool {
    //     // Convert byte arrays to points and scalars
    //     let g1_point = self.bytes_to_point(g1);
    //     let g2_point = self.bytes_to_point(g2);
    //     let h1_point = self.bytes_to_point(h1);
    //     let h2_point = self.bytes_to_point(h2);
    //     let r1_point = self.bytes_to_point(&pi.pi1);
    //     let r2_point = self.bytes_to_point(&pi.pi2);
    //     let z = match self.bytes_to_scalar(&pi.pi3) {
    //         Some(z) => z,
    //         None => return false,
    //     };
        
    //     // Create the hash input (R1, R2, g1, g2, h1, h2, message)
    //     let inputs = [&r1_bytes[..], &r2_bytes[..], g1, g2, h1, h2, message.unwrap_or(&[])];
    //     let let hash_input = build_hash_input(&inputs);

    //     // let mut hash_input = Vec::with_capacity(
    //     //     pi.pi1.len() + pi.pi2.len() + g1.len() + g2.len() + h1.len() + h2.len() + 
    //     //     message.map_or(0, |m| m.len())
    //     // );
    //     // hash_input.extend_from_slice(&pi.pi1);
    //     // hash_input.extend_from_slice(&pi.pi2);
    //     // hash_input.extend_from_slice(g1);
    //     // hash_input.extend_from_slice(g2);
    //     // hash_input.extend_from_slice(h1);
    //     // hash_input.extend_from_slice(h2);
    //     // if let Some(msg) = message {
    //     //     hash_input.extend_from_slice(msg);
    //     // }
        
    //     // Compute c = H(R1, R2, g1, g2, h1, h2, message)
    //     let c = self.hash_to_scalar(&hash_input);
        
    //     // Verify: g1^z == R1 * h1^c and g2^z == R2 * h2^c
    //     let g1_z = g1_point * z;
    //     let h1_c = h1_point * c;
    //     let expected1 = r1_point + h1_c;
        
    //     let g2_z = g2_point * z;
    //     let h2_c = h2_point * c;
    //     let expected2 = r2_point + h2_c;
        
    //     g1_z == expected1 && g2_z == expected2
    // }

    // fn precomp(
    //     &mut self,
    //     pk_aut: &[BytesP256AuthPubKey],
    //     pk: &BytesP256ElemLen,
    //     // id_cred: &IdCred,
    //     id_cred: EdhocBuffer<16>,
    // ) -> (BytesP256ElemLen, BytesHashLen) {
    //     // Verify all authority keys
    //     for pk in pk_aut {
    //         if !self.vok_log(&pk.pk1, &pk.pk2, None) {
    //             panic!("Error: authority keys invalid");
    //         }
    //     }
        
    //     // Compute h as the product of all authority public keys
    //     let mut h_point = self.bytes_to_point(&pk_aut[0].pk1);
    //     for i in 1..pk_aut.len() {
    //         let pk_point = self.bytes_to_point(&pk_aut[i].pk1);
    //         h_point = h_point + pk_point;
    //     }

    //     // Compute w as concatenation of authority public keys and hash of peer identity
    //     let mut w = Vec::new();
        
    //     // Add all authority public keys to the concatenation
    //     for auth_pk in pk_aut {
    //         w.extend_from_slice(&auth_pk.pk1);
    //     }
        
    //     // Add hash of id_cred
    //     let peer_id_hash = self.sha256_digest(id_cred);
    //     w.extend_from_slice(&peer_id_hash);
        
    //     // Return the computed values
    //     (h_point.to_bytes(), w)

    // }

    // fn initiator_sok(
    //     &mut self,
    //     h: &BytesP256ElemLen,
    //     g_r: &BytesP256ElemLen, 
    //     g_x: &BytesP256ElemLen, 
    //     g_y: &BytesP256ElemLen, 
    //     x: &BytesP256ElemLen, 
    //     i: &BytesP256ElemLen,
    //     w: &BytesHashLen, 
    // ) -> () {
    //     // Compute H_I^1 = (h_I * g^y)^x
    //     let h_point_1 = self.bytes_to_point(h);
    //     let g_y_point = self.bytes_to_point(g_y);
    //     let h_g_y = h_point + g_y_point;
    //     let h_1 = h_g_y * x;
    //     let h_bytes_1 = h_1.to_affine().x().to_bytes();

    //     // Compute H_I^2 = (h_I * g^r)^x
    //     let h_point_1 = self.bytes_to_point(h);
    //     let g_r_point = self.bytes_to_point(g_r);
    //     let h_g_r = h_point + g_r_point;
    //     let h_2 = h_g_r * x;
    //     let h_bytes_2 = h_2.to_affine().x().to_bytes();

    //     // Generate proof pi
    //     let h_g_y_bytes = h_g_y.to_affine().x().to_bytes();
    //     let h_g_r_bytes = h_g_r.to_affine().x().to_bytes();
        
    //     let pi = self.sok_log_eq(
    //         x,
    //         &g_x,
    //         &h_g_y_bytes.into(),
    //         &h_g_r_bytes.into(),
    //         Some(w),
    //     );
    // }

    // fn responder_sok(
    //     &mut self,
    //     h: &BytesP256ElemLen,
    //     g_i: &BytesP256ElemLen, 
    //     g_y: &BytesP256ElemLen, 
    //     g_x: &BytesP256ElemLen, 
    //     y: &BytesP256ElemLen, 
    //     r: &BytesP256ElemLen,
    //     w: &BytesHashLen, 
    // ) -> () {
    //     // Compute Y = g^y
    //     // let y_point = p256::ProjectivePoint::generator() * y;
    //     // let y_bytes = x_point.to_affine().x().to_bytes();

    //     // Compute H1 = (h_R * g^x)^y
    //     let h_point_1 = self.bytes_to_point(h);
    //     let g_x_point = self.bytes_to_point(g_x);
    //     let h_g_x = h_point + g_x_point;
    //     let h_1 = h_g_x * y;
    //     let h_bytes_1 = h_1.to_affine().x().to_bytes();

    //     // Compute H2 = (h_R * g^i)^y
    //     let h_point_1 = self.bytes_to_point(h);
    //     let g_i_point = self.bytes_to_point(g_i);
    //     let h_g_i = h_point + g_i_point;
    //     let h_2 = h_g_i * y;
    //     let h_bytes_2 = h_2.to_affine().x().to_bytes();

    //     // Generate proof pi
    //     let h_g_x_bytes = h_g_x.to_affine().x().to_bytes();
    //     let h_g_i_bytes = h_g_i.to_affine().x().to_bytes();
        
    //     let pi = self.sok_log_eq(
    //         y,
    //         &g_y,
    //         &h_g_x_bytes.into(),
    //         &h_g_i_bytes.into(),
    //         Some(w),
    //     );
    // }
}

