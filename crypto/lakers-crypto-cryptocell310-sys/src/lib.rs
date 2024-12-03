#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![no_std]

extern crate num_bigint;
extern crate num_traits;
use num_bigint::BigUint;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

use core::ffi::c_void;
use lakers_shared::{Crypto as CryptoTrait, *};

fn convert_array(input: &[u32]) -> [u8; SHA256_DIGEST_LEN] {
    assert!(input.len() == SHA256_DIGEST_LEN / 4);

    let mut output = [0x00u8; SHA256_DIGEST_LEN];
    for i in 0..SHA256_DIGEST_LEN / 4 {
        output[4 * i..4 * i + 4].copy_from_slice(&input[i].to_le_bytes());
    }
    output
}

// shared mutable global state for crypto backend (not thread-safe)
static mut rnd_context: CRYS_RND_State_t = CRYS_RND_State_t {
    Seed: [0; 12usize],
    PreviousRandValue: [0; 4usize],
    PreviousAdditionalInput: [0; 17usize],
    AdditionalInput: [0; 16usize],
    AddInputSizeWords: 0,
    EntropySourceSizeWords: 0,
    ReseedCounter: 0,
    KeySizeWords: 0,
    StateFlag: 0,
    TrngProcesState: 0,
    ValidTag: 0,
    EntropySizeBits: 0,
};
static mut rnd_work_buffer: CRYS_RND_WorkBuff_t = CRYS_RND_WorkBuff_t {
    crysRndWorkBuff: [0; 1528usize]
};

pub unsafe fn edhoc_rs_crypto_init() {
    unsafe {
        SaSi_LibInit();
        let ret = CRYS_RndInit(
            &mut rnd_context as *mut _ as *mut c_void,
            &mut rnd_work_buffer as *mut _,
        );
        if ret != CRYS_OK {
            panic!("Crypto backend initialization failed");
        }
    }
}

#[derive(Debug)]
pub struct Crypto;

impl CryptoTrait for Crypto {
    // fn sok_log(
    //     &mut self,
    //     ephemeral_private_key: &BytesP256ElemLen, // x
    //     static_private_key: &BytesP256ElemLen, // i
    //     ephemeral_public_key: &BytesP256ElemLen, // Y = g^y
    //     static_public_key: &BytesP256ElemLen, // R = g^r
    //     message: &mut [u8], // w_I
    //     hash: &BytesHashLen // h_I
    // ) -> (BytesP256ElemLen, BytesP256ElemLen, BytesP256ElemLen) {
    //     // generate a radnom number
    //     let mut w =  [0u8; P256_ELEM_LEN];
    //     w.copy_from_slice(&[self.get_random_byte()]);

    //     let mut q =  [0u8; P256_ELEM_LEN];
    //     q.copy_from_slice(&[self.get_random_byte()]);

    //     // compute I_1 = g^w
    //     let I_1 = self.compute_g_to(&w);

    //     // Compute I_2 = (hg^y)^w
    //     let point_I_2 = self.scalar_mult_mod(hash, ephemeral_public_key);
    //     let I_2 = self.expon(&point_I_2, &w);

    //     //  Compute I_3 = (hg^r)^w) where R is the public DH key of Responder
    //     let point_I_3 = self.scalar_mult_mod(hash, static_public_key);
    //     let I_3 = self.expon(&point_I_3, &w);

    //     //  compute I_4
    //     let I_4 = self.compute_g_to(&q);

    //     //  compute I_5 = (hg^y)^q)
    //     let point_I_5 = self.scalar_mult_mod(hash, ephemeral_public_key);
    //     let I_5 = self.expon(&point_I_5, &q);

    //     // compute the challenge \alpha_I
    //     let mut input_c = [0u8; MAX_BUFFER_LEN]; //[0u8; MAX_MESSAGE_SIZE_LEN];
    //     let mut offset = 0;
    //     input_c[offset..offset + I_1.len()].copy_from_slice(I_1.as_slice());
    //     offset += I_1.len();
    //     input_c[offset..offset + I_2.len()].copy_from_slice(I_2.as_slice());
    //     offset += I_2.len();
    //     input_c[offset..offset + I_3.len()].copy_from_slice(I_3.as_slice());
    //     offset += I_3.len();
    //     input_c[offset..offset + I_4.len()].copy_from_slice(I_4.as_slice());
    //     offset += I_4.len();
    //     input_c[offset..offset + I_5.len()].copy_from_slice(I_5.as_slice());
    //     offset += I_5.len();
    //     input_c[offset..offset + message.len()].copy_from_slice(message);
    //     offset += message.len();
    //     let alpha_I = self.sha256_digest(&input_c, offset);

    //     // Compute \beta_I = w + alpha_I * x
    //     let sum_beta_I = self.scalar_mult_mod(&alpha_I, ephemeral_private_key);
    //     let beta_I = self.scalar_add_mod(&w, &sum_beta_I);

    //     //  compute \gamma_I = q + alpha_I * i
    //     let sum_gamma_I = self.scalar_mult_mod(&alpha_I, static_private_key);
    //     let gamma_I = self.scalar_add_mod(&q, &sum_gamma_I);

    //     // return the proof
    //     (alpha_I, beta_I, gamma_I)

    // }

    // fn scalar_mult_mod(
    //     &mut self,
    //     a: &BytesP256ElemLen, 
    //     b: &BytesP256ElemLen
    // ) -> BytesP256ElemLen {
    //     let a_big =  BigUint::from_bytes_be(a);
    //     let b_big = BigUint::from_bytes_be(b);
    //     let p256_order: [u8; 32] = [
    //         0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    //         0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51]
    //     let p256_order_big = BigUint::from_bytes_be(p256_order.as_slice());

    //     let product_big = (a_big * b_big) % p256_order_big;

    //     let mut bytes = product_big.to_bytes_be();
    //     while bytes.len() < P256_ELEM_LEN {
    //         bytes.insert(0, 0);  // Insert leading zeros
    //     }

    //     let mut product = [0u8; P256_ELEM_LEN];
    //     product.copy_from_slice(&bytes[bytes.len() - P256_ELEM_LEN..]);

    //     product
    // }

    // fn scalar_add_mod(
    //     &mut self,
    //     a: &BytesP256ElemLen, 
    //     b: &BytesP256ElemLen
    // ) -> BytesP256ElemLen {
    //     let a_big =  BigUint::from_bytes_be(a);
    //     let b_big = BigUint::from_bytes_be(b);
    //     let p256_order: [u8; 32] = [
    //         0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    //         0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51]
    //     let p256_order_big = BigUint::from_bytes_be(p256_order.as_slice());

    //     let sum_big = (a_big + b_big) % p256_order_big;

    //     let mut bytes = sum_big.to_bytes_be();
    //     while bytes.len() < P256_ELEM_LEN {
    //         bytes.insert(0, 0);  // Insert leading zeros
    //     }

    //     let mut sum = [0u8; P256_ELEM_LEN];
    //     sum.copy_from_slice(&bytes[bytes.len() - P256_ELEM_LEN..]);

    //     sum
    // }

    // fn expon(
    //     &mut self,
    //     point: &BytesP256ElemLen, // The curve point
    //     scalar: &BytesP256ElemLen, // The scalar
    // ) -> BytesP256ElemLen {
    //     let mut result = [0u8; P256_ELEM_LEN];
    //     let domain = unsafe { CRYS_ECPKI_GetEcDomain(CRYS_ECPKI_DomainID_t_CRYS_ECPKI_DomainID_secp256r1) };

    //     unsafe {
    //         let mut public_key = CRYS_ECPKI_UserPublKey_t::default(); // Create public key structure
    //         let mut private_key = CRYS_ECPKI_UserPrivKey_t::default(); // Create private key structure
    //         let mut tmp_data = CRYS_ECDH_TempData_t::default(); // Temporary data buffer
    //         let mut output_len: u32 = result.len() as u32;

    //         // Build the public key from the given point
    //         // FIXME. SHould it be in compressed form? If so:
    //         // let mut point_compressed = [0x0u8; P256_ELEM_LEN + 1];
    //         // point_compressed[0] = 0x02;
    //         // point_compressed[1..].copy_from_slice(&point[..]);
    //         _DX_ECPKI_BuildPublKey(
    //             domain,
    //             point.clone().as_mut_ptr(),
    //             point.len() as u32,
    //             EC_PublKeyCheckMode_t_CheckPointersAndSizesOnly,
    //             &mut public_key,
    //             core::ptr::null_mut(),
    //         );
    
    //         // Build the private key from the scalar
    //         CRYS_ECPKI_BuildPrivKey(
    //             domain,
    //             scalar.as_ptr(),
    //             scalar.len() as u32,
    //             &mut private_key,
    //         );
    
    //         // Perform scalar multiplication using the ECDH function
    //         let res = CRYS_ECDH_SVDP_DH(
    //             &mut public_key,
    //             &mut private_key,
    //             result.as_mut_ptr(),
    //             &mut output_len,
    //             &mut tmp_data,
    //         );
    
    //         if res != CRYS_OK {
    //             panic!("multiplication failed: {:?}", res);
    //         }
    //     }
    
    //     result
    // }


    // fn compute_g_to(&mut self, scalar: &[u8; P256_ELEM_LEN]) -> [u8; P256_ELEM_LEN] {
    //     // maybe there is a way of retreiving instead of doing it by hand
    //     let g_x = [0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47,
    //     0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2,
    //     0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0,
    //     0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96];

    //     //  in its compressed form
    //     let mut g = [0u8; P256_ELEM_LEN + 1];
    //     g[0] = 0x02;
    //     g[1..].copy_from_slice(&g_x);

    //     let mut result = [0u8; P256_ELEM_LEN];
    //     let domain = unsafe { CRYS_ECPKI_GetEcDomain(CRYS_ECPKI_DomainID_t_CRYS_ECPKI_DomainID_secp256r1) };

    //     unsafe {
    //         let mut public_key = CRYS_ECPKI_UserPublKey_t::default(); // Create public key structure
    //         let mut private_key = CRYS_ECPKI_UserPrivKey_t::default(); // Create private key structure
    //         let mut tmp_data = CRYS_ECDH_TempData_t::default(); // Temporary data buffer
    //         let mut output_len: u32 = result.len() as u32;

    //         // Build the public key from the given point
    //         _DX_ECPKI_BuildPublKey(
    //             domain,
    //             g.as_mut_ptr(),
    //             g.len() as u32,
    //             EC_PublKeyCheckMode_t_CheckPointersAndSizesOnly,
    //             &mut public_key,
    //             core::ptr::null_mut(),
    //         );
    
    //         // Build the private key from the scalar
    //         CRYS_ECPKI_BuildPrivKey(
    //             domain,
    //             scalar.as_ptr(),
    //             scalar.len() as u32,
    //             &mut private_key,
    //         );
    
    //         // Perform scalar multiplication using the ECDH function
    //         let res = CRYS_ECDH_SVDP_DH(
    //             &mut public_key,
    //             &mut private_key,
    //             result.as_mut_ptr(),
    //             &mut output_len,
    //             &mut tmp_data,
    //         );
    
    //         if res != CRYS_OK {
    //             panic!("multiplication failed: {:?}", res);
    //         }
    //     }
    
    //     result
    // }

    // fn vok_log(
    //     &mut self, 
    //     ephemeral_public_key_I: &BytesP256ElemLen, // X = g^x
    //     ephemeral_public_key_R: &BytesP256ElemLen, // Y = g^y
    //     static_public_key: &BytesP256ElemLen, // R = g^r
    //     hash: &BytesHashLen, 
    //     proof: &(BytesP256ElemLen, BytesP256ElemLen, BytesP256ElemLen),
    //     message: &mut [u8]
    // ) -> bool {
    //     // Extract R and z from the proof
    //     let (alpha_I, beta_I,gamma_I ) = proof;

    //     // Compute c = H(R, h, m)
    //     let mut input_c = [0u8; MAX_BUFFER_LEN]; //[0u8; MAX_MESSAGE_SIZE_LEN];
    //     let mut offset = 0;
    //     input_c[offset..offset + alpha_I.len()].copy_from_slice(alpha_I.as_slice());
    //     offset += alpha_I.len();
    //     input_c[offset..offset + hash.len()].copy_from_slice(hash);
    //     offset += hash.len();
    //     input_c[offset..offset + message.len()].copy_from_slice(message);
    //     offset += message.len();
    //     let c = self.sha256_digest(&input_c, offset);

    //     // Verify if g^z == R * h^c
    //     self.verify_sok_equation(g_r, z, hash, &c)
    // }

    // fn verify_sok_equation(
    //     &mut self,
    //     g_r: &BytesP256ElemLen,
    //     z: &[u8; P256_ELEM_LEN],
    //     hash: &BytesHashLen, 
    //     c: &BytesP256ElemLen
    // ) -> bool {
    //     // maybe there is a way of retreiving instead of doing it by hand
    //     let g_x = [0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47,
    //     0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2,
    //     0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0,
    //     0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96];
    //     //  in its compressed form
    //     let mut g = [0u8; P256_ELEM_LEN + 1];
    //     g[0] = 0x02;
    //     g[1..].copy_from_slice(&g_x);

    //     // compute g^z
    //     let g_to_the_z = self.compute_g_to(&z);

    //     //  compute h^c
    //     let h_to_the_c = self.expon(hash, c);

    //     //  crypto cell addition???
    //     let g_r_plus_h_to_the_c = self.add_point(g_r, h_to_the_c);

    //     // return comparison of g_r_plus_h_to_the_c == g_to_the_z

    // }

    fn sha256_digest(&mut self, message: &BytesMaxBuffer, message_len: usize) -> BytesHashLen {
        let mut buffer: [u32; 64 / 4] = [0x00; 64 / 4];

        unsafe {
            CRYS_HASH(
                CRYS_HASH_OperationMode_t_CRYS_HASH_SHA256_mode,
                message.clone().as_mut_ptr(),
                message_len,
                buffer.as_mut_ptr(),
            );
        }

        convert_array(&buffer[0..SHA256_DIGEST_LEN / 4])
    }

    fn hkdf_expand(
        &mut self,
        prk: &BytesHashLen,
        info: &BytesMaxInfoBuffer,
        info_len: usize,
        length: usize,
    ) -> BytesMaxBuffer {
        let mut buffer = [0x00u8; MAX_BUFFER_LEN];
        unsafe {
            CRYS_HKDF_KeyDerivFunc(
                CRYS_HKDF_HASH_OpMode_t_CRYS_HKDF_HASH_SHA256_mode,
                core::ptr::null_mut(),
                0 as usize,
                prk.clone().as_mut_ptr(),
                prk.len() as u32,
                info.clone().as_mut_ptr(),
                info_len as u32,
                buffer.as_mut_ptr(),
                length as u32,
                SaSiBool_SASI_TRUE,
            );
        }

        buffer
    }

    fn hkdf_extract(&mut self, salt: &BytesHashLen, ikm: &BytesP256ElemLen) -> BytesHashLen {
        // Implementation of HKDF-Extract as per RFC 5869

        // TODO generalize if salt is not provided
        let output = self.hmac_sha256(&mut ikm.clone()[..], *salt);

        output
    }

    fn aes_ccm_encrypt_tag_8(
        &mut self,
        key: &BytesCcmKeyLen,
        iv: &BytesCcmIvLen,
        ad: &[u8],
        plaintext: &BufferPlaintext3,
    ) -> BufferCiphertext3 {
        let mut output: BufferCiphertext3 = BufferCiphertext3::new();
        let mut tag: CRYS_AESCCM_Mac_Res_t = Default::default();
        let mut aesccm_key: CRYS_AESCCM_Key_t = Default::default();
        let mut aesccm_ad = [0x00u8; ENC_STRUCTURE_LEN];

        aesccm_key[0..AES_CCM_KEY_LEN].copy_from_slice(&key[..]);
        aesccm_ad[0..ad.len()].copy_from_slice(&ad[..]);

        let err = unsafe {
            CC_AESCCM(
                SaSiAesEncryptMode_t_SASI_AES_ENCRYPT,
                aesccm_key.as_mut_ptr(),
                CRYS_AESCCM_KeySize_t_CRYS_AES_Key128BitSize,
                iv.clone().as_mut_ptr(),
                iv.len() as u8,
                aesccm_ad.as_mut_ptr(),
                ad.len() as u32,
                plaintext.content.clone().as_mut_ptr(),
                plaintext.len as u32,
                output.content.as_mut_ptr(),
                AES_CCM_TAG_LEN as u8, // authentication tag length
                tag.as_mut_ptr(),
                0 as u32, // CCM
            )
        };

        output.content[plaintext.len..plaintext.len + AES_CCM_TAG_LEN]
            .copy_from_slice(&tag[..AES_CCM_TAG_LEN]);
        output.len = plaintext.len + AES_CCM_TAG_LEN;

        output
    }

    fn aes_ccm_decrypt_tag_8(
        &mut self,
        key: &BytesCcmKeyLen,
        iv: &BytesCcmIvLen,
        ad: &[u8],
        ciphertext: &BufferCiphertext3,
    ) -> Result<BufferPlaintext3, EDHOCError> {
        let mut output: BufferPlaintext3 = BufferPlaintext3::new();
        let mut aesccm_key: CRYS_AESCCM_Key_t = Default::default();

        aesccm_key[0..AES_CCM_KEY_LEN].copy_from_slice(&key[..]);

        let mut err = EDHOCError::MacVerificationFailed;

        unsafe {
            match CC_AESCCM(
                SaSiAesEncryptMode_t_SASI_AES_DECRYPT,
                aesccm_key.as_mut_ptr(),
                CRYS_AESCCM_KeySize_t_CRYS_AES_Key128BitSize,
                iv.clone().as_mut_ptr(),
                iv.len() as u8,
                ad.as_ptr() as *mut _,
                ad.len() as u32,
                ciphertext.content.clone().as_mut_ptr(),
                (ciphertext.len - AES_CCM_TAG_LEN) as u32,
                output.content.as_mut_ptr(),
                AES_CCM_TAG_LEN as u8, // authentication tag length
                ciphertext.content.clone()[ciphertext.len - AES_CCM_TAG_LEN..].as_mut_ptr(),
                0 as u32, // CCM
            ) {
                CRYS_OK => {
                    output.len = ciphertext.len - AES_CCM_TAG_LEN;
                    Ok(output)
                }
                _ => Err(EDHOCError::MacVerificationFailed),
            }
        }
    }

    fn p256_ecdh(
        &mut self,
        private_key: &BytesP256ElemLen,
        public_key: &BytesP256ElemLen,
    ) -> BytesP256ElemLen {
        let mut output = [0x0u8; P256_ELEM_LEN];
        let mut output_len: u32 = output.len() as u32;

        let mut tmp: CRYS_ECDH_TempData_t = Default::default();

        let mut public_key_compressed = [0x0u8; P256_ELEM_LEN + 1];
        public_key_compressed[0] = 0x02;
        public_key_compressed[1..].copy_from_slice(&public_key[..]);

        let mut public_key_cc310: CRYS_ECPKI_UserPublKey_t = Default::default();

        let mut domain =
            unsafe { CRYS_ECPKI_GetEcDomain(CRYS_ECPKI_DomainID_t_CRYS_ECPKI_DomainID_secp256r1) };

        unsafe {
            _DX_ECPKI_BuildPublKey(
                domain,
                public_key_compressed.as_mut_ptr(),
                (P256_ELEM_LEN + 1) as u32,
                EC_PublKeyCheckMode_t_CheckPointersAndSizesOnly,
                &mut public_key_cc310,
                core::ptr::null_mut(),
            );
        }

        let mut private_key_cc310: CRYS_ECPKI_UserPrivKey_t = Default::default();

        unsafe {
            CRYS_ECPKI_BuildPrivKey(
                domain,
                private_key.clone().as_mut_ptr(),
                P256_ELEM_LEN as u32,
                &mut private_key_cc310,
            );
        }

        unsafe {
            CRYS_ECDH_SVDP_DH(
                &mut public_key_cc310,
                &mut private_key_cc310,
                output.as_mut_ptr(),
                &mut output_len,
                &mut tmp,
            );
        }

        output
    }

    fn get_random_byte(&mut self) -> u8 {
        // let mut rnd_context = CRYS_RND_State_t::default();
        // let mut rnd_work_buffer = CRYS_RND_WorkBuff_t::default();
        // unsafe {
        //     SaSi_LibInit();
        //     CRYS_RndInit(
        //         &mut rnd_context as *mut _ as *mut c_void,
        //         &mut rnd_work_buffer as *mut _,
        //     );
        // }
        let mut buffer = [0u8; 1];
        unsafe {
            CRYS_RND_GenerateVector(
                &mut rnd_context as *mut _ as *mut c_void,
                1,
                buffer.as_mut_ptr(),
            );
        }
        buffer[0]
    }

    fn p256_generate_key_pair(&mut self) -> (BytesP256ElemLen, BytesP256ElemLen) {
        // let mut rnd_context = CRYS_RND_State_t::default();
        // let mut rnd_work_buffer = CRYS_RND_WorkBuff_t::default();
        // unsafe {
        //     SaSi_LibInit();
        //     CRYS_RndInit(
        //         &mut rnd_context as *mut _ as *mut c_void,
        //         &mut rnd_work_buffer as *mut _,
        //     );
        // }
        let rnd_generate_vect_func: SaSiRndGenerateVectWorkFunc_t = Some(CRYS_RND_GenerateVector);
        let mut curve_256 =
            unsafe { CRYS_ECPKI_GetEcDomain(CRYS_ECPKI_DomainID_t_CRYS_ECPKI_DomainID_secp256r1) };
        let mut crys_private_key: *mut CRYS_ECPKI_UserPrivKey_t =
            &mut CRYS_ECPKI_UserPrivKey_t::default();
        let mut crys_public_key: *mut CRYS_ECPKI_UserPublKey_t =
            &mut CRYS_ECPKI_UserPublKey_t::default();
        let mut temp_data: *mut CRYS_ECPKI_KG_TempData_t = &mut CRYS_ECPKI_KG_TempData_t::default();
        let mut temp_fips_buffer: *mut CRYS_ECPKI_KG_FipsContext_t =
            &mut CRYS_ECPKI_KG_FipsContext_t::default();

        unsafe {
            CRYS_ECPKI_GenKeyPair(
                &mut rnd_context as *mut _ as *mut c_void,
                rnd_generate_vect_func,
                curve_256,
                crys_private_key,
                crys_public_key,
                temp_data,
                temp_fips_buffer,
            );
        }

        let mut private_key: [u8; P256_ELEM_LEN] = [0x0; P256_ELEM_LEN];
        let mut key_size: u32 = P256_ELEM_LEN.try_into().unwrap();

        unsafe {
            CRYS_ECPKI_ExportPrivKey(crys_private_key, private_key.as_mut_ptr(), &mut key_size);
        }

        // let private_key = BytesP256ElemLen::from_public_slice(&private_key[..]);

        let mut public_key: [u8; P256_ELEM_LEN + 1] = [0x0; P256_ELEM_LEN + 1];
        let mut key_size: u32 = (P256_ELEM_LEN as u32) + 1;
        let compressed_flag: CRYS_ECPKI_PointCompression_t =
            CRYS_ECPKI_PointCompression_t_CRYS_EC_PointCompressed;

        unsafe {
            CRYS_ECPKI_ExportPublKey(
                crys_public_key,
                compressed_flag,
                public_key.as_mut_ptr(),
                &mut key_size,
            );
        }

        let public_key: [u8; P256_ELEM_LEN] = public_key[1..33].try_into().unwrap(); // discard sign byte

        (private_key, public_key)
    }
}

impl Crypto {
    fn hmac_sha256(
        &mut self,
        message: &mut [u8],
        mut key: [u8; SHA256_DIGEST_LEN],
    ) -> BytesHashLen {
        let mut buffer: [u32; 64 / 4] = [0x00; 64 / 4];

        unsafe {
            CRYS_HMAC(
                CRYS_HASH_OperationMode_t_CRYS_HASH_SHA256_mode,
                key.as_mut_ptr(),
                key.len() as u16,
                message.as_mut_ptr(),
                message.len(),
                buffer.as_mut_ptr(),
            );
        }

        convert_array(&buffer[..SHA256_DIGEST_LEN / 4])
    }
}
