#![no_std]

use lakers_shared::{
    BufferCiphertext3, BufferPlaintext3, BytesCcmIvLen, BytesCcmKeyLen, BytesHashLen,
    BytesMaxBuffer, BytesMaxInfoBuffer, BytesP256ElemLen, Crypto as CryptoTrait, EDHOCError,
    AES_CCM_TAG_LEN, MAX_BUFFER_LEN, BytesP256AuthPubKey,SokLogProof,SokLogEqProof,
};

use ccm::AeadInPlace;
use ccm::KeyInit;
use p256::elliptic_curve::point::AffineCoordinates;
use p256::elliptic_curve::point::DecompressPoint;
use sha2::Digest;
// use cortex_m::asm;
use stm32wba::stm32wba55;
use stm32wba::stm32wba55::Peripherals as peripherals;
use stm32wba::stm32wba55::PKA as PKA;
use stm32wba::stm32wba55::HASH as HASH;


type AesCcm16_64_128 = ccm::Ccm<aes::Aes128, ccm::consts::U8, ccm::consts::U13>;

/// A type representing cryptographic operations through various RustCrypto crates (eg. [aes],
/// [ccm], [p256]).
///
/// Its size depends on the implementation of Rng passed in at creation.
pub struct Crypto {
    p: peripherals,
    // hash: peripherals::HASH,
    // pka: peripherals::PKA,
}

impl Crypto {
    pub const fn new(p: peripherals ) -> Self {
        Self { p}
    }

    pub fn lakers_crypto_rustcrypto_stm_init(&self) {

        let hash = Self::stm32wba_init_hash(self);
        let pka = Self::stm32wba_init_pka(self);
    }

    fn stm32wba_init_pka(&self) -> &PKA {
        // TODO
        &self.p.PKA
    }

    fn stm32wba_init_hash(&self) -> &HASH {
        // TODO
        &self.p.HASH
    }
}

// impl core::fmt::Debug for Crypto {
//     fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
//         f.debug_struct("lakers_crypto_rustcrypto::Crypto")
//             .field("rng", &core::any::type_name::<Rng>())
//             .finish()
//     }
// }

impl CryptoTrait for Crypto {
   
    fn sha256_digest(&mut self, message: &BytesMaxBuffer, message_len: usize) -> BytesHashLen {
        // Pack bytes into a word (big-endian for SHA-256)
        let mut word = 0u32;
        for (i, &byte) in message.iter().enumerate() {
            // Shift existing bits and add new byte
            word |= u32::from(byte) << (8 * (3 - (i % 4)));
            
            // Write word when we have 4 bytes or at the end of the message
            if ((i + 1) % 4 == 0) || (i == message_len - 1) {
                // If it's the last word and not a full 4-byte word, add padding
                if i == message_len - 1 && message_len % 4 != 0 {
                    word |= 0x80 >> (8 * (i % 4 + 1));
                }
                
                // info!("Writing word: 0x{:08x}", word);
                unsafe {
                    self.p.HASH.hash_din().write(|w| w.bits(word));
                    word = 0;
                }
            }
        }


        // If message length is not a multiple of 4, ensure proper padding
        if message_len % 4 != 0 {
            // Set NBLW to the number of valid bits in the last word
            unsafe {
                self.p.HASH.hash_str().write(|w| w.nblw().bits((message_len as u8 % 4) * 8));
            }
        }

        // Start padding and digest computation
        self.p.HASH.hash_str().write(|w| w.dcal().set_bit());

        // // Wait for busy bit to clear
        // while self.p.HASH.hash_sr().read().busy().bit_is_set() {
        //     asm::nop();
        // }

        // // Also check that DCAL bit has been cleared by hardware
        // while self.p.HASH.hash_sr().read().dcis().bit_is_clear() {
        //     asm::nop();
        // }

        // // Read final hash
        // let hash_result = [
        //     hash.hash_hr0().read().bits(),
        //     hash.hash_hr1().read().bits(),
        //     hash.hash_hr2().read().bits(),
        //     hash.hash_hr3().read().bits(),
        //     hash.hash_hr4().read().bits(),
        //     hash.hash_hr5().read().bits(),
        //     hash.hash_hr6().read().bits(),
        //     hash.hash_hr7().read().bits(),
        // ];

        [0u8;32]

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
        let secret = p256::SecretKey::random(&mut self.rng);

        let public_key = secret.public_key().as_affine().x();
        let private_key = secret.to_bytes();

        (private_key.into(), public_key.into())
        // ([0u8; BytesP256ElemLen], [0u8; BytesP256ElemLen])
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

    // fn bytes_to_point(&self, bytes: &[u8]) -> p256::ProjectivePoint {
    //     let affine_point = p256::AffinePoint::decompress(
    //         bytes.into(),
    //         1.into(), // Y coordinate choice
    //     ).expect("Invalid public key point");
    
    //     p256::ProjectivePoint::from(affine_point) // Convert to projective point
    // }

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

    // fn sok_log_eq(
    //     &mut self,
    //     x: BytesP256ElemLen,
    //     i: BytesP256ElemLen,
    //     g_x: &BytesP256ElemLen,
    //     h_g_y: &BytesP256ElemLen,
    //     h_g_r: &BytesP256ElemLen,
    //     message: Option<&[u8]>,
    // ) -> SokLogEqProof {
    //     // Define the generator
    //     let g = p256::ProjectivePoint::generator();

    //     // Generate random value r_I, s_I
    //     let r = p256::NonZeroScalar::random(&mut self.rng);
    //     let s = p256::NonZeroScalar::random(&mut self.rng);
        
    //     // Convert byte arrays to points
    //     let h_g_y_point = self.bytes_to_point(h_g_y);
    //     let h_g_r_point = self.bytes_to_point(h_g_r);
        
    //     // Compute I_1 = g^r_I
    //     let I_1_point = g * r;
    //     let I_1 = I_1_point.to_affine().x().to_bytes();

    //     // Compute I_2 = (h_I g^y)^r
    //     let I_2 = h_g_y_point * r;

    //     // Compute I_3 = (h_I g^r)^r
    //     let I_3 = h_g_r_point * r;

    //     // Compute I_4 = g^s
    //     let I_4_point = g * s;
    //     let I_4 = I_4_point.to_affine().x().to_bytes();

    //     // Compute I_5 = (h_I g^y)^s
    //     let I_5 = h_g_y_point * s;
        
    //     // Create the hash input (I_1, I_2, I_3, I_4, I_5, message)
    //     let inputs = [I_1, I_2, I_3, I_4, I_5, message.unwrap_or(&[])];
    //     let hash_input = build_hash_input(&inputs);
        
    //     // Compute alpha = H(I_1, I_2, I_3, I_4, I_5, message)
    //     let alpha = self.hash_to_scalar(&hash_input);
        
    //     // Compute beta = r - x*alpha
    //     let beta = r - (x * alpha);

    //     // Compute gamma = s - i*alpha
    //     let gamma = s - (i * alpha);
        
    //     // Return the proof (alpha, beta, gamma)
    //     let mut proof = SokLogEqProof::default();
    //     proof.pi1.copy_from_slice(&alpha);
    //     proof.pi2.copy_from_slice(&beta.to_bytes());
    //     proof.pi3.copy_from_slice(&gamma.to_bytes());
        
    //     proof
    // }
    
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
    //     // Compute X = g^x
    //     // let x_point = p256::ProjectivePoint::generator() * x;
    //     // let x_bytes = x_point.to_affine().x().to_bytes();

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

