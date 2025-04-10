#![no_std]

use lakers_shared::{A, A_SIGN, B, BASE, BASE_POINT_X, BASE_POINT_Y, COEF_A_OFFSET, COEF_A_OFFSET_ADD, COEF_A_SIGN_OFFSET, COEF_A_SIGN_OFFSET_ADD, COEF_B_OFFSET, MODE, MODULUS_LENGTH_OFFSET, MODULUS_LENGTH_OFFSET_ADD, MODULUS_OFFSET, MODULUS_OFFSET_ADD, MODULUS_OFFSET_PTA, MODULUS_REDUC, MODULUS_SUB, MONTGOMERY_PTA, N, OPERAND_A_ARITHEMTIC_MULT, OPERAND_A_REDUC, OPERAND_A_SUB, OPERAND_B_ARITHEMTIC_MULT, OPERAND_B_SUB, OPERAND_LENGTH, OPERAND_LENGTH_MULT, OPERAND_LENGTH_REDUC, OPERAND_LENGTH_SUB, PKA_RAM_OFFSET, POINT_P_X, POINT_P_X_PTA, POINT_P_Y, POINT_P_Y_PTA, POINT_P_Z, POINT_P_Z_PTA, POINT_Q_X, POINT_Q_Y, POINT_Q_Z, POINT_X_OFFSET, POINT_Y_OFFSET, PRIME_LENGTH_OFFSET, PRIME_LENGTH_OFFSET_ADD, PRIME_OFFSET, PRIME_ORDER, R2MODN, RAM_BASE, RAM_NUM_DW, RESULT_ARITHMETIC_MULT, RESULT_ERROR_ADD, RESULT_ERROR_OFFSET, RESULT_ERROR_PTA, RESULT_REDUC, RESULT_SUB, RESULT_X_ADD, RESULT_X_OFFSET, RESULT_X_PTA, RESULT_Y_ADD, RESULT_Y_OFFSET, RESULT_Y_PTA, SCALAR_K_ADD, SCALAR_M_ADD, SCALAR_OFFSET, WORD_LENGTH, Z_COORDINATE 
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
use defmt::{info, trace};
use hexlit::hex;

// use embassy_nrf::gpio::Output;
// use embedded_hal::digital::v2::OutputPin;

type AesCcm16_64_128 = ccm::Ccm<aes::Aes128, ccm::consts::U8, ccm::consts::U13>;

pub const X: [u8; 32] = hex!("368ec1f69aeb659ba37d5a8d45b21bdc0299dceaa8ef235f3ca42ce3530f9525");
pub const G_X_X_COORD: [u8; 32] = hex!("8af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b6");
pub const G_X_Y_COORD: [u8; 32] = hex!("51e8af6c6edb781601ad1d9c5fa8bf7aa15716c7c06a5d038503c614ff80c9b3");
pub const CRED_I: &[u8] = &hex!("A2027734322D35302D33312D46462D45462D33372D33322D333908A101A5010202412B2001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8");
pub const I: &[u8] = &hex!("fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b");
pub const SK: [u8; 32] = hex!("5c4172aca8b82b5a62e66f722216f5a10f72aa69f42c1d1cd3ccd7bfd29ca4e9");

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



pub struct Crypto {
    // TODO
}

impl Crypto {
    pub fn new() -> Self {
        Self { }
    }

    pub fn lakers_crypto_rustcrypto_stm_init(&self) {
        
    }

}

impl core::fmt::Debug for Crypto  {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        f.debug_struct("lakers_crypto_rustcrypto::Crypto")
            // Exclude the rng field from Debug output
            .finish()
    }
}

impl CryptoTrait for Crypto  {

    fn sha256_digest(&mut self, message: &BytesMaxBuffer, message_len: usize) -> BytesHashLen {
        let mut hasher = sha2::Sha256::new();
        hasher.update(&message[..message_len]);
        hasher.finalize().into()
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
        (X, G_X_X_COORD)
    }

    unsafe fn precomp(
        &mut self,
        pk_aut: &[BytesP256AuthPubKey],
        id_cred_i: &[u8],
    ) -> (BytesP256ElemLen, BytesHashLen) {
        trace!("Precomputation phase");

        trace!("Verify authorities keys");
        // Verify all authority keys
        // gpio.set_high();
        for pk in pk_aut {
            if !self.vok_log(pk.pk1, &pk.pk2, None) {
                panic!("Error: authority keys invalid");
            }
        }
        // gpio.set_low();
        
        // Compute h as the product of all authority public keys
        trace!("Computation of h");
        // gpio.set_high();
        let (mut h_point_x, mut h_point_y) = pk_aut[0].pk1;
        let mut h = coordinates_to_projective_point(h_point_x, h_point_y);
        for i in 1..pk_aut.len() {
            let (pk_point_x, pk_point_y) = pk_aut[i].pk1;
            let pk_proj = coordinates_to_projective_point(pk_point_x, pk_point_y);
            h = h + pk_proj;
        }
        // gpio.set_low();
        
        trace!("Computation of w");
        // gpio.set_high();
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
        // gpio.set_low();

        // Return (h, w)        
        (h_point_x, w)
    }

    // Authority key generation function
    unsafe fn keygen_a(&mut self) -> (BytesP256AuthPubKey, BytesP256ElemLen) {
        trace!("KeyAuthGen");
        // Generate random secret key
        // let sk = p256::NonZeroScalar::random(&mut self.rng);
        // For now we replace it with a hard coded constant SK
        // info!("SK: {:#X}", SK);
        let sk_scalar = Scalar::from_repr(SK.into()).unwrap();

        // pk1 = g^sk (g is the generator point in P256)
        // gpio.set_high();
        let (pk1_x, pk1_y) = ecc_generator_mult(sk_scalar);
        // gpio.set_low();
        // info!("pk1_x: {:#X}   pk1_y: {:#X}", pk1_x, pk1_y);

        // Create proof of knowledge of sk
        // FIX: Should we pass both coordinates? How to make sure is always the 0x2 for y-coordinate?
        // gpio.set_high();
        let pk2 = self.sok_log(SK, (pk1_x, pk1_y), None);
        // gpio.set_low();

        // Create the authority public key structure
        // gpio.set_high();
        let mut pk = BytesP256AuthPubKey::default();
        pk.pk1 = (pk1_x, pk1_y);
        pk.pk2 = pk2;
        // gpio.set_low();

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
        let (g_r_x, g_r_y) = ecc_generator_mult(r_scalar);

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
        let g_r_proj_point = coordinates_to_projective_point(g_r_x, g_r_y);

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
        let (g_z_x, g_z_y) = ecc_generator_mult(z_scalar);

        // Convert h_x and h_y bytes into an AffinePoint
        let h_point_proj = coordinates_to_projective_point(h_point_x, h_point_y);
        let h_c = h_point_proj * c_scalar;
        let expected_point = h_c + g_r_proj_point;

        let expected_point_affine = expected_point.to_affine();
        let uncompressed = expected_point_affine.to_encoded_point(false);
        let expected_point_x: [u8; 32] = uncompressed.x().unwrap().clone().into();
        let expected_point_y: [u8; 32] = uncompressed.y().unwrap().clone().into();
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

        let (h_point_x, h_point_y) = bytes_to_point(&h);
        let h_proj_point = coordinates_to_projective_point(h_point_x, h_point_y);

        let (g_y_point_x, g_y_point_y) = bytes_to_point(&g_y);
        let g_y_proj_point = coordinates_to_projective_point(g_y_point_x, g_y_point_y);

        let (g_r_point_x, g_r_point_y) = bytes_to_point(&g_r);
        let g_r_proj_point = coordinates_to_projective_point(g_r_point_x, g_r_point_x);

        let x_scalar = Scalar::from_repr(x.into()).unwrap();

        // Compute H_I^1 = (h_I * g^y)^x
        let h_i_1_temp = h_proj_point + g_y_proj_point;
        let h_i_1 = h_i_1_temp * x_scalar;

        // Compute H_I^2 = (h_I * g^r)^x
        let h_i_2_temp = h_proj_point + g_r_proj_point;
        let h_i_1 = h_i_2_temp * x_scalar;

        // Generate proof pi
        // Generate random value r_I, s_I
        let r = hex!("d1f3a4c8b66e30f78a53e5b7896ab8a2ffefc0bde45a7a7e13347157956c8e2a");
        let r_scalar = Scalar::from_repr(r.into()).unwrap();
        let s = hex!("5bfe2d83d8b44059f01b0e6efef7622ab0806e67dfed50d9d48f845e7f4b35a1");
        let s_scalar = Scalar::from_repr(s.into()).unwrap();

        // Compute I_1 = g^r_I
        let i_1 = ecc_generator_mult_projective(r_scalar);
        
        // Compute I_2 = (h_I g^y)^r
        let i_2 = h_i_1_temp * r_scalar;

        // Compute I_3 = (h_I g^r)^r
        let i_3 = h_i_2_temp * r_scalar;

        // Compute I_4 = g^s
        let i_4 = ecc_generator_mult_projective(s_scalar);

        // Compute I_5 = (h_I g^y)^s
        let i_5 = h_i_1_temp * s_scalar;

        // Create the hash input (I_1, I_2, I_3, I_4, I_5, message)
        // we need to add I_1 + I_2 + I_3 + I_4 + I_5
        let sum = i_1 + i_2 + i_3 + i_4 + i_5;
        let (sum_x, sum_y) = projective_to_coordinates(sum);

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

