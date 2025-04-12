//! Cryptography trait back-end for the lakers-crypto crate

use super::*;

/// Returns the SUITES_I array, or an error if selected_suite is not supported.
///
/// The SUITES_I list will contain:
/// - the selected suite at the last position
/// - an ordered list of preferred suites in the first positions
pub fn prepare_suites_i(
    supported_suites: &EdhocBuffer<MAX_SUITES_LEN>,
    selected_suite: u8,
) -> Result<EdhocBuffer<MAX_SUITES_LEN>, EDHOCError> {
    // TODO: implement a re-positioning algorithm, considering preferred and selected suites (see Section 5.2.2 of RFC 9528)
    //       for now, we only support a single suite so we just return it
    // NOTE: should we assume that supported_suites == preferred_suites?
    if supported_suites.contains(&(selected_suite)) {
        EdhocBuffer::<MAX_SUITES_LEN>::new_from_slice(&[selected_suite.into()])
            .map_err(|_| EDHOCError::UnsupportedCipherSuite)
    } else {
        Err(EDHOCError::UnsupportedCipherSuite)
    }
}

/// Interface between the lakers crate and any implementations of the required crypto primitives.
///
/// Sending cryptographic operations through a trait gives the library the flexibility to use
/// hardware acceleration on microcontrollers, implementations that facilitate hacspec/hax
/// verification, or software implementations.
///
/// The crypto trait itself operates on an exclusive reference, which is useful for the hardware
/// implementations that can only perform a single operation at a time.
///
/// Many implementations will have a Default constructor or will be Clone (even Copy); either
/// facilitates storing multiple EDHOC exchanges at a time. When neither is an option, the
/// remaining options are to wrap a Crypto implementation into interior mutability using the
/// platform's mutex, or to refactor the main initiator and responder objects into a form where the
/// cryptography implementation can be taken out and stored separately.
pub trait Crypto: core::fmt::Debug {
    /// Returns the list of cryptographic suites supported by the backend implementation.
    fn supported_suites(&self) -> EdhocBuffer<MAX_SUITES_LEN> {
        EdhocBuffer::<MAX_SUITES_LEN>::new_from_slice(&[EDHOCSuite::CipherSuite2 as u8])
            .expect("This should never fail, as the slice is of the correct length")
    }
    fn sha256_digest(&mut self, message: &BytesMaxBuffer, message_len: usize) -> BytesHashLen;
    fn hkdf_expand(
        &mut self,
        prk: &BytesHashLen,
        info: &BytesMaxInfoBuffer,
        info_len: usize,
        length: usize,
    ) -> BytesMaxBuffer;
    fn hkdf_extract(&mut self, salt: &BytesHashLen, ikm: &BytesP256ElemLen) -> BytesHashLen;
    fn aes_ccm_encrypt_tag_8(
        &mut self,
        key: &BytesCcmKeyLen,
        iv: &BytesCcmIvLen,
        ad: &[u8],
        plaintext: &BufferPlaintext3,
    ) -> BufferCiphertext3;
    fn aes_ccm_decrypt_tag_8(
        &mut self,
        key: &BytesCcmKeyLen,
        iv: &BytesCcmIvLen,
        ad: &[u8],
        ciphertext: &BufferCiphertext3,
    ) -> Result<BufferPlaintext3, EDHOCError>;
    fn p256_ecdh(
        &mut self,
        private_key: &BytesP256ElemLen,
        public_key: &BytesP256ElemLen,
    ) -> BytesP256ElemLen;
    fn get_random_byte(&mut self) -> u8;
    fn p256_generate_key_pair(&mut self) -> (BytesP256ElemLen, BytesP256ElemLen);
    unsafe fn sok_log_eq(
        &mut self,
        h: BytesP256ElemLen,
        g_r: BytesP256ElemLen, 
        g_x: BytesP256ElemLen, 
        g_y: BytesP256ElemLen, 
        x: BytesP256ElemLen, 
        i: BytesP256ElemLen,
        message: Option<&[u8]>,
    ) -> SokLogEqProof;
    unsafe fn pka_ecc_mult_scalar(&mut self, point_x: BytesP256ElemLen, point_y: BytesP256ElemLen, scalar: BytesP256ElemLen) -> (BytesP256ElemLen, BytesP256ElemLen);
    unsafe fn pka_ecc_point_add(
        &mut self, 
        point_a_x: BytesP256ElemLen, 
        point_a_y: BytesP256ElemLen, 
        point_b_x: BytesP256ElemLen, 
        point_b_y: BytesP256ElemLen
    ) -> (BytesP256ElemLen, BytesP256ElemLen);
    unsafe fn pka_ecc_projective_to_affine(
        &mut self, 
        point_a_x: BytesP256ElemLen, 
        point_a_y: BytesP256ElemLen,
        point_a_z: BytesP256ElemLen,
    ) -> (BytesP256ElemLen, BytesP256ElemLen );
    unsafe fn pka_mod_mult(
        &mut self, 
        a: &BytesP256ElemLen, 
        b: &BytesP256ElemLen, 
    ) -> BytesP256ElemLen;
    unsafe fn pka_mod_sub(
        &mut self, 
        a: &BytesP256ElemLen, 
        b: &BytesP256ElemLen, 
    ) -> BytesP256ElemLen;
    unsafe fn pka_mod_add(
        &mut self, 
        a: &BytesP256ElemLen, 
        b: &BytesP256ElemLen, 
    ) -> BytesP256ElemLen ;
    unsafe fn sok_log(
        &mut self, 
        x: BytesP256ElemLen, 
        h: (BytesP256ElemLen, BytesP256ElemLen), 
        message: Option<&[u8]>
    ) -> SokLogProof ;
    unsafe fn keygen_a(&mut self, gpio: GpioPin) -> (BytesP256AuthPubKey, BytesP256ElemLen);
    unsafe fn precomp(
        &mut self,
        pk_aut: &[BytesP256AuthPubKey],
        id_cred_i: &[u8],
        gpio: GpioPin,
    ) -> (BytesP256ElemLen, BytesHashLen);
    unsafe fn vok_log(
        &mut self, 
        h: (BytesP256ElemLen, BytesP256ElemLen), 
        pi: &SokLogProof, 
        message: Option<&[u8]>
    ) -> bool;

}
