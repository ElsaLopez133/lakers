use lakers_shared::{Crypto as CryptoTrait, *};
mod edhoc;
pub use edhoc::*;

#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "python-bindings", pyclass)]
#[repr(C)]


fn compute_prk_3e2m(
    crypto: &mut impl CryptoTrait,
    salt_3e2m: &BytesHashLen,
    psk: &BytesP256ElemLen, //TODO: what is th epsk type? len?
) -> BytesHashLen {
    crypto.hkdf_extract(salt_3e2m, &psk)
}

//prk_4e3m = prk_3e2m

fn compute_mac_2(
    crypto: &mut impl CryptoTrait,
    prk_3e2m: &BytesHashLen,
    c_r: ConnId,
    id_cred_psk: &BytesIdCredPSK, //TODO
    th_2: &BytesHashLen,
    ead_2: &Option<EADItem>,
) -> BytesMac2 {
    // compute MAC_2
    let (context, context_len) = encode_kdf_context(Some(c_r), id_cred_psk, th_2, cred_r, ead_2);

    // MAC_2 = EDHOC-KDF( PRK_3e2m, 2, context_2, mac_length_2 )
    // context_2 = << c_r, id_cred_psk, th_2, ? ead_2 >>
    let mut mac_2: BytesMac2 = [0x00; MAC_LENGTH_2];
    mac_2[..].copy_from_slice(
        &edhoc_kdf(crypto, prk_3e2m, 2_u8, &context, context_len, MAC_LENGTH_2)[..MAC_LENGTH_2],
    );

    mac_2
}

fn compute_mac_3(
    crypto: &mut impl CryptoTrait,
    prk_4e3m: &BytesHashLen,
    th_3: &BytesHashLen,
    id_cred_psk: &BytesIdCred,
    cred_i: &[u8],
    ead_3: &Option<EADItem>,
) -> BytesMac3 {
    // MAC_3 = EDHOC-KDF( PRK_4e3m, 6, context_3, mac_length_3 )
    // context_3 = << id_cred_psk, th_3, ? ead_3 >>
    let (context, context_len) = encode_kdf_context(None, id_cred_psk, th_3, cred_i, ead_3);

    // compute mac_3
    let output_buf = edhoc_kdf(
        crypto,
        prk_4e3m,
        6u8, // registered label for "MAC_3"
        &context,
        context_len,
        MAC_LENGTH_3,
    );

    let mut output: BytesMac3 = [0x00; MAC_LENGTH_3];
    output[..MAC_LENGTH_3].copy_from_slice(&output_buf[..MAC_LENGTH_3]);
    output
}



