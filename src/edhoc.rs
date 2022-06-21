#![no_std]

use hacspec_lib::*;
pub mod consts;

use consts::*;

pub fn encode_message_1(
    method: U8,
    suites: &BytesSupportedSuites,
    g_x: &BytesP256ElemLen,
    c_i: i8,
    mut output: BytesMaxBuffer,
) -> (BytesMaxBuffer, usize) {
    output[0] = method; // CBOR unsigned int less than 24 is encoded verbatim

    let mut index: usize = 0;

    if suites.len() == 1 {
        output[1] = suites[0];
        index = 2;
    } else {
        output[1] = U8(0x80u8 | suites.len() as u8);
        output = output.update(2, suites);
        index = suites.len() + 2;
    }
    output[index] = U8(CBOR_BYTE_STRING); // CBOR byte string magic number
    output[index + 1] = U8(P256_ELEM_LEN as u8); // length of the byte string
    output = output.update(index + 2, g_x);
    if c_i >= 0i8 {
        output[index + 2 + P256_ELEM_LEN] = U8(c_i as u8); // CBOR uint less than 24 is encoded verbatim
    } else {
        output[index + 2 + P256_ELEM_LEN] = U8(0x20u8 | (-1i8 + -c_i) as u8);
    }

    (output, index + 3 + P256_ELEM_LEN)
}

pub fn parse_message_2(
    rcvd_message_2: &BytesMessage2,
    mut g_y: BytesP256ElemLen,
    mut ciphertext_2: BytesCiphertext2,
    mut c_r: U8,
) -> (BytesP256ElemLen, BytesCiphertext2, U8) {
    // FIXME decode negative integers as well
    c_r = rcvd_message_2[MESSAGE_2_LEN - 1];
    g_y = g_y.update(0, &rcvd_message_2.slice(2, P256_ELEM_LEN));
    ciphertext_2 = ciphertext_2.update(
        0,
        &rcvd_message_2.slice(2 + P256_ELEM_LEN, CIPHERTEXT_2_LEN),
    );

    (g_y, ciphertext_2, c_r)
}