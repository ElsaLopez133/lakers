use crate::consts::*;
use crate::shared::*;
use crate::SoKError;
use lakers_shared::{Crypto as CryptoTrait, *};

#[derive(Default, Debug)]
#[repr(C)]
pub struct InitiaitorSoK {
    pub msg: EdhocMessageBuffer,
    pub message_len: usize,
}

// #[derive(Default, Debug)]
// #[repr(C)]
// pub struct InitiaitorSoKWaitEAD2 {
//     prk: BytesHashLen,
//     pub h_message_1: BytesHashLen,
// }

// #[derive(Default, Debug)]
// #[repr(C)]
// pub struct InitiaitorLIKEDone {
//     pub voucher: BytesMac,
// }

impl InitiaitorSoK {
    pub fn new( msg: EdhocMessageBuffer, message_len: usize) -> Self {
        InitiaitorLIKE { msg, message_len }
    }

    pub fn prepare_ead_1<Crypto: CryptoTrait>(
        &self,
        crypto: &mut Crypto,
    ) -> (InitiaitorSoKWaitEAD2, EADItem) {

        // Compute the hash for the message
        let hash_output = crypto.sha256_digest(&self.msg, self.message_len);
        let value = Some(encode_ead_1_value(&self.loc_w, &enc_id));

        let ead_1 = EADItem {
            label: EAD_SOK_LABEL,
            is_critical: true,
            value,
        };

        (
            // InitiaitorSoKWaitEAD2 {
            //     prk,
            //     h_message_1: [0; SHA256_DIGEST_LEN],
            // },
            ead_1,
        )
    }
}

fn encode_ead_1_value(
    loc_w: &EdhocMessageBuffer,
    enc_id: &EdhocMessageBuffer,
) -> EdhocMessageBuffer {
    let mut output = EdhocMessageBuffer::new();

    output.content[0] = CBOR_BYTE_STRING;
    // put length at output.content[1] after other sizes are known

    output.content[2] = CBOR_TEXT_STRING;
    output.content[3] = loc_w.len as u8;
    output.content[4..4 + loc_w.len].copy_from_slice(loc_w.as_slice());

    output.content[4 + loc_w.len] = CBOR_MAJOR_BYTE_STRING + enc_id.len as u8;
    output.content[5 + loc_w.len..5 + loc_w.len + enc_id.len].copy_from_slice(enc_id.as_slice());

    output.len = 5 + loc_w.len + enc_id.len;
    output.content[1] = (output.len - 2) as u8;

    output
}
