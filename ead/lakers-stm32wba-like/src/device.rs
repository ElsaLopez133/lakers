use crate::consts::*;
use crate::SoKError;
// use lakers_shared::{Crypto as CryptoTrait, *};
pub use {lakers_shared::Crypto as CryptoTrait, lakers_shared::*};


#[derive(Debug)]
#[repr(C)]
pub struct InitiatorSoK<'a> {
    state: &'a ProcessingM2,
    g_r: &'a BytesP256ElemLen,
    // state: EdhocInitiatorProcessingM2,
    // TODO
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

impl<'a> InitiatorSoK<'a> {  
    pub fn new(state: &'a ProcessingM2, g_r: &'a BytesP256ElemLen) -> Self {
        InitiatorSoK { state, g_r }
    }

    pub unsafe fn prepare_ead_3<Crypto: CryptoTrait>(
        &self,
        crypto: &mut Crypto,
        h: BytesP256ElemLen,
        g_r: BytesP256ElemLen, 
        // g_x: &BytesP256ElemLen, 
        // g_y: &BytesP256ElemLen, 
        // x: &BytesP256ElemLen, 
        i: BytesP256ElemLen,
        w: BytesHashLen, 
    ) -> EADItem {

        let pi = crypto.sok_log_eq(
            h,
            g_r,
            self.state.g_x,
            self.state.g_y,
            self.state.x,
            i,
            Some(&w),
        );

        let mut value = EdhocMessageBuffer::new();
        value.extend_from_slice(&pi.pi1).unwrap();
        value.extend_from_slice(&pi.pi2).unwrap();
        value.extend_from_slice(&pi.pi3).unwrap();
        let value = Some(value);

        let ead_1 = EADItem {
            label: EAD_SOK_LABEL as u16,
            is_critical: true,
            value,
        };

        ead_1
    }
}