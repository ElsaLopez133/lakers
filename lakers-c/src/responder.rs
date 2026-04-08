use lakers::{
    // EdhocInitiator as EdhocInitiatorRust, // alias to conflict with the C-compatible struct
    *,
};
use lakers_crypto::{default_crypto, CryptoTrait};

use crate::*;

/// structs compatible with the C FFI

#[repr(C)]
pub struct EdhocResponder {
    pub start: ResponderStart,
    pub processing_m1: ProcessingM1C,
    pub wait_m3: WaitM3C,
    pub processing_m3: ProcessingM3C,
    pub processed_m3: ProcessedM3,
    pub completed: Completed,
}

#[no_mangle]
pub unsafe extern "C" fn responder_new(responder: *mut crate::responder::EdhocResponder) -> i8 {
    let mut crypto = default_crypto();
    let (y, g_y) = crypto.p256_generate_key_pair();

    let start = ResponderStart { y, g_y };

    core::ptr::write(&mut (*responder).start, start);

    0
}

#[no_mangle]
pub unsafe extern "C" fn responder_process_message_1(
    responder_c: *mut EdhocResponder,
    message_1: *const EdhocMessageBuffer,
    c_i_out: *mut u8,
    ead_1_c_out: *mut EadItemsC,
) -> i8 {
    if responder_c.is_null() || message_1.is_null() || c_i_out.is_null() || ead_1_c_out.is_null() {
        return -1;
    }

    let crypto = &mut default_crypto();
    let state = core::ptr::read(&(*responder_c).start);

    match r_process_message_1(&state, crypto, &(*message_1)) {
        Ok((state, c_i, ead_1)) => {
            ProcessingM1C::copy_into_c(state, &mut (*responder_c).processing_m1);

            let c_i = c_i.as_slice();
            assert_eq!(c_i.len(), 1, "C API only supports short C_I");
            *c_i_out = c_i[0];

            EadItemsC::copy_into_c(ead_1, ead_1_c_out);

            0
        }
        Err(err) => err as i8,
    }
}

#[no_mangle]
pub unsafe extern "C" fn responder_prepare_message_2(
    responder_c: *mut EdhocResponder,
    r: *const BytesP256ElemLen,
    cred_r: *mut CredentialC,
    cred_transfer: CredentialTransfer,
    c_r: *mut u8,
    ead_2_c: *mut EadItemsC,
    message_2: *mut EdhocMessageBuffer,
) -> i8 {
    if responder_c.is_null() || cred_r.is_null() || message_2.is_null() {
        return -1;
    }

    let crypto = &mut default_crypto();
    let state = core::ptr::read(&(*responder_c).processing_m1).to_rust();

    let c_r = if c_r.is_null() {
        generate_connection_identifier_cbor(crypto)
    } else {
        #[allow(deprecated)]
        ConnId::from_int_raw(*c_r)
    };

    let ead_2 = if ead_2_c.is_null() {
        EadItems::new()
    } else {
        (*ead_2_c).to_rust()
    };

    let method_details = match state.method {
        EDHOCMethod::StatStat => {
            if r.is_null() {
                return -1;
            }
            PrepareMessage2Details::StatStat {
                r: &*r,
                cred_transfer,
            }
        }
        EDHOCMethod::PSK => PrepareMessage2Details::Psk,
        _ => return -1,
    };

    match r_prepare_message_2(
        &state,
        crypto,
        (*cred_r).to_rust(),
        method_details,
        c_r,
        &ead_2,
    ) {
        Ok((state, msg_2)) => {
            WaitM3C::copy_into_c(state, &mut (*responder_c).wait_m3);
            *message_2 = msg_2;
            0
        }
        Err(err) => err as i8,
    }
}

#[no_mangle]
pub unsafe extern "C" fn responder_parse_message_3(
    responder_c: *mut EdhocResponder,
    message_3: *const EdhocMessageBuffer,
    id_cred_i_out: *mut IdCred,
    ead_3_c_out: *mut EadItemsC,
) -> i8 {
    if responder_c.is_null()
        || message_3.is_null()
        || id_cred_i_out.is_null()
        || ead_3_c_out.is_null()
    {
        return -1;
    }

    let crypto = &mut default_crypto();
    let state = core::ptr::read(&(*responder_c).wait_m3).to_rust();

    match r_parse_message_3(&state, crypto, &(*message_3)) {
        Ok((state, id_cred_i, ead_3)) => {
            ProcessingM3C::copy_into_c(state, &mut (*responder_c).processing_m3);
            *id_cred_i_out = id_cred_i;
            EadItemsC::copy_into_c(ead_3, ead_3_c_out);
            (*responder_c).processing_m3.ead_3 = ead_3_c_out;
            0
        }
        Err(err) => err as i8,
    }
}

#[no_mangle]
pub unsafe extern "C" fn responder_verify_message_3(
    responder_c: *mut EdhocResponder,
    cred_expected: *mut CredentialC,
    prk_out_c: *mut [u8; SHA256_DIGEST_LEN],
) -> i8 {
    if responder_c.is_null() || prk_out_c.is_null() {
        return -1;
    }

    let crypto = &mut default_crypto();
    let state = core::ptr::read(&(*responder_c).processing_m3).to_rust();

    let cred_expected = if cred_expected.is_null() {
        None
    } else {
        Some((*cred_expected).to_rust())
    };

    let valid_cred_i = match &state.method_specifics {
        ProcessingM3MethodSpecifics::StatStat { id_cred_i, .. } => {
            lakers::credential_check_or_fetch(cred_expected, id_cred_i.clone())
        }
        ProcessingM3MethodSpecifics::Psk { id_cred_psk, .. } => cred_expected
            .ok_or(EDHOCError::MissingIdentity)
            .and_then(|cred| {
                if id_cred_psk.reference_only() {
                    let expected = cred.by_kid()?;
                    if expected.as_full_value() == id_cred_psk.as_full_value() {
                        Ok(cred)
                    } else {
                        Err(EDHOCError::UnexpectedCredential)
                    }
                } else {
                    let expected = cred.by_value()?;
                    if expected.as_full_value() == id_cred_psk.as_full_value() {
                        Ok(cred)
                    } else {
                        Err(EDHOCError::UnexpectedCredential)
                    }
                }
            }),
    };

    match valid_cred_i.and_then(|valid_cred_i| r_verify_message_3(&state, crypto, valid_cred_i)) {
        Ok((state, prk_out)) => {
            (*responder_c).processed_m3 = state;
            *prk_out_c = prk_out;
            0
        }
        Err(err) => err as i8,
    }
}

#[no_mangle]
pub unsafe extern "C" fn responder_prepare_message_4(
    responder_c: *mut EdhocResponder,
    ead_4_c: *mut EadItemsC,
    message_4: *mut EdhocMessageBuffer,
) -> i8 {
    if responder_c.is_null() || message_4.is_null() {
        return -1;
    }

    let crypto = &mut default_crypto();
    let state = core::ptr::read(&(*responder_c).processed_m3);

    let ead_4 = if ead_4_c.is_null() {
        EadItems::new()
    } else {
        (*ead_4_c).to_rust()
    };

    match r_prepare_message_4(&state, crypto, &ead_4) {
        Ok((state, msg_4)) => {
            (*responder_c).completed = state;
            *message_4 = msg_4;
            0
        }
        Err(err) => err as i8,
    }
}

#[no_mangle]
pub unsafe extern "C" fn responder_completed_without_message_4(
    responder_c: *mut EdhocResponder,
) -> i8 {
    if responder_c.is_null() {
        return -1;
    }

    let state = core::ptr::read(&(*responder_c).processed_m3);

    match r_complete_without_message_4(&state) {
        Ok(state) => {
            (*responder_c).completed = state;
            0
        }
        Err(err) => err as i8,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hexlit::hex;

    const R_STATSTAT: BytesP256ElemLen =
        hex!("72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac");
    const I_STATSTAT: BytesP256ElemLen =
        hex!("fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b");
    const CRED_I_STATSTAT: &[u8] = &hex!(
        "A2027734322D35302D33312D46462D45462D33372D33322D333908A101A5010202412B2001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8"
    );
    const CRED_R_STATSTAT: &[u8] = &hex!(
        "A2026008A101A5010202410A2001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072"
    );

    fn make_ffi_responder() -> EdhocResponder {
        EdhocResponder {
            start: ResponderStart {
                y: Default::default(),
                g_y: Default::default(),
            },
            processing_m1: ProcessingM1C {
                method: EDHOCMethod::StatStat,
                y: Default::default(),
                g_y: Default::default(),
                c_i: 0,
                g_x: Default::default(),
                h_message_1: Default::default(),
            },
            wait_m3: WaitM3C::default(),
            processing_m3: ProcessingM3C::default(),
            processed_m3: ProcessedM3 {
                prk_4e3m: Default::default(),
                th_4: Default::default(),
                prk_out: Default::default(),
                prk_exporter: Default::default(),
            },
            completed: Completed {
                prk_out: Default::default(),
                prk_exporter: Default::default(),
            },
        }
    }

    fn credential_to_c(cred: Credential) -> CredentialC {
        let mut cred_c = core::mem::MaybeUninit::<CredentialC>::uninit();
        unsafe {
            CredentialC::copy_into_c(cred, cred_c.as_mut_ptr());
            cred_c.assume_init()
        }
    }

    #[test]
    fn responder_process_message_1_returns_connection_id() {
        let initiator = lakers::EdhocInitiator::new(
            default_crypto(),
            EDHOCMethod::StatStat,
            EDHOCSuite::CipherSuite2,
        );
        let (initiator, message_1) = initiator.prepare_message_1(None, &EadItems::new()).unwrap();

        let mut responder = make_ffi_responder();
        let mut c_i_out = 0u8;
        let mut ead_1_out = EadItemsC::default();

        let rc = unsafe {
            responder_new(&mut responder);
            responder_process_message_1(&mut responder, &message_1, &mut c_i_out, &mut ead_1_out)
        };

        assert_eq!(rc, 0);
        assert_eq!(responder.processing_m1.method, EDHOCMethod::StatStat);
        assert_eq!(responder.processing_m1.c_i, c_i_out);
        let _ = initiator;
    }

    #[test]
    fn responder_statstat_handshake_matches_prk_out() {
        let cred_i = Credential::parse_ccs(CRED_I_STATSTAT.try_into().unwrap()).unwrap();
        let cred_r = Credential::parse_ccs(CRED_R_STATSTAT.try_into().unwrap()).unwrap();

        let mut initiator = lakers::EdhocInitiator::new(
            default_crypto(),
            EDHOCMethod::StatStat,
            EDHOCSuite::CipherSuite2,
        );
        initiator
            .set_identity(
                InitiatorIdentity::StatStat { i: I_STATSTAT },
                cred_i.clone(),
            )
            .unwrap();

        let mut responder = make_ffi_responder();

        let (initiator, message_1) = initiator.prepare_message_1(None, &EadItems::new()).unwrap();

        let mut c_i_out = 0u8;
        let mut ead_1_out = EadItemsC::default();
        let process_m1_rc = unsafe {
            responder_new(&mut responder);
            responder_process_message_1(&mut responder, &message_1, &mut c_i_out, &mut ead_1_out)
        };
        assert_eq!(process_m1_rc, 0);

        let mut cred_r_c = credential_to_c(cred_r.clone());
        let mut message_2 = EdhocMessageBuffer::default();
        let prepare_m2_rc = unsafe {
            responder_prepare_message_2(
                &mut responder,
                &R_STATSTAT,
                &mut cred_r_c,
                CredentialTransfer::ByReference,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut message_2,
            )
        };
        assert_eq!(prepare_m2_rc, 0);

        let (initiator, _c_r, _ead_2) = initiator.parse_message_2(&message_2).unwrap();
        let initiator = initiator.verify_message_2(Some(cred_r.clone())).unwrap();
        let (_initiator_wait_m4, message_3, i_prk_out) = initiator
            .prepare_message_3(CredentialTransfer::ByReference, &EadItems::new())
            .unwrap();

        let mut id_cred_i_out = IdCred::default();
        let mut ead_3_out = EadItemsC::default();
        let parse_m3_rc = unsafe {
            responder_parse_message_3(
                &mut responder,
                &message_3,
                &mut id_cred_i_out,
                &mut ead_3_out,
            )
        };
        assert_eq!(parse_m3_rc, 0);

        let mut cred_i_c = credential_to_c(cred_i);
        let mut r_prk_out = [0u8; SHA256_DIGEST_LEN];
        let verify_m3_rc =
            unsafe { responder_verify_message_3(&mut responder, &mut cred_i_c, &mut r_prk_out) };
        assert_eq!(verify_m3_rc, 0);
        assert_eq!(i_prk_out, r_prk_out);
    }
}
