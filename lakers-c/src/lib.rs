#![no_std]
/// This module contains the FFI bindings for the lakers-c library.
/// Normally the structs can be derived from the Rust structs, except in cases
/// where we need to hide fields that are not compatible with C, such as `Option<..>`.
/// Specifically in the case of `Option<..>` we use a pointer instead, where `NULL` indicates `None`.
///
/// Example command to compile this module for the nRF52840:
/// cargo build --target='thumbv7em-none-eabihf' --no-default-features --features="crypto-cryptocell310"
use lakers::{credential_check_or_fetch as credential_check_or_fetch_rust, *};
use lakers_crypto::{default_crypto, CryptoTrait};

#[cfg(feature = "ead-authz")]
pub mod ead_authz;
pub mod initiator;

#[cfg(test)]
extern crate std;

// crate type staticlib requires a panic handler and an allocator
use embedded_alloc::Heap;
#[cfg(not(test))]
#[global_allocator]
static HEAP: Heap = Heap::empty();

#[cfg(test)]
#[global_allocator]
static ALLOC: std::alloc::System = std::alloc::System;

/// Note that while the Rust version supports optional value to indicate an empty value,
/// in the C version we use an empty buffer for that case.
#[derive(Default, Clone, Debug)]
#[repr(C)]
pub struct EADItemC {
    pub label: u16,
    pub is_critical: bool,
    /// The value is only emitted if this is true (otherwise it is an EAD item that has just a label)
    pub has_value: bool,
    /// The bytes of the option
    pub value: EADBuffer,
}

impl EADItemC {
    pub fn to_rust(&self) -> EADItem {
        EADItem::new_full(
            self.label,
            self.is_critical,
            if self.has_value {
                Some(self.value.as_slice())
            } else {
                None
            },
        )
        .unwrap()
    }

    pub unsafe fn copy_into_c(ead: EADItem, ead_c: *mut EADItemC) {
        (*ead_c).label = ead.label();
        (*ead_c).is_critical = ead.is_critical();
        (*ead_c).has_value = ead.value_bytes().is_some();
        (*ead_c).value =
            EdhocBuffer::new_from_slice(ead.value_bytes().unwrap_or_default()).unwrap();
    }
}

#[derive(Default, Clone, Debug)]
#[repr(C)]
pub struct EadItemsC {
    pub items: [EADItemC; MAX_EAD_ITEMS],
    pub len: usize,
}

impl EadItemsC {
    pub fn to_rust(&self) -> EadItems {
        let mut items = EadItems::new();

        for i in self.items.iter() {
            items
                .try_push(i.clone().to_rust())
                .expect("EadItemsC can not contain more items than EadItems");
        }

        items
    }

    pub unsafe fn copy_into_c(ead: EadItems, ead_c: *mut EadItemsC) {
        (*ead_c).len = ead.len();

        for (i, item) in ead.iter().enumerate() {
            EADItemC::copy_into_c(item.clone(), &mut (*ead_c).items[i]);
        }
    }

    pub fn try_push(&mut self, item: EADItemC) -> Result<(), EADItemC> {
        if self.len == MAX_EAD_ITEMS {
            return Err(item);
        }
        self.items[self.len] = item;
        self.len += 1;
        Ok(())
    }
}

#[repr(C)]
pub enum ProcessingM2MethodSpecificsKindC {
    Pm2StatStat,
    Pm2Psk,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct ProcessingM2StatStatC {
    pub mac_2: BytesMac2,
    pub id_cred_r: IdCred,
}

impl Default for ProcessingM2StatStatC {
    fn default() -> Self {
        Self {
            mac_2: Default::default(),
            id_cred_r: Default::default(),
        }
    }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct ProcessingM2PskC {}

impl Default for ProcessingM2PskC {
    fn default() -> Self {
        Self {}
    }
}

#[repr(C)]
pub union ProcessingM2MethodSpecificsDataC {
    pub statstat: ProcessingM2StatStatC,
    pub psk: ProcessingM2PskC,
}

#[repr(C)]
pub struct ProcessingM2MethodSpecificsC {
    pub kind: ProcessingM2MethodSpecificsKindC,
    pub data: ProcessingM2MethodSpecificsDataC,
}

#[repr(C)]
pub struct ProcessingM2C {
    pub method_specifics: ProcessingM2MethodSpecificsC,
    pub prk_2e: BytesHashLen,
    pub th_2: BytesHashLen,
    pub x: BytesP256ElemLen,
    pub g_y: BytesP256ElemLen,
    pub plaintext_2: EdhocMessageBuffer,
    pub c_r: u8,
    pub ead_2: *mut EadItemsC,
}

impl Default for ProcessingM2C {
    fn default() -> Self {
        ProcessingM2C {
            method_specifics: ProcessingM2MethodSpecificsC {
                kind: ProcessingM2MethodSpecificsKindC::Pm2StatStat,
                data: ProcessingM2MethodSpecificsDataC {
                    statstat: ProcessingM2StatStatC::default(),
                },
            },
            prk_2e: Default::default(),
            th_2: Default::default(),
            x: Default::default(),
            g_y: Default::default(),
            plaintext_2: Default::default(),
            c_r: Default::default(),
            ead_2: core::ptr::null_mut(),
        }
    }
}

impl ProcessingM2C {
    pub fn to_rust(&self) -> ProcessingM2 {
        let method_specifics = match self.method_specifics.kind {
            ProcessingM2MethodSpecificsKindC::Pm2StatStat => {
                // SAFETY: Accessing a union field is unsafe. We just matched on
                // `self.method_specifics.kind == ProcessingM2MethodSpecificsKindC::Pm2StatStat`,
                // so `data.statstat` is the active variant.
                let stat = unsafe { &self.method_specifics.data.statstat };
                ProcessingM2MethodSpecifics::StatStat {
                    mac_2: stat.mac_2,
                    id_cred_r: stat.id_cred_r.clone(),
                }
            }
            ProcessingM2MethodSpecificsKindC::Pm2Psk => ProcessingM2MethodSpecifics::Psk {},
        };

        ProcessingM2 {
            method_specifics,
            prk_2e: self.prk_2e,
            th_2: self.th_2,
            x: self.x,
            g_y: self.g_y,
            plaintext_2: self.plaintext_2.clone(),
            #[allow(deprecated)]
            c_r: ConnId::from_int_raw(self.c_r),
            ead_2: unsafe { (*self.ead_2).to_rust() },
        }
    }

    /// note that it is a shallow copy (ead_2 is handled separately by the caller)
    pub unsafe fn copy_into_c(processing_m2: ProcessingM2, processing_m2_c: *mut ProcessingM2C) {
        if processing_m2_c.is_null() {
            panic!("processing_m2_c is null");
        }

        (*processing_m2_c).prk_2e = processing_m2.prk_2e;
        (*processing_m2_c).th_2 = processing_m2.th_2;
        (*processing_m2_c).x = processing_m2.x;
        (*processing_m2_c).g_y = processing_m2.g_y;
        (*processing_m2_c).plaintext_2 = processing_m2.plaintext_2;
        let c_r = processing_m2.c_r.as_slice();
        assert_eq!(c_r.len(), 1, "C API only supports short C_R");
        (*processing_m2_c).c_r = c_r[0];

        match processing_m2.method_specifics {
            ProcessingM2MethodSpecifics::StatStat { mac_2, id_cred_r } => {
                (*processing_m2_c).method_specifics = ProcessingM2MethodSpecificsC {
                    kind: ProcessingM2MethodSpecificsKindC::Pm2StatStat,
                    data: ProcessingM2MethodSpecificsDataC {
                        statstat: ProcessingM2StatStatC {
                            mac_2: mac_2,
                            id_cred_r: id_cred_r,
                        },
                    },
                };
            }
            ProcessingM2MethodSpecifics::Psk {} => {
                (*processing_m2_c).method_specifics = ProcessingM2MethodSpecificsC {
                    kind: ProcessingM2MethodSpecificsKindC::Pm2Psk,
                    data: ProcessingM2MethodSpecificsDataC {
                        psk: ProcessingM2PskC {},
                    },
                };
            }
        }
    }
}

//Adding Copy to avoid the use of ManuallyDrop in lakers-c
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(C)]
pub struct CredentialC {
    pub bytes: BufferCred,
    pub key: CredentialKey,
    /// differs from Rust: here we assume the kid is always present
    /// this is to simplify the C API, since C doesn't support Option<T>
    /// the alternative would be to use a pointer, but then we need to care about memory management
    pub kid: BufferKid,
    pub cred_type: CredentialType,
}

impl Default for CredentialC {
    fn default() -> Self {
        Self {
            bytes: Default::default(),
            key: CredentialKey::Symmetric([0; 16]),
            kid: Default::default(),
            cred_type: CredentialType::CCS_PSK,
        }
    }
}

impl CredentialC {
    pub fn to_rust(&self) -> Credential {
        Credential {
            bytes: self.bytes.clone(),
            key: self.key,
            kid: Some(self.kid.clone()),
            cred_type: self.cred_type,
        }
    }

    pub unsafe fn copy_into_c(cred: Credential, cred_c: *mut CredentialC) {
        (*cred_c).bytes = cred.bytes;
        (*cred_c).key = cred.key;
        (*cred_c).kid = cred.kid.unwrap();
        (*cred_c).cred_type = cred.cred_type;
    }
}

#[repr(C)]
pub enum ProcessedM2MethodSpecificsKindC {
    Prm2StatStat,
    Prm2Psk,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct ProcessedM2StatStatC {}

impl Default for ProcessedM2StatStatC {
    fn default() -> Self {
        Self {}
    }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct ProcessedM2PskC {
    cred_r: CredentialC,
}

impl Default for ProcessedM2PskC {
    fn default() -> Self {
        Self {
            cred_r: CredentialC::default(),
        }
    }
}

#[repr(C)]
pub union ProcessedM2MethodSpecificsDataC {
    pub statstat: ProcessedM2StatStatC,
    pub psk: ProcessedM2PskC,
}

#[repr(C)]
pub struct ProcessedM2MethodSpecificsC {
    pub kind: ProcessedM2MethodSpecificsKindC,
    pub data: ProcessedM2MethodSpecificsDataC,
}

#[repr(C)]
pub struct ProcessedM2C {
    pub method_specifics: ProcessedM2MethodSpecificsC,
    pub prk_3e2m: BytesHashLen,
    pub prk_4e3m: BytesHashLen,
    pub th_3: BytesHashLen,
}

impl Default for ProcessedM2C {
    fn default() -> Self {
        Self {
            method_specifics: ProcessedM2MethodSpecificsC {
                kind: ProcessedM2MethodSpecificsKindC::Prm2StatStat,
                data: ProcessedM2MethodSpecificsDataC {
                    // Initialize the union with the largest payload shape so the backing
                    // storage is fully initialized even when the logical tag is StatStat.
                    psk: ProcessedM2PskC::default(),
                },
            },
            prk_3e2m: Default::default(),
            prk_4e3m: Default::default(),
            th_3: Default::default(),
        }
    }
}

impl ProcessedM2C {
    pub fn to_rust(&self) -> ProcessedM2 {
        let method_specifics = match self.method_specifics.kind {
            ProcessedM2MethodSpecificsKindC::Prm2StatStat => {
                ProcessedM2MethodSpecifics::StatStat {}
            }
            ProcessedM2MethodSpecificsKindC::Prm2Psk => {
                // SAFETY: Accessing a union field is unsafe. We just matched on
                // `self.method_specifics.kind == ProcessedM2MethodSpecificsKindC::Prm2Psk`,
                // so `data.psk` is the active variant.
                let psk = unsafe { &self.method_specifics.data.psk };
                ProcessedM2MethodSpecifics::Psk {
                    cred_r: psk.cred_r.to_rust(),
                }
            }
        };

        ProcessedM2 {
            method_specifics,
            prk_3e2m: self.prk_3e2m,
            prk_4e3m: self.prk_4e3m,
            th_3: self.th_3,
        }
    }

    pub unsafe fn copy_into_c(processed_m2: ProcessedM2, processed_m2_c: *mut ProcessedM2C) {
        if processed_m2_c.is_null() {
            panic!("processed_m2_c is null");
        }

        (*processed_m2_c).prk_3e2m = processed_m2.prk_3e2m;
        (*processed_m2_c).prk_4e3m = processed_m2.prk_4e3m;
        (*processed_m2_c).th_3 = processed_m2.th_3;

        match processed_m2.method_specifics {
            ProcessedM2MethodSpecifics::StatStat {} => {
                (*processed_m2_c).method_specifics = ProcessedM2MethodSpecificsC {
                    kind: ProcessedM2MethodSpecificsKindC::Prm2StatStat,
                    data: ProcessedM2MethodSpecificsDataC {
                        statstat: ProcessedM2StatStatC {},
                    },
                };
            }
            ProcessedM2MethodSpecifics::Psk { cred_r } => {
                let cred_r_c = CredentialC {
                    bytes: cred_r.bytes,
                    key: cred_r.key,
                    kid: cred_r.kid.unwrap(),
                    cred_type: cred_r.cred_type,
                };
                (*processed_m2_c).method_specifics = ProcessedM2MethodSpecificsC {
                    kind: ProcessedM2MethodSpecificsKindC::Prm2Psk,
                    data: ProcessedM2MethodSpecificsDataC {
                        psk: ProcessedM2PskC { cred_r: cred_r_c },
                    },
                };
            }
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn credential_new(
    cred: *mut CredentialC,
    value: *const u8,
    value_len: usize,
) -> i8 {
    let value = core::slice::from_raw_parts(value, value_len);
    match Credential::parse_ccs(value) {
        Ok(cred_parsed) => {
            CredentialC::copy_into_c(cred_parsed, cred);
            0
        }
        Err(_) => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn credential_check_or_fetch(
    cred_expected: *mut CredentialC,
    id_cred_received: *mut IdCred,
    cred_out: *mut CredentialC,
) -> i8 {
    let cred_expected = if cred_expected.is_null() {
        None
    } else {
        Some((*cred_expected).to_rust())
    };

    let id_cred_received_value = (*id_cred_received).clone();
    match credential_check_or_fetch_rust(cred_expected, id_cred_received_value) {
        Ok(valid_cred) => {
            CredentialC::copy_into_c(valid_cred, cred_out);
            0
        }
        Err(err) => err as i8,
    }
}

// This function is useful to test the FFI
#[no_mangle]
pub extern "C" fn p256_generate_key_pair_from_c(out_private_key: *mut u8, out_public_key: *mut u8) {
    let (private_key, public_key) = default_crypto().p256_generate_key_pair();

    unsafe {
        // copy the arrays to the pointers received from C
        // this makes sure that data is not dropped when the function returns
        core::ptr::copy_nonoverlapping(
            private_key.as_ptr(),
            out_private_key,
            lakers::P256_ELEM_LEN,
        );
        core::ptr::copy_nonoverlapping(public_key.as_ptr(), out_public_key, lakers::P256_ELEM_LEN);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn processing_m2_default_to_rust_is_statstat() {
        let mut ead_2_c = EadItemsC::default();
        let mut value = ProcessingM2C::default();
        value.ead_2 = &mut ead_2_c;
        let rust = value.to_rust();
        assert!(matches!(
            rust.method_specifics,
            ProcessingM2MethodSpecifics::StatStat { .. }
        ));
    }

    #[test]
    fn processed_m2_default_to_rust_is_statstat() {
        let value = ProcessedM2C::default();
        let rust = value.to_rust();
        assert!(matches!(
            rust.method_specifics,
            ProcessedM2MethodSpecifics::StatStat {}
        ));
    }
    #[test]
    fn credential_c_roundtrip() {
        let cred = Credential {
            bytes: BufferCred::new_from_slice(&[1, 2, 3]).unwrap(),
            key: CredentialKey::Symmetric([7; 16]),
            kid: Some(BufferKid::new_from_slice(&[9]).unwrap()),
            cred_type: CredentialType::CCS_PSK,
        };

        let mut c = CredentialC::default();
        unsafe { CredentialC::copy_into_c(cred.clone(), &mut c) };
        let roundtrip = c.to_rust();

        assert_eq!(roundtrip, cred);
    }

    #[test]
    fn processed_m2_psk_roundtrip() {
        let cred = Credential {
            bytes: BufferCred::new_from_slice(&[1, 2, 3]).unwrap(),
            key: CredentialKey::Symmetric([5; 16]),
            kid: Some(BufferKid::new_from_slice(&[8]).unwrap()),
            cred_type: CredentialType::CCS_PSK,
        };

        let rust_value = ProcessedM2 {
            method_specifics: ProcessedM2MethodSpecifics::Psk {
                cred_r: cred.clone(),
            },
            prk_3e2m: Default::default(),
            prk_4e3m: Default::default(),
            th_3: Default::default(),
        };

        let mut c_value = ProcessedM2C::default();
        unsafe { ProcessedM2C::copy_into_c(rust_value, &mut c_value) };
        let roundtrip = c_value.to_rust();

        match roundtrip.method_specifics {
            ProcessedM2MethodSpecifics::Psk { cred_r } => assert_eq!(cred_r, cred),
            _ => panic!("expected psk"),
        }
    }

    #[test]
    fn processed_m2_statstat_roundtrip() {
        let rust_value = ProcessedM2 {
            method_specifics: ProcessedM2MethodSpecifics::StatStat {},
            prk_3e2m: Default::default(),
            prk_4e3m: Default::default(),
            th_3: Default::default(),
        };

        let mut c_value = ProcessedM2C::default();
        unsafe { ProcessedM2C::copy_into_c(rust_value, &mut c_value) };
        let roundtrip = c_value.to_rust();

        assert!(matches!(
            roundtrip.method_specifics,
            ProcessedM2MethodSpecifics::StatStat {}
        ));
    }

    #[test]
    fn processing_m2_psk_roundtrip() {
        let rust_value = ProcessingM2 {
            method_specifics: ProcessingM2MethodSpecifics::Psk {},
            prk_2e: Default::default(),
            th_2: Default::default(),
            x: Default::default(),
            g_y: Default::default(),
            plaintext_2: Default::default(),
            #[allow(deprecated)]
            c_r: ConnId::from_int_raw(0),
            ead_2: EadItems::new(),
        };

        let mut ead_2_c = EadItemsC::default();
        let mut c_value = ProcessingM2C::default();
        c_value.ead_2 = &mut ead_2_c;
        unsafe { ProcessingM2C::copy_into_c(rust_value, &mut c_value) };
        let roundtrip = c_value.to_rust();

        assert!(matches!(
            roundtrip.method_specifics,
            ProcessingM2MethodSpecifics::Psk {}
        ));
    }

    #[test]
    fn processing_m2_statstat_roundtrip() {
        let rust_value = ProcessingM2 {
            method_specifics: ProcessingM2MethodSpecifics::StatStat {
                mac_2: Default::default(),
                id_cred_r: IdCred::default(),
            },
            prk_2e: Default::default(),
            th_2: Default::default(),
            x: Default::default(),
            g_y: Default::default(),
            plaintext_2: Default::default(),
            #[allow(deprecated)]
            c_r: ConnId::from_int_raw(0),
            ead_2: EadItems::new(),
        };

        let mut ead_2_c = EadItemsC::default();
        let mut c_value = ProcessingM2C::default();
        c_value.ead_2 = &mut ead_2_c;
        unsafe { ProcessingM2C::copy_into_c(rust_value, &mut c_value) };
        let roundtrip = c_value.to_rust();

        assert!(matches!(
            roundtrip.method_specifics,
            ProcessingM2MethodSpecifics::StatStat { .. }
        ));
    }
}
