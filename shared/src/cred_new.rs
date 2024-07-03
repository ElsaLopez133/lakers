use super::*;

pub type BufferCred = EdhocBuffer<128>; // arbitrary size
pub type BufferKid = EdhocBuffer<16>; // variable size, up to 16 bytes
pub type BufferIdCred = EdhocBuffer<128>; // variable size, can contain either the contents of a BufferCred or a BufferKid
pub type BytesKeyAES128 = [u8; 16];
pub type BytesKeyEC2 = [u8; 32];
pub type BytesKeyOKP = [u8; 32];
pub type BytesX5T = [u8; 8];
pub type BytesC5T = [u8; 8];

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CredentialKey {
    Symmetric(BytesKeyAES128),
    EC2Compact(BytesKeyEC2),
    // Add other key types as needed
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CredentialType {
    CCS,
    CCS_PSK,
    // C509,
}

pub struct Credential {
    /// Original bytes of the credential, CBOR-encoded
    pub bytes: BufferCred,
    pub key: CredentialKey,
    pub kid: Option<BufferKid>, // other types of identifiers can be added, such as `pub x5t: Option<BytesX5T>`
    pub cred_type: CredentialType,
}

// FIXME: should handle errors instead of panicking
impl Credential {
    /// Creates a new credential with the given bytes, key and type.
    pub fn new(bytes: BufferCred, key: CredentialKey, cred_type: CredentialType) -> Self {
        Self {
            bytes,
            key,
            kid: None,
            cred_type,
        }
    }

    pub fn with_kid(self, kid: BufferKid) -> Self {
        Self {
            kid: Some(kid),
            ..self
        }
    }

    /// Parse a CCS style credential
    ///
    /// If the given value matches the shape Lakers expects of a CCS, its public key and key ID are
    /// extracted into a full credential.
    pub fn parse_ccs(value: &[u8]) -> Result<Self, EDHOCError> {
        // Implementing in terms of the old structure, to be moved in here in later versions of
        // this change set
        let (public_key, kid) = CredentialRPK::parse(value)?;
        Ok(Self {
            bytes: BufferCred::new_from_slice(value).map_err(|_| EDHOCError::ParsingError)?,
            key: CredentialKey::EC2Compact(public_key),
            kid: Some(BufferKid::new_from_slice(&[kid]).unwrap()),
            cred_type: CredentialType::CCS,
        })
    }

    /// Parse a CCS style credential, but the key is a symmetric key
    ///
    /// If the given value matches the shape Lakers expects of a CCS, its public key and key ID are
    /// extracted into a full credential.
    pub fn parse_ccs_psk(value: &[u8]) -> Result<Self, EDHOCError> {
        // TODO: actually implement this
        const CCS_PREFIX_LEN: usize = 3;
        const CNF_AND_COSE_KEY_PREFIX_LEN: usize = 8;
        const COSE_KEY_FIRST_ITEMS_LEN: usize = 3; //COSE for symmetric key
        const SYMMETRIC_KEY_LEN: usize = 16; // Assuming a 128-bit symmetric key

        if value.len()
            < CCS_PREFIX_LEN
                + 1
                + CNF_AND_COSE_KEY_PREFIX_LEN
                + COSE_KEY_FIRST_ITEMS_LEN
                + SYMMETRIC_KEY_LEN
        {
            Err(EDHOCError::ParsingError)
        } else {
            let subject_len = CBORDecoder::info_of(value[2]) as usize;

            let id_cred_offset: usize = CCS_PREFIX_LEN
                .checked_add(subject_len)
                .and_then(|x| x.checked_add(CNF_AND_COSE_KEY_PREFIX_LEN))
                .ok_or(EDHOCError::ParsingError)?;

            let symmetric_key_offset: usize = id_cred_offset
                .checked_add(COSE_KEY_FIRST_ITEMS_LEN)
                .ok_or(EDHOCError::ParsingError)?;

            if symmetric_key_offset
                .checked_add(SYMMETRIC_KEY_LEN)
                .map_or(false, |end| end <= value.len())
            {
                let symmetric_key: [u8; SYMMETRIC_KEY_LEN] = value
                    [symmetric_key_offset..symmetric_key_offset + SYMMETRIC_KEY_LEN]
                    .try_into()
                    .map_err(|_| EDHOCError::ParsingError)?;

                let kid = value[id_cred_offset];

                Ok(Self {
                    bytes: BufferCred::new_from_slice(value)
                        .map_err(|_| EDHOCError::ParsingError)?,
                    key: CredentialKey::Symmetric(symmetric_key),
                    kid: Some(BufferKid::new_from_slice(&[kid]).unwrap()),
                    cred_type: CredentialType::CCS_PSK,
                })
            } else {
                Err(EDHOCError::ParsingError)
            }
        }
    }
    /// Returns a COSE_Header map with a single entry representing a credential by value.
    ///
    /// For example, if the credential is a CCS:
    ///   { /kccs/ 14: bytes }
    pub fn by_value(&self) -> BufferIdCred {
        match self.cred_type {
            CredentialType::CCS => {
                let mut cred = BufferIdCred::new();
                cred.extend_from_slice(&[CBOR_MAJOR_MAP + 1, KCSS_LABEL])
                    .map_err(|_| EDHOCError::CredentialTooLongError)
                    .unwrap();
                cred.extend_from_slice(self.bytes.as_slice()).unwrap();
                cred
            }
            CredentialType::CCS_PSK => panic!("Symmetric keys cannot be sent by value"),
        }
    }

    /// Returns a COSE_Header map with a single entry representing a credential by reference.
    ///
    /// For example, if the reference is a kid:
    ///   { /kid/ 4: kid }
    ///
    /// TODO: accept a parameter to specify the type of reference, e.g. kid, x5t, etc.
    pub fn by_reference(&self) -> BufferIdCred {
        let Some(kid) = self.kid.as_ref() else {
            panic!("Kid not set");
        };
        let mut id_cred = BufferIdCred::new();
        id_cred
            .extend_from_slice(&[CBOR_MAJOR_MAP + 1, KID_LABEL])
            .unwrap();
        id_cred
            .push(CBOR_MAJOR_BYTE_STRING | kid.len() as u8)
            .unwrap();
        if kid.len() == 1 {
            id_cred.extend_from_slice(kid.as_slice()).unwrap();
        } else {
            todo!("Larger kid not supported yet");
        }
        id_cred
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hexlit::hex;

    const CRED_TV: &[u8] = &hex!("a2026b6578616d706c652e65647508a101a501020241322001215820bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f02258204519e257236b2a0ce2023f0931f1f386ca7afda64fcde0108c224c51eabf6072");
    const G_A_TV: &[u8] = &hex!("BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F0");
    const ID_CRED_TV: &[u8] = &hex!("a1044132");
    const KID_VALUE_TV: &[u8] = &hex!("32");

    const CRED_PSK: &[u8] =
        &hex!("A202686D79646F74626F7408A101A30104024132205050930FF462A77A3540CF546325DEA214");
    const K: &[u8] = &hex!("50930FF462A77A3540CF546325DEA214");
    const KID_VALUE_PSK: &[u8] = &hex!("32");

    #[test]
    fn test_new_cred_ccs() {
        let cred = Credential::new(
            CRED_TV.try_into().unwrap(),
            CredentialKey::EC2Compact(G_A_TV.try_into().unwrap()),
            CredentialType::CCS,
        );
        assert_eq!(cred.bytes.as_slice(), CRED_TV);
    }

    #[test]
    fn test_new_cred_ccs_psk() {
        let cred = Credential::new(
            CRED_PSK.try_into().unwrap(),
            CredentialKey::Symmetric(K.try_into().unwrap()),
            CredentialType::CCS_PSK,
        );
        assert_eq!(cred.bytes.as_slice(), CRED_PSK);
    }

    #[test]
    fn test_parse_ccs() {
        let cred = Credential::parse_ccs(CRED_TV).unwrap();
        assert_eq!(cred.bytes.as_slice(), CRED_TV);
        assert_eq!(
            cred.key,
            CredentialKey::EC2Compact(G_A_TV.try_into().unwrap())
        );
        assert_eq!(cred.kid.unwrap().as_slice(), KID_VALUE_TV);
        assert_eq!(cred.cred_type, CredentialType::CCS);
    }

    #[test]
    fn test_parse_ccs_psk() {
        let cred = Credential::parse_ccs_psk(CRED_PSK).unwrap();
        assert_eq!(cred.bytes.as_slice(), CRED_PSK);
        assert_eq!(cred.key, CredentialKey::Symmetric(K.try_into().unwrap()));
        assert_eq!(cred.kid.unwrap().as_slice(), KID_VALUE_PSK);
        assert_eq!(cred.cred_type, CredentialType::CCS_PSK);
    }
}
