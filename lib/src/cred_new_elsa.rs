use core::panic;

pub type BufferCred = EdhocBuffer<128>;
pub type BufferKid = EdhocBuffer<16>;
pub type BufferIdCred = EdhocBuffer<128>;
pub type BytesKey128 = [u8; 16];
pub type BytesKeyEC2 = [u8; 32];
pub type BytesKeyOKP = [u8; 32];
pub type BytesX5T = [u8; 8];
pub type BytesC5T = [u8; 8];

// Define the CredentialType enum
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CredentialType {
    CCS,
    CCS_PSK,
    X509,
    // Add other types as needed
}

// Define the ReferenceMethod enum
pub enum ReferenceMethod {
    Kid(BufferKid),
    X5t(BytesX5T),
    C5t(BytesC5T),
    // Add other methods as needed
}

// Define the CredentialKey enum
pub enum CredentialKey<'a> {
    Symmetric(&'a [u8]),
    EC2 { x: &'a [u8], y: Option<&'a [u8]> },
    // OKP(&'a [u8]),
    // Add other key types as needed
}

// Define the Credential trait
pub trait Credential {
    fn credential_type(&self) -> CredentialType;
    fn get_credential_key(&self) -> CredentialKey;
    fn by_value(&self, cred_bytes: &[u8]) -> Option<BufferIdCred>;
    fn by_reference(&self) -> Vec<ReferenceMethod>;
}

// Cose_Key
#[derive(Clone, Debug)]
pub struct CoseKey {
    pub kty: i8,
    pub kid: BufferKid,
    pub x: Option<BytesKeyEC2>,
    pub y: Option<BytesKeyEC2>,
    pub k: Option<BytesKey128>,
}

impl CoseKey {
    pub fn new(kty: i8, kid: BufferKid) -> Self {
        Self {
            kty,
            kid,
            x: None,
            y: None,
            k: None,
        }
    }

    pub fn with_x(self, x: BytesKeyEC2) -> Self {
        Self { x: Some(x), ..self }
    }

    pub fn set_y(self, y: BytesKeyEC2) -> Self {
        Self { y: Some(y), ..self }
    }

    pub fn set_k(self, k: BytesKey128) -> Self {
        Self { k: Some(k), ..self }
    }
}

impl Credential for CoseKey {
    fn credential_type(&self) -> CredentialType {
        match self.kty {
            2 => CredentialType::CCS,
            4 => CredentialType::CCS_PSK,
            _ => panic!("Unsupported key type"),
        }
    }

    fn get_credential_key(&self) -> CredentialKey {
        match self.kty {
            2 => CredentialKey::EC2 { 
                x: self.x.as_ref().unwrap(), 
                y: self.y.as_ref().map(|y| y.as_ref()) 
            },
            4 => CredentialKey::Symmetric(self.k.as_ref().unwrap()),
            _ => panic!("No key found"),
        }
    }

    fn by_value(&self, cred_bytes: &[u8]) -> Option<BufferIdCred> {
        if self.credential_type() == CredentialType::CCS_PSK {
            None
        } else {
            let mut cred = BufferIdCred::new();
            cred.extend_from_slice(&[CBOR_MAJOR_MAP + 1, KCSS_LABEL])
            .map_err(|_| EDHOCError::CredentialTooLongError)
            .unwrap();

        // Add CBOR byte string header
        if cred_bytes.len() <= 23 {
            cred.push(0x40 + cred_bytes.len() as u8).unwrap();
        } else if cred_bytes.len() <= 255 {
            cred.extend_from_slice(&[0x58, cred_bytes.len() as u8]).unwrap();
        } else {
            // Handle longer lengths if needed
        }

        cred.extend_from_slice(cred_bytes).unwrap();
        cred
        }
    }

    fn by_reference(&self) -> Vec<ReferenceMethod> {
        vec![ReferenceMethod::Kid(self.kid.clone())]
    }
}
// Implement Credential for X509
impl Credential for X509 {
    fn credential_type(&self) -> CredentialType {
        CredentialType::X509
    }

    fn get_credential_key(&self) -> CredentialKey {
        CredentialKey::EC2 { x: &self.public_key, y: None }
    }

    fn by_value(&self) -> Option<BufferIdCred> {
        // ??
    }

    fn by_reference(&self) -> Vec<ReferenceMethod> {
        let mut refs = Vec::new();
        if let Some(x5t) = self.x5t {
            refs.push(ReferenceMethod::X5t(x5t));
        }
        if let Some(c5t) = self.c5t {
            refs.push(ReferenceMethod::C5t(c5t));
        }
        refs
    }
}

