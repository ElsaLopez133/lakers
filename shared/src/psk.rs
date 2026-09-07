use crate::{EdhocBuffer, EdhocBufferError, MAX_PSK_LEN, MIN_PSK_LEN};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A pre-shared key for the EDHOC PSK method.
///
/// This wraps an [`EdhocBuffer`] rather than being an alias for one, so that the key material is
/// covered by three guarantees that a bare buffer cannot give:
///
/// * **It is at least [`MIN_PSK_LEN`] bytes long.** The only way to obtain a value of this type is
///   [`BufferPsk::new_from_slice`], which rejects anything shorter, so no code path can produce a
///   PSK with insufficient entropy.
/// * **It does not reveal the key material.** A derived `Debug` would let the key leak into logs
///   and panic messages, so `Debug` is implemented by hand and prints only a redaction marker. A
///   derived `PartialEq` would compare the key in non-constant time, leaking it through a timing
///   side channel, so it is not implemented at all. The inner buffer is private so that neither
///   can be reached through it. `Clone` *is* implemented: duplicating a key reveals nothing, it
///   only affects how many copies are in memory. Do not turn the other two into derives.
/// * **It is erased when it is dropped.** `ZeroizeOnDrop` overwrites the key material at the end
///   of the value's scope, using volatile writes the optimiser is not allowed to remove. A plain
///   `fill(0)` would not do: the bytes are provably never read again, so dead store elimination
///   deletes it in release builds.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[repr(C)]
pub struct BufferPsk {
    inner: EdhocBuffer<MAX_PSK_LEN>,
}
impl BufferPsk {
    pub const fn new_from_slice(slice: &[u8]) -> Result<Self, EdhocBufferError> {
        if slice.len() < MIN_PSK_LEN {
            return Err(EdhocBufferError::SliceTooShort);
        }
        match EdhocBuffer::new_from_slice(slice) {
            Ok(inner) => Ok(Self { inner }),
            Err(e) => Err(e),
        }
    }
    pub fn as_slice(&self) -> &[u8] {
        self.inner.as_slice()
    }
}

impl core::fmt::Debug for BufferPsk {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("BufferPsk(<redacted>)")
    }
}
#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_zeroize() {
        let mut k = BufferPsk::new_from_slice(&[0xAB; 32]).unwrap();
        k.zeroize();
        assert!(k.as_slice().is_empty());
    }
}
