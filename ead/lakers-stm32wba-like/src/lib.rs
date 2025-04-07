#![no_std]

mod device;

pub use device::InitiatorSoK;

pub mod consts {
    pub const EAD_SOK_LABEL: u8 = 0x2;
}

#[derive(PartialEq, Debug)]
#[repr(C)]
pub enum SoKError {
    InvalidEADLabel,
    EmptyEADValue,
}