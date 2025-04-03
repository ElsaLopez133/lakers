#![no_std]

mod device;
mod shared;

pub use device::{InitiaitorSoK};

pub mod consts {
    pub const EAD_SOK_LABEL: u8 = 0x2;
}

#[derive(PartialEq, Debug)]
#[repr(C)]
pub enum SoKError {
    InvalidEADLabel,
    EmptyEADValue,
}