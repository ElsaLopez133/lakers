#![no_std]

use edhoc_consts::*;

// initiator side
pub fn i_prepare_ead_1() -> Option<EADItem> {
    Some(EADItem::new())
}

pub fn i_process_ead_2(ead_2: EADItem) -> Result<(), ()> {
    Ok(())
}

pub fn i_prepare_ead_3() -> Option<EADItem> {
    Some(EADItem::new())
}

// responder side
pub fn r_process_ead_1(ead_1: EADItem) -> Result<(), ()> {
    Ok(())
}

pub fn r_prepare_ead_2() -> Option<EADItem> {
    Some(EADItem::new())
}

pub fn r_process_ead_3(ead_3: EADItem) -> Result<(), ()> {
    Ok(())
}