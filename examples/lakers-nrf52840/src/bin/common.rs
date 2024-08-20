use embassy_nrf::radio::ble::Radio;
use embassy_nrf::saadc::Time;
use embassy_nrf::{peripherals, radio};
use embassy_time::Duration;
use embassy_time::TimeoutError;
use embassy_time::WithTimeout;
use hexlit::hex;

use defmt::info;

pub const MAX_PDU: usize = 258;
pub const FREQ: u32 = 2408;
pub const ADV_ADDRESS: u32 = 0x12345678;
pub const ADV_CRC_INIT: u32 = 0xffff;
pub const CRC_POLY: u32 = 0x00065b;


oub const ID_CRED: &[u8] = &hex!("a1044120");
pub const CRED_PSK: &[u8] =
    &hex!("A202686D79646F74626F7408A101A30104024132205050930FF462A77A3540CF546325DEA214");

#[derive(Debug)]
pub enum PacketError {
    SliceTooLong,
    SliceTooShort,
    ParsingError,
    TimeoutError,
    RadioError,
}
pub struct Packet {
    pub len: usize, // total length that gets transmitted over the air, equals length of pdu + 1, for pdu_header
    pub pdu_header: Option<u8>, // 1-byte application-level header, used for filtering the packets
    pub pdu: [u8; MAX_PDU], // application-level payload
}

impl Default for Packet {
    fn default() -> Self {
        Packet {
            len: 0,
            pdu_header: None,
            pdu: [0u8; MAX_PDU],
        }
    }
}

impl Packet {
    pub fn new() -> Self {
        Packet {
            len: 0,
            pdu_header: None,
            pdu: [0u8; MAX_PDU],
        }
    }

    pub fn new_from_slice(slice: &[u8], header: Option<u8>) -> Result<Self, PacketError> {
        let mut buffer = Self::new();
        if buffer.fill_with_slice(slice, header).is_ok() {
            Ok(buffer)
        } else {
            Err(PacketError::SliceTooLong)
        }
    }

    pub fn fill_with_slice(&mut self, slice: &[u8], header: Option<u8>) -> Result<(), PacketError> {
        if slice.len() <= self.pdu.len() {
            self.len = slice.len();
            self.pdu_header = header;
            self.pdu[..self.len].copy_from_slice(slice);
            Ok(())
        } else {
            Err(PacketError::SliceTooLong)
        }
    }

    pub fn as_bytes(&mut self) -> &[u8] {
        let mut offset = 0;
        let mut len: usize = 0;

        if let Some(header) = self.pdu_header {
            offset = 3;
            len = self.len + 1;
        } else {
            offset = 2;
            len = self.len;
        }
        self.pdu.copy_within(..self.len, offset);
        self.pdu[0] = 0x00;
        self.pdu[1] = len as u8;

        if let Some(header) = self.pdu_header {
            self.pdu[2] = header;
        }
        &self.pdu[..len]
    }
}

impl TryInto<Packet> for &[u8] {
    type Error = ();

    fn try_into(self) -> Result<Packet, Self::Error> {
        let mut packet: Packet = Default::default();

        if self.len() > 1 {
            packet.len = self[1] as usize;
            packet.pdu[..packet.len].copy_from_slice(&self[2..2 + packet.len]);
            Ok(packet)
        } else {
            Err(())
        }
    }
}

impl From<TimeoutError> for PacketError {
    fn from(error: TimeoutError) -> Self {
        PacketError::TimeoutError
    }
}

impl From<embassy_nrf::radio::Error> for PacketError {
    fn from(error: embassy_nrf::radio::Error) -> Self {
        match error {
            _ => PacketError::RadioError,
        }
    }
}

pub async fn receive_and_filter(
    radio: &mut Radio<'static, embassy_nrf::peripherals::RADIO>,
    header: Option<u8>,
) -> Result<Packet, PacketError> {
    let mut buffer: [u8; MAX_PDU] = [0x00u8; MAX_PDU];
    loop {
        radio.receive(&mut buffer).await?;
        if let Ok(pckt) = <&[u8] as TryInto<Packet>>::try_into(&(buffer[..])) {
            if let Some(header) = header {
                if pckt.pdu[0] == header {
                    return Ok(pckt);
                } else {
                    continue;
                }
            } else {
                // header is None
                return Ok(pckt);
            }
        } else {
            continue;
        }
    }
}

pub async fn transmit_and_wait_response(
    radio: &mut Radio<'static, embassy_nrf::peripherals::RADIO>,
    mut packet: Packet,
    filter: Option<u8>,
) -> Result<Packet, PacketError> {
    let mut rcvd_packet: Packet = Default::default();
    let mut buffer: [u8; MAX_PDU] = [0x00u8; MAX_PDU];

    radio.transmit(packet.as_bytes()).await?;
    let resp = receive_and_filter(radio, filter).await?;

    Ok(resp)
}

pub async fn transmit_without_response(
    radio: &mut Radio<'static, embassy_nrf::peripherals::RADIO>,
    mut packet: Packet,
) -> Result<(), PacketError> {
    radio.transmit(packet.as_bytes()).await?;
    Ok(())
}

use core::ffi::{c_char, c_void};
#[no_mangle]
pub extern "C" fn strstr(cs: *const c_char, ct: *const c_char) -> *mut c_char {
    panic!("strstr handler!");
    core::ptr::null_mut()
}
