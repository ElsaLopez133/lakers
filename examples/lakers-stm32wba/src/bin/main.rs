#![no_std]
#![no_main]

// Reference Manual: file:///C:/Users/elopezpe/OneDrive/Documentos/PhD/micro/stm32eba55cg/rm0493-multiprotocol-wireless-bluetooth-low-energy-and-ieee802154-stm32wba5xxx-arm-based-32-bit-mcus-stmicroelectronics-en.pdf

use stm32wba::stm32wba55;
use {defmt_rtt as _, panic_probe as _};
use cortex_m_rt::entry;
use cortex_m::asm;
use lakers::*;
use lakers_shared::{Crypto as CryptoTrait, *};
use lakers_shared::{BASE_POINT_X, BASE_POINT_Y, SCALAR};
use lakers_crypto_rustcrypto_stm::Crypto;
use lakers_crypto_rustcrypto_stm::{u32_to_u8, u8_to_u32};
use defmt::info;
// use defmt::trace;
use defmt_or_log::trace;
use hexlit::hex;
use stm32_metapac::usart::Usart;
use lakers_stm32wba_like::*; 

pub const X: [u8; 32] = hex!("368ec1f69aeb659ba37d5a8d45b21bdc0299dceaa8ef235f3ca42ce3530f9525");
pub const G_X_X_COORD: [u8; 32] = hex!("8af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b6");
pub const G_X_Y_COORD: [u8; 32] = hex!("51e8af6c6edb781601ad1d9c5fa8bf7aa15716c7c06a5d038503c614ff80c9b3");
pub const CRED_I: &[u8] = &hex!("A2027734322D35302D33312D46462D45462D33372D33322D333908A101A5010202412B2001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8");
pub const I: &[u8] = &hex!("fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b");

pub const SK: [u8; 32] = hex!("5c4172aca8b82b5a62e66f722216f5a10f72aa69f42c1d1cd3ccd7bfd29ca4e9");
pub const MESSAGE_2: [u8; 45] = hex!("582b419701d7f00a26c2dc587a36dd752549f33763c893422c8ea0f955a13a4ff5d59862a1eef9e0e7e1886fcd");

pub const CRED_R: &[u8] = &hex!("A2026008A101A5010202410A2001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072");
pub const R: &[u8] = &hex!("72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac");
pub const G_R_X_COORD: [u8; 32] = hex!("bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f0");
pub const G_R_Y_COORD: [u8; 32] = hex!("4519e257236b2a0ce2023f0931f1f386ca7afda64fcd e0108c224c51eabf6072");
// pub const CRED_R: &[u8] = &hex!("A2026008A101A501020241322001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072");
// pub const CRED_R: &[u8] = &hex!("a2026b6578616d706c652e65647508a101a5010241322001215820bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f02258204519e257236b2a0ce2023f0931f1f386ca7afda64fcde0108c224c51eabf6072");

#[entry]
unsafe fn main() -> ! {
    // Access peripherals via PAC
    let p = &stm32wba55::Peripherals::take().unwrap();
    let hash = &p.HASH;
    let pka = &p.PKA;
    let rng = &p.RNG;
    let rcc = &p.RCC;
    
    // call lakers-crypto-rustcrypto-stm private init function
    let mut crypto = Crypto::new(&p, hash, pka, rng);
    crypto.lakers_crypto_rustcrypto_stm_init();

    // Configure the Initiator
    let cred_i = Credential::parse_ccs(CRED_I.try_into().unwrap()).unwrap();
    let id_cred_i = cred_i.by_kid().unwrap();
    let cred_r = Credential::parse_ccs(CRED_R.try_into().unwrap()).unwrap();

    trace!("Setting the initiator and the responder");
    let mut initiator = EdhocInitiator::new(
        lakers_crypto::default_crypto(p, hash, pka, rng),
        EDHOCMethod::StatStat,
        EDHOCSuite::CipherSuite2,
    );

    let responder = EdhocResponder::new(
        lakers_crypto::default_crypto(p, hash, pka, rng),
        EDHOCMethod::StatStat,
        R.try_into().unwrap(),
        cred_r,
    );

    // Precomputation phase. 
    // Keys of the authorities and compute h (product of pk of authorities) and w (hash with id_cred_i)
    // sk is the secret key and pk = (g^sk, ni)
    let (pk, sk) = crypto.keygen_a();
    let (h, w) = crypto.precomp(&[pk], id_cred_i.as_full_value());
    // info!("pk.pk1: {:?}  sk: {:?}   h: {:?}   w: {:?}", pk.pk1, sk, h, w);

    // To follow the example, c_i= 37
    trace!("------------Initiator message_1------------");
    // let c_i = ConnId::from_int_raw(0x37);
    let c_i = generate_connection_identifier_cbor(&mut lakers_crypto::default_crypto(&p, hash, pka, rng));
    // info!("c_i: {:#X}", c_i.as_slice());
    let (initiator, message_1) = initiator.prepare_message_1(Some(c_i), &None).unwrap();
    info!("message_1: {:#X}", message_1.content[..message_1.len]);

    // Repsonder parses message_1 and sends message_2
    trace!("------------Responder message_2------------");
    let (responder, _c_i, _ead_1) = responder.process_message_1(&message_1).unwrap();
    let (responder, message_2) = responder
        .prepare_message_2(CredentialTransfer::ByReference, None, &None)
        .unwrap();    
    info!("message_2: {:#X}", message_2.content[..message_2.len]);

    trace!("------------Initiator message_3------------");
    let (mut initiator, _c_r, id_cred_r, _ead_2) =
    initiator.parse_message_2(&message_2).unwrap();
    let valid_cred_r = credential_check_or_fetch(Some(cred_r), id_cred_r).unwrap();
    initiator
        .set_identity(
            I.try_into().expect("Wrong length of initiator private key"),
            cred_i.clone(),
        )
        .unwrap(); // exposing own identity only after validating cred_r

    // Prepare ead_3
    let i: [u8; 32] = I.try_into().expect("h should be exactly 32 bytes");
    let public_key = match valid_cred_r.key {
        CredentialKey::EC2Compact(public_key) => public_key,
        _ => panic!("Invalid key type. Expected EC2Compact."),
    };
    
    let initiator_sok = lakers_stm32wba_like::InitiatorSoK::new(&initiator.state, &public_key);
    let ead_3 = initiator_sok.prepare_ead_3(&mut crypto, h, public_key, i, w);
    info!("ead_3: {:#X}", ead_3.value.unwrap().content[..ead_3.value.unwrap().len]);

    let initiator = initiator.verify_message_2(valid_cred_r).unwrap();
    let (initiator, message_3, i_prk_out) = initiator
        .prepare_message_3(CredentialTransfer::ByReference, &Some(ead_3))
        .unwrap();
    info!("message_3: {:#X}", message_3.content[..message_3.len]);
    
    trace!("------------Responder message_4------------");
    let (responder, id_cred_i, _ead_3) = responder.parse_message_3(&message_3).unwrap();
    let valid_cred_i = credential_check_or_fetch(Some(cred_i), id_cred_i).unwrap();
    let (responder, r_prk_out) = responder.verify_message_3(valid_cred_i).unwrap();

    let mut initiator = initiator.completed_without_message_4().unwrap();
    let mut responder = responder.completed_without_message_4().unwrap();
    
    // check that prk_out is equal at initiator and responder side
    assert_eq!(i_prk_out, r_prk_out);
    info!("Handshake completed");

    // derive OSCORE secret and salt at both sides and compare
    let i_oscore_secret = initiator.edhoc_exporter(0u8, &[], 16); // label is 0
    let i_oscore_salt = initiator.edhoc_exporter(1u8, &[], 8); // label is 1

    let r_oscore_secret = responder.edhoc_exporter(0u8, &[], 16); // label is 0
    let r_oscore_salt = responder.edhoc_exporter(1u8, &[], 8); // label is 1

    assert_eq!(i_oscore_secret, r_oscore_secret);
    assert_eq!(i_oscore_salt, r_oscore_salt);

    // // Initiator sends message 1. Responder processes it and sends message_2. Initator processes message_2
    // let mut buffer_2 = [0u8; MAX_MESSAGE_SIZE_LEN ];
    // buffer_2[..0 + MESSAGE_2.len()].copy_from_slice(&MESSAGE_2);
    // let message_2: EdhocMessageBuffer = EdhocMessageBuffer { content: buffer_2, len: MESSAGE_2.len() + 0 };
    // // info!("message_2 :{:#X}", message_2.content[..message_2.len]);

    // let (initiator, c_r, id_cred_r, ead_2) = initiator.parse_message_2(&message_2).unwrap();
    // // info!("c_r: {:#X}   id_cred_r: {:#X}", c_r.as_slice(), id_cred_r.as_full_value());
    // let valid_cred_r = credential_check_or_fetch(Some(cred_r), id_cred_r).unwrap();
    // // info!("valid_cred_r: {:#X}", valid_cred_r.bytes.as_slice());
    // let initiator = initiator.verify_message_2(valid_cred_r).unwrap();

    loop {}
}