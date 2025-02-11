// use coap::CoAPClient;
// use coap_lite::ResponseType;
use hexlit::hex;
use lakers::*;
use log::*;
use std::time::Duration;

const CRED_PSK: &[u8] =
    &hex!("A202686D79646F74626F7408A101A30104024110205050930FF462A77A3540CF546325DEA214");

fn main() {
    match client_handshake() {
        Ok(_) => println!("Handshake completed"),
        Err(e) => panic!("Handshake failed with error: {:?}", e),
    }
}

fn client_handshake() -> Result<(), EDHOCError> {

    let cred: Credential = Credential::parse_ccs_symmetric(CRED_PSK.try_into().unwrap()).unwrap();
    println!("cred_psk: {:?}", cred);

    let mut initiator = EdhocInitiator::new(
        lakers_crypto::default_crypto(),
        EDHOCMethod::PSK2,
        EDHOCSuite::CipherSuite2,
    );
    println!("\n---------MESSAGE_1-----------\n");
    let c_i = generate_connection_identifier_cbor(&mut lakers_crypto::default_crypto());
    initiator.set_identity(cred);
    let (initiator, message_1) = initiator.prepare_message_1(Some(c_i), &None)?;
    println!("message_1 len = {}", message_1.len);
    
    Ok(())
}

