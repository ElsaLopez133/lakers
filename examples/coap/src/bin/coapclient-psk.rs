use coap::CoAPClient;
use coap_lite::ResponseType;
use hexlit::hex;
use lakers::*;
use log::*;
use std::time::Duration;

const ID_CRED: &[u8] = &hex!("a1044120");
const CRED_PSK: &[u8] =
    &hex!("A202686D79646F74626F7408A101A30104024132205050930FF462A77A3540CF546325DEA214");

fn main() {
    env_logger::init();
    info!("Starting EDHOC CoAP Client");
    match client_handshake() {
        Ok(_) => println!("Handshake completed"),
        Err(e) => panic!("Handshake failed with error: {:?}", e),
    }
}

fn client_handshake() -> Result<(), EDHOCError> {
    let url = "coap://127.0.0.1:5683/.well-known/edhoc";
    let timeout = Duration::new(5, 0);
    println!("Client request: {}", url);

    let cred: Credential = Credential::parse_ccs_symmetric(CRED_PSK.try_into().unwrap()).unwrap();

    let mut initiator = EdhocInitiator::new(
        lakers_crypto::default_crypto(),
        EDHOCMethod::Psk_var1,
        EDHOCSuite::CipherSuite2,
    );

    // Send Message 1 over CoAP and convert the response to byte
    let mut msg_1_buf = Vec::from([0xf5u8]); // EDHOC message_1 when transported over CoAP is prepended with CBOR true
    let c_i = generate_connection_identifier_cbor(&mut lakers_crypto::default_crypto());
    initiator.set_identity(None, cred);
    let (initiator, message_1) = initiator.prepare_message_1(Some(c_i), &None)?;
    msg_1_buf.extend_from_slice(message_1.as_slice());
    println!("message_1 len = {}", msg_1_buf.len());

    let response = CoAPClient::post_with_timeout(url, msg_1_buf, timeout).unwrap();
    if response.get_status() != &ResponseType::Changed {
        panic!("Message 1 response error: {:?}", response.get_status());
    }
    println!("response_vec = {:02x?}", response.message.payload);
    println!("message_2 len = {}", response.message.payload.len());

    let message_2 = EdhocMessageBuffer::new_from_slice(&response.message.payload[..]).unwrap();
    let (mut initiator, c_r, id_cred_r, _ead_2) = initiator.parse_message_2(&message_2)?;
    let valid_cred_r = credential_check_or_fetch(Some(cred), id_cred_r.unwrap()).unwrap();
    let initiator = initiator.verify_message_2(valid_cred_r)?;

    let mut msg_3 = Vec::from(c_r.as_cbor());
    let (mut initiator, message_3, prk_out) =
        initiator.prepare_message_3(CredentialTransfer::ByReference, &None)?;
    msg_3.extend_from_slice(message_3.as_slice());
    println!("message_3 len = {}", msg_3.len());

    let _response = CoAPClient::post_with_timeout(url, msg_3, timeout).unwrap();
    // we don't care about the response to message_3 for now

    println!("EDHOC exchange successfully completed");
    println!("PRK_out: {:02x?}", prk_out);

    let mut oscore_secret = initiator.edhoc_exporter(0u8, &[], 16); // label is 0
    let mut oscore_salt = initiator.edhoc_exporter(1u8, &[], 8); // label is 1

    println!("OSCORE secret: {:02x?}", oscore_secret);
    println!("OSCORE salt: {:02x?}", oscore_salt);

    // context of key update is a test vector from draft-ietf-lake-traces
    let prk_out_new = initiator.edhoc_key_update(&[
        0xa0, 0x11, 0x58, 0xfd, 0xb8, 0x20, 0x89, 0x0c, 0xd6, 0xbe, 0x16, 0x96, 0x02, 0xb8, 0xbc,
        0xea,
    ]);

    println!("PRK_out after key update: {:02x?}?", prk_out_new);

    // compute OSCORE secret and salt after key update
    oscore_secret = initiator.edhoc_exporter(0u8, &[], 16); // label is 0
    oscore_salt = initiator.edhoc_exporter(1u8, &[], 8); // label is 1

    println!("OSCORE secret after key update: {:02x?}", oscore_secret);
    println!("OSCORE salt after key update: {:02x?}", oscore_salt);

    Ok(())
}
