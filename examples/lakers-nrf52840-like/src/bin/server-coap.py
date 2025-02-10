import asyncio
import logging
from aiocoap import Context, Message
from aiocoap.resource import Site, Resource
import lakers
from lakers import EdhocResponder, Credential, ConnId, CredentialTransfer

# Credentials and identifiers matching the Rust implementation
ID_CRED_I = bytes.fromhex("a104412b")
ID_CRED_R = bytes.fromhex("a104410a")
CRED_I = bytes.fromhex("A2027734322D35302D33312D46462D45462D33372D33322D333908A101A5010202412B2001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8")
CRED_R = bytes.fromhex("A2026008A101A5010202410A2001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072")
R = bytes.fromhex("72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac")

class EdhocResource(Resource):
    def __init__(self):
        super().__init__()
        
        # Logging setup
        logging.basicConfig(level=logging.INFO, 
                            format='%(asctime)s - %(levelname)s: %(message)s')
        self.logger = logging.getLogger(__name__)
        
        # Store EDHOC connection states
        self.edhoc_connections = []

    async def render_post(self, request):
        try:
            payload = request.payload
            self.logger.info(f"Received message: {list(payload)}")

            # Check if this is an initial EDHOC message
            if payload[0] == 0xf5:
                return await self.handle_message_1(payload[1:])
            else:
                return await self.handle_message_3(payload)

        except Exception as e:
            self.logger.error(f"EDHOC Processing Error: {e}")
            return Message(payload=b'Error processing message')

    async def handle_message_1(self, message_1_payload):
        # Initialize Responder
        responder = EdhocResponder(R, CRED_R)

        # Process message 1
        message_1 = lakers.EdhocMessageBuffer.new_from_slice(message_1_payload)
        c_i, ead_1 = responder.process_message_1(message_1)
        self.logger.info(f"connection identifier {list(c_i)}")
        
        # Prepare message 2
        c_r = ConnId.from_int_raw(10) 
        message_2 = self.responder.prepare_message_2(
            CredentialTransfer.ByReference, 
            c_r, 
            ead_1
        )
        # Prepend CBOR true (0xF5) to message_2
        message_2_with_true = b"\xf5" + message_2.as_slice()

        # Store the connection state
        self.edhoc_connections.append((c_r, responder))
        
        self.logger.info(f"Sending message 2: {list(message_2.as_slice())}")
        return Message(payload=message_2_with_true.as_slice())

    async def handle_message_3(self, payload):
        # Extract connection identifier and message 3
        c_r_rcvd = ConnId.from_int_raw(payload[0])
        message_3 = lakers.EdhocMessageBuffer.new_from_slice(payload[1:])
        
        # Find and remove the corresponding responder state
        responder = self.take_state(c_r_rcvd)
        
        # Process message 3
        id_cred_i, ead_3 = self.responder.parse_message_3(message_3)
        self.logger.info(f"id_cred_i: {list(id_cred_i)}")
        
        # Verify credentials
        valid_cred_i = lakers.credential_check_or_fetch(id_cred_i, CRED_I)
        
        # Verify message 3
        prk_out = self.responder.verify_message_3(valid_cred_i)
        self.responder.completed_without_message_4()
        self.logger.info(f"prk_out: {list(prk_out)}")
        
        # Derive OSCORE keys (similar to Rust implementation)
        oscore_secret = responder.edhoc_exporter(0, [], 16)
        oscore_salt = responder.edhoc_exporter(1, [], 8)
        
        self.logger.info("EDHOC exchange completed")
        self.logger.info(f"OSCORE Secret: {oscore_secret.hex()}")
        self.logger.info(f"OSCORE Salt: {oscore_salt.hex()}")
        
        return Message(payload=b'')

    def take_state(self, c_r_rcvd):
        """Find and remove the responder state for a given connection identifier"""
        for i, (c_r, responder) in enumerate(self.edhoc_connections):
            if c_r == c_r_rcvd:
                # Remove and return the responder
                return self.edhoc_connections.pop(i)[1]
        
        raise ValueError("No stored state available for that Connection Identifier")

class EdhocServer:
    def __init__(self, host='127.0.0.1', port=5683):
        self.host = host
        self.port = port

    async def run(self):
        # Create a site with the EDHOC resource
        site = Site()
        site.add_resource(['.well-known', 'edhoc'], EdhocResource())

        # Create and run the server
        server = await Context.create_server_context(site, bind=(self.host, self.port))
        
        print(f"EDHOC CoAP Server listening on {self.host}:{self.port}")
        
        try:
            # Run indefinitely
            await server.wait_closed()
        except KeyboardInterrupt:
            await server.shutdown()


def main():
    logging.basicConfig(level=logging.INFO)
    
    server = EdhocServer(host='127.0.0.1', port=5683)
    
    asyncio.run(server.run())

if __name__ == "__main__":
    main()