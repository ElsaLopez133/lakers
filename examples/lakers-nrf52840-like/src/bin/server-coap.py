import asyncio
import logging
import aiocoap
# from aiocoap import *
from aiocoap import Message, Context
from aiocoap.resource import Site, Resource
import lakers
from lakers import EdhocResponder, CredentialTransfer

# Credentials and identifiers matching the Rust implementation
ID_CRED_I = bytes.fromhex("a104412b")
ID_CRED_R = bytes.fromhex("a104410a")
CRED_I = bytes.fromhex("A2027734322D35302D33312D46462D45462D33372D33322D333908A101A5010202412B2001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8")
CRED_R = bytes.fromhex("A2026008A101A5010202410A2001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072")
R = bytes.fromhex("72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac")

class EdhocResource(Resource):
    # We inherit the features from Resource class
    def __init__(self):
        super().__init__()
        self.edhoc_connections = []
        self.responder = EdhocResponder(R, CRED_R)

    async def render_post(self, request):
        # We overwrite the render_post function of Resource class
        try:
            payload = request.payload
            path = request.opt.uri_path

            # print("Request Debug Info:")
            # print(f"Payload: {list(payload)}")
            # print(f"URI Path: {request.opt.uri_path}")
            # print(f"URI Host: {request.opt.uri_host}")

            # print(f"Full URI: {request.get_request_uri()}")  
            # print(f"Path segments: {path}")
            # print(f"All options: {request.opt}")
            # print(f"Remote: {request.remote}")
            # print(f"Code: {request.code}")
            
            if not path:
                uri_path = request.get_request_uri().split('://')[-1].split('/', 1)[-1]
                path = uri_path.split('/')
                print(f"Extracted path: {path}")

            if path == ['.well-known', 'edhoc'] or (isinstance(path, str) and path == '.well-known/edhoc'):
                print(f"Received message: {list(payload)}")
                
                if payload[0] == 0xf5:
                    # Process message 1 (EDHOC)
                    print("----message_1-----")
                    message_1 = payload[1:]
                    c_i, ead_1 = self.responder.process_message_1(message_1)
                    
                    c_r = [0xA]  # ConnId.from_int_raw(10)                    
                    message_2 = self.responder.prepare_message_2(CredentialTransfer.ByReference, c_r, None)
                    message_2 = b"\xf5" + message_2 

                    response = Message(
                        code=aiocoap.CHANGED, 
                        payload=message_2
                    )
                    
                    self.edhoc_connections.append((c_r, self.responder))
                    print(f"Message 2: {list(response.payload)}")
                    
                    return response
                
                elif payload[0] != 0xf5:
                    print("----message_3-----")
                    # Process message 3
                    c_r_rcvd = [payload[0]]
                    self.responder = self.take_state(c_r_rcvd)
                    message_3 = payload[1:]
                    
                    id_cred_i, ead_3 = self.responder.parse_message_3(message_3)
                    valid_cred_i = lakers.credential_check_or_fetch(id_cred_i, CRED_I)
                    prk_out = self.responder.verify_message_3(valid_cred_i)
                    print(f"prk_out: {list(prk_out)}")

                    self.responder.completed_without_message_4()

                    # Send an empty message as ack
                    # ack = b"0x00"
                    # response = Message(
                    #     code=aiocoap.CHANGED, 
                    #     payload=ack
                    # )
                    # print(f"ack: {list(response.payload)}")   

                    # Derive OSCORE keys
                    oscore_secret = self.responder.edhoc_exporter(0, [], 16)
                    oscore_salt = self.responder.edhoc_exporter(1, [], 8)

                    print("EDHOC Handshake Complete!")
                    print(f"OSCORE Secret: {list(oscore_secret)}")
                    print(f"OSCORE Salt: {list(oscore_salt)}")

                    return Message(code=aiocoap.CHANGED, payload=b"\x00")
            
            # Resource not found
            return Message(code=aiocoap.NOT_FOUND, payload=b"Resource not found")
        
        except Exception as e:
            print(f"Error: {e}")
            return Message(code=aiocoap.BAD_REQUEST, payload=str(e).encode())

    def take_state(self, c_r_rcvd):
        for i, (c_r, responder) in enumerate(self.edhoc_connections):
            if c_r == c_r_rcvd:
                self.edhoc_connections.pop(i)
                return responder
        raise ValueError("No stored state available for that C_R")

class EdhocServer:
    def __init__(self, host='127.0.0.1', port=5683):
        self.host = host
        self.port = port

    async def run(self):
        site = Site()
        site.add_resource(['.well-known', 'edhoc'], EdhocResource())
        
        server = await Context.create_server_context(site, bind=(self.host, self.port))
        print(f"EDHOC CoAP Server listening on {self.host}:{self.port}")
        try:
            await asyncio.sleep(3600)
        except KeyboardInterrupt:
            print("Shutting down server...")
            await server.shutdown()

def main():
    logging.basicConfig(level=logging.INFO)
    server = EdhocServer(host='127.0.0.1', port=5683)
    asyncio.run(server.run())

if __name__ == "__main__":
    main()
