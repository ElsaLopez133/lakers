import asyncio
import logging
import aiocoap
from aiocoap import Message
from aiocoap.resource import Site, Resource

class EdhocCoAPResource(Resource):
    def __init__(self, server_coap_uri):
        super().__init__()
        self.server_coap_uri = server_coap_uri
        self.logger = logging.getLogger(__name__)

    async def render_post(self, request):
        self.logger.info(f"Received EDHOC message from client proxy: {list(request.payload)}")
        
        # Forward to actual server
        response_payload = await self.forward_to_server(request.payload)
        
        # Create response
        response = Message(
            code=aiocoap.CHANGED,
            payload=response_payload if response_payload else b''
        )
        
        self.logger.info(f"Sending response back to client proxy: {list(response.payload)}")
        return response
    
    async def forward_to_server(self, payload):
        try:
            context = await aiocoap.Context.create_client_context()
            request = Message(
                code=aiocoap.POST, 
                uri=self.server_coap_uri,
                payload=payload
            )
            response = await context.request(request).response
            self.logger.info(f"Response from actual server: {list(response.payload)}")
            return response.payload
        except Exception as e:
            self.logger.error(f"Error forwarding to server: {e}")
            return None

class EdhocServerProxy:
    def __init__(self, host='::', port=5684,
                 server_coap_uri='coap://localhost:5683/.well-known/edhoc'):
        self.host = host
        self.port = port
        self.server_coap_uri = server_coap_uri
        self.logger = logging.getLogger(__name__)
    
    async def run(self):
        # Resource tree creation
        site = Site()
        
        # Add EDHOC resource
        edhoc_resource = EdhocCoAPResource(self.server_coap_uri)
        site.add_resource(['.well-known', 'edhoc'], edhoc_resource)
        
        self.logger.info(f"EDHOC Server Proxy listening on {self.host}:{self.port}")
        self.logger.info(f"Forwarding to server at {self.server_coap_uri}")
        
        context = await aiocoap.Context.create_server_context(site,
                                                            bind=(self.host, self.port))
        
        try:
            await asyncio.sleep(3600) 
        except KeyboardInterrupt:
            self.logger.info("Shutting down server proxy...")
            await context.shutdown()

def main():
    logging.basicConfig(level=logging.INFO)
    server_proxy = EdhocServerProxy(host='::', port=5684)
    asyncio.run(server_proxy.run())

if __name__ == "__main__":
    main()