import serial
import asyncio
import logging
import aiocoap

class EdhocSerialToCoAPProxy:
    def __init__(self, 
                 serial_port='/dev/ttyACM0', 
                 serial_baud=9600, 
                 coap_server='coap://localhost:5683/.well-known/edhoc'):
        
        # Serial configuration
        self.ser = serial.Serial(
            serial_port, 
            serial_baud, 
            timeout=1,
            bytesize=serial.EIGHTBITS,
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE
        )
        
        # CoAP server endpoint
        self.coap_server_uri = coap_server
        
        # Logging setup
        logging.basicConfig(level=logging.INFO, 
                            format='%(asctime)s - %(levelname)s: %(message)s')
        self.logger = logging.getLogger(__name__)

    async def send_coap_message(self, payload):
        try:
            context = await aiocoap.Context.create_client_context()
            request = aiocoap.Message(code=aiocoap.Code.POST, uri=self.coap_server_uri, payload=payload)
            response = await context.request(request).response
            self.logger.info(f"CoAP Response: {list(response.payload)}")
            
            # If response is not empty, send it back to serial
            if response.payload:
                self.ser.write(response.payload)
                self.ser.flush()
            
            return response.payload
        except Exception as e:
            self.logger.error(f"CoAP send error: {e}")
            return None

    async def process_serial_messages(self):
        self.logger.info("Starting Serial to CoAP Proxy")
        
        while True:
            if self.ser.in_waiting:
                message_raw = self.ser.read(self.ser.in_waiting)
                self.logger.info(f"Received serial message: {list(message_raw)}")
                
                payload = message_raw
                
                # Send to CoAP server
                await self.send_coap_message(payload)
                            
            # Small delay
            await asyncio.sleep(0.1)

async def main():
    proxy = EdhocSerialToCoAPProxy()
    await proxy.process_serial_messages()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Proxy stopped")