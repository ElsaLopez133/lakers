import serial
import asyncio
import logging
import aiocoap
import time

class EdhocSerialToCoAPProxy:
    def __init__(self, 
                 serial_port='/dev/ttyACM0', 
                 serial_baud=9600, 
                 proxy_coap_server='coap://127.0.0.1:5684/.well-known/edhoc'):
        
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
        self.coap_server_uri = proxy_coap_server
        
        self.current_state = "WAITING_FOR_MSG1"
        self.buffer = bytearray()
        self.message_counter = 0

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
                self.buffer.clear() 
                                
                start_time = time.time()
                timeout = 0.5
                
                while (time.time() - start_time) < timeout:
                    if self.ser.in_waiting:
                        chunk = self.ser.read(self.ser.in_waiting)
                        self.buffer.extend(chunk)
                    await asyncio.sleep(0.05)
                
                if len(self.buffer) > 0:
                    self.logger.info(f"Collected message after timeout: {list(self.buffer)}")
                    
                    # Send to CoAP server
                    await self.send_coap_message(bytes(self.buffer))
                    self.message_counter += 1
                    
                    # Update state based on message type
                    if len(self.buffer) > 0 and self.buffer[0] == 0xF5 and self.current_state == "WAITING_FOR_MSG1":
                        self.current_state = "WAITING_FOR_MSG3"
                    elif self.current_state == "WAITING_FOR_MSG3":
                        self.current_state = "HANDSHAKE_COMPLETE"
                    
                    self.logger.info(f"Updated state: {self.current_state}")

                    await asyncio.sleep(0.5)
            
            await asyncio.sleep(0.1)

async def main():
    proxy = EdhocSerialToCoAPProxy(proxy_coap_server='coap://127.0.0.1:5684/.well-known/edhoc')
    await proxy.process_serial_messages()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Proxy stopped")