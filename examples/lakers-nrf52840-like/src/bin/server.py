import serial
import serial.tools.list_ports
import time
import lakers
import cbor2
import pytest
from lakers import CredentialTransfer, EdhocInitiator, EdhocResponder

R = bytes.fromhex("72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac")
CRED_R = bytes.fromhex("A2026008A101A5010202410A2001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072")
CRED_I = bytes.fromhex("A2027734322D35302D33312D46462D45462D33372D33322D333908A101A5010202412B2001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8")

class EdhocServerSerial:
    def __init__(self, port='/dev/ttyACM0', baud_rate=9600):
        self.ser = serial.Serial(
            port, 
            baud_rate, 
            timeout=1,
            bytesize=serial.EIGHTBITS,
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE
        )
        
        # Initialize EDHOC responder
        self.responder = EdhocResponder(R, CRED_R)

    def run(self):
        print(f"Listening on {self.ser.port} at {self.ser.baudrate} baud...")
        stage = 0

        while True:
            if self.ser.in_waiting:
                message_raw = self.ser.readline()
                print(f"Received message: {list(message_raw)}")

                try:
                    if stage == 0:
                        # Process message 1
                        c_i, ead_1 = self.responder.process_message_1(message_raw)
                        print(f"connection identifier {list(c_i)}")
                        
                        # Prepare message 2
                        message_2 = self.responder.prepare_message_2(
                            CredentialTransfer.ByReference, 
                            None, 
                            ead_1
                        )
                        
                        # Send message 2
                        print(f"Sending message 2: {list(message_2)}")
                        self.ser.write(message_2)
                        # self.ser.write(b'\r\n')
                        self.ser.flush()
                        stage = 1

                    elif stage == 1:
                        # Process message 3
                        print("message_3")
                        id_cred_i, ead_3 = self.responder.parse_message_3(message_raw)
                        print(f"id_cred_i: {list(id_cred_i)}")
                        
                        # Verify message 3
                        valid_cred_i = lakers.credential_check_or_fetch(id_cred_i, CRED_I)
                        # print(f"valid_cred_i: {list(valid_cred_i)}")
                        # print(f"cred_i: {list(CRED_I)}")

                        prk_out = self.responder.verify_message_3(valid_cred_i)
                        
                        # Derive OSCORE keys
                        oscore_secret = self.responder.edhoc_exporter(0, [], 16)
                        oscore_salt = self.responder.edhoc_exporter(1, [], 8)
                        
                        print("EDHOC Handshake Complete!")
                        print(f"OSCORE Secret: {list(oscore_secret)}")
                        print(f"OSCORE Salt: {list(oscore_salt)}")
                        
                        stage = 2

                except Exception as e:
                    print(f"EDHOC Error: {e}")
                    stage = 0

if __name__ == "__main__":
    server = EdhocServerSerial()
    server.run()