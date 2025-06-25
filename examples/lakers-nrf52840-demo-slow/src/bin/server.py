import serial
import serial.tools.list_ports
import cbor2
import pytest
import lakers
from lakers import CredentialTransfer, EdhocResponder
import time
import logging

logging.basicConfig(level=5)

R = bytes.fromhex("72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac")
# CRED_R = bytes.fromhex("A2026008A101A5010202410A2001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072")
# CRED_I = bytes.fromhex("A2027734322D35302D33312D46462D45462D33372D33322D333908A101A5010202412B2001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8")
CRED_PSK = bytes.fromhex("A202686D79646F74626F7408A101A30104024110205050930FF462A77A3540CF546325DEA214");

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
        self.responder = EdhocResponder(CRED_PSK)
        self.edhoc_connections = []

    def run(self):
        print(f"Server listening on {self.ser.port} at {self.ser.baudrate} baud...")

        while True:
            if self.ser.in_waiting:
                message_raw = []
                # message_raw = self.ser.readline()
                
                start_time = time.time()
                timeout = 0.5

                while (time.time() - start_time) < timeout:
                    if self.ser.in_waiting:
                        message_raw.extend(self.ser.read(self.ser.in_waiting))
                    # time.sleep(0.05)

                # If we received a message, process it
                if message_raw:
                    print(f"Received message: {list(message_raw)}")
                    print(f"length: {len(message_raw)}")

                    if all(b == 0 for b in message_raw):
                        print("Received an invalid message (all zeros). Ignoring...")
                        continue  # Ignore all-zero messages
                    try:
                        if message_raw[0] == 0xf5:
                            # Process message 1
                            c_i, ead_1 = self.responder.process_message_1(message_raw[1:])
                            print(f"connection identifier {list(c_i)}")
                            
                            # Prepare message 2
                            c_r = [0xA] # ConnId.from_int_raw(10)
                            message_2 = self.responder.prepare_message_2(
                                # CredentialTransfer.ByReference, 
                                c_r, 
                                ead_1
                            )
                            message_2_with_true = b"\xf5" + message_2
                            
                            # Send message 2
                            print(f"Sending message 2: {list(message_2_with_true)}")
                            print(f"len of message_2: {len(list(message_2_with_true))}")
                            # Store the connection state
                            self.edhoc_connections.append((c_r, self.responder))

                            self.ser.write(message_2_with_true)
                            # self.ser.write(b'\r\n')
                            self.ser.flush()
                            # time.sleep(5)

                        else:
                            # Process message 3
                            print("message_3")
                            c_r_rcvd = [message_raw[0]] # ConnId.from_int_raw(message_raw[0])
                            print(f"c_r_rcv: {c_r_rcvd}")
                            id_cred_i, ead_3 = self.responder.parse_message_3(message_raw[1:])
                            print(f"id_cred_i: {list(id_cred_i)}")

                            # Find and remove the corresponding responder state
                            self.responder = self.take_state(c_r_rcvd)
                            
                            # Verify message 3
                            valid_cred_i = lakers.credential_check_or_fetch(id_cred_i, CRED_PSK)
                            print(f"valid_cred_i: {list(valid_cred_i)}")
                            # print(f"cred_psk: {list(CRED_PSK)}")

                            print("Verify message_3")
                            self.responder.verify_message_3(valid_cred_i)
                            print("Prepare message_4")
                            message_4, prk_out = self.responder.prepare_message_4()
                            # Sending message_4
                            print(f"Sending message 4: {list(message_4)}")
                            print(f"len of message_4: {len(list(message_4))}")
                            print(f"prk_out: {list(prk_out)}")
                            
                            self.ser.write(message_4)
                            # self.ser.write(b'\r\n')
                            self.ser.flush()
                            
                            # Derive OSCORE keys
                            oscore_secret = self.responder.edhoc_exporter(0, [], 16)
                            oscore_salt = self.responder.edhoc_exporter(1, [], 8)

                            print("EDHOC Handshake Complete!")
                            print(f"OSCORE Secret: {list(oscore_secret)}")
                            print(f"OSCORE Salt: {list(oscore_salt)}")
                            
                            break

                    except Exception as e:
                        print(f"EDHOC Error: {e}")
        
    def take_state(self, c_r_rcvd):
        print(f"edhoc_connections; {self.edhoc_connections}")
        for i, (c_r, self.responder) in enumerate(self.edhoc_connections):
            if c_r == c_r_rcvd:
                # Remove and return the responder
                return self.edhoc_connections.pop(i)[1]
        
        raise ValueError("No stored state available for that Connection Identifier")


if __name__ == "__main__":
    server = EdhocServerSerial()
    server.run()