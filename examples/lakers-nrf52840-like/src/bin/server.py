import serial
import serial.tools.list_ports
import time

# # Find and print available ports
# ports = list(serial.tools.list_ports.comports())
# for port, desc, hwid in ports:
#     print(f"Available Port: {port}, Description: {desc}")

# Adjust the port
PORT = '/dev/ttyACM0'  # Linux
BAUD_RATE = 9600

ser = serial.Serial(
    PORT,
    BAUD_RATE,
    timeout=1,
    bytesize=serial.EIGHTBITS,
    parity=serial.PARITY_NONE,
    stopbits=serial.STOPBITS_ONE
)

print(f"Listening on {PORT} at {BAUD_RATE} baud...")
counter = 0

try:
    while True:
        if ser.in_waiting:
            counter += 1
            print(f"---------Iteration {counter}-------------")
            client_msg = ser.readline().decode('utf-8', errors='ignore').strip()
            print(f"Received message_1: {client_msg}")
            
            time.sleep(0.1)
            
            # Prepare response
            response = f"Server received: {client_msg}\r"
            
            # Send response back to client
            print(f"Sending response: {response.strip()}")
            ser.write(response.encode('utf-8'))
            ser.flush()
            time.sleep(1)

except KeyboardInterrupt:
    print("Stopping server.")
finally:
    ser.close()