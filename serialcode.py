import serial
import re


# Configure the serial port
ser = serial.Serial(
    port='COM22',        # Replace with your serial port, e.g., 'COM3', '/dev/ttyUSB0'
    baudrate=9600,      # Set the baud rate (must match the device's setting)
    timeout=1           # Timeout in seconds
)

print("Serial connection established. Waiting for data...")

try:
    while True:
        # Read a line from the serial port (ends with '\n')
        if ser.in_waiting > 0:  # Check if data is available to read
            serial_data = ser.readline().decode('utf-8').strip()
            input_string = serial_data#"apple,banana,orange,grape"
            print(input_string)
            try:
                split_list = input_string.split(',')
                file_name = "energydata.txt"
                with open(file_name, "w") as file:
                    file.write(input_string)
                    print(f"Text has been written to {file_name}")
                
            except:
                print("Waiting for Data")

                
except KeyboardInterrupt:
    print("\nExiting...")
finally:
    ser.close()  # Close the serial port
