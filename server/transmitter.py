import numpy as np
# import matplotlib.pyplot as plt
from scipy.io import wavfile
import adi # ADALM-PLUTO SDR interface library
# import scipy.signal as signal

print("Transmitter running")

file_name = 'handel.wav'
samplerate_data, data = wavfile.read(file_name)

# Parameters
max_value = np.max(np.abs(data)) # <= 32767 (int16)
sample_rate = 1e6  # Sample rate (1 MHz)
center_freq = 915e6  # Center frequency (915 MHz)
num_symbols = len(data) # Number of symbols
tx_gain = -10 # Range of TX gains to test

tx_data = data / max_value
tx_data *= 2 ** 14  # Scale samples for Pluto SDR

# Initialize the ADALM-PLUTO SDR

serial = '104473b04a06000ffbff3900f5de83267e'

import subprocess
import re

def get_usb_port_from_serial(serial):
    try:
        # Run iio_info -s and get the output
        output = subprocess.check_output(["iio_info", "-s"]).decode("utf-8")
    except Exception as e:
        print(f"Error running iio_info: {e}")
        return None

    # Regex to find the USB port associated with the given serial number
    pattern = re.compile(rf"\d+:.*serial={serial}\s+\[usb:(\S+)\]")

    for line in output.splitlines():
        match = pattern.search(line)
        if match:
            return match.group(1)  # Return the USB port

    print(f"No device found with serial {serial}")
    return None

usb = get_usb_port_from_serial(serial)

sdr = adi.Pluto(f"usb:{usb}")
sdr.sample_rate = int(sample_rate)

# # Configure the transmitter
sdr.tx_rf_bandwidth = int(sample_rate)  # Set RF bandwidth equal to sample rate
sdr.tx_lo = int(center_freq)            # Set the center frequency for transmission
sdr.tx_hardwaregain_chan0 = tx_gain    # Set the transmission gain
sdr.tx_destroy_buffer()

# Start transmission
sdr.tx_cyclic_buffer = True  # Enable cyclic buffer mode to continuously transmit
sdr.tx(tx_data)              # Transmit the generated samples

while True:
    pass # So it never terminates.

# Stop transmission
# sdr.tx_destroy_buffer()  # Destroy the buffer to stop transmission