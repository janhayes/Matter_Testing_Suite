#!/usr/bin/env python3
# Companion module for BruteForceAttackWithDiscriminator.py

import asyncio
import time
from bleak import BleakScanner
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

# Official designated 16-bit Service UUID for Matter broadcasts
MATTER_UUID = "0000fff6-0000-1000-8000-00805f9b34fb"
start_time = 0
duration = 0

stop_event = asyncio.Event() # Stops the scan

'''
Matter BLE Advertisement specifications that is good to know :
Byte 0: Flags (usually 0x00 for standard commissioning)
Bytes 1-2: 12-bit Discriminator (Little Endian)

The following bytes are optional but have been seen in Shelly and IKEA devices
Bytes 3-4: 16-bit Vendor ID (Little Endian)
Bytes 5-6: 16-bit Product ID (Little Endian)
'''

def detection_callback(device: BLEDevice, advertisement_data: AdvertisementData):
    # Check if the Matter UUID is present in the service data dictionary
    if MATTER_UUID in advertisement_data.service_data:
        raw_payload = advertisement_data.service_data[MATTER_UUID]

        # Get the rssi val
        rssi = advertisement_data.rssi

        # Expecting at least 3 bytes to contain the discriminator value
        if len(raw_payload) >= 3:
            # Extract and piece together the 12-bit Discriminator that are stored 
            # in the Little Endian byte order
            discriminator = ((raw_payload[2] & 0x0F) << 8) | raw_payload[1]

            print(f"INFO - Matter Device Discovered:")
            print(f"  MAC Address:   {device.address}")

            # Show both the parsed version of the discriminator and the original 
            # hex version
            print(f"  Discriminator: {discriminator} (Hex: 0x{discriminator:03X})") 

            # Try extract Vendor and Product ID if they are present in the packet, 
            # confirms data leakage. Gemini AI was used to help provide sample 
            # code for payload extraction.
            if len(raw_payload) >= 7:
                vid = (raw_payload[4] << 8) | raw_payload[3]
                pid = (raw_payload[6] << 8) | raw_payload[5]
                print(f"  Vendor ID:     {vid} (Hex: 0x{vid:04X})")
                print(f"  Product ID:    {pid} (Hex: 0x{pid:04X})")
            print(f"  RSSI Value:    {rssi}")

            stop_event.set() # Stop the while loop that called this function

async def start_ble_scan():
    print("INFO - Starting background scanning for Matter BLE devices... "
    "(Press Ctrl+C to stop)")

    # track the start time
    start_time = time.time()

    # Initialize the scanner, then use callback function to extract BLE data
    scanner = BleakScanner(detection_callback)

    try:
        async with scanner:
            # Keep scanning until interuption 
            while not stop_event.is_set(): 
                await asyncio.sleep(1.0)
            
            duration = time.time() - start_time
            print(f"INFO -  Since BLE Scan, duration is {duration:.2f}s")
    except Exception as e:
        print(f"ERROR - Unable to load the DBUS, unable to sniff BLE packets" 
              "with the current hardware setup. exception raised: \n{e}")

def initiate_scan():
    try:
        asyncio.run(start_ble_scan())
    except KeyboardInterrupt:
        print("\nCtrl+C interupt. Scan stopped.")

# Allow the script to be run on its own
if __name__ == '__main__':
    initiate_scan()