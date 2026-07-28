#!/usr/bin/env python3

'''
This module provides CommissionDevice.py the crucial step of decoding Matter QR 
images to Base-38 encoded string. There may be some difficult getting the cv2 
library working or installed, installing zbarimg then modifying this code to run 
it as a subprocess and reporting the stdout might be good alternative. 
'''

from pathlib import Path
# In Ubuntu run "sudo apt install python3-opencv" or pip install opencv-python
import cv2 

try:
    # When imported as part of the lib package
    from . import CommissionDevice as commissiondevice
    from . import SetupPayload as setuppayload # Use the Matter SDK supplied script
except ImportError:
    # When run directly
    import CommissionDevice as commissiondevice
    import SetupPayload as setuppayload # Use the Matter SDK supplied script

import subprocess
import yaml
import re
import os
from datetime import datetime

# List all the available images in the folder labelled 'qr'
def list_image_files(folder_path='qr'):
    # Convert string path to a Path object
    path = Path(folder_path)

    # Available menu actions to the user
    qr_menu_actions = {
        '1': 'back'
    }

    # What to do with recently scanned device
    save_menu_actions = {
        '1': 'Commission Device',
        '2': 'Saved to Devices list',
        '3': 'None, just exit to main menu'
    }

    # Setting the minimum default number of actions to 2
    qr_menu_actions_count = 2
    
    # Check if the path exists and is actually a directory
    if not path.exists():
        # Try the alternative path 
        folder_path = '../qr' 
        path = Path(folder_path)
        if not path.exists():
            print(f"Error: The folder '{folder_path}' does not exist.")
            return
    if not path.is_dir():
        print(f"Error: '{folder_path}' is a file, not a folder.")
        return

    # Define the image extensions we want to look for (case-insensitive)
    img_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.bmp'}
    
    print(f"Scanning for images in: {path.resolve()}\n")
    
    # Counter for found images
    image_count = 0
    
    # Iterate through all files in the directory
    for file in path.iterdir():
        # Check if it's a file and its extension is in our image list
        if file.is_file() and file.suffix.lower() in img_extensions:
            print(f"[IMAGE] {file.name}")
            qr_menu_actions[str(qr_menu_actions_count)]=file.name
            qr_menu_actions_count += 1
            image_count += 1
            
    if image_count == 0:
        print("INFO - No image files found in this folder. Make sure these\
               are either jpg, png or bmp files")
    else:
        print(f"\nTotal QR images found: {image_count}")
        print(f"\nqr_menu_actions.keys(): {qr_menu_actions.keys()} and values:\
               {qr_menu_actions.values()}")
        menu_count = 2
        while True:
            print("\nMenu:")
            print("1. Go back to main menu")
            for im in range(image_count):
                print(f"{(im+2)}. Scan and add QR image: \
                      {qr_menu_actions[str(im+2)]}")
            choice = get_valid_choice("Select an option: ", \
                                      qr_menu_actions.keys())
            print(f"Choice is: {choice}")
            if choice == '1': # Go back to the main menu
                break
            else:
                print(f"Need to perform our action here on the file: \
                      {qr_menu_actions[choice]}")
        
                print(f"Full path is {str(path)+"/"+qr_menu_actions[choice]}")

                qr_img = cv2.imread(folder_path+"/"+qr_menu_actions[choice])

                detector = cv2.QRCodeDetector()

                 # Returns a tuple
                data, points, _ = detector.detectAndDecode(qr_img)

                if data:
                    print(data) # Print out Matter Commissioning QR code

                    # New method
                    matter_device = setuppayload.SetupPayload.parse(data)
                    print(matter_device.pincode)
                    print(matter_device.long_discriminator)
                    print(matter_device.vid)
                    print(matter_device.pid)
                    print(matter_device.flow)
                    print(matter_device.__dict__)

                if isinstance(matter_device, object):
                    while True:
                        print("Options:")
                        print("1 - Set up this device for commissioning")
                        print("2 - Store this device to a devices list")
                        print("3 - Quit to main menu")
                        choice = get_valid_choice("Select an option: ", \
                                                  save_menu_actions.keys())
                        if choice == '1':
                            print("INFO - Commission this device")
                            now = datetime.now()
                            timestamp = now.strftime("%Y%m%d_%H%M")

                            # Assign a unique name and timestamp for debug purpose
                            device_name = "dev_"+timestamp 
                                                
                            commissiondevice.commission_lighting_app(device_name,\
                                matter_device.vid,matter_device.pid,
                                matter_device.pincode,
                                matter_device.long_discriminator)
                            break
                        elif choice == '2': # Go back to the main menu
                            print(f"matter_device values:\n{matter_device}")
                            print(f"Creating a yaml device entry:\n\
                                  {append_to_yaml_file('config/devices.yaml',\
                                                       matter_device.__dict__)}")                            
                            break
                        else:
                            print("Not adding to yaml, going back to main menu")
                            break

                break

    
# With a given Matter QR code, use chip-tools to decipher it
def process_matter_qr_image(qr_code):
    print(f"INFO - Running the function process_matter_qr_image with the\
           qr code: {qr_code}") 

    cmd = [
        './bin/chip-tool',
        'payload',
        'parse-setup-payload',
        qr_code
    ]

    save_menu_actions = {
        'y': 'yes',
        'n': 'no'
    }
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout= 5 # Should take less than 5 seconds
        )

        print(f"Our result is {result}")

        # Let's print our output
        if result.returncode == 0:
            print(f"Our chip-tool output is:\n\n{result.stdout}")

            # Our regular expression pattern to extract key values. 
            # Had a bit of help from Gemini here to generated the REs
            key_name_pattern = r"\[SPL\]\s*(.*?)\s*:\s+"
            key_value_pattern = r"\[SPL\].*?:\s+([a-zA-Z0-9]+)" # 

            device_data = {} # Our device dictionary

            # Going add a timestamp to our device
            now = datetime.now()
            timestamp = now.strftime("%Y%m%d_%H%M")

            device_data["name"] = "dev_"+timestamp
            device_data["src"] = "qr"

            for line in result.stdout.splitlines():
                print(f"The line is: {line}")

                match_value = re.search(key_value_pattern, line)

                match_name = re.search(key_name_pattern, line)

                if match_value:
                    value = match_value.group(1)
                    print(f"Extracted value: '{value}'")

                    keyname = match_name.group(1)
                    print(f"Extracted keyname: '{keyname}'")

                    # Exclude this additional line
                    if 'base38Representation' not in keyname: 
                        device_data[keyname.lower()]=value

            print(device_data)
            return device_data
        else: 
            return "nothing"

    except subprocess.TimeoutExpired:
        print("INFO - subprocess.TimeoutExpired")
        return "timeout"
    except FileNotFoundError:
        print("ERROR - FileNotFoundError")
        return "fatal"
    except Exception as e:
        print(f"FAIL - (Script Exception: {e})")
        return "fatal"

# Output the result of the QR code to a yaml file
def append_to_yaml_file(file_path, data):

    data['flow'] = "0" # Set the flow to 0 to avoid getting a formatting issue 
    data['name'] = "dev_pid_"+str(data.get('pid')) 

    device_path = file_path
    print(f"device path is {device_path}")
    #yaml_string = create_yaml_entry_for_device(data)
    currentDirectory = os.getcwd()
    if currentDirectory.endswith("lib"):
        device_path = "../"+device_path
        print(f"device path updated to {device_path}")

    if os.path.exists(device_path) and os.path.getsize(device_path) > 0:
        with open(device_path, "r", encoding="utf-8") as f:
            existing_data = yaml.safe_load(f) or {}
    else:
        existing_data = {"devices": []}

    #Append the new farm dictionary directly into the existing list
    if "devices" not in existing_data or not isinstance(existing_data["devices"],\
                                                         list):
        existing_data["devices"] = []

    # Reverse the entry to ensure that name becomes the first entry
    reversed_data = dict(reversed(data.items()))
    existing_data["devices"].append(reversed_data)

    #Overwrite the file with the newly updated, perfectly formatted dictionary
    with open(device_path, "w", encoding="utf-8") as f:
        yaml.dump(existing_data, f, default_flow_style=False, sort_keys=False,\
                   indent=4)

def get_valid_choice(prompt, valid_choices):
    while True:
        choice = input(prompt)
        if choice in valid_choices:
            return choice
        else:
            print(f"Invalid input. Please choose from \
                  {', '.join(valid_choices)}.")