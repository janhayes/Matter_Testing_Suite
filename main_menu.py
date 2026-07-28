#!/usr/bin/env python3

# Combines all the module into one package

import lib.BruteForceAttackWithDiscriminator as bruteforcematter # Bruteforce script that builds on Duttagupta et al's script 
import lib.QRDecoder as qrdecoder # Simple QR decoder script that utilizes opencv library to extract the unique MT commissioning byte value, and chip-tools to parse the commissioning data
import lib.CommissionDevice as commissiondevice # The main script that interacts with an existing SDK sample, chip-lighting-app, to arm a device for the commissioning attack
import lib.ActiveMatterScan as ActiveScanner # Uses MDNS service discovery to identify Matter related devices in the network
import lib.PassiveMatterScan as PassiveScanner # Fingerprinting script used to identify Matter command clusters 

import yaml
import sys
import os
from pathlib import Path
import subprocess
import re

def exit_program():
    print("Exiting program.")
    exit()

# Loads the Bruteforce / Discriminator script  
def bruteforce_device():
    print("Loading Bruteforce Module")
    bruteforcematter.display_options()

# Directly commission or save a device from a QR code
def add_device_qr():
    print("Adding device via QR code")
    qrdecoder.list_image_files('qr')

# Prepares a new virtual matter device for the onboarding process
def commission_new_device():
    print("commission new device")
    commissiondevice.display_options()

# Runs the mdns discovery script
def active_scan():
    print("run active scan")
    ActiveScanner.start_scan()

# Runs the fingerprinting script
def passive_scan():
    print("run passive scan")
    PassiveScanner.display_options()

# This checks the available actions that can be selected from the menu
def get_valid_choice(prompt, valid_choices):
    while True:
        choice = input(prompt)
        if choice in valid_choices:
            return choice
        else:
            print(f"Invalid input. Please choose from {', '.join(valid_choices)}.")

# This menu code is based on the sample provided from https://tabbydata.com/how-to-make-a-menu-in-python/
def main():
    items = []

    menu_actions = {
        '1': bruteforce_device,
        '2': commission_new_device,
        '3': active_scan,
        '4': passive_scan,
        '5': exit_program
    }

    while True:
        print("\nMenu:")
        print("1. Bruteforce Matter Device Commissioning")
        print("2. Commission Virtual Device")
        print("3. Active Network Scan using mDNS")
        print("4. Passive Network Scan (requires sudo)")
        print("5. Exit")

        choice = get_valid_choice("Select an option: ", menu_actions.keys())
        menu_actions[choice]()
   
if __name__ == "__main__":
    main()
