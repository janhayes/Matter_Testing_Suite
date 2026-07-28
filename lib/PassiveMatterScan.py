#!/usr/bin/env python3

'''
This is the Fingerprinting engine that is built on Schlett et al’s research. 
Depending on the direction and udp payload size for each Matter transaction, 
it is possible to identify command clusters being used. This module also use 
Euclidean vector distance calculation with other signatures to indicate 
close collisions.
'''
import yaml
import json
import base64
import time
import math
# Used for extracting the Module's stored matter transactions
from pathlib import Path 
import os 
from datetime import datetime # We need this for our timestamp
from scapy.all import sniff, UDP, IP, IPv6, Raw, get_if_list,\
      conf,get_if_addr, AsyncSniffer

# Timestamp properties
now = datetime.now()
timestamp = now.strftime("%Y%m%d_%H%M")

# Global var to record timining difference from the first transaction and 
# subsequent transactions
deltatmstmp = 0 
logfolderpath = "log/" # Default location of stored matter transactions

currentDirectory = os.getcwd()
# Check if the module was run on its own rather than from the parent module
if currentDirectory.endswith("lib"): 
    logfolderpath = "../log/"
# Store for matter transactions, for offline analysis
jsonfile = f"{logfolderpath}/conversation__{timestamp}.jsonl" 


# List the most recent matter conversations to analyse
def list_matter_conversations(folder_path='log', conv_tracker=''):
    path = Path(folder_path)

    # Available menu actions to the user
    menu_actions = {
        '1': 'back'
    }

    # Check if the path exists and is actually a directory
    if not path.exists():
        print(f"ERROR - The folder '{folder_path}' does not exist.")
        return
    if not path.is_dir():
        print(f"ERROR - '{folder_path}' is a file, not a folder.")
        return

    # We use these values to filter our captured matter conversations
    conversation_prefix = 'conversation__'
    conversation_suffix = '.jsonl'

    print(f"INFO - Scanning for stored transaction logs in: {path.resolve()}\n")
    
    # Counter for found images
    conv_count = 0
    menu_actions_count = 2

    # Iterate through all files in the directory
    for file in path.iterdir():
        # Check if it's a file and its extension is in our image list
        if file.is_file() and conversation_prefix in file.name and \
            file.suffix.lower() in conversation_suffix:
            menu_actions[str(menu_actions_count)]=file.name
            menu_actions_count += 1
            conv_count += 1

    if conv_count == 0:
        print("ERROR - No Matter conversation files found in this folder. Try \
              recording some conversations and then try this option again")
    else:
        menu_count = 2
        while True:
            print("\nMenu:")
            print("1. Go back to main menu")
            for im in range(conv_count):
                print(f"{(im+2)}. Analyse Conversation: {menu_actions[str(im+2)]}")
            choice = get_valid_choice("Select an option: ", menu_actions.keys())
            print(f"Choice is: {choice}")
            if choice == '1': # Go back to the main menu
                break
            else:
                # Let's analyse our conversation
                print(f"menu_actions[choice]:{menu_actions[choice]}") 
                conv_log = logfolderpath+menu_actions[choice]
                conv_tracker.read_converstation(conv_log)
                break

# Carry out selected menu action, print error message for invalid selection 
def get_valid_choice(prompt, valid_choices):
    while True:
        choice = input(prompt)
        if choice in valid_choices:
            return choice
        else:
            print(f"ERROR - Invalid input ({choice}). Please choose from \
                  {', '.join(valid_choices)}.")

def display_options(fingerprint_path = "config/fingerprints.yaml"):

    tracker = MatterConversationTracker(fingerprint_path)

    while True:
        print("\nMenu:")
        print("1. Go back to main menu")
        print("2. Monitor live traffic")
        print("3. Record Matter Traffic")
        print("4. Read previously recorded Matter Traffic")
        choice = input("Select an option: ")
        if choice == '1': # Go back to the main menu
            break
        elif choice == '2': # Monitor Live Matter Traffic
            print(f"INFO - Monitoring live traffic")
            record_converstations(tracker.packet_callback)
            tracker.print_fingerprint_results(tracker.PACKET_EVENTS)
            #break
        elif choice == '3': # Record Matter Traffic to log
            print(f"INFO - Recording live traffic to a conversation file")
            record_converstations()
            tracker.print_fingerprint_results(tracker.PACKET_EVENTS)
        elif choice == '4': # Record Matter Traffic to log
            print(f"INFO - Analysing previous conversations")
            list_matter_conversations(logfolderpath,tracker)
            tracker.print_fingerprint_results(tracker.PACKET_EVENTS)
            # Clear the results afterwards,for later log analysis
            tracker.PACKET_EVENTS = {}
        else:
            #Exit anyway
            break

def packet_handler(pkt):
    global deltatmstmp # link to the global var

    # Extract data (Handling both IPv4 and IPv6 addresses for Matter)
    data = {
        "timestamp": pkt.time,
        "src_mac": pkt.src,
        "dst_mac": pkt.dst
    }

    # Calculate the timing distance between first packet and current
    if deltatmstmp != 0:
        data["delta_time"] = pkt.time - deltatmstmp
        
    else:
        data["delta_time"] = 0
        deltatmstmp = pkt.time
    
    if pkt.haslayer(IP): # Matter operational nodes like Shelly use ipv6
        data["src_ipv4"] = pkt[IP].src
        data["dst_ipv4"] = pkt[IP].dst
    
    if pkt.haslayer(IPv6):
        data["src_ipv6"] = pkt[IPv6].src
        data["dst_ipv6"] = pkt[IPv6].dst
    
    # Payload data for later analysis
    if pkt.haslayer(UDP) and pkt.haslayer(Raw):
        data["payload"] = base64.b64encode(pkt[UDP].payload.load).decode('utf-8')
        data["payload_len"] = len(pkt[UDP].payload)
    else:
        data["payload"] = None
        data["payload_len"] = 0
    
    # Write as a single line to the file
    with open(jsonfile, "a") as f:
        f.write(json.dumps(data) + "\n")

# This is the main method to start recording the Matter communications to the log file
def record_converstations(custom_function=packet_handler):
    netIntrfc = get_if_list()

    print(f"INFO - Sniffing Matter traffic and recording to {jsonfile} . \
          Press 'ctrl + C'  to stop the sniffing.")

    sniff_session = AsyncSniffer(iface=netIntrfc,filter="udp port 5540", \
                                 prn=custom_function, store=0,promisc=False)

    sniff_session.start() 

    try:
        # Main thread loop. Just watch for the 'q' key
        while True:
            time.sleep(0.1)  # Small sleep to avoid 100% CPU usage loop       
    except KeyboardInterrupt:
        print("\nCtrl+C detected.")
    
    finally:
        # This ensures that cleanup happens, whether you hit Ctrl+C, 
        # or if the script runs into an unexpected error.
        if sniff_session.running:
            print("Cleaning up Scapy background sockets...")
            try:
                sniff_session.stop()
                print("Sniffer stopped successfully.")
            except Exception as e:
                # Catching the exception here prevents it from crashing 
                # your script re-entry
                print(f"Handled a cleanup exception: {e}")

class MatterConversationTracker:

    # When a device is not recognised, create a yaml entry
    def create_yaml_entry(self, captured_input):
        data = captured_input
        
        # Extract only the fields we care about (length and direction)
        signature = [
            {"length": item['length'], "direction": item['direction']} 
            for item in data
        ]
        
        # Build the dictionary structure 
        fingerprint = {
            "name": "Unknown device",
            "packets" : len(captured_input),
            "signature": signature
        }

        # default_flow_style=False makes it look like the readable YAML 
        return yaml.dump(fingerprint, default_flow_style=False, sort_keys=False,\
                         indent=4)
    
    # Get the direction of the conversation, is it going to the device to
    # the controller
    def get_direction(self, dst_ip,src_ip):
        if dst_ip in self.CONTROLLER_IP:
            return "device_to_controller"
        elif src_ip in self.CONTROLLER_IP: 
            return "controller_to_device"
        elif dst_ip == self.DEVICE_1:
            return "dev2_to_dev1"
        elif src_ip == self.DEVICE_1:
            return "dev1_to_dev2"
        else:
            print(f"Devices are unknown, assigning temporary names")
            self.DEVICE_1 = src_ip
            self.DEVICE_2 = dst_ip
            print(f"Setting unknown controller to TRUE")
            self.CONTROLLER_UNKNOWN = True
            return "dev1_to_dev2"
            
    def load_fingerprints(self, file_path):
        if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
            with open(file_path, 'r') as file:
                data = yaml.safe_load(file)
        else:
            data = {'devices':''}
        
        # Use a tuple because lists are not hashable (cannot be dict keys)
        return data['devices']
    
    # Calculate the distance between two signatures, portion of this code was 
    # generated by Gemini.
    def calc_sig_distance(self, sig1, sig2):

        if [d['direction'] for d in sig1] != [d['direction'] for d in sig2]:
            # Return a high number if there is a directional mismatch
            return 99999
        
        vector1 = [d['length'] for d in sig1]
        vector2 = [d['length'] for d in sig2]

        distance = math.sqrt(sum((a - b) ** 2 for a, b in zip(vector1, vector2)))
        return distance
    
    # Used as part of the signature check when neither device is known to be the 
    # controller
    def flip_device_val(self,direction,reverse_val):
        if direction == "dev2_to_dev1":
            if reverse_val:
                self.TEMP_CONTROLLER_1 = 'Dev1'
                return "device_to_controller"
            else:
                self.TEMP_CONTROLLER_2 = 'Dev1'
                return "controller_to_device"
        else:
            if reverse_val:
                self.TEMP_CONTROLLER_1 = 'Dev2'
                return "controller_to_device"
            else:
                self.TEMP_CONTROLLER_2 = 'Dev2'
                return "device_to_controller"
    
    def identify_signature(self, captured_conversation, db):
        captured_signature = []
        captured_signature2 = [] # This is the secondary
        # we get the first direction and compare this later to properly map the device
        first_direction = captured_conversation[0].get('direction') 
        dst_ip = captured_conversation[0].get('dst') 
        src_ip = captured_conversation[0].get('src')

        # Check if the controller is already known
        if dst_ip in self.CONTROLLER_IP or src_ip in self.CONTROLLER_IP:
            self.CONTROLLER_UNKNOWN = False
        
        # Transform captured conversation into a signature structure
        for item in captured_conversation:
            if self.CONTROLLER_UNKNOWN == True:
                print(f"INFO - Assuming the direction of the first packet is Controller \
                      to Device, direction should be \
                      {self.flip_device_val(item["direction"],True)}")
                self.CONTROLLER_IP.append(src_ip)
                captured_signature.append({"length": item["length"], "direction": \
                                           self.flip_device_val(item["direction"],True)}) 
            else:
                captured_signature.append({"length": item["length"], "direction": \
                                           item["direction"]})
        
        self.CONTROLLER_UNKNOWN = False

        filtered_devices = [] # We filter the existing signatures by the conversation size

        # Retrieve only packets that are of a certain length
        for device_info in db:
            if device_info.get('packets') == len(captured_signature):
                filtered_devices.append(device_info)
        # Check to see if captured signature length has matched any known signatures
        if not filtered_devices: 
            # Reports signatures that contain more or less packets than expected and does 
            # not have any sigs to compare with
            self.increment_event(f'Unmatched Signature Length') 

        if self.CONTROLLER_UNKNOWN:
            print("INFO - Controller is not known, skipping signature distance calculation")
            print(f"INFO - Destination IP is {dst_ip}")
            print(f"INFO - Source IP is {src_ip}")
        else:
            print(f"INFO - Distance Calculation")

            # At this point, we have not found any matching signatures, instead we can find 
            # the closest matches
            for device_info in filtered_devices:
                dist = self.calc_sig_distance(device_info['signature'],captured_signature)
                # Only report the distances when transactions match the packet amount
                if dist != 99999: 
                    print(f"\nINFO -Fingerprint: {device_info.get('name')}")
                    print(f"INFO -Distance: {dist}\n")
                    # Record the number of close matches
                    self.increment_event('Distance of '+str(dist)+': '+device_info.get('name'))

            print(f"INFO - End of Distance Calculation")

        # Check if captured signature matches with any known signatures
        for device_info in filtered_devices:
            # Access device_info['signature'] directly
            if device_info['signature'] == captured_signature:
                
                if self.CONTROLLER_UNKNOWN:
                    self.CONTROLLER_UNKNOWN = False

                    # Retrieve the packet direction 
                    entry_direction = {device_info['signature'][0].get('direction')}

                    if "controller_to_device" in entry_direction:
                        self.CONTROLLER_IP.append(src_ip)
                    else:
                        self.CONTROLLER_IP.append(dst_ip)

                # For reporting number of detected clusters
                self.increment_event(device_info.get('name'))

                return f"\nINFO - Match Found! \nCluster: {device_info.get('name')}\n"
            # Check if the second version of the signature, matches a known signature
            # if available then we check the alternative capture sig with device/controllers 
            # role switched
            elif captured_signature2 and device_info['signature'] == captured_signature2: 
                                    
                if self.CONTROLLER_UNKNOWN:
                    self.CONTROLLER_UNKNOWN = False

                    # Retrieve the packet direction 
                    entry_direction = {device_info['signature'][0].get('direction')}

                    if entry_direction == "controller_to_device":
                        self.CONTROLLER_IP.append(src_ip)
                    else:
                        self.CONTROLLER_IP.append(dst_ip)
    
                self.increment_event(device_info.get('name'))
                return f"Info Match Found! Cluster: {device_info.get('name')}"
 
        return "\nINFO - Unknown fingerprint, add the following entry to the fingerprints.yaml:\
            \n\n"+self.create_yaml_entry(captured_signature)

    # Increment the event value from the fingerprinting method                  
    def increment_event(self, event_val):
        #print(f"---------------- incremementng event value {event_val}")
        if self.PACKET_EVENTS.get(event_val):
            self.PACKET_EVENTS[event_val]+=1
        else:
            #print(f"No existing PACKET_EVENTS entry exists")
            self.PACKET_EVENTS[event_val]=1

    #Print out the results of fingerprints based on the Conversation name
    def print_fingerprint_results(self,event_dict):
        print(f"Number of transactions analysed: {self.transaction_count}\n")
        for ev in event_dict:
            print(f"{ev} : {event_dict[ev]}")

    def __init__(self,fingerprints_loc="config/fingerprints.yaml"):
        self.CONTROLLER_UNKNOWN = True
        self.TEMP_CONTROLLER_1 = 'Dev1'
        self.TEMP_CONTROLLER_2 = 'Dev2'

        self.transaction_count = 0 # Count the number of transactions

        # Set known Ipv4 or Ipv6 here to bypass controller detection process
        self.CONTROLLER_IP = [] 

        # Key value pair, the number of events are incremement for every identified fingerprint
        self.PACKET_EVENTS = {}

        # This list acts as your array to store the conversation
        self.conversation = []
        
        # Load our Yaml file if it's available
        self.db = self.load_fingerprints(fingerprints_loc)

        self.DEVICE_1 = ''
        self.DEVICE_2 = ''

    def packet_callback(self, packet):
        # Ensure it is a UDP packet and on the relevant port
        if packet.haslayer(UDP) and (packet[UDP].dport == 5540 or packet[UDP].sport == 5540):
            
            # Determine destination IP (handling both IPv4 and IPv6)
            dst_ip = None
            if packet.haslayer(IP):
                dst_ip = packet[IP].dst
            elif packet.haslayer(IPv6):
                dst_ip = packet[IPv6].dst

            src_ip = None
            if packet.haslayer(IP):
                src_ip = packet[IP].src
            elif packet.haslayer(IPv6):
                src_ip = packet[IPv6].src
 
            udp_length = len(packet[UDP].payload) # Only care about the payload length
            
            # Append to our conversation list
            msg_id = len(self.conversation) + 1
            entry = {
                "message": msg_id,
                "length": udp_length,
                "src": src_ip,
                "dst": dst_ip,
                "direction": self.get_direction(dst_ip,src_ip)                
            }
            self.conversation.append(entry)

            if udp_length == 34: # The standaloneack termination packet
                self.process_transaction()
                # Reset for the next conversation
                self.conversation = []

    def process_transaction(self):
        result = self.identify_signature(self.conversation, self.db)
        print(f"{result}") 

    # Offline analysis
    def read_converstation(self, filepath):
        self.transaction_count = 0 # reset the count for every new file read
        with open(filepath, 'r') as f:
            for line in f:
                packet = json.loads(line)

                msg_id = len(self.conversation) + 1
                entry = {
                    "length": packet['payload_len']           
                }

                if 'src_ipv4' in packet:
                    entry["dst"] = packet['dst_ipv4']
                elif 'src_ipv6' in packet:
                    entry["dst"] = packet['dst_ipv6']

                if 'src_ipv4' in packet:
                    entry["src"] = packet['src_ipv4']
                elif 'src_ipv6' in packet:
                    entry["src"] = packet['src_ipv6']
                
                entry["direction"] = self.get_direction(entry["dst"],entry["src"])

                self.conversation.append(entry)
                
                if packet['payload_len'] == 34:
                    self.transaction_count += 1

                    if 'src_ipv4' in packet:
                        print(f"INFO - Conversation complete. Total messages: \
                              {len(self.conversation)}")
                        self.process_transaction()
                        self.conversation = []
                    elif 'src_ipv6' in packet:
                        print(f"INFO - Conversation complete. Total messages: \
                              {len(self.conversation)}")
                        self.process_transaction()
                        self.conversation = []
            
if __name__ == "__main__":
    fingerprint_path = "../config/fingerprints.yaml"
    display_options(fingerprint_path)