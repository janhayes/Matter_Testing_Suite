#!/usr/bin/env python3
'''
Replicates the Avahi Browser command for discovering Matter devices already 
commissioned: avahi-browse -d local -r _matter._tcp/_matter._udp/_matterc._udp
Modified from a code sample provided by Zeroconf's Github page at 
https://github.com/python-zeroconf/python-zeroconf
'''
 
import time
from zeroconf import ServiceBrowser,ServiceListener, Zeroconf

class MyListener(ServiceListener):
    def __init__(self):
        # Timer
        self.start_time = time.time()
        self.matter_nodes = {}

    # Handle service removal
    def remove_service(self, zeroconf, type, name):
        print(f"INFO - Service {name} removed")

    # Handle service discovery
    def add_service(self, zeroconf, type, name):
         # Sends out a Query Multicast packet requesting devices to respond
        info = zeroconf.get_service_info(type, name)
        # Check to make sure that the entry is only added the first time
        if info and name not in self.matter_nodes: 
            print("\n")
            self.matter_nodes[name] = {}
            properties = getattr(info, "properties")
            if properties:
                vp_val=properties.get(b"VP") # Retrieve the byte value
                t_val = properties.get(b"T") # Retrieve the byte value
                if type == "_matterd._udp.local.":
                    print("INFO - Commissioner Device Discovered")
                    self.matter_nodes[name]["Type"] = "Comissioner"
                elif type == "_matterc._udp.local.":
                    print("INFO - Commissioning Device Discovered")
                    self.matter_nodes[name]["Type"] = "Node"
                elif t_val and t_val.decode("utf-8") == "6" \
                    and type == "_matter._tcp.local.":
                    # T value of 6 represents both a TCP client and a TCP 
                    # server acccording to the Matter Spec
                    print("INFO - Matter Controller Discovered!") 
                    self.matter_nodes[name]["Type"] = "Controller"
                elif type == "_matter._tcp.local." and info.port != 5540:
                    print("INFO - Likely Matter Controller Discovered")
                    self.matter_nodes[name]["Type"] = "Controller"
                else:
                    print("INFO - Matter Node Discovered")
                    self.matter_nodes[name]["Type"] = "Node"

                if properties.get(b"VP"):
                    vp_val = properties.get(b"VP").decode("utf-8")
                    vid, pid = map(int, vp_val.split("+"))
                    # Following IDs can be looked up at
                    # https://webui.dcl.csa-iot.org/models
                    print(f"Vendor ID : {vid}")
                    print(f"Product ID: {pid}")
                    self.matter_nodes[name]["Vendor ID"] = vid
                    self.matter_nodes[name]["Product ID"] = pid

                if properties.get(b"D"):
                    discriminator_val = properties.get(b"D").decode("utf-8")
                    print(f"Discriminator: {discriminator_val}") 
                    self.matter_nodes[name]["Discriminator"] = discriminator_val

            print(f"INFO - Matter Node Designation: {name}")
            print(f"INFO - Device Address: {info.parsed_addresses()}")
            self.matter_nodes[name]["Address"] = info.parsed_addresses()
            print(f"INFO - Port #: {info.port}")
            self.matter_nodes[name]["Port"] = info.port
            duration = time.time() - self.start_time
            self.matter_nodes[name]["Duration"] = duration
            print(f"INFO - Discovered since scan in seconds: {duration:.2f}s")


    def update_service(self, zeroconf, type, name): # Handles service change
        print(f"INFO - Service {name} updated")

# Output Matter devices discovered
def print_devices(obj):
    for node, attrs in obj.items():
        print(f"\nMatter Node Designation: {node}")
        for key, value in attrs.items():
            if key == "Duration":
                print(f"  {key}: {value:.2f}s")
            else:
                print(f"  {key}: {value}")

# MDNS Scanner
def start_scan():
    zeroconf = Zeroconf()
    listener = MyListener()
    matter_browser = ServiceBrowser(zeroconf, [
            "_matter._tcp.local.", 
            "_matter._udp.local.",
            "_matterc._udp.local.", # commissionable devices over udp
            "_matterd._udp.local.", # commissioner devices over udp
        ], listener) 
    try:
        print("INFO - Scanning for Matter devices on the local network " \
        "that are broadcasting MDNS. To stop the scan, use Ctrl+C.")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        print(f"\nINFO - Keyboard Interupt Detected printing Discovered " \
               "machine values")
        print_devices(listener.matter_nodes)
        zeroconf.close()

if __name__ == "__main__":
    start_scan()