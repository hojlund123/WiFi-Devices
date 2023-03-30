from flask import Flask, render_template
from scapy.all import ARP, Ether, srp
import socket
import os
from mac_vendor_lookup import MacLookup
from pcapfile import savefile

app = Flask(__name__)

@app.route("/")
def index():
    # Define the network range to scan
    network = "192.168.1.0/24"

    # Create an ARP request packet
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network)

    # Send the ARP request and wait for the response
    responses, _ = srp(arp_request, timeout=1, verbose=False)

    # Update local file for MacLookup vendors
    MacLookup().update_vendors()

    # Parse the responses and extract the MAC addresses and IP addresses
    devices = []
    for response in responses:
        mac_address = response[1].hwsrc
        ip_address = response[1].psrc
        hostname = socket.getfqdn(ip_address) # Get the hostname using DNS

        # Create a MacLookup object
        mac_lookup = MacLookup()

        # Look up the vendor information for a MAC address
        vendor_info = mac_lookup.lookup(mac_address)

        # OS Info
        os_info = get_os_info(ip_address)

        # Append all to devices
        devices.append((ip_address, hostname, mac_address, vendor_info, os_info))
        print(ip_address, hostname, mac_address, vendor_info, os_info)
    return render_template("index.html", devices=devices)

def get_os_info(ip_address):
    # Define the network interface to capture packets on
    iface = "wlp1s0"

    # Define the number of packets to capture
    num_packets = 2

    # Define the filter expression to capture packets for the specified IP address
    filter_expr = f"host {ip_address}"

    # Capture the packets and save them to a temporary file
    capture_file = f"/tmp/capture_{ip_address}.pcap"
    os.system(f"tcpdump -i {iface} -c {num_packets} -w {capture_file} {filter_expr}")

    # Read the captured packets from the file
    with open(capture_file, "rb") as f:
        packets = savefile.load_savefile(f).packets

    # Extract the operating system information from the packets
    os_info = set()
    for packet in packets:
        ether = Ether(packet.raw())
        if "IP" in ether:
            ip = ether["IP"]
            if "TCP" in ip:
                tcp = ip["TCP"]
                os_info.add((tcp["window"], tcp["flags"], tcp["options"]))

    # Convert the operating system information to a string representation
    os_str = ""
    for os_entry in os_info:
        os_str += f"Window size: {os_entry[0]}, Flags: {os_entry[1]}, Options: {os_entry[2]}\n"

    # Remove the temporary capture file
    os.system(f"rm {capture_file}")

    return os_str

if __name__ == "__main__":
    app.run(debug=True)
