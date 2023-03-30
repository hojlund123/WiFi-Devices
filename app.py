from flask import Flask, render_template
from scapy.all import ARP, Ether, srp
from mac_vendor_lookup import MacLookup
import socket

app = Flask(__name__)

@app.route("/")
def index():
    # Define the network range to scan
    network = "192.168.1.0/24"

    # Create an ARP request packet
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network)

    # Send the ARP request and wait for the response
    responses, _ = srp(arp_request, timeout=1, verbose=False)

    # Parse the responses and extract the device information
    devices = []
    for response in responses:
        ip_address = response[1].psrc
        hostname = socket.getfqdn(ip_address)
        mac_address = response[1].hwsrc
        vendor_info = MacLookup().lookup(mac_address)
        os_info = get_os_info(ip_address)
        devices.append((ip_address, hostname, mac_address, vendor_info["name"], os_info))

    return render_template("index.html", devices=devices)

def get_os_info(ip_address):
    # TODO: Implement this function to obtain the OS information for a device
    # You can use packet sniffing tools like Wireshark to capture network traffic
    # and analyze it to obtain this information, or use other techniques like
    # fingerprinting or active scanning.
    return "Unknown"

if __name__ == "__main__":
    app.run(debug=True)
