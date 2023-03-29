# WiFi Devices
Webapp written in Flask, used to scan the local network to show who is online.

### Work in progress

This code uses the nmap library to scan all hosts on the 192.168.1.0/24 network and print out the IP addresses of all devices that are currently online.

To create a web application in Flask that shows the online devices, you can build a simple HTML page that displays the list of online devices using the Flask framework.

Retrieving device names requires a different approach than scanning for IP addresses, as the device name is typically not included in the scan results.

One possible approach is to use the socket library in Python to perform a reverse DNS lookup on each IP address in the scan results.
