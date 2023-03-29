from flask import Flask, render_template
import nmap
import socket

app = Flask(__name__)

@app.route('/')
def index():
    nm = nmap.PortScanner()
    nm.scan(hosts='192.168.1.0/24', arguments='-sP')

    devices = []
    for host in nm.all_hosts():
        if nm[host]['status']['state'] == 'up':
            try:
                hostname = socket.gethostbyaddr(host)[0]
            except socket.herror:
                hostname = 'unknown'
            devices.append((host, hostname))

    return render_template('devices.html', devices=devices)

if __name__ == '__main__':
    app.run()
