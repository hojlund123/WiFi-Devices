from flask import Flask, render_template
import nmap

app = Flask(__name__)

@app.route('/')
def index():
    nm = nmap.PortScanner()
    nm.scan(hosts='192.168.1.0/24', arguments='-sP')

    devices = []
    for host in nm.all_hosts():
        if nm[host]['status']['state'] == 'up':
            devices.append(host)

    return render_template('devices.html', devices=devices)

if __name__ == '__main__':
    app.run()
