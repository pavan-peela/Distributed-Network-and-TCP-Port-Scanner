import json
import socketio
from scapy.all import *

#########################################################
# Define socket client, define json objects
# Declare global session_id
#########################################################

sio = socketio.Client()
session_id = ""


class IPScan(object):
    def __init__(self, msg):
        self.__dict__ = json.loads(msg)


class PortScan(object):
    def __init__(self, msg):
        self.__dict__ = json.loads(msg)

#########################################################
# Catch exception on server_disconnected
#########################################################


class ServerDisconnectedException(Exception):
    # Raised when server is disconnected
    pass

#########################################################
# Utility methods using scapy to implement scan functionality
# check_host() : Ping the IP used to check if IP is alive
# grab_banner() : Used to perform tcp_connect() and grab HTTP banner
# normal_port_scan() : Method implementing normal port scan functionality
# stealth_scan() : Method implementing TCP SYN scan functionality
# fin_scan() : Method implementing TCP FIN scan functionality
# __port_scan() : Utility method used to check type of scan
#########################################################


def check_host(ip):  # Function to check if target is up
    # conf.verb = 0 # Hide output
    ping = sr1(IP(dst=ip)/ICMP(), timeout=2)  # Ping the target
    if str(type(ping)) == "<class 'NoneType'>":  # print "\n[*] Target is Up, Beginning Scan..."
        return False
    else:
        return True


def grab_banner(ip, port):
    try:
        socket.setdefaulttimeout(2)
        s = socket.socket()
        result = s.connect((str(ip), port))
        msg = "GET / HTTP/1.0\r\nHost: "+str(ip)+"\r\n\r\n"
        ans = s.send(msg.encode('utf-8'))
        ans = s.recv(1024)
        ans = ans.decode('utf-8')
        print(ans)
        s.close()
        return ans
    except Exception as e:
        print('Exception:', e)
        return "Open"


def normal_port_scan(ip, port):
    print("Normal PortScan Requested")
    src_port = RandShort()
    res = sr1(IP(dst=ip) / TCP(sport=src_port, dport=port, flags="S"), timeout=2)
    if str(type(res)) == "<class 'NoneType'>":
        return "Closed"
    elif res.haslayer(TCP):
        if res.getlayer(TCP).flags == 0x12:
            return grab_banner(ip, port)
        elif res.getlayer(TCP).flags == 0x14:
            return "Closed"
    return "Closed"


def stealth_scan(ip, port):
    print("Stealth PortScan Requested")
    src_port = RandShort()
    res = sr1(IP(dst=ip) / TCP(sport=src_port, dport=port, flags="S"), timeout=2)
    if str(type(res)) == "<class 'NoneType'>":
        return "Filtered"
    elif res.haslayer(TCP):
        if res.getlayer(TCP).flags == 0x12:
            send_rst = sr(IP(dst=ip) / TCP(sport=src_port, dport=port, flags="R"), timeout=2)
            return "Open"
        elif res.getlayer(TCP).flags == 0x14:
            return "Closed"
    return "Closed"


def fin_scan(ip, port):
    print("FIN PortScan Requested")
    res = sr1(IP(dst=ip) / TCP(dport=port, flags="F"), timeout=2)
    if str(type(res)) == "<class 'NoneType'>":
        return "Open | Filtered"
    elif res.haslayer(TCP):
        if res.getlayer(TCP).flags == 0x14:
            return "Closed"
    return "Closed"


def __port_scan(ip, port, type):
    if type == '1':
        return normal_port_scan(ip, port)
    elif type == '2':
        return stealth_scan(ip, port)
    elif type == '3':
        return fin_scan(ip, port)

#########################################################
# Socket io events - registered(), disconnect()
# Requests from server events - ip_scan(), port_scan()
#########################################################


@sio.on('registered')
def on_registered(sid):
    global session_id
    session_id = sid
    print('Connected - Session id:', session_id)


@sio.on('disconnect')
def on_disconnect():
    raise ServerDisconnectedException


@sio.on('IP_scan')
def ip_scan(message):
    print('IP Scan requested!')
    ipscan = IPScan(message)
    res = {}
    for ip in ipscan.ips:
        if check_host(ip):
            res[ip] = 'Alive'
        else:
            res[ip] = 'Not Alive'
    print(res)
    sio.emit('scanres', res)


@sio.on('Port_Scan')
def port_scan(message):
    print('Port Scan requested!')
    portscan = PortScan(message)
    res = {}
    for i in portscan.port:
        val = __port_scan(portscan.ip, i, portscan.mode)
        res[i] = val
    sio.emit('scanres', res)

#########################################################
# Take server ip and port input from cmd line
# Connect to server and catch exceptions
#########################################################


if len(sys.argv) > 2:
    server_ip = sys.argv[1]
    server_port = sys.argv[2]
else:
    print('Invalid arguments. Usage:\n# sudo python scan_node.py [server_ip] [server_port]')
    sys.exit()

sio.connect('http://' + server_ip + ':' + server_port)

try:
    sio.wait()
except KeyboardInterrupt:
    pass
except ServerDisconnectedException:
    print('Server disconnected')

sio.disconnect()
