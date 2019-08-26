from html import escape
from flask import Flask, render_template, request
import json
import ipaddress
from scapy.all import *
import pandas as pd
from gevent import monkey
monkey.patch_all()
from flask_socketio import SocketIO

#########################################################
# Define App, init socket_io, define json objects
# Declare global scanning node, request and response dicts
#########################################################

app = Flask(__name__)
sio = SocketIO(app)

scanning_nodes_dict = dict()
scanning_req = dict()
scanning_res = dict()


class IPScan(object):
    def __init__(self, ips):
        self.ips = ips


class PortScan(object):
    def __init__(self, msg):
        self.__dict__ = json.loads(msg)

#########################################################
# Define socket_io events
# on_connect() : Add client to global scanning_node_dict
# on_disconnect() : Remove client from global dict
# on_scan_result() : Take result from socket_io message
#                    and store in global scan_res dict
#########################################################


@sio.on('connect')
def on_connect():
    print('Client connected:', request.sid)
    sio.emit('registered', request.sid, room=request.sid)
    scanning_nodes_dict[request.sid] = 0


@sio.on('disconnect')
def on_disconnect():
    print('Client disconnected:', request.sid)
    app.logger.info('Client disconnected : %s', request.sid)
    del scanning_nodes_dict[request.sid]


@sio.on('scanres')
def on_scan_result(message):
    global scanning_res, scanning_nodes_dict
    scanning_res[request.sid] = message
    scanning_nodes_dict[request.sid] = 0
    print('Scan result received from scanning_node')
    print(scanning_res[request.sid])

#########################################################
# Utility methods
# append_to_csv() : Append scan results to csv for past_scans
# reset_dicts() : Reset global request/response dicts
#                 at the end of scan
# ip_scan() : Utility method to send scan request to client
#             specified by client id
#########################################################


def append_to_csv(mode, obj, msg):
    new_msg = []
    if mode == 1 :
        new_msg.append('IPAliveScan')
        new_msg.append(obj)
        new_msg.append(msg['scan_status'])
        new_msg.append(msg['scan_res'])
    elif mode == 2:
        new_msg.append('IPSubnetAliveScan')
        new_msg.append(obj)
        new_msg.append(msg['scan_status'])
        new_msg.append(msg['scan_res'])
    elif mode == 3:
        if obj['type'] == '1':
            new_msg.append('NormalPortScan')
        elif obj['type'] == '2':
            new_msg.append('StealthPortScan')
        elif obj['type'] == '3':
            new_msg.append('FinPortScan')
        new_msg.append(obj['ip'] +'::' + obj['portRange'])
        new_msg.append(msg['scan_status'])
        new_msg.append(msg['scan_res'])
    df = pd.read_csv('past_scans.csv', header=0)
    df.loc[-1] = new_msg
    df.index = df.index+1
    df.sort_index(inplace=True)
    if df.shape[0] == 15:
        df=df[:-1]
    df.to_csv('past_scans.csv', index=False)


def get_past_scans():
    old_width = pd.get_option('display.max_colwidth')
    pd.set_option('display.max_colwidth', -1)
    ret = pd.read_csv('past_scans.csv').to_html(escape=True, classes='table table-striped', index=False)
    pd.set_option('display.max_colwidth', old_width)
    return ret


def reset_dicts():
    global scanning_req, scanning_res
    scanning_res = dict()
    scanning_req = dict()


def ip_scan(ip, client_id):
    ipscan = IPScan(ip)
    message = json.dumps(ipscan.__dict__)
    print('Request to client:%r, message:%r' % (client_id, message))
    scanning_nodes_dict[client_id] = 1
    sio.emit('IP_scan', message, room=client_id)

#########################################################
# Define app routes
# hello_world() : renders index.html on homepage
# render_past_scans() : renders past_scans from csv in new tab
# ip_alive() : Main functionality to check if IP_alive
# ip_subnet_alive() : Main functionality to check if a subnet
#                     of IPs are alive
# port_scan() : Main functionality to perform port scan
#               in various modes on all ports in an IP
#########################################################


@app.route("/")
def hello_world():
    return render_template('index.html')


@app.route("/pastScans")
def render_past_scans():
    global dict_table
    dict_table = get_past_scans()
    return render_template('pastScans.html', dict_table=dict_table)


@app.route("/checkIP", methods=['POST'])
def ip_alive():
    print('IP alive')
    reset_dicts()
    global scanning_res
    retry = 1
    x = request.json
    ip = x['ip'].split(',')

    res = dict()
    res['scan_status'] = 'Failed'
    res['scan_res'] = dict()

    scanning_nodes = list(scanning_nodes_dict.keys())
    if len(scanning_nodes) == 0:
        return json.dumps(res)

    random.shuffle(scanning_nodes)
    client_id = scanning_nodes[0]
    ip_scan(ip, client_id)

    while len(scanning_res) == 0 and retry <= 10:
        time.sleep(1)
        retry = retry + 1

    if retry > 10:
        print('Timeout Reached')
        return json.dumps(res)

    res['scan_res'] = scanning_res[client_id]
    res['scan_status'] = 'Success'

    append_to_csv(1, x['ip'], res)

    return json.dumps(res)


@app.route("/checkIPSubnet", methods=['POST'])
def ip_subnet_alive():
    print('IP Subnet alive')
    reset_dicts()
    global scanning_req, scanning_res, scanning_nodes_dict
    retry = 1
    x = request.json

    res = dict()
    res['scan_status'] = 'Failed'
    res['scan_res'] = dict()

    scanning_nodes = list(scanning_nodes_dict.keys())
    if len(scanning_nodes) == 0:
        return json.dumps(res)

    ip = list(ipaddress.ip_network(x['ip'], False).hosts())
    ip = [str(x) for x in ip]
    res['scan_res'] = {i: 'Not Scanned' for i in ip}

    if x['random'] == 'TRUE':
        print('Random ordering requested')
        random.shuffle(scanning_nodes)
        random.shuffle(ip)

    list_size = int(len(ip)/len(scanning_nodes))
    node_id, start = 0, 0

    while node_id < len(scanning_nodes):
        scanning_req[scanning_nodes[node_id]] = ip[int(start):int(start+list_size)]
        node_id = node_id + 1
        start = start + list_size

    if start < len(ip):
        for ind in range(start, len(ip)):
            scanning_req[scanning_nodes[node_id - 1]].append(ip[ind])

    for key in scanning_nodes_dict.keys():
        scanning_nodes_dict[key] = 1
        ip_scan(scanning_req[key], key)

    while len(scanning_res) != len(scanning_nodes) and retry <= (4 * list_size):
        time.sleep(1)
        retry = retry + 1

    if retry > (4 * list_size):
        print('Timeout Reached')
    else:
        res['scan_status'] = 'Success'

    for node in scanning_nodes:
        if node in scanning_res:
            for key, value in scanning_res[node].items():
                res['scan_res'][key] = value

    append_to_csv(2, x['ip'], res)

    return json.dumps(res)


@app.route("/portScan", methods=['POST'])
def port_scan():
    print('Port scan')
    reset_dicts()
    global scanning_req, scanning_res, scanning_nodes_dict
    x = request.json
    retry = 1

    res = dict()
    res['scan_status'] = 'Failed'
    res['scan_res'] = dict()

    scanning_nodes = list(scanning_nodes_dict.keys())
    if len(scanning_nodes) == 0:
        return json.dumps(res)

    x = json.loads(json.dumps(x))
    port_val = x['portRange'].split('-')
    port_list = [i for i in range(int(port_val[0]), int(port_val[1]) + 1)]
    res['scan_res'] = {str(i): 'Not Scanned' for i in port_list}

    if x['random'] == 'TRUE':
        print('Random ordering requested')
        random.shuffle(scanning_nodes)
        random.shuffle(port_list)

    temp_obj = dict()
    temp_obj['ip'] = x['ip']
    temp_obj['mode'] = x['type']

    list_size = int(len(port_list) / len(scanning_nodes))

    # To handle, if number of ports to scan is less than number of scanning nodes
    node_id = 0
    start = 0
    while node_id < len(scanning_nodes):
        temp_list = port_list[int(start): int(start + list_size)]
        temp_obj['port'] = temp_list
        scanning_req[scanning_nodes[node_id]] = copy.deepcopy(temp_obj)
        node_id = node_id + 1
        start = start + list_size

    if start < len(port_list):
        for ind in range(start, len(port_list)):
            scanning_req[scanning_nodes[node_id - 1]]['port'].append(port_list[ind])

    for key in scanning_nodes_dict.keys():
        scanning_nodes_dict[key] = 1
        message = json.dumps(scanning_req[key])
        print('Request to client:%r, message:%r' % (key, message))
        sio.emit('Port_Scan', message, room=key)

    while len(scanning_res) != len(scanning_nodes) and retry <= (4 * list_size):
        time.sleep(1)
        retry = retry + 1

    if retry > (4 * list_size):
        print('Timeout Reached')
    else:
        res['scan_status'] = 'Success'

    for node in scanning_nodes:
        if node in scanning_res:
            for key, value in scanning_res[node].items():
                res['scan_res'][key] = escape(value)

    append_to_csv(3, x, res)

    return json.dumps(res)

#########################################################
# Run flask app
#########################################################


if __name__ == "__main__":
    sio.run(app, port=8899)
