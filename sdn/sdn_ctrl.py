'''
Simple SDN Controller that communicates with Open vSwitches via a Wrapper.
'''
from flask import Flask, json, make_response, request
from urllib.request import urlopen, Request
import ast
import datetime
import time

app = Flask(__name__)

hosts = dict()
hosts['fw'] = dict(host='10.1.3.39', ports=['7', '8'], mac='52:54:00:09:38:52')
hosts['ddos'] = dict(host='10.1.3.39', ports=['9', '10'], mac='52:54:00:d3:db:f1')
hosts['ips'] = dict(host='10.1.3.48', ports=['4', '5'], mac='52:54:00:e3:6f:ac')
hosts['c39-to-c49'] = dict(host='10.1.3.39', ports=['1', '1'])
hosts['c48-to-c49'] = dict(host='10.1.3.48', ports=['1', '1'])
hosts['ingress'] = dict(host='10.1.3.39', ports=['6', '6'], mac='52:54:00:91:60:4d',
                        ip='192.168.66.200')
hosts['egress'] = dict(host='10.1.3.48', ports=['3', '3'], mac='52:54:00:93:cd:2d',
                       ip='192.168.66.201')
OPENFLOW = 'hard_timeout=300,priority=100,dl_type=0x0800,in_port={},dl_src={},nw_src={},nw_dst={},actions=mod_dl_src:{},output:{}'


@app.route('/mod_routing', methods=['POST'])
def mod_routing():
    # send http request to switches
    #timestamp in format Hour-Minute-Seconds-Microseconds
    timestamp = datetime.datetime.fromtimestamp(time.time()).strftime('%H-%M-%S-%f')
    routes = dict()
    routes['10.1.3.39'] = list()
    routes['10.1.3.48'] = list()
    print(request.json["list"])
    new_conf = ast.literal_eval(request.json["list"])
    ingress_ip = hosts['ingress']['ip']
    egress_ip = hosts['egress']['ip']

    # From ingress to next.
    ingr = hosts['ingress']
    next_hop = hosts[new_conf[1]]
    if next_hop['host'] == '10.1.3.39':
        routes['10.1.3.39'].append(OPENFLOW.format(
            ingr['ports'][0],
            ingr['mac'],
            ingress_ip,
            egress_ip,
            next_hop['mac'],
            next_hop['ports'][0]))
    elif next_hop['host'] == '10.1.3.48':
        routes['10.1.3.39'].append(OPENFLOW.format(
            ingr['ports'][0],
            ingr['mac'],
            ingress_ip,
            egress_ip,
            next_hop['mac'],
            '1'))

    for i in range(1, len(new_conf) - 1):
        host1 = hosts[new_conf[i]]
        host2 = hosts[new_conf[i + 1]]
        if host1['host'] == '10.1.3.39' and host2['host'] == '10.1.3.39':
            routes[host1['host']].append(
                OPENFLOW.format(host1['ports'][1],
                                host1['mac'],
                                ingress_ip,
                                egress_ip,
                                host2['mac'],
                                host2['ports'][0]))
        if host1['host'] == '10.1.3.39' and host2['host'] == '10.1.3.48':
            routes[host1['host']].append(
                OPENFLOW.format(host1['ports'][1],
                                host1['mac'],
                                ingress_ip,
                                egress_ip,
                                host2['mac'],
                                '1'))
            routes[host2['host']].append(
                OPENFLOW.format('1',
                                host2['mac'],
                                ingress_ip,
                                egress_ip,
                                host2['mac'],
                                host2['ports'][0]))

        if host1['host'] == '10.1.3.48' and host2['host'] == '10.1.3.48':
            routes[host1['host']].append(
                OPENFLOW.format(host1['ports'][1],
                                host1['mac'],
                                ingress_ip,
                                egress_ip,
                                host2['mac'],
                                host2['ports'][0]))
        if host1['host'] == '10.1.3.48' and host2['host'] == '10.1.3.39':
            routes[host1['host']].append(
                OPENFLOW.format(host1['ports'][1],
                                host1['mac'],
                                ingress_ip,
                                egress_ip,
                                host2['mac'],
                                '1'))
            routes[host2['host']].append(
                OPENFLOW.format('1',
                                host2['mac'],
                                ingress_ip,
                                egress_ip,
                                host2['mac'],
                                host2['ports'][0]))

        # Dirty solution
        if hosts[new_conf[i - 1]]['host'] == '10.1.3.39' and hosts[new_conf[i]][
            'host'] == '10.1.3.48':
            if hosts[new_conf[i + 1]]['host'] == '10.1.3.39':
                routes['10.1.3.48'].append(
                    OPENFLOW.format(
                        '1',
                        hosts[new_conf[i]]['mac'],
                        ingress_ip,
                        egress_ip,
                        hosts[new_conf[i]]['mac'],
                        hosts[new_conf[i]]['ports'][0]))
                routes['10.1.3.48'].append(
                    OPENFLOW.format(
                        hosts[new_conf[i]]['ports'][1],
                        hosts[new_conf[i]]['mac'],
                        ingress_ip,
                        egress_ip,
                        hosts[new_conf[i + 1]]['mac'],
                        '1'))

                # From last hop to egress
    last_hop = hosts[new_conf[-1]]
    egress = hosts['egress']
    if last_hop['host'] == '10.1.3.39':
        routes['10.1.3.39'].append(OPENFLOW.format(
            last_hop['ports'][1],
            last_hop['mac'],
            ingress_ip,
            egress_ip,
            egress['mac'],
            '1'))
        routes['10.1.3.48'].append(OPENFLOW.format(
            '1',
            egress['mac'],
            ingress_ip,
            egress_ip,
            egress['mac'],
            egress['ports'][0]))
    elif last_hop['host'] == '10.1.3.48':
        routes['10.1.3.48'].append(OPENFLOW.format(
            last_hop['ports'][1],
            last_hop['mac'],
            ingress_ip,
            egress_ip,
            egress['mac'],
            egress['ports'][0]))

    rules_json = json.dumps(routes)

    logfile = open('c39-%s' % (timestamp), 'w')
    for route in routes["10.1.3.39"]:
        logfile.write("%s\n"%(route))
    logfile.close()
    logfile = open('c48-%s' % (timestamp), 'w')
    for route in routes["10.1.3.48"]:
        logfile.write("%s\n" % (route))
    logfile.close()
    conn = Request('http://10.1.3.39:5051/rules', rules_json.encode('utf-8'),
                  {'Content-Type': 'application/json'})
    resp = urlopen(conn)
    conn2 = Request('http://10.1.3.48:5051/rules', rules_json.encode('utf-8'),
                   {'Content-Type': 'application/json'})
    resp2 = urlopen(conn2)
    return make_response('Response from switch wrapper:%s' % (resp2.getcode()), resp2.getcode())

if (__name__ == '__main__'):
    app.run(debug=False, host='0.0.0.0', port=5050)
