#!/usr/bin/env python3
import subprocess, json, logging, os, re, sys
sys.path.insert(0, os.path.dirname(__file__))
from detector import analyze

RULES_PATH = os.path.join(os.path.dirname(__file__), '../rules/rules.json')
LOGS_PATH = os.path.join(os.path.dirname(__file__), '../logs/firewall.log')

logging.basicConfig(filename=LOGS_PATH, level=logging.INFO, format='%(asctime)s %(message)s')

def load_rules():
    with open(RULES_PATH) as f:
        return json.load(f)['rules']

def parse_packet(line):
    p = {'src_ip': None, 'dst_ip': None, 'protocol': None, 'dst_port': None}
    if 'ICMP' in line or 'icmp' in line: p['protocol'] = 'ICMP'
    elif 'Flags' in line: p['protocol'] = 'TCP'
    elif 'UDP' in line or 'udp' in line: p['protocol'] = 'UDP'
    m = re.search(r'IP (\S+) > (\S+):', line)
    if m:
        src, dst = m.group(1), m.group(2)
        p['src_ip'] = src.rsplit('.', 1)[0]
        p['dst_ip'] = dst.rsplit('.', 1)[0]
        pm = re.search(r'\.(\d+):', dst)
        if pm: p['dst_port'] = int(pm.group(1))
    return p

def evaluate(packet, rules):
    for rule in rules:
        if not rule['enabled']: continue
        if rule['protocol'] and rule['protocol'] != packet['protocol']: continue
        if rule['src_ip'] and rule['src_ip'] != packet['src_ip']: continue
        if rule['dst_port'] and rule['dst_port'] != packet['dst_port']: continue
        return rule['action'], rule['name']
    return 'ALLOW', 'default'

def process_line(line, rules):
    line = line.strip()
    if not line or 'IP' not in line: return
    p = parse_packet(line)
    if not p['src_ip']: return
    analyze(p['src_ip'], p['dst_port'])
    action, rule_name = evaluate(p, rules)
    msg = f"[{action}] {p['protocol']} {p['src_ip']} -> {p['dst_ip']} | rule: {rule_name}"
    print(msg)
    logging.info(msg)

if __name__ == '__main__':
    print('Firewall + Detector iniciado. Capturando trafico en eth0... (Ctrl+C para parar)')
    cmd = ['sudo', 'tcpdump', '-i', 'eth0', '-n', '-l', '--immediate-mode', 'ip']
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    try:
        while True:
            line = proc.stdout.readline()
            if not line: break
            process_line(line, load_rules())
    except KeyboardInterrupt:
        proc.terminate()
        print('\nFirewall detenido.')
