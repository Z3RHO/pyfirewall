#!/usr/bin/env python3
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO
import json, os, threading, subprocess, re, time
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../core'))
from detector import analyze, get_blocked_ips
from ai_analyzer import analyze_async
from database import init_db, save_event, save_alert, get_recent_events, get_recent_alerts, get_stats

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins='*')

RULES_PATH = os.path.join(os.path.dirname(__file__), '../rules/rules.json')

cached_rules = []
rules_mtime = 0
ai_requested = set()

def load_rules():
    global cached_rules, rules_mtime
    try:
        mtime = os.path.getmtime(RULES_PATH)
        if mtime != rules_mtime:
            with open(RULES_PATH) as f:
                cached_rules = json.load(f)['rules']
            rules_mtime = mtime
    except Exception:
        pass
    return cached_rules

def save_rules(rules):
    with open(RULES_PATH, 'w') as f:
        json.dump({'rules': rules}, f, indent=2)

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

def on_ai_result(src_ip, alert_type, result):
    save_alert(src_ip, alert_type, result)
    analysis = {'time': time.strftime('%H:%M:%S'), 'src_ip': src_ip, 'alert_type': alert_type, 'analysis': result}
    socketio.emit('ai_analysis', analysis)

def capture_traffic():
    cmd = ['sudo', 'tcpdump', '-i', 'eth0', '-n', '-l', '--immediate-mode', 'ip']
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    while True:
        line = proc.stdout.readline()
        if not line: break
        line = line.strip()
        if not line or 'IP' not in line: continue
        p = parse_packet(line)
        if not p['src_ip']: continue
        alerts = analyze(p['src_ip'], p['dst_port'])
        action, rule_name = evaluate(p, load_rules())
        save_event(action, p['protocol'], p['src_ip'], p['dst_ip'], rule_name, alerts)
        event = {'time': time.strftime('%H:%M:%S'), 'action': action, 'protocol': p['protocol'], 'src': p['src_ip'], 'dst': p['dst_ip'], 'rule': rule_name, 'alerts': alerts}
        socketio.emit('packet', event)
        if alerts:
            key = f'{p["src_ip"]}_{alerts[0]}'
            if key not in ai_requested:
                ai_requested.add(key)
                analyze_async(p['src_ip'], alerts[0], 'Trafico sospechoso detectado', lambda r, ip=p['src_ip'], a=alerts[0]: on_ai_result(ip, a, r))

@app.route('/')
def index(): return render_template('index.html')

@app.route('/api/events')
def get_events(): return jsonify(get_recent_events(100))

@app.route('/api/rules')
def get_rules(): return jsonify(load_rules())

@app.route('/api/rules/add', methods=['POST'])
def add_rule():
    data = request.json
    rules = load_rules()
    new_id = max([r['id'] for r in rules], default=0) + 1
    new_rule = {'id': new_id, 'name': data.get('name', f'Rule {new_id}'), 'action': data.get('action', 'BLOCK'), 'protocol': data.get('protocol') or None, 'src_ip': data.get('src_ip') or None, 'dst_port': int(data['dst_port']) if data.get('dst_port') else None, 'enabled': True}
    rules.insert(len(rules)-1, new_rule)
    save_rules(rules)
    global rules_mtime
    rules_mtime = 0
    socketio.emit('rules_updated', load_rules())
    return jsonify({'ok': True, 'rule': new_rule})

@app.route('/api/rules/delete/<int:rule_id>', methods=['DELETE'])
def delete_rule(rule_id):
    rules = load_rules()
    rules = [r for r in rules if r['id'] != rule_id]
    save_rules(rules)
    global rules_mtime
    rules_mtime = 0
    socketio.emit('rules_updated', load_rules())
    return jsonify({'ok': True})

@app.route('/api/blocked')
def get_blocked(): return jsonify(get_blocked_ips())

@app.route('/api/unblock/<src_ip>', methods=['POST'])
def unblock_ip(src_ip):
    import subprocess
    from detector import blocked_ips
    blocked_ips.discard(src_ip)
    subprocess.run(['sudo', 'iptables', '-D', 'INPUT', '-s', src_ip, '-j', 'DROP'], capture_output=True)
    socketio.emit('unblocked', {'ip': src_ip})
    return jsonify({'ok': True})

@app.route('/api/alerts')
def get_alerts(): return jsonify(get_recent_alerts(50))

@app.route('/api/stats')
def get_stats_route(): return jsonify(get_stats())

@app.route('/api/export')
def export_csv():
    from flask import Response
    events = get_recent_events(1000)
    lines = ['timestamp,action,protocol,src_ip,dst_ip,rule,alerts']
    for e in events:
        lines.append(f'{e["timestamp"]},{e["action"]},{e["protocol"]},{e["src_ip"]},{e["dst_ip"]},{e["rule"]},{e["alerts"]}')
    return Response('\n'.join(lines), mimetype='text/csv', headers={'Content-Disposition': 'attachment;filename=firewall_logs.csv'})

if __name__ == '__main__':
    init_db()
    load_rules()
    t = threading.Thread(target=capture_traffic, daemon=True)
    t.start()
    print('Dashboard corriendo en http://0.0.0.0:5000')
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)
