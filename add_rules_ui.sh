#!/bin/bash
python3 - << 'PYEOF'
import os

# Update app.py to add rule management endpoints
app = open(os.path.expanduser("~/firewall/dashboard/app.py"), "r")
content = app.read()
app.close()

# Add Flask request import and rule management endpoints
app = open(os.path.expanduser("~/firewall/dashboard/app.py"), "w")
app.write("#!/usr/bin/env python3\n")
app.write("from flask import Flask, render_template, jsonify, request\n")
app.write("from flask_socketio import SocketIO\n")
app.write("import json, os, threading, subprocess, re, time\n")
app.write("import sys\n")
app.write("sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../core'))\n")
app.write("from detector import analyze, get_blocked_ips\n")
app.write("from ai_analyzer import analyze_async\n")
app.write("\n")
app.write("app = Flask(__name__)\n")
app.write("socketio = SocketIO(app, cors_allowed_origins='*')\n")
app.write("\n")
app.write("RULES_PATH = os.path.join(os.path.dirname(__file__), '../rules/rules.json')\n")
app.write("LOGS_PATH = os.path.join(os.path.dirname(__file__), '../logs/firewall.log')\n")
app.write("\n")
app.write("events = []\n")
app.write("ai_analyses = []\n")
app.write("cached_rules = []\n")
app.write("rules_mtime = 0\n")
app.write("\n")
app.write("def load_rules():\n")
app.write("    global cached_rules, rules_mtime\n")
app.write("    try:\n")
app.write("        mtime = os.path.getmtime(RULES_PATH)\n")
app.write("        if mtime != rules_mtime:\n")
app.write("            with open(RULES_PATH) as f:\n")
app.write("                cached_rules = json.load(f)['rules']\n")
app.write("            rules_mtime = mtime\n")
app.write("    except Exception:\n")
app.write("        pass\n")
app.write("    return cached_rules\n")
app.write("\n")
app.write("def save_rules(rules):\n")
app.write("    with open(RULES_PATH, 'w') as f:\n")
app.write("        json.dump({'rules': rules}, f, indent=2)\n")
app.write("\n")
app.write("def parse_packet(line):\n")
app.write("    p = {'src_ip': None, 'dst_ip': None, 'protocol': None, 'dst_port': None}\n")
app.write("    if 'ICMP' in line or 'icmp' in line: p['protocol'] = 'ICMP'\n")
app.write("    elif 'Flags' in line: p['protocol'] = 'TCP'\n")
app.write("    elif 'UDP' in line or 'udp' in line: p['protocol'] = 'UDP'\n")
app.write("    m = re.search(r'IP (\\S+) > (\\S+):', line)\n")
app.write("    if m:\n")
app.write("        src, dst = m.group(1), m.group(2)\n")
app.write("        p['src_ip'] = src.rsplit('.', 1)[0]\n")
app.write("        p['dst_ip'] = dst.rsplit('.', 1)[0]\n")
app.write("        pm = re.search(r'\\.(\\d+):', dst)\n")
app.write("        if pm: p['dst_port'] = int(pm.group(1))\n")
app.write("    return p\n")
app.write("\n")
app.write("def evaluate(packet, rules):\n")
app.write("    for rule in rules:\n")
app.write("        if not rule['enabled']: continue\n")
app.write("        if rule['protocol'] and rule['protocol'] != packet['protocol']: continue\n")
app.write("        if rule['src_ip'] and rule['src_ip'] != packet['src_ip']: continue\n")
app.write("        if rule['dst_port'] and rule['dst_port'] != packet['dst_port']: continue\n")
app.write("        return rule['action'], rule['name']\n")
app.write("    return 'ALLOW', 'default'\n")
app.write("\n")
app.write("def on_ai_result(src_ip, alert_type, result):\n")
app.write("    analysis = {'time': time.strftime('%H:%M:%S'), 'src_ip': src_ip, 'alert_type': alert_type, 'analysis': result}\n")
app.write("    ai_analyses.append(analysis)\n")
app.write("    if len(ai_analyses) > 20: ai_analyses.pop(0)\n")
app.write("    socketio.emit('ai_analysis', analysis)\n")
app.write("\n")
app.write("ai_requested = set()\n")
app.write("\n")
app.write("def capture_traffic():\n")
app.write("    cmd = ['sudo', 'tcpdump', '-i', 'eth0', '-n', '-l', '--immediate-mode', 'ip']\n")
app.write("    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)\n")
app.write("    while True:\n")
app.write("        line = proc.stdout.readline()\n")
app.write("        if not line: break\n")
app.write("        line = line.strip()\n")
app.write("        if not line or 'IP' not in line: continue\n")
app.write("        p = parse_packet(line)\n")
app.write("        if not p['src_ip']: continue\n")
app.write("        alerts = analyze(p['src_ip'], p['dst_port'])\n")
app.write("        action, rule_name = evaluate(p, load_rules())\n")
app.write("        event = {'time': time.strftime('%H:%M:%S'), 'action': action, 'protocol': p['protocol'], 'src': p['src_ip'], 'dst': p['dst_ip'], 'rule': rule_name, 'alerts': alerts}\n")
app.write("        events.append(event)\n")
app.write("        if len(events) > 200: events.pop(0)\n")
app.write("        socketio.emit('packet', event)\n")
app.write("        if alerts:\n")
app.write("            key = f'{p[\"src_ip\"]}_{alerts[0]}'\n")
app.write("            if key not in ai_requested:\n")
app.write("                ai_requested.add(key)\n")
app.write("                analyze_async(p['src_ip'], alerts[0], 'Trafico masivo detectado', lambda r, ip=p['src_ip'], a=alerts[0]: on_ai_result(ip, a, r))\n")
app.write("\n")
app.write("@app.route('/')\n")
app.write("def index(): return render_template('index.html')\n")
app.write("\n")
app.write("@app.route('/api/events')\n")
app.write("def get_events(): return jsonify(events[-50:])\n")
app.write("\n")
app.write("@app.route('/api/rules')\n")
app.write("def get_rules(): return jsonify(load_rules())\n")
app.write("\n")
app.write("@app.route('/api/rules/add', methods=['POST'])\n")
app.write("def add_rule():\n")
app.write("    data = request.json\n")
app.write("    rules = load_rules()\n")
app.write("    new_id = max([r['id'] for r in rules], default=0) + 1\n")
app.write("    new_rule = {\n")
app.write("        'id': new_id,\n")
app.write("        'name': data.get('name', f'Rule {new_id}'),\n")
app.write("        'action': data.get('action', 'BLOCK'),\n")
app.write("        'protocol': data.get('protocol') or None,\n")
app.write("        'src_ip': data.get('src_ip') or None,\n")
app.write("        'dst_port': int(data['dst_port']) if data.get('dst_port') else None,\n")
app.write("        'enabled': True\n")
app.write("    }\n")
app.write("    rules.insert(len(rules)-1, new_rule)\n")
app.write("    save_rules(rules)\n")
app.write("    global rules_mtime\n")
app.write("    rules_mtime = 0\n")
app.write("    socketio.emit('rules_updated', load_rules())\n")
app.write("    return jsonify({'ok': True, 'rule': new_rule})\n")
app.write("\n")
app.write("@app.route('/api/rules/delete/<int:rule_id>', methods=['DELETE'])\n")
app.write("def delete_rule(rule_id):\n")
app.write("    rules = load_rules()\n")
app.write("    rules = [r for r in rules if r['id'] != rule_id]\n")
app.write("    save_rules(rules)\n")
app.write("    global rules_mtime\n")
app.write("    rules_mtime = 0\n")
app.write("    socketio.emit('rules_updated', load_rules())\n")
app.write("    return jsonify({'ok': True})\n")
app.write("\n")
app.write("@app.route('/api/blocked')\n")
app.write("def get_blocked(): return jsonify(get_blocked_ips())\n")
app.write("\n")
app.write("@app.route('/api/ai')\n")
app.write("def get_ai(): return jsonify(ai_analyses)\n")
app.write("\n")
app.write("@app.route('/api/stats')\n")
app.write("def get_stats():\n")
app.write("    total = len(events)\n")
app.write("    blocked = sum(1 for e in events if e['action'] == 'BLOCK')\n")
app.write("    warnings = sum(1 for e in events if e['alerts'])\n")
app.write("    return jsonify({'total': total, 'blocked': blocked, 'warnings': warnings, 'allowed': total - blocked})\n")
app.write("\n")
app.write("if __name__ == '__main__':\n")
app.write("    load_rules()\n")
app.write("    t = threading.Thread(target=capture_traffic, daemon=True)\n")
app.write("    t.start()\n")
app.write("    print('Dashboard corriendo en http://0.0.0.0:5000')\n")
app.write("    socketio.run(app, host='0.0.0.0', port=5000, debug=False)\n")
app.close()

# Update HTML with rule management form
html = open(os.path.expanduser("~/firewall/dashboard/templates/index.html"), "r")
content = html.read()
html.close()

# Insert rule form before closing </div> of rules panel
old = "      <ul class='rules-list' id='rules-list'></ul>\n    </div>\n"
new = (
    "      <ul class='rules-list' id='rules-list'></ul>\n"
    "      <div style='margin-top:12px;border-top:1px solid #1e3a5f;padding-top:12px'>\n"
    "        <div style='font-size:11px;color:#64748b;margin-bottom:8px'>Añadir regla</div>\n"
    "        <input id='r-name' placeholder='Nombre' style='width:100%;margin-bottom:4px;background:#0a0e1a;border:1px solid #1e3a5f;color:#e0e6f0;padding:5px 8px;border-radius:4px;font-size:12px'>\n"
    "        <select id='r-action' style='width:48%;margin-bottom:4px;background:#0a0e1a;border:1px solid #1e3a5f;color:#e0e6f0;padding:5px 8px;border-radius:4px;font-size:12px'>\n"
    "          <option value='BLOCK'>BLOCK</option>\n"
    "          <option value='ALLOW'>ALLOW</option>\n"
    "        </select>\n"
    "        <select id='r-proto' style='width:48%;margin-bottom:4px;margin-left:4%;background:#0a0e1a;border:1px solid #1e3a5f;color:#e0e6f0;padding:5px 8px;border-radius:4px;font-size:12px'>\n"
    "          <option value=''>Any proto</option>\n"
    "          <option value='TCP'>TCP</option>\n"
    "          <option value='UDP'>UDP</option>\n"
    "          <option value='ICMP'>ICMP</option>\n"
    "        </select>\n"
    "        <input id='r-ip' placeholder='IP origen (opcional)' style='width:48%;margin-bottom:4px;background:#0a0e1a;border:1px solid #1e3a5f;color:#e0e6f0;padding:5px 8px;border-radius:4px;font-size:12px'>\n"
    "        <input id='r-port' placeholder='Puerto destino (opcional)' type='number' style='width:48%;margin-bottom:4px;margin-left:4%;background:#0a0e1a;border:1px solid #1e3a5f;color:#e0e6f0;padding:5px 8px;border-radius:4px;font-size:12px'>\n"
    "        <button onclick='addRule()' style='width:100%;padding:6px;background:#1e3a5f;color:#38bdf8;border:none;border-radius:4px;font-size:12px;cursor:pointer;font-family:monospace'>+ Añadir regla</button>\n"
    "      </div>\n"
    "    </div>\n"
)
content = content.replace(old, new)

# Add addRule JS function before closing </script>
old_js = "loadRules();\nloadBlocked();\nsetInterval(loadBlocked, 5000);\n</script>"
new_js = (
    "loadRules();\n"
    "loadBlocked();\n"
    "setInterval(loadBlocked, 5000);\n"
    "\n"
    "function addRule() {\n"
    "  const rule = {\n"
    "    name: document.getElementById('r-name').value || 'Nueva regla',\n"
    "    action: document.getElementById('r-action').value,\n"
    "    protocol: document.getElementById('r-proto').value,\n"
    "    src_ip: document.getElementById('r-ip').value,\n"
    "    dst_port: document.getElementById('r-port').value\n"
    "  };\n"
    "  fetch('/api/rules/add', {\n"
    "    method: 'POST',\n"
    "    headers: {'Content-Type': 'application/json'},\n"
    "    body: JSON.stringify(rule)\n"
    "  }).then(r => r.json()).then(() => { loadRules(); });\n"
    "  document.getElementById('r-name').value = '';\n"
    "  document.getElementById('r-ip').value = '';\n"
    "  document.getElementById('r-port').value = '';\n"
    "}\n"
    "\n"
    "function deleteRule(id) {\n"
    "  fetch('/api/rules/delete/' + id, {method: 'DELETE'})\n"
    "    .then(() => loadRules());\n"
    "}\n"
    "\n"
    "socket.on('rules_updated', (rules) => {\n"
    "  const ul = document.getElementById('rules-list');\n"
    "  ul.innerHTML = rules.map(r => `<li><span>${r.name}</span><div style='display:flex;gap:4px;align-items:center'><span class='badge ${r.action===\"ALLOW\"?\"badge-allow\":\"badge-block\"}'>${r.action}</span><span onclick='deleteRule(${r.id})' style='cursor:pointer;color:#ef4444;font-size:14px;line-height:1'>×</span></div></li>`).join('');\n"
    "});\n"
    "</script>"
)
content = content.replace("loadRules();\nloadBlocked();\nsetInterval(loadBlocked, 5000);\n</script>", new_js)

# Update loadRules to include delete button
old_load = "ul.innerHTML = rules.map(r => `<li><span>${r.name}</span><span class='badge ${r.action===\"ALLOW\"?\"badge-allow\":\"badge-block\"}'>${r.action}</span></li>`).join('');"
new_load = "ul.innerHTML = rules.map(r => `<li><span>${r.name}</span><div style='display:flex;gap:4px;align-items:center'><span class='badge ${r.action===\"ALLOW\"?\"badge-allow\":\"badge-block\"}'>${r.action}</span><span onclick='deleteRule(${r.id})' style='cursor:pointer;color:#ef4444;font-size:14px;line-height:1'>x</span></div></li>`).join('');"
content = content.replace(old_load, new_load)

html = open(os.path.expanduser("~/firewall/dashboard/templates/index.html"), "w")
html.write(content)
html.close()

print("Gestion de reglas añadida OK")
PYEOF
