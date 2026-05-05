#!/bin/bash
python3 - << 'PYEOF'
import os

# Add unblock endpoint to app.py
content = open(os.path.expanduser("~/firewall/dashboard/app.py")).read()

old = "@app.route('/api/blocked')\ndef get_blocked(): return jsonify(get_blocked_ips())\n"
new = (
    "@app.route('/api/blocked')\n"
    "def get_blocked(): return jsonify(get_blocked_ips())\n"
    "\n"
    "@app.route('/api/unblock/<src_ip>', methods=['POST'])\n"
    "def unblock_ip(src_ip):\n"
    "    import subprocess\n"
    "    from detector import blocked_ips\n"
    "    blocked_ips.discard(src_ip)\n"
    "    subprocess.run(['sudo', 'iptables', '-D', 'INPUT', '-s', src_ip, '-j', 'DROP'], capture_output=True)\n"
    "    socketio.emit('unblocked', {'ip': src_ip})\n"
    "    return jsonify({'ok': True})\n"
)
content = content.replace(old, new)
open(os.path.expanduser("~/firewall/dashboard/app.py"), "w").write(content)

# Update HTML to add unblock button and export button
html = open(os.path.expanduser("~/firewall/dashboard/templates/index.html")).read()

# Add export button to header
old_header = "<span style='margin-left:auto;font-size:12px;color:#64748b' id='status'>Conectando...</span>"
new_header = (
    "<div style='margin-left:auto;display:flex;gap:8px;align-items:center'>\n"
    "      <a href='/api/export' style='font-size:11px;color:#38bdf8;text-decoration:none;padding:4px 10px;border:1px solid #1e3a5f;border-radius:4px'>⬇ Exportar CSV</a>\n"
    "      <span style='font-size:12px;color:#64748b' id='status'>Conectando...</span>\n"
    "    </div>"
)
html = html.replace(old_header, new_header)

# Add unblock button to blocked IPs list
old_blocked = "ul.innerHTML = ips.length ? ips.map(ip => `<li><span>${ip}</span><span class='badge badge-block'>BLOCKED</span></li>`).join('') : '<li style=\"color:#64748b\">Ninguna IP bloqueada</li>';"
new_blocked = "ul.innerHTML = ips.length ? ips.map(ip => `<li><span>${ip}</span><div style='display:flex;gap:4px;align-items:center'><span class='badge badge-block'>BLOCKED</span><span onclick='unblockIp(\"${ip}\")' style='cursor:pointer;color:#22c55e;font-size:11px;padding:2px 6px;border:1px solid #22c55e;border-radius:4px'>desbloquear</span></div></li>`).join('') : '<li style=\"color:#64748b\">Ninguna IP bloqueada</li>';"
html = html.replace(old_blocked, new_blocked)

# Add unblockIp function before closing script tag
old_end = "loadRules();\nloadBlocked();\nsetInterval(loadBlocked, 5000);"
new_end = (
    "function unblockIp(ip) {\n"
    "  fetch('/api/unblock/' + ip, {method: 'POST'})\n"
    "    .then(() => loadBlocked());\n"
    "}\n"
    "\n"
    "socket.on('unblocked', () => { loadBlocked(); });\n"
    "\n"
    "loadRules();\nloadBlocked();\nsetInterval(loadBlocked, 5000);"
)
html = html.replace(old_end, new_end)

open(os.path.expanduser("~/firewall/dashboard/templates/index.html"), "w").write(html)

print("Desbloqueo y exportacion CSV añadidos OK")
PYEOF
