#!/bin/bash
python3 - << 'PYEOF'
import json, os

rules = {"rules": [
    {"id": 1, "name": "Block ICMP", "action": "BLOCK", "protocol": "ICMP", "src_ip": None, "dst_port": None, "enabled": True},
    {"id": 2, "name": "Block Telnet", "action": "BLOCK", "protocol": "TCP", "src_ip": None, "dst_port": 23, "enabled": True},
    {"id": 3, "name": "Allow all", "action": "ALLOW", "protocol": None, "src_ip": None, "dst_port": None, "enabled": True}
]}

with open(os.path.expanduser("~/firewall/rules/rules.json"), "w") as f:
    json.dump(rules, f, indent=2)
print("Reglas actualizadas OK")
PYEOF
