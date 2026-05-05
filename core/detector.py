#!/usr/bin/env python3
from collections import defaultdict
import time, logging, os, subprocess

LOGS_PATH = os.path.join(os.path.dirname(__file__), '../logs/firewall.log')
logging.basicConfig(filename=LOGS_PATH, level=logging.INFO, format='%(asctime)s %(message)s')

WHITELIST = {'192.168.64.1', '127.0.0.1'}
PORTSCAN_WINDOW = 10
PORTSCAN_THRESHOLD = 3
RATELIMIT_WINDOW = 5
RATELIMIT_THRESHOLD = 20

port_tracker = defaultdict(list)
rate_tracker = defaultdict(list)
blocked_ips = set()
alerted_ips = set()

def block_ip(src_ip, reason):
    if src_ip in blocked_ips or src_ip in WHITELIST: return
    blocked_ips.add(src_ip)
    subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', src_ip, '-j', 'DROP'], capture_output=True)
    msg = f'[BLOCK] IP {src_ip} bloqueada automaticamente por {reason}'
    print(msg)
    logging.warning(msg)

def check_port_scan(src_ip, dst_port):
    if dst_port is None or src_ip in WHITELIST: return None
    now = time.time()
    port_tracker[src_ip] = [(ts, port) for ts, port in port_tracker[src_ip] if now - ts < PORTSCAN_WINDOW]
    port_tracker[src_ip].append((now, dst_port))
    unique_ports = set(p for _, p in port_tracker[src_ip])
    if len(unique_ports) >= PORTSCAN_THRESHOLD:
        if src_ip not in alerted_ips:
            alerted_ips.add(src_ip)
            msg = f'[WARNING] PORT SCAN detectado desde {src_ip} - {len(unique_ports)} puertos en {PORTSCAN_WINDOW}s: {sorted(unique_ports)}'
            print(msg)
            logging.warning(msg)
            block_ip(src_ip, 'PORT_SCAN')
            return 'PORT_SCAN'
    else:
        alerted_ips.discard(src_ip)
    return None

def check_rate_limit(src_ip):
    if src_ip in WHITELIST: return None
    now = time.time()
    rate_tracker[src_ip] = [ts for ts in rate_tracker[src_ip] if now - ts < RATELIMIT_WINDOW]
    rate_tracker[src_ip].append(now)
    count = len(rate_tracker[src_ip])
    if count >= RATELIMIT_THRESHOLD:
        msg = f'[WARNING] RATE LIMIT excedido desde {src_ip} - {count} paquetes en {RATELIMIT_WINDOW}s'
        print(msg)
        logging.warning(msg)
        block_ip(src_ip, 'RATE_LIMIT')
        return 'RATE_LIMIT'
    return None

def analyze(src_ip, dst_port):
    alerts = []
    r1 = check_port_scan(src_ip, dst_port)
    if r1: alerts.append(r1)
    r2 = check_rate_limit(src_ip)
    if r2: alerts.append(r2)
    return alerts

def get_blocked_ips():
    return list(blocked_ips)
