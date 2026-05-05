# PyFirewall

A Python-based network firewall with real-time traffic monitoring, anomaly detection, automatic IP blocking, and a web dashboard. Built on a virtualized network environment using VirtualBox with Kali Linux.

> Personal cybersecurity project — Business + Cybersecurity student

---

## Features

- **Packet inspection** — captures and analyzes live traffic using tcpdump
- **Rule engine** — configurable allow/block rules by IP, port, and protocol (JSON-based, hot-reload)
- **Anomaly detection** — port scan detection and rate limiting
- **Auto-blocking** — automatically blocks offending IPs via iptables
- **Real-time logging** — all events stored in SQLite with severity levels
- **Web dashboard** — live traffic visualization, rule management, IP unblocking, and alert feed
- **CSV export** — download full event logs as CSV
- **AI analysis** — optional Claude AI integration for threat explanation (requires API key)

---

## Architecture

```
┌─────────────────────────────────────────────┐
│           Virtual Network (VirtualBox)       │
│                                             │
│  ┌─────────────┐        ┌────────────────┐  │
│  │  Attacker   │──────▶ │    Firewall    │  │
│  │  VM (Kali)  │        │  (Kali Linux)  │  │
│  └─────────────┘        └───────┬────────┘  │
│                                 │           │
│              ┌──────────────────┼──────┐    │
│              ▼                  ▼      ▼    │
│        Rule engine         Detector  Logger │
│              └──────────────────┴──────┘    │
│                                 │           │
│                    ┌────────────▼──────┐    │
│                    │  Dashboard (Flask) │    │
│                    │  + SQLite storage  │    │
│                    └───────────────────┘    │
└─────────────────────────────────────────────┘
```

---

## Project Structure

```
firewall/
├── core/
│   ├── engine_v2.py      # Packet capture and rule evaluation (tcpdump)
│   ├── detector.py       # Anomaly detection (port scan, rate limiting)
│   ├── database.py       # SQLite persistence layer
│   └── ai_analyzer.py    # Claude AI threat analysis (optional)
├── dashboard/
│   ├── app.py            # Flask API + WebSocket server
│   └── templates/
│       └── index.html    # Frontend (HTML/JS/Chart.js)
├── rules/
│   └── rules.json        # Firewall rules configuration
├── db/
│   └── firewall.db       # SQLite database
└── logs/
    └── firewall.log      # Event log
```

---

## Setup

### Requirements

- Linux (tested on Kali Linux)
- Python 3.10+
- tcpdump
- iptables

### Installation

```bash
git clone https://github.com/Z3RHO/pyfirewall.git
cd pyfirewall
pip3 install flask flask-socketio
```

### Run the dashboard

```bash
sudo python3 dashboard/app.py
# Open http://localhost:5000
```

### Optional: AI analysis

```bash
export ANTHROPIC_API_KEY="your-key-here"
sudo -E python3 dashboard/app.py
```

---

## Usage

### Defining rules

Edit `rules/rules.json` or use the dashboard UI:

```json
{
  "rules": [
    {
      "id": 1,
      "name": "Block Telnet",
      "action": "BLOCK",
      "protocol": "TCP",
      "src_ip": null,
      "dst_port": 23,
      "enabled": true
    },
    {
      "id": 2,
      "name": "Allow all",
      "action": "ALLOW",
      "protocol": null,
      "src_ip": null,
      "dst_port": null,
      "enabled": true
    }
  ]
}
```

Rules are evaluated top-down — first match wins. Rules reload automatically without restarting.

### Simulating attacks (from attacker VM)

```bash
# Port scan (triggers anomaly detection)
sudo nmap -sS TARGET_IP

# Flood test (triggers rate limiting)
sudo ping -f TARGET_IP
```

---

## Dashboard

- Real-time traffic chart (Allow vs Block)
- Live event log with protocol, source, destination, and rule
- Active rules panel with add/delete from UI
- Blocked IPs panel with one-click unblock
- AI analysis panel (when API key configured)
- CSV export of all events

---

## Roadmap

- [x] Packet capture engine (tcpdump)
- [x] JSON rule engine with hot-reload
- [x] Anomaly detection (port scan, rate limiting)
- [x] Auto-blocking with iptables
- [x] SQLite event persistence
- [x] Web dashboard (Flask + WebSockets)
- [x] Real-time traffic charts (Chart.js)
- [x] Rule management from UI
- [x] IP unblocking from UI
- [x] CSV log export
- [x] AI threat analysis (Claude)
- [ ] Second VM attack demo (in progress)

---

## Tech Stack

| Layer | Technology |
|---|---|
| Packet capture | tcpdump |
| Rule enforcement | iptables |
| Detection | Custom Python algorithms |
| Storage | SQLite |
| API | Flask, Flask-SocketIO |
| Frontend | HTML, JavaScript, Chart.js |
| AI | Anthropic Claude API |
| Environment | VirtualBox, Kali Linux |

---

## License

MIT
