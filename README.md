markdown

# NetWatch Ultimate: Real-Time Network Monitor & SIEM Dashboard

A custom host-based intrusion detection system (HIDS) with live network traffic monitoring, GeoIP visualization, deep packet inspection, data loss prevention, and a simple honeypot — built as a personal project to explore network security hands-on.

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-Web%20Framework-green)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-MIT-yellowgreen)](LICENSE)
[![Commits](https://img.shields.io/github/commit-activity/m/neerajsait/Network-Monitor)](https://github.com/neerajsait/Network-Monitor/commits/main)

## Why I Built This
I’ve always been curious about what’s really happening under the hood on a network — how packets flow, how attacks like scanning or data exfiltration actually look in real time. Most open-source tools are either too simple or overly enterprise-level, so I decided to build my own monitor in my free time.  

This started as a learning experiment outside my day-to-day full-stack work (Java/Spring Boot/React). I wanted to get comfortable with packet-level networking, play with Scapy, and see if I could make a usable dashboard without freezing the system. It’s still a work-in-progress prototype, but it’s functional and taught me a ton.

## Key Features
### Security & Detection
- **Deep Packet Inspection (DPI)** → Analyzes packet payloads for suspicious patterns
- **Data Loss Prevention (DLP)** → Regex-based detection of unencrypted sensitive data (e.g., credit card numbers)
- **Honeypot Trap** → Listens on port 9999 to log unauthorized scans (great for spotting Nmap activity)
- **Lateral Movement Detection** → Flags suspicious internal IP scans and connections
- **DNS Sniffing** → Captures live DNS queries to spot shadow IT or C2 callbacks

### Visualization & Monitoring
- **Live Process Mapping** → Shows which processes/apps are making connections (PID + name)
- **GeoIP Tracking** → Resolves external IPs to city, country, and ISP for anomaly spotting
- **Real-Time Resource Monitoring** → CPU, RAM, and bandwidth usage

### Performance
- **Multi-Threaded Design** → Packet sniffing and scans run in background threads (no UI freeze)
- **WebSocket Updates** → Live dashboard via Flask-SocketIO

## Screenshots
*(Add these soon — they make a huge difference! Take a few shots of the dashboard running and upload them to a `/screenshots` folder.)*

<!-- Example placeholders — replace with real images -->
<!-- ![Dashboard Overview](screenshots/dashboard.png) -->
<!-- ![GeoIP Map](screenshots/geoip.png) -->
<!-- ![Honeypot Logs](screenshots/honeypot.png) -->

## Tech Stack
- **Backend** — Python 3.8+
- **Web Framework** — Flask + Flask-SocketIO
- **Packet Manipulation** — Scapy (requires Npcap on Windows or libpcap on Linux)
- **System Metrics** — Psutil
- **Network Tools** — Requests, Ping3

## Installation & Setup
### Prerequisites
- Python 3.8+
- **Windows users**: Install [Npcap](https://npcap.com/) (check "Install Npcap in WinPcap API-compatible Mode")
- Admin/root privileges (required for raw packet capture)

### Steps
1. Clone the repo
   ```bash
   git clone https://github.com/neerajsait/Network-Monitor.git
   cd Network-Monitor

(Recommended) Create a virtual environmentbash

python -m venv venv
source venv/bin/activate    # On Windows: venv\Scripts\activate

Install dependenciesbash

pip install flask flask-socketio psutil scapy requests ping3

Run the app (as Administrator/root)bash

# Windows (Admin CMD/PowerShell)
python app.py

# Linux/macOS
sudo python3 app.py

Open the dashboard
Visit http://localhost:5000 in your browser

What I Learned & ChallengesScapy is powerful but tricky with threading — I spent a lot of time making sure background packet capture didn’t block the Flask server.
Getting live updates via WebSockets was new to me; Flask-SocketIO made it smoother than I expected.
Performance on high-traffic networks was rough at first — added filters and async scans to keep it responsive.
Learned a ton about real-world security concepts like honeypots, DPI, and why admin privileges are non-negotiable for raw sockets.

Future ImprovementsAdd interactive GeoIP maps (e.g., with Folium or Leaflet)
More DLP patterns (SSN, API keys, etc.)
Export logs/reports to CSV/PDF
Docker support for easier deployment
Better alerting (email/Slack notifications)

Ethics & Legal NoteFor educational purposes only.
Use this tool ONLY on networks and systems you own or have explicit permission to monitor. Packet sniffing without authorization is illegal in most places. I’m not responsible for any misuse.LicenseMIT License — see the LICENSE file for details.Built in my free time by @neerajsait while working on full-stack projects. Feedback welcome!

Copy-paste this directly into your `README.md` (replace the old one).  
It keeps all the strong technical details from your current README, fixes the broken clone command, adds the personal sections we talked about (to make it feel authentically yours), and includes placeholders/reminders for screenshots.  

Once you add a couple of real screenshots and push the update, this repo will look seriously professional and credible. You’ve got a solid project here — this README will show it off properly!

