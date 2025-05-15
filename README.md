# Network Monitoring Application

A Flask-based web application for **real-time network traffic monitoring**, **anomaly detection**, and **deep packet inspection**. It provides a browser-based dashboard and RESTful APIs to visualize, analyze, and export network activity and security insights.

---

## 🧩 Key Features

- Real-time monitoring of active network connections
- GeoIP and hostname resolution
- Deep Packet Inspection (DPI) with cardholder data detection
- DNS query capture and domain resolution
- Anomaly detection (e.g., port scans, high CPU usage)
- WebSocket-based live traffic visualization
- REST APIs and CSV export for connections & anomalies

---

## 📋 Table of Contents

- [Prerequisites](#prerequisites)
- [Installation and Setup](#installation-and-setup)
- [Application Structure](#application-structure)
- [Modules and Functions](#modules-and-functions)
- [API Endpoints](#api-endpoints)
- [Data Structures](#data-structures)
- [Usage](#usage)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)
- [Extending the Application](#extending-the-application)

---

## ✅ Prerequisites

- **OS**: Linux (preferred), macOS, or Windows (limited support)
- **Python**: 3.8+
- **Permissions**: Root/admin access for packet capture
- **Network Interface**: Default is `eth0`, customizable

### Dependencies

- `Flask`
- `Flask-SocketIO`
- `psutil`
- `scapy`
- `ping3`
- `requests`
- `dnspython`

### External Services

- [ipinfo.io](https://ipinfo.io/) API token (set as `IPINFO_TOKEN`)

---

## ⚙️ Installation and Setup

```bash
# Clone the repo
git clone <repository-url>
cd <repository-directory>

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install flask flask-socketio psutil ping3 requests dnspython scapy





## 🔧 Modules and Functions

### Core Functions

- **`get_app_info(pid)`**  
  Retrieves the process name and path using a given process ID.

- **`get_geoip_info(ip)`**  
  Fetches GeoIP information (country, city, organization, etc.) using the ipinfo.io API.

- **`get_hostname(ip)`**  
  Performs a reverse DNS lookup to resolve the IP address to a hostname.

- **`get_network_metrics(ip)`**  
  Uses `ping3` to measure latency (ping) and packet loss to a target IP.

- **`detect_cardholder_data(payload)`**  
  Scans packet payloads for patterns resembling sensitive cardholder data.

- **`capture_packets(interface)`**  
  Listens on a network interface using `scapy` for packet inspection and extracts metadata.

- **`capture_dns_queries(interface)`**  
  Captures DNS queries using `scapy` and logs domain request attempts.

- **`resolve_domain(domain)`**  
  Resolves a domain name to its corresponding IP address using `dnspython`.

- **`detect_anomalies(connections)`**  
  Analyzes active connections to identify potential threats like long-living connections, packet anomalies, or suspicious activity.

- **`detect_port_scanning()`**  
  Detects signs of port scanning by monitoring repetitive requests across multiple ports.

- **`get_interface_stats()`**  
  Retrieves usage statistics (bytes sent/received) for each network interface using `psutil`.

- **`get_network_data()`**  
  Aggregates all current network connections, performs data enrichment (e.g., GeoIP), and returns a structured list.

- **`get_top_apps()`**  
  Returns the top N applications generating the most network traffic.

- **`background_task()`**  
  A repeating background task (every 5 seconds) that emits updated connection and interface data to the front end using WebSockets.

---

## 🌐 API Endpoints

### Web Interface

- **`GET /`**  
  Loads the browser-based network monitoring dashboard (`index.html`).

### 📡 Network Data

- **`GET /api/connections`**  
  Returns all currently active and enriched network connection data.

- **`GET /api/interfaces`**  
  Retrieves real-time network usage statistics (e.g., upload/download speed).

- **`GET /api/packets`**  
  Returns a log of inspected packets captured from the network interface.

- **`GET /api/dns_queries`**  
  Retrieves recent DNS queries made by the system.

- **`GET /api/pie_data`**  
  Provides application-level traffic distribution data for pie chart rendering.

### 🛠️ Helper & Export

- **`GET /api/help`**  
  Provides tooltip descriptions and metadata for the UI.

- **`POST /api/connections/filter`**  
  Accepts filter criteria (e.g., IP address, protocol, port) and returns matching connections.

- **`GET /api/export`**  
  Exports current connection data to a downloadable CSV file.

- **`GET /api/export_anomalies`**  
  Exports detected anomalies (e.g., scans, long sessions) to a CSV report.
### 📜 License
This project is open-source.
