# NetWatch Ultimate: SIEM & Network Threat Monitor

![Python](https://img.shields.io/badge/Python-3.9%2B-blue) ![Flask](https://img.shields.io/badge/Framework-Flask-green) ![Security](https://img.shields.io/badge/Security-Scapy%20%26%20DPI-red)

**NetWatch Ultimate** is a custom Host-Based Intrusion Detection System (HIDS) and SIEM dashboard designed to monitor live network traffic, visualize active connections via GeoIP, and detect anomalies in real-time.

It features **Deep Packet Inspection (DPI)** to identify unencrypted sensitive data (DLP) and utilizes a **multi-threaded architecture** to ensure low-latency monitoring without system freeze.

---

## 🚀 Key Features

### 🛡️ Intrusion Detection & Security
* **Deep Packet Inspection (DPI):** Analyzes raw TCP/UDP packet payloads using `Scapy` to identify suspicious data.
* **Data Loss Prevention (DLP):** Implements Regex-based pattern matching to detect unencrypted Credit Card leaks (PCI-DSS compliance check).
* **Honeypot Trap:** Listens on **Port 9999** to detect and log unauthorized LAN scanning attempts (e.g., Nmap scans).
* **Lateral Movement Detection:** Identifies suspicious internal IP scans and connection attempts.

### 🌐 Network Visualization
* **Live Process Mapping:** Correlates network connections to specific Process IDs (PIDs) and Application names.
* **GeoIP Tracking:** Resolves IP addresses to physical locations (City, Country, ISP) to spot anomalous cross-border traffic (e.g., C2 connections).
* **DNS Sniffing:** Captures and logs DNS queries in real-time to detect "Shadow IT" or malware callbacks.

### ⚡ Performance
* **Multi-Threaded Architecture:** Network sniffing runs on daemon threads to prevent blocking the Flask web server.
* **Non-Blocking LAN Scan:** Discovers devices on the local network asynchronously without freezing the UI.
* **Resource Monitoring:** Real-time tracking of CPU, RAM, and Bandwidth usage.

---

## 🛠️ Tech Stack

* **Core:** Python 3.x
* **Web Framework:** Flask, Flask-SocketIO (WebSockets)
* **Packet Sniffing:** Scapy (w/ Npcap or Libpcap)
* **System Metrics:** Psutil
* **Network Utils:** Ping3, Requests

---

## ⚙️ Installation

### Prerequisites
1.  **Python 3.8+**
2.  **Npcap (Windows Only):** Install [Npcap](https://npcap.com/) with **"Install in API-compatible Mode"** checked.
3.  **Root/Admin Privileges:** Required for packet sniffing.

### Setup

1.  **Clone the repository**
    ```bash
    git clone 
    cd 
    ```

2.  **Install Dependencies**
    ```bash
    pip install flask flask-socketio psutil scapy requests ping3
    ```

---

## 🖥️ Usage

1.  **Run the Application**
    * **Windows:** Run Command Prompt or PowerShell as **Administrator**.
    * **Linux/Mac:** Use `sudo`.

    ```bash
    # Windows
    python app.py

    # Linux
    sudo python3 app.py
    ```

2.  **Access the Dashboard**
    Open your browser and navigate to:
    `http://localhost:5000`

---

## ⚠️ Disclaimer

**Educational Purpose Only.**
This tool is intended for use on networks and systems you own or have explicit permission to monitor. Unauthorized packet sniffing or network scanning is illegal in many jurisdictions. The developer assumes no liability for misuse.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
