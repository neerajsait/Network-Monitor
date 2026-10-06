# Network Monitor

A local Flask-based host intrusion detection dashboard: sniffs packets, logs network connections, and monitors system resources.

## How it works
1. Scapy captures packets and DNS queries in background threads.
2. Psutil tracks live processes and system vitals (CPU, RAM).
3. The Flask backend serves a live dashboard via WebSockets (SocketIO).
4. A simple honeypot listens on port 9999 for unauthorized scans.

## Tech
Python, Flask, SocketIO, Scapy, Psutil, JavaScript, HTML.

## Setup
Install dependencies and run `python app.py` (requires Administrator/root privileges for packet sniffing).

## Note
This is a personal learning experiment for network monitoring. Use only on networks you own or have permission to monitor.
