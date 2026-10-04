# Network-Monitor

> A local Flask dashboard for experimenting with host and network visibility.

## Overview

The application samples host and network information and uses Scapy and Socket.IO for live updates and packet-related views. It is a learning prototype, not a validated enterprise SIEM or intrusion-prevention system.

## What’s in this repo

- Host/network metrics and live dashboard updates
- Packet and DNS monitoring helpers
- A small honeypot listener and GeoIP/latency-related lookups

## Stack

Python, Flask, Flask-SocketIO, psutil, Scapy, ping3, and requests.

## Getting started

1. Install the Python dependencies used by `app.py` and the platform’s packet-capture prerequisites (Npcap on Windows or libpcap on supported systems).
2. Run `python app.py` with the permissions required for capture, then open the local address it reports.
3. Use it only on systems and networks you are authorized to monitor.

## Notes

Packet capture may require elevated privileges and can expose sensitive traffic. Do not run this on a shared or third-party network without explicit authorization; the detection results are experimental.
