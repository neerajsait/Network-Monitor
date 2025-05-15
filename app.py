from flask import Flask, render_template, jsonify, send_file, g, request
from flask_socketio import SocketIO
import psutil
import socket
import requests
import csv
import io
import threading
import time
from datetime import datetime
from collections import defaultdict
from ping3 import ping
import json
import sys
import re
from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, Raw
from dns import resolver

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
socketio = SocketIO(app, cors_allowed_origins="*")

# Replace with your ipinfo.io token
IPINFO_TOKEN = "352aedaf3914f5"

# Global data structures
connection_data = []
disconnected_connections = []
connection_times = {}
connection_sessions = {}
reconnect_counts = defaultdict(int)
port_attempts = defaultdict(list)
known_apps = set()
anomalies_log = []
geoip_cache = {}
hostname_cache = {}
process_cache = {}
network_metrics_cache = {}
dns_queries = []
CACHE_TIMEOUT = 3600  # 1 hour
PROCESS_CACHE_TIMEOUT = 60  # seconds
METRICS_INTERVAL = 30  # seconds

def get_app_info(pid):
    """Get application name, executable path, CPU, and memory usage from PID."""
    current_time = time.time()
    if pid in process_cache and (current_time - process_cache[pid][2]) < PROCESS_CACHE_TIMEOUT:
        return process_cache[pid][:4]
    try:
        process = psutil.Process(pid)
        name, exe = process.name(), process.exe()
        cpu_percent = process.cpu_percent(interval=0.1)
        memory_percent = process.memory_percent()
        process_cache[pid] = (name, exe, current_time, cpu_percent, memory_percent)
        return name, exe, cpu_percent, memory_percent
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        process_cache[pid] = ("Unknown", "Unknown", current_time, 0.0, 0.0)
        return "Unknown", "Unknown", 0.0, 0.0

def get_geoip_info(ip):
    """Get GeoIP info including coordinates for an IP using ipinfo.io."""
    current_time = time.time()
    if ip in geoip_cache and (current_time - geoip_cache[ip][1]) < CACHE_TIMEOUT:
        return geoip_cache[ip][0]
    if ip in ['127.0.0.1', 'localhost', '::1'] or ip.startswith('192.168.'):
        geoip_cache[ip] = ({"city": "Local", "country": "Local", "loc": "0,0", "is_anonymous": False}, current_time)
        return geoip_cache[ip][0]
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json?token={IPINFO_TOKEN}")
        geo_info = response.json() if response.status_code == 200 else {"city": "Unknown", "country": "Unknown", "loc": "0,0", "is_anonymous": False}
        geo_info['is_anonymous'] = geo_info.get('privacy', {}).get('tor', False) or geo_info.get('privacy', {}).get('vpn', False)
        geoip_cache[ip] = (geo_info, current_time)
        return geo_info
    except Exception as e:
        print(f"GeoIP lookup error for {ip}: {e}")
        geoip_cache[ip] = ({"city": "Unknown", "country": "Unknown", "loc": "0,0", "is_anonymous": False}, current_time)
        return geoip_cache[ip][0]

def get_hostname(ip):
    """Resolve IP to hostname."""
    current_time = time.time()
    if ip in hostname_cache and (current_time - hostname_cache[ip][1]) < CACHE_TIMEOUT:
        return hostname_cache[ip][0]
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        hostname_cache[ip] = (hostname, current_time)
        return hostname
    except socket.herror:
        hostname_cache[ip] = ("Unknown", current_time)
        return hostname_cache[ip][0]

def get_network_metrics(ip):
    """Measure latency and packet loss for an IP."""
    current_time = time.time()
    if ip in network_metrics_cache and (current_time - network_metrics_cache[ip][1]) < METRICS_INTERVAL:
        return network_metrics_cache[ip][0]
    metrics = {"latency_ms": None, "packet_loss_percent": None}
    try:
        latency = ping(ip, unit='ms', timeout=2)
        success_count = sum(1 for _ in range(4) if ping(ip, unit='ms', timeout=2) is not None)
        packet_loss = ((4 - success_count) / 4) * 100
        metrics = {
            "latency_ms": round(latency, 2) if latency else None,
            "packet_loss_percent": round(packet_loss, 2)
        }
    except Exception as e:
        print(f"Error measuring network metrics for {ip}: {e}")
    network_metrics_cache[ip] = (metrics, current_time)
    return metrics

def detect_cardholder_data(payload):
    """Detect potential cardholder data in packet payload."""
    card_pattern = r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\b'
    return bool(re.search(card_pattern, payload))

def capture_packets(interface="eth0", count=10):
    """Capture packets for deep packet inspection."""
    packets = []
    def process_packet(packet):
        if IP in packet and TCP in packet and Raw in packet:
            payload = packet[Raw].load.decode(errors='ignore')
            pkt_info = {
                "src_ip": packet[IP].src,
                "dst_ip": packet[IP].dst,
                "protocol": "TCP",
                "src_port": packet[TCP].sport,
                "dst_port": packet[TCP].dport,
                "payload": payload[:100],
                "card_data_detected": detect_cardholder_data(payload)
            }
            if pkt_info["card_data_detected"]:
                socketio.emit('alert', {
                    'message': f"Cardholder data detected in unencrypted traffic from {pkt_info['src_ip']}"
                })
            packets.append(pkt_info)
    try:
        sniff(iface=interface, prn=process_packet, count=count, timeout=10)
    except Exception as e:
        print(f"Packet capture error: {e}")
    return packets

def capture_dns_queries(interface="eth0", count=10):
    """Capture DNS queries."""
    global dns_queries
    def process_packet(packet):
        if DNS in packet and DNSQR in packet:
            query = packet[DNSQR].qname.decode()
            dns_queries.append({
                "query": query,
                "time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "src_ip": packet[IP].src,
                "resolved_ips": resolve_domain(query)
            })
    try:
        sniff(iface=interface, filter="port 53", prn=process_packet, count=count, timeout=10)
    except Exception as e:
        print(f"DNS capture error: {e}")
    return dns_queries[-100:]

def resolve_domain(domain):
    """Resolve domain to IP addresses."""
    try:
        answers = resolver.resolve(domain, 'A')
        return [str(rdata) for rdata in answers]
    except Exception:
        return []

def detect_anomalies(connections):
    """Detect anomalies based on traffic, reconnects, and resource usage."""
    anomalies = []
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    for conn in connections:
        traffic_threshold = 10_000_000
        reconnect_threshold = 10
        cpu_threshold = 80.0
        memory_threshold = 80.0
        total_traffic = conn['bytes_sent'] + conn['bytes_recv']
        
        if total_traffic > traffic_threshold:
            anomaly = {
                'app_name': conn['app_name'],
                'remote_address': conn['remote_address'],
                'reason': f"High traffic: {total_traffic} bytes",
                'time_of_detection': current_time,
                'bytes_sent': conn['bytes_sent'],
                'bytes_recv': conn['bytes_recv'],
                'city': conn['city'],
                'country': conn['country'],
                'protocol': conn['detailed_protocol'],
                'duration': conn['duration'],
                'reconnect_count': conn['reconnect_count']
            }
            anomalies.append(anomaly)
            socketio.emit('alert', {'message': f"Anomaly detected: {conn['app_name']} with {total_traffic} bytes"})
        
        if conn['reconnect_count'] > reconnect_threshold:
            anomaly = {
                'app_name': conn['app_name'],
                'remote_address': conn['remote_address'],
                'reason': f"High reconnects: {conn['reconnect_count']} times",
                'time_of_detection': current_time,
                'bytes_sent': conn['bytes_sent'],
                'bytes_recv': conn['bytes_recv'],
                'city': conn['city'],
                'country': conn['country'],
                'protocol': conn['detailed_protocol'],
                'duration': conn['duration'],
                'reconnect_count': conn['reconnect_count']
            }
            anomalies.append(anomaly)
            socketio.emit('alert', {'message': f"Anomaly detected: {conn['app_name']} with {conn['reconnect_count']} reconnects"})
        
        if conn['cpu_percent'] > cpu_threshold or conn['memory_percent'] > memory_threshold:
            anomaly = {
                'app_name': conn['app_name'],
                'remote_address': conn['remote_address'],
                'reason': f"High resource usage: CPU {conn['cpu_percent']}%, Memory {conn['memory_percent']}%",
                'time_of_detection': current_time,
                'bytes_sent': conn['bytes_sent'],
                'bytes_recv': conn['bytes_recv'],
                'city': conn['city'],
                'country': conn['country'],
                'protocol': conn['detailed_protocol'],
                'duration': conn['duration'],
                'reconnect_count': conn['reconnect_count']
            }
            anomalies.append(anomaly)
            socketio.emit('alert', {'message': f"Anomaly detected: {conn['app_name']} with high resource usage"})
    
    return anomalies

def detect_port_scanning():
    """Detect potential port scanning."""
    alerts = []
    current_time = time.time()
    scan_threshold = 5
    time_window = 10
    
    for ip, attempts in port_attempts.items():
        recent_attempts = [attempt for attempt in attempts if current_time - attempt[1] < time_window]
        ports = set(attempt[0] for attempt in recent_attempts)
        
        if len(ports) >= scan_threshold:
            alerts.append({
                'remote_ip': ip,
                'ports': list(ports),
                'reason': f"Possible port scan: {len(ports)} ports in {time_window}s"
            })
            socketio.emit('alert', {'message': f"Possible port scan from {ip} on {len(ports)} ports"})
        
        port_attempts[ip] = recent_attempts
    
    return alerts

def get_interface_stats():
    """Get bandwidth usage per network interface and total data usage in GB."""
    try:
        stats = psutil.net_io_counters(pernic=True)
        total_bytes = 0
        interfaces = []
        for iface, data in stats.items():
            total_bytes += data.bytes_sent + data.bytes_recv
            interfaces.append({
                "interface": iface,
                "bytes_sent": data.bytes_sent,
                "bytes_recv": data.bytes_recv,
                "packets_sent": data.packets_sent,
                "packets_recv": data.packets_recv
            })
        total_data_usage_gb = round(total_bytes / 1_000_000_000, 2)
        return {
            "interfaces": interfaces,
            "total_data_usage_gb": total_data_usage_gb
        }
    except Exception as e:
        print(f"Error fetching interface stats: {e}")
        return {"interfaces": [], "total_data_usage_gb": 0}

def identify_protocol(port, protocol):
    """Identify protocol based on port number."""
    common_ports = {
        80: "HTTP", 443: "HTTPS", 53: "DNS",
        22: "SSH", 21: "FTP", 25: "SMTP",
        3389: "RDP", 3306: "MySQL"
    }
    return common_ports.get(port, protocol)

def get_network_data():
    """Fetch network connection data using psutil."""
    global connection_data, disconnected_connections, connection_sessions, anomalies_log
    connections = []
    current_connections = set()
    current_time = time.time()
    protocol_stats = defaultdict(lambda: {"bytes_sent": 0, "bytes_recv": 0, "count": 0})
    
    try:
        for conn in psutil.net_connections(kind='inet'):
            if not conn.pid or not conn.raddr:
                continue
                
            conn_key = (conn.pid, conn.raddr.ip, conn.raddr.port)
            current_connections.add(conn_key)
            
            if conn_key not in connection_times:
                connection_times[conn_key] = current_time
                connection_sessions[conn_key] = {
                    "start_time": datetime.fromtimestamp(current_time).strftime('%Y-%m-%d %H:%M:%S'),
                    "end_time": None,
                    "duration": 0
                }
            
            duration = int(current_time - connection_times[conn_key])
            connection_sessions[conn_key]["duration"] = duration
            
            app_name, app_path, cpu_percent, memory_percent = get_app_info(conn.pid)
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
            geo_info = get_geoip_info(conn.raddr.ip)
            hostname = get_hostname(conn.raddr.ip)
            network_metrics = get_network_metrics(conn.raddr.ip)
            bytes_sent = psutil.net_io_counters().bytes_sent
            bytes_recv = psutil.net_io_counters().bytes_recv
            protocol = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
            detailed_protocol = identify_protocol(conn.raddr.port, protocol)
            
            reconnect_counts[conn.raddr.ip] += 1
            port_attempts[conn.raddr.ip].append((conn.raddr.port, current_time))
            
            protocol_stats[detailed_protocol]["bytes_sent"] += bytes_sent
            protocol_stats[detailed_protocol]["bytes_recv"] += bytes_recv
            protocol_stats[detailed_protocol]["count"] += 1
            
            if app_name not in known_apps and app_name != "Unknown":
                known_apps.add(app_name)
                socketio.emit('alert', {'message': f"New app detected: {app_name}"})
            
            connection = {
                "app_name": app_name,
                "app_path": app_path,
                "pid": conn.pid,
                "local_address": laddr,
                "remote_address": raddr,
                "hostname": hostname,
                "status": conn.status,
                "bytes_sent": bytes_sent,
                "bytes_recv": bytes_recv,
                "city": geo_info.get("city", "N/A"),
                "country": geo_info.get("country", "N/A"),
                "geo": geo_info,
                "protocol": protocol,
                "detailed_protocol": detailed_protocol,
                "duration": duration,
                "reconnect_count": reconnect_counts[conn.raddr.ip],
                "latency_ms": network_metrics["latency_ms"],
                "packet_loss_percent": network_metrics["packet_loss_percent"],
                "time_of_detection": connection_sessions[conn_key]["start_time"],
                "session_status": "Active",
                "end_time": None,
                "is_anonymous": geo_info.get("is_anonymous", False),
                "cpu_percent": cpu_percent,
                "memory_percent": memory_percent
            }
            if connection["is_anonymous"]:
                socketio.emit('alert', {'message': f"Anonymous connection detected from {conn.raddr.ip} (Tor/Proxy)"})
            connections.append(connection)
        
        anomalies_log.extend(detect_anomalies(connections))
        anomalies_log = anomalies_log[-1000:]
        
        for conn_key in list(connection_times):
            if conn_key not in current_connections:
                connection_sessions[conn_key]["end_time"] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                last_conn = next((c for c in connection_data if 
                    c["pid"] == conn_key[0] and 
                    c["remote_address"] == f"{conn_key[1]}:{conn_key[2]}"), None)
                if last_conn:
                    last_conn["session_status"] = "Disconnected"
                    last_conn["duration"] = connection_sessions[conn_key]["duration"]
                    last_conn["end_time"] = connection_sessions[conn_key]["end_time"]
                    disconnected_connections.append(last_conn)
                del connection_times[conn_key]
        
        disconnected_connections = disconnected_connections[-100:]
        
        detect_port_scanning()
        
        socketio.emit('protocol_stats', protocol_stats)
        
    except Exception as e:
        print(f"Error fetching network data: {e}")
    
    return connections

def get_top_apps():
    """Get top 5 apps by total traffic."""
    data = get_network_data()
    app_traffic = defaultdict(int)
    for conn in data:
        app = conn['app_name']
        bytes_total = conn['bytes_sent'] + conn['bytes_recv']
        app_traffic[app] += bytes_total
    sorted_apps = sorted(app_traffic.items(), key=lambda x: x[1], reverse=True)[:5]
    return [{"app_name": app, "traffic": traffic} for app, traffic in sorted_apps]

def background_task():
    """Background task to emit network data every 5 seconds."""
    while True:
        start_time = time.time()
        global connection_data
        connection_data = get_network_data()
        interface_stats = get_interface_stats()
        packets = capture_packets()
        dns_queries = capture_dns_queries()
        payload = {
            'connections': connection_data,
            'disconnected_connections': disconnected_connections,
            'top_apps': get_top_apps(),
            'interfaces': interface_stats["interfaces"],
            'total_data_usage_gb': interface_stats["total_data_usage_gb"],
            'packets': packets,
            'dns_queries': dns_queries
        }
        socketio.emit('traffic_update', payload)
        print(f"Payload size: {sys.getsizeof(json.dumps(payload))} bytes")
        elapsed_time = time.time() - start_time
        sleep_time = max(5 - elapsed_time, 1)
        time.sleep(sleep_time)

@app.before_request
def start_background_task():
    """Start the background task only once."""
    if not hasattr(g, 'initialized'):
        g.initialized = True
        thread = threading.Thread(target=background_task)
        thread.daemon = True
        thread.start()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/connections')
def api_connections():
    return jsonify(get_network_data())

@app.route('/api/interfaces')
def api_interfaces():
    return jsonify(get_interface_stats())

@app.route('/api/packets')
def api_packets():
    return jsonify(capture_packets())

@app.route('/api/dns_queries')
def api_dns_queries():
    queries = capture_dns_queries()
    return jsonify(queries)

@app.route('/api/pie_data')
def api_pie_data():
    """Generate data for pie chart (traffic by app)."""
    data = get_network_data()
    app_traffic = {}
    for conn in data:
        app = conn['app_name']
        bytes_total = conn['bytes_sent'] + conn['bytes_recv']
        app_traffic[app] = app_traffic.get(app, 0) + bytes_total
    return jsonify([
        {"app_name": app, "traffic": traffic}
        for app, traffic in app_traffic.items()
    ])

@app.route('/api/help')
def api_help():
    """Provide metric explanations for tooltips."""
    return jsonify({
        "latency_ms": "Time for a packet to travel to the destination and back. <100ms is good, >200ms is poor.",
        "packet_loss_percent": "Percentage of packets lost. 0% is ideal, >1% disrupts VoIP/streaming.",
        "bytes_sent": "Data sent by the application. High values (>10MB) may indicate heavy usage or anomalies.",
        "bytes_recv": "Data received by the application. High values (>10MB) may indicate heavy usage or anomalies.",
        "reconnect_count": "Reconnection attempts from an IP. >10 in 10s may indicate scanning.",
        "cpu_percent": "CPU usage by the process. >80% may indicate resource-intensive or suspicious activity.",
        "memory_percent": "Memory usage by the process. >80% may indicate resource-intensive or suspicious activity."
    })

@app.route('/api/connections/filter', methods=['POST'])
def filter_connections():
    """Filter connections based on user-provided criteria."""
    filters = request.get_json() or {}
    filtered_connections = connection_data + disconnected_connections
    
    for key, value in filters.items():
        if key in ['app_name', 'remote_address', 'local_address', 'hostname', 'city', 'country', 'protocol', 'detailed_protocol', 'status', 'session_status']:
            value = value.lower()
            filtered_connections = [
                conn for conn in filtered_connections
                if value in str(conn.get(key, '')).lower()
            ]
        elif key in ['pid', 'bytes_sent', 'bytes_recv', 'duration', 'reconnect_count', 'cpu_percent', 'memory_percent']:
            try:
                value = float(value)
                filtered_connections = [
                    conn for conn in filtered_connections
                    if conn.get(key, 0) == value
                ]
            except ValueError:
                continue
    
    return jsonify(filtered_connections)

@app.route('/api/export')
def export_csv():
    """Export connection data as CSV."""
    interface_stats = get_interface_stats()
    output = io.StringIO()
    fieldnames = [
        "app_name", "app_path", "pid", "local_address", "remote_address", "hostname",
        "status", "bytes_sent", "bytes_recv", "city", "country", "protocol", "detailed_protocol",
        "duration", "reconnect_count", "latency_ms", "packet_loss_percent", "time_of_detection",
        "session_status", "end_time", "is_anonymous", "cpu_percent", "memory_percent", "total_data_usage_gb"
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for conn in connection_data + disconnected_connections:
        conn_copy = conn.copy()
        conn_copy["total_data_usage_gb"] = interface_stats["total_data_usage_gb"]
        writer.writerow(conn_copy)
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f"network_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    )

@app.route('/api/export_anomalies')
def export_anomalies_csv():
    """Export anomalies as CSV."""
    interface_stats = get_interface_stats()
    output = io.StringIO()
    fieldnames = [
        "app_name", "remote_address", "reason", "time_of_detection",
        "bytes_sent", "bytes_recv", "city", "country", "protocol",
        "duration", "reconnect_count", "total_data_usage_gb"
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for anomaly in anomalies_log:
        anomaly_copy = anomaly.copy()
        anomaly_copy["total_data_usage_gb"] = interface_stats["total_data_usage_gb"]
        writer.writerow(anomaly_copy)
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f"anomalies_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    )

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)