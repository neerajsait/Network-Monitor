from flask import Flask, render_template
from flask_socketio import SocketIO
import psutil
import socket
import requests
import re
import os
import time
import json
import atexit
import threading
from datetime import datetime
from collections import deque
from ping3 import ping
from scapy.all import get_if_list, sniff, IP, TCP, UDP, Raw, DNSQR, ARP, Ether, srp, conf


def get_default_interface():
    try:
        gateways = psutil.net_if_addrs()
        for iface, addrs in gateways.items():
            for addr in addrs:
                if addr.family == socket.AF_INET and addr.address != '127.0.0.1':
                    if addr.netmask and addr.netmask.startswith('255'):
                        return iface
        for iface in get_if_list():
            if iface != "lo" and "loopback" not in iface.lower():
                return iface
    except:
        pass
    return conf.iface

IFACE = get_default_interface()
print(f"\n[NETWORK] Using Interface: {IFACE}")


app = Flask(__name__)
app.config['SECRET_KEY'] = 'netwatch_ultimate_2025'
IPINFO_TOKEN = os.getenv("IPINFO_TOKEN", "")


socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')


process_cache = {}
geoip_cache = {}
metrics_cache = {}
connection_times = {}
dns_queries = deque(maxlen=60)
session_log = []
lan_devices = []
honey_pot_log = []
scan_in_progress = False  

CACHE_TTL = 3600
METRICS_TTL = 30


def safe_emit(event, data):
    try:
        socketio.emit(event, data)
    except:
        pass


def honey_pot_listener():
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('0.0.0.0', 9999))
        server.listen(5)
        print(f"[HONEY POT] Listening on port 9999")
        while True:
            client, addr = server.accept()
            ip = addr[0]
            msg = f"HONEY POT HIT → {ip}"
            print(msg)
            event = {"time": datetime.now().strftime("%H:%M:%S"), "type": "INTRUSION", "ip": ip}
            session_log.append(event)
            honey_pot_log.append(event)
            safe_emit('alert', {'type': 'danger', 'message': msg})
            client.close()
    except Exception as e:
        print(f"[!] Honey Pot Error: {e}")

threading.Thread(target=honey_pot_listener, daemon=True).start()


def get_app_info(pid):
    if not pid: return "System", "Kernel", 0.0, 0.0
    now = time.time()
    
    if pid in process_cache:
        name, exe, _ = process_cache[pid]
    else:
        try:
            p = psutil.Process(pid)
            name = p.name()
            exe = p.exe() or "N/A"
            process_cache[pid] = (name, exe, now)
        except:
            return "Unknown", "Denied", 0.0, 0.0

    try:
        p = psutil.Process(pid)
        cpu = p.cpu_percent(interval=None)
        mem = p.memory_percent()
        return name, exe, cpu, mem
    except:
        return name, exe, 0.0, 0.0

def get_geoip(ip):
    if ip.startswith(('127.', '192.168.', '10.', '172.', '::1')):
        return {"city": "Local", "country": "LAN", "loc": "0,0", "org": "Private", "is_anonymous": False}
    
    now = time.time()
    if ip in geoip_cache and (now - geoip_cache[ip][1]) < CACHE_TTL:
        return geoip_cache[ip][0]
    
    try:
        url = f"https://ipinfo.io/{ip}/json?token={IPINFO_TOKEN}" if IPINFO_TOKEN else f"http://ip-api.com/json/{ip}"
        r = requests.get(url, timeout=2).json() 
        
        loc = r.get('loc') or f"{r.get('lat',0)},{r.get('lon',0)}"
        data = {
            "city": r.get('city', 'Unknown'),
            "country": r.get('country', r.get('countryCode', '??')),
            "loc": loc,
            "org": r.get('org', ''),
            "is_anonymous": bool(r.get('proxy') or r.get('hosting') or r.get('privacy', {}).get('vpn'))
        }
        geoip_cache[ip] = (data, now)
        return data
    except:
        return {"city": "??", "country": "??", "loc": "0,0", "org": "", "is_anonymous": False}

def get_latency(ip):
    if ip.startswith(('127.', '192.168.', '10.', '172.')): return 0
    now = time.time()
    if ip in metrics_cache and (now - metrics_cache[ip][1]) < METRICS_TTL:
        return metrics_cache[ip][0]
    try:
        lat = ping(ip, unit='ms', timeout=0.5)
        latency = round(lat, 1) if lat else 0
    except: latency = 0
    metrics_cache[ip] = (latency, now)
    return latency

def get_vitals():
    bat = psutil.sensors_battery()
    return {
        "cpu": psutil.cpu_percent(),
        "ram": psutil.virtual_memory().percent,
        "battery": bat.percent if bat else 100
    }

def get_traffic_stats():
    s = psutil.net_io_counters()
    return round((s.bytes_sent + s.bytes_recv) / 1024**3, 2)


def get_network_data():
    connections = []
    active = set()
    now = time.time()

    try:
        for conn in psutil.net_connections(kind='inet'):
            if not conn.raddr or conn.status != 'ESTABLISHED': continue
            
            key = (conn.pid or 0, conn.raddr.ip, conn.raddr.port)
            active.add(key)
            if key not in connection_times: connection_times[key] = now
            
            app_name, exe, cpu, _ = get_app_info(conn.pid)
            geo = get_geoip(conn.raddr.ip)
            latency = get_latency(conn.raddr.ip)
            
            connections.append({
                "app_name": app_name,
                "pid": conn.pid,
                "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}",
                "remote_ip": conn.raddr.ip,
                "country": geo["country"],
                "org": geo["org"],
                "loc": geo["loc"],
                "latency_ms": latency,
                "protocol": "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
                "cpu": round(cpu, 1)
            })
            
        for k in list(connection_times.keys()):
            if k not in active: del connection_times[k]
            
    except: pass
    return connections


def capture_packets():
    if scan_in_progress: return [] 
    packets = []
    def handler(pkt):
        if IP in pkt and Raw in pkt:
            try:
                payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                if re.search(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b', payload):
                    safe_emit('alert', {'type': 'danger', 'message': f"CARD LEAK DETECTED → {pkt[IP].dst}"})
                packets.append({
                    "src": pkt[IP].src,
                    "dst": pkt[IP].dst,
                    "proto": "TCP" if TCP in pkt else "UDP",
                    "payload_preview": payload[:50].replace('\n', ' ')
                })
            except: pass
    try:
        sniff(iface=IFACE, prn=handler, filter="tcp or udp", timeout=0.15, store=False, count=5)
    except: pass
    return packets

def capture_dns():
    if scan_in_progress: return [] 
    def handler(pkt):
        if DNSQR in pkt:
            try:
                q = pkt[DNSQR].qname.decode().rstrip('.')
                dns_queries.append({
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "query": q,
                    "src": pkt[IP].src
                })
            except: pass
    try:
        sniff(iface=IFACE, filter="port 53", prn=handler, timeout=0.15, store=False, count=3)
    except: pass
    return list(dns_queries)[-10:]


def perform_lan_scan_task():
    global scan_in_progress
    if scan_in_progress: return
    scan_in_progress = True

    try:
        safe_emit('alert', {'type': 'info', 'message': 'Scanning LAN... (Hold tight)'})

        
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('8.8.8.8', 1))
            my_ip = s.getsockname()[0]
        except:
            my_ip = '127.0.0.1'
        finally:
            s.close()

        network = '.'.join(my_ip.split('.')[:-1]) + '.0/24'
        
        
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network), timeout=2, verbose=0, iface=IFACE)

        devices = []
        for sent, recv in ans:
            devices.append({"ip": recv.psrc, "mac": recv.hwsrc.upper()})

        global lan_devices
        lan_devices = devices

        safe_emit('lan_update', devices)
        safe_emit('alert', {'type': 'success', 'message': f'Found {len(devices)} devices'})

    except Exception as e:
        safe_emit('alert', {'type': 'danger', 'message': f'Scan failed: {str(e)}'})
    finally:
        scan_in_progress = False

@socketio.on('scan_lan')
def lan_scan():
    if scan_in_progress:
        safe_emit('alert', {'type': 'warning', 'message': 'Scan already in progress!'})
        return
    threading.Thread(target=perform_lan_scan_task, daemon=True).start()

@socketio.on('kill_process')
def kill_process(data):
    try:
        pid = int(data['pid'])
        psutil.Process(pid).terminate()
        safe_emit('alert', {'type': 'success', 'message': f'Killed PID {pid}'})
    except:
        safe_emit('alert', {'type': 'danger', 'message': 'Kill Failed'})


def background_monitor():
    while True:
        try:
            socketio.emit('update', {
                "connections": get_network_data(),
                "packets": capture_packets(),
                "dns_queries": capture_dns(),
                "vitals": get_vitals(),
                "total_data_gb": get_traffic_stats(),
                "lan_devices": lan_devices,
                "honey_pot_hits": len(honey_pot_log),
                "timestamp": datetime.now().strftime("%H:%M:%S")
            })
            time.sleep(0.3)
        except Exception as e:
            print(f"Monitor error: {e}")
            time.sleep(2)

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    threading.Thread(target=background_monitor, daemon=True).start()
    
    print("\n" + "="*60)
    print(" NETWATCH ULTIMATE 2025 :: THREADING MODE ACTIVE")
    print(f" DASHBOARD → http://localhost:5000")
    print("="*60 + "\n")
    
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)
