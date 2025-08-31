from fastapi import FastAPI, APIRouter, WebSocket, WebSocketDisconnect, File, UploadFile, Form, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
import asyncio
import json
import hashlib
import aiofiles
import vt
import aiohttp
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Union
import uuid
from datetime import datetime, timezone
import scapy.all as scapy
import netifaces
import psutil
import socket
import re
from concurrent.futures import ThreadPoolExecutor
import threading
import time
from collections import defaultdict, deque
import magic
from urllib.parse import urlparse

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# VirusTotal API Key
VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY')

# Create upload directory
UPLOAD_DIR = Path("/tmp/cryptopulse_uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

# Create the main app
app = FastAPI()
api_router = APIRouter(prefix="/api")

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except:
                pass

manager = ConnectionManager()

# Enhanced Models
class Device(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    mac_address: str
    ip_address: str
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    device_type: str = "Unknown"
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    risk_score: int = 0
    status: str = "Active"
    is_rogue: bool = False
    is_wifi_threat: bool = False
    authentication_attempts: int = 0
    open_ports: List[int] = Field(default_factory=list)
    connection_count: int = 0
    data_transfer: int = 0
    suspicious_activity: List[str] = Field(default_factory=list)

class MalwareAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    file_hash: str
    filename: str
    file_size: int
    scan_date: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    threat_detected: bool = False
    threat_type: Optional[str] = None
    detection_ratio: str = "0/0"
    scan_results: Dict = Field(default_factory=dict)
    risk_level: str = "Unknown"
    virustotal_link: Optional[str] = None

class URLAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    url: str
    scan_date: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    is_malicious: bool = False
    threat_categories: List[str] = Field(default_factory=list)
    detection_ratio: str = "0/0"
    scan_results: Dict = Field(default_factory=dict)
    risk_level: str = "Unknown"
    virustotal_link: Optional[str] = None

class DOSAlert(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source_ip: str
    target_ip: str
    attack_type: str
    severity: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    packet_count: int = 0
    duration_seconds: float = 0.0
    blocked: bool = False

class NetworkScan(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scan_type: str
    target_network: str
    devices_found: int
    malware_detected: int = 0
    threats_found: int = 0
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    duration_seconds: float
    status: str

class ThreatAlert(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    device_id: Optional[str] = None
    alert_type: str
    severity: str
    description: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    resolved: bool = False
    source_ip: Optional[str] = None
    target: Optional[str] = None

# Enhanced Network Scanner with DoS Detection and Performance Optimization
class EnhancedNetworkScanner:
    def __init__(self):
        self.known_devices = {}
        self.scanning = False
        self.scan_progress = 0
        self.scan_cache = {}  # Cache for recent scan results
        self.cache_timeout = 300  # 5 minutes cache timeout
        self.dos_monitor = DOSMonitor()
        self.wifi_monitor = WiFiThreatMonitor()
        self.malware_scanner = MalwareScanner()
        self.executor = ThreadPoolExecutor(max_workers=8)  # Increased workers for better performance

    def get_network_interfaces(self):
        """Get available network interfaces with caching"""
        cache_key = "network_interfaces"
        current_time = time.time()
        
        # Check cache first
        if cache_key in self.scan_cache:
            cached_time, cached_data = self.scan_cache[cache_key]
            if current_time - cached_time < 60:  # Cache for 1 minute
                return cached_data
        
        interfaces = []
        for interface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addrs:
                for addr_info in addrs[netifaces.AF_INET]:
                    if 'addr' in addr_info and addr_info['addr'] != '127.0.0.1':
                        interfaces.append({
                            'interface': interface,
                            'ip': addr_info['addr'],
                            'netmask': addr_info.get('netmask', '255.255.255.0')
                        })
        
        # Cache the result
        self.scan_cache[cache_key] = (current_time, interfaces)
        return interfaces

    def scan_wifi_networks(self):
        """Enhanced WiFi network scanning for nearby access points"""
        try:
            # This is a simplified version - in production you'd use proper WiFi scanning libraries
            # For now, we'll simulate WiFi network discovery
            wifi_networks = []
            
            # Try to get WiFi interface information
            for interface in netifaces.interfaces():
                if 'wlan' in interface or 'wifi' in interface.lower():
                    # Simulate discovered WiFi networks
                    # In a real implementation, you'd use libraries like pywifi or subprocess calls to iwlist
                    simulated_networks = [
                        {
                            'ssid': 'PublicWiFi-Free',
                            'bssid': '00:1a:2b:3c:4d:5e',
                            'security': 'Open',
                            'signal_strength': -45,
                            'channel': 6,
                            'frequency': '2437 MHz',
                            'encryption': None,
                            'threat_level': 'High',  # Open networks are risky
                            'threats': ['Open Network', 'Potential Honeypot']
                        },
                        {
                            'ssid': 'Home_Network_5G',
                            'bssid': '00:2b:3c:4d:5e:6f',
                            'security': 'WPA2-PSK',
                            'signal_strength': -60,
                            'channel': 36,
                            'frequency': '5180 MHz',
                            'encryption': 'AES',
                            'threat_level': 'Low',
                            'threats': []
                        },
                        {
                            'ssid': 'FREE_INTERNET',
                            'bssid': '00:3c:4d:5e:6f:7a',
                            'security': 'Open',
                            'signal_strength': -70,
                            'channel': 11,
                            'frequency': '2462 MHz',
                            'encryption': None,
                            'threat_level': 'Critical',
                            'threats': ['Suspicious SSID', 'Open Network', 'Potential Evil Twin']
                        }
                    ]
                    wifi_networks.extend(simulated_networks)
            
            return wifi_networks
            
        except Exception as e:
            logging.error(f"WiFi scanning error: {e}")
            return []

    def analyze_wifi_security(self, networks):
        """Analyze WiFi networks for security threats"""
        threats_found = []
        
        for network in networks:
            network_threats = []
            
            # Check for open networks
            if network.get('security') == 'Open':
                network_threats.append('Open Network - No Encryption')
                network['threat_level'] = 'High'
            
            # Check for suspicious SSIDs
            suspicious_ssids = ['free', 'wifi', 'internet', 'guest', 'public', 'hotspot']
            ssid_lower = network.get('ssid', '').lower()
            if any(term in ssid_lower for term in suspicious_ssids):
                network_threats.append('Suspicious SSID Pattern')
                if network.get('threat_level') == 'Low':
                    network['threat_level'] = 'Medium'
            
            # Check for weak encryption
            if network.get('security') in ['WEP', 'WPA']:
                network_threats.append('Weak Encryption Protocol')
                network['threat_level'] = 'Medium'
            
            # Check signal strength (very strong signals from unknown networks could be suspicious)
            if network.get('signal_strength', -100) > -30:
                network_threats.append('Unusually Strong Signal')
            
            # Update network with threats
            network['threats'] = network_threats
            if network_threats:
                threats_found.extend(network_threats)
        
        return threats_found

    def parallel_port_scan(self, ip_address, ports=None):
        """Optimized parallel port scanning"""
        if ports is None:
            ports = [22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443]
        
        def scan_port(port):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)  # Faster timeout
            try:
                result = sock.connect_ex((ip_address, port))
                return port if result == 0 else None
            except:
                return None
            finally:
                sock.close()
        
        # Use ThreadPoolExecutor for parallel port scanning
        open_ports = []
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_port = {executor.submit(scan_port, port): port for port in ports}
            for future in future_to_port:
                result = future.result()
                if result:
                    open_ports.append(result)
        
        return sorted(open_ports)

    def calculate_network_range(self, ip, netmask):
        """Calculate network range for scanning"""
        try:
            import ipaddress
            network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
            return str(network.network_address) + "/" + str(network.prefixlen)
        except:
            # Fallback to /24 network
            ip_parts = ip.split('.')
            return f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"

    def perform_arp_scan(self, network_range):
        """Perform ARP scan to discover devices"""
        try:
            # Create ARP request
            arp_request = scapy.ARP(pdst=network_range)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            
            # Send request and receive response
            answered_list = scapy.srp(arp_request_broadcast, timeout=3, verbose=False)[0]
            
            devices = []
            for element in answered_list:
                device_dict = {
                    "ip": element[1].psrc,
                    "mac": element[1].hwsrc,
                    "hostname": self.get_hostname(element[1].psrc)
                }
                devices.append(device_dict)
            
            return devices
        except Exception as e:
            logging.error(f"ARP scan error: {e}")
            return []

    def get_hostname(self, ip):
        """Get hostname for IP address"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return None

    def detect_device_type(self, mac, hostname, open_ports):
        """Enhanced device type detection"""
        mac_vendors = {
            "Apple": ["00:03:93", "00:05:02", "00:0a:95", "00:0d:93", "a4:c3:61", "28:cf:e9"],
            "Samsung": ["00:07:ab", "00:0d:e5", "00:12:fb", "00:15:b9", "08:ec:a9"],
            "Router": ["00:1b:2f", "00:1e:58", "00:22:6b", "d8:50:e6", "ac:86:74"],
            "Printer": ["00:00:48", "00:01:e6", "00:04:76", "18:cc:18"],
            "IoT": ["b8:27:eb", "dc:a6:32", "e4:5f:01"],
            "Gaming": ["00:0c:76", "00:15:5d", "00:50:f2"]
        }
        
        # Check MAC address vendor
        mac_prefix = mac[:8].upper()
        for device_type, prefixes in mac_vendors.items():
            for prefix in prefixes:
                if mac_prefix.startswith(prefix.upper()):
                    return device_type
        
        # Check hostname patterns
        if hostname:
            hostname_lower = hostname.lower()
            if any(term in hostname_lower for term in ["router", "gateway", "ap", "access"]):
                return "Router"
            elif any(term in hostname_lower for term in ["printer", "canon", "hp", "epson"]):
                return "Printer"
            elif any(term in hostname_lower for term in ["iphone", "android", "mobile", "samsung"]):
                return "Mobile"
            elif any(term in hostname_lower for term in ["pi", "raspberry", "arduino", "esp"]):
                return "IoT"
        
        # Check open ports for device classification
        if 80 in open_ports or 443 in open_ports:
            if 22 in open_ports:
                return "Server"
            return "IoT/Camera"
        elif 22 in open_ports:
            return "Linux/Server"
        elif 135 in open_ports or 445 in open_ports:
            return "Windows"
        elif 21 in open_ports:
            return "FTP Server"
        
        return "Unknown"

    def calculate_risk_score(self, device, is_new=False):
        """Enhanced risk scoring with WiFi and DoS factors"""
        risk_score = 0
        
        # New device penalty
        if is_new:
            risk_score += 25
        
        # WiFi threat detection
        if device.get("is_wifi_threat"):
            risk_score += 40
        
        # Unknown device type penalty
        if device.get("device_type") == "Unknown":
            risk_score += 20
        
        # No hostname penalty (could indicate stealth device)
        if not device.get("hostname"):
            risk_score += 15
        
        # Multiple open ports penalty
        open_ports_count = len(device.get("open_ports", []))
        if open_ports_count > 10:
            risk_score += 30
        elif open_ports_count > 5:
            risk_score += 20
        elif open_ports_count > 0:
            risk_score += 10
        
        # High connection count (potential bot/scanner)
        connection_count = device.get("connection_count", 0)
        if connection_count > 100:
            risk_score += 25
        elif connection_count > 50:
            risk_score += 15
        
        # Suspicious activity penalty
        suspicious_activities = len(device.get("suspicious_activity", []))
        if suspicious_activities > 0:
            risk_score += suspicious_activities * 15
        
        return min(max(risk_score, 0), 100)

    def quick_port_scan(self, ip, common_ports=[22, 23, 53, 80, 135, 139, 443, 445, 993, 995, 8080, 3389, 5900]):
        """Enhanced port scan with more ports - DEPRECATED: Use parallel_port_scan instead"""
        return self.parallel_port_scan(ip, common_ports)

    def detect_wifi_threats(self, device_data):
        """Detect WiFi-related threats"""
        threats = []
        mac = device_data.get("mac", "")
        hostname = device_data.get("hostname", "")
        
        # Check for rogue access points
        if any(term in hostname.lower() if hostname else "" for term in ["ap", "access", "point", "hotspot"]):
            threats.append("Potential Rogue Access Point")
        
        # Check for suspicious MAC addresses (randomized/spoofed)
        if mac.startswith("02:") or mac.startswith("06:") or mac.startswith("0a:") or mac.startswith("0e:"):
            threats.append("Randomized MAC Address")
        
        # Check for evil twin detection patterns
        if hostname and any(term in hostname.lower() for term in ["free", "wifi", "guest", "public"]):
            threats.append("Suspicious Access Point Name")
        
        return threats

    def is_suspicious_device(self, device_data, open_ports):
        """Enhanced suspicious device detection"""
        suspicious_indicators = 0
        
        # No hostname (stealth device)
        if not device_data.get("hostname"):
            suspicious_indicators += 1
        
        # Too many open ports (scanning/bot behavior)
        if len(open_ports) > 15:
            suspicious_indicators += 2
        
        # Suspicious port combinations
        if 22 in open_ports and 80 in open_ports and 443 in open_ports:
            suspicious_indicators += 1
        
        # Check for common malware ports
        malware_ports = [4444, 5554, 9999, 31337, 12345, 54321]
        if any(port in open_ports for port in malware_ports):
            suspicious_indicators += 2
        
        # WiFi threat indicators
        wifi_threats = self.detect_wifi_threats(device_data)
        if wifi_threats:
            suspicious_indicators += len(wifi_threats)
        
        return suspicious_indicators >= 2

    def prepare_for_mongo(self, data):
        """Prepare data for MongoDB storage"""
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, datetime):
                    data[key] = value.isoformat()
                elif isinstance(value, list) and value and isinstance(value[0], datetime):
                    data[key] = [v.isoformat() if isinstance(v, datetime) else v for v in value]
        return data

    async def scan_network(self):
        """Enhanced network scanning with threat detection and performance optimization"""
        if self.scanning:
            return {"status": "already_scanning"}
        
        self.scanning = True
        self.scan_progress = 0
        scan_start = datetime.now(timezone.utc)
        
        try:
            # Broadcast scan start
            await manager.broadcast(json.dumps({
                "type": "scan_started",
                "progress": 0,
                "message": "Starting network discovery..."
            }))
            
            # Get network interfaces with caching
            interfaces = self.get_network_interfaces()
            if not interfaces:
                return {"status": "no_interfaces"}
            
            all_devices = []
            malware_count = 0
            threats_count = 0
            wifi_networks = []
            wifi_threats = []
            
            self.scan_progress = 10
            await manager.broadcast(json.dumps({
                "type": "scan_progress", 
                "progress": self.scan_progress,
                "message": "Scanning WiFi networks..."
            }))
            
            # Enhanced WiFi Network Scanning
            try:
                wifi_networks = self.scan_wifi_networks()
                wifi_threats = self.analyze_wifi_security(wifi_networks)
                logging.info(f"Found {len(wifi_networks)} WiFi networks with {len(wifi_threats)} threats")
            except Exception as e:
                logging.error(f"WiFi scanning error: {e}")
            
            # Start DoS monitoring in background
            self.dos_monitor.start_monitoring()
            
            self.scan_progress = 20
            await manager.broadcast(json.dumps({
                "type": "scan_progress", 
                "progress": self.scan_progress,
                "message": "Discovering network devices..."
            }))
            
            # Scan each interface (optimized)
            for idx, interface_info in enumerate(interfaces[:2]):  # Limit to 2 interfaces for performance
                network_range = self.calculate_network_range(
                    interface_info['ip'], 
                    interface_info['netmask']
                )
                
                # Perform enhanced ARP scan with progress updates
                devices = await self.perform_optimized_arp_scan(network_range)
                
                self.scan_progress = 30 + (idx * 20)
                await manager.broadcast(json.dumps({
                    "type": "scan_progress", 
                    "progress": self.scan_progress,
                    "message": f"Analyzing {len(devices)} discovered devices..."
                }))
                
                # Process discovered devices in parallel batches
                batch_size = 5
                for i in range(0, len(devices), batch_size):
                    device_batch = devices[i:i+batch_size]
                    
                    # Process batch in parallel
                    batch_futures = []
                    for device_data in device_batch:
                        future = self.executor.submit(self.process_single_device, device_data)
                        batch_futures.append((future, device_data))
                    
                    # Collect results
                    for future, device_data in batch_futures:
                        try:
                            device_info = future.result(timeout=10)  # 10 second timeout per device
                            if device_info:
                                all_devices.append(device_info)
                                self.known_devices[device_info["mac_address"]] = device_info
                                
                                # Count threats
                                if device_info.get("is_rogue") or device_info.get("is_wifi_threat"):
                                    threats_count += 1
                                    
                        except Exception as e:
                            logging.error(f"Device processing error for {device_data}: {e}")
                    
                    # Update progress
                    progress = min(50 + int((i / len(devices)) * 30), 80)
                    self.scan_progress = progress
                    await manager.broadcast(json.dumps({
                        "type": "scan_progress", 
                        "progress": self.scan_progress,
                        "message": f"Processed {min(i + batch_size, len(devices))} of {len(devices)} devices..."
                    }))
            
            self.scan_progress = 85
            await manager.broadcast(json.dumps({
                "type": "scan_progress", 
                "progress": self.scan_progress,
                "message": "Finalizing threat analysis..."
            }))
            
            # Stop DoS monitoring
            dos_alerts = self.dos_monitor.stop_monitoring()
            
            # Update all devices in database
            await self.batch_update_devices(all_devices)
            
            # Create enhanced scan record
            scan_duration = (datetime.now(timezone.utc) - scan_start).total_seconds()
            scan_record = NetworkScan(
                scan_type="Enhanced_ARP_Discovery_v2",
                target_network=network_range if 'network_range' in locals() else "auto-detected",
                devices_found=len(all_devices),
                malware_detected=malware_count,
                threats_found=threats_count + len(wifi_threats),
                duration_seconds=scan_duration,
                status="Completed"
            )
            
            # Save scan to database
            await db.network_scans.insert_one(self.prepare_for_mongo(scan_record.dict()))
            
            self.scan_progress = 100
            # Broadcast final results with enhanced data
            broadcast_data = {
                "type": "enhanced_scan_complete",
                "devices": all_devices,
                "wifi_networks": wifi_networks,
                "wifi_threats": wifi_threats,
                "threats_found": threats_count + len(wifi_threats),
                "dos_alerts": len(dos_alerts),
                "scan_info": self.prepare_for_mongo(scan_record.dict()),
                "progress": 100
            }
            await manager.broadcast(json.dumps(broadcast_data))
            
            return {
                "status": "completed",
                "devices_found": len(all_devices),
                "wifi_networks_found": len(wifi_networks),
                "threats_found": threats_count + len(wifi_threats),
                "scan_duration": scan_duration
            }
            
        except Exception as e:
            logging.error(f"Enhanced network scan error: {e}")
            await manager.broadcast(json.dumps({
                "type": "scan_error",
                "error": str(e),
                "progress": 0
            }))
            return {"status": "error", "message": str(e)}
        finally:
            self.scanning = False
            self.scan_progress = 0

    def process_single_device(self, device_data):
        """Process a single device for optimization"""
        try:
            mac = device_data["mac"]
            is_new_device = mac not in self.known_devices
            
            # Enhanced port scan with timeout
            open_ports = self.parallel_port_scan(device_data["ip"])
            
            # WiFi threat detection
            wifi_threats = self.detect_wifi_threats(device_data)
            
            # Device type detection
            device_type = self.detect_device_type(
                mac, device_data["hostname"], open_ports
            )
            
            # Create enhanced device object
            device_info = {
                "mac_address": mac,
                "ip_address": device_data["ip"],
                "hostname": device_data["hostname"],
                "device_type": device_type,
                "open_ports": open_ports,
                "is_wifi_threat": len(wifi_threats) > 0,
                "suspicious_activity": wifi_threats,
                "connection_count": len(open_ports) * 2,  # Estimated
                "is_rogue": is_new_device and self.is_suspicious_device(device_data, open_ports)
            }
            
            # Calculate enhanced risk score
            device_info["risk_score"] = self.calculate_risk_score(device_info, is_new_device)
            
            return device_info
            
        except Exception as e:
            logging.error(f"Single device processing error: {e}")
            return None

    async def perform_optimized_arp_scan(self, network_range):
        """Optimized ARP scan with better performance"""
        try:
            # Use asyncio for better performance
            loop = asyncio.get_event_loop()
            devices = await loop.run_in_executor(
                self.executor, 
                self.perform_arp_scan, 
                network_range
            )
            return devices
        except Exception as e:
            logging.error(f"Optimized ARP scan error: {e}")
            return []

    async def batch_update_devices(self, all_devices):
        """Batch update devices for better database performance"""
        try:
            for device_info in all_devices:
                mac = device_info["mac_address"]
                is_new_device = mac not in self.known_devices or not await db.devices.find_one({"mac_address": mac})
                
                if is_new_device:
                    device = Device(**device_info)
                    await db.devices.insert_one(self.prepare_for_mongo(device.dict()))
                    
                    # Create alerts for threats (optimized)
                    await self.create_threat_alerts(device_info, device.id)
                else:
                    # Bulk update existing device
                    await db.devices.update_one(
                        {"mac_address": mac},
                        {
                            "$set": {
                                "last_seen": datetime.now(timezone.utc).isoformat(),
                                "ip_address": device_info["ip_address"],
                                "hostname": device_info["hostname"],
                                "open_ports": device_info["open_ports"],
                                "risk_score": device_info["risk_score"],
                                "is_wifi_threat": device_info["is_wifi_threat"],
                                "suspicious_activity": device_info["suspicious_activity"],
                                "connection_count": device_info["connection_count"]
                            }
                        }
                    )
        except Exception as e:
            logging.error(f"Batch device update error: {e}")

    async def create_threat_alerts(self, device_info, device_id):
        """Create threat alerts for new devices"""
        try:
            alerts_to_create = []
            
            if device_info.get("is_rogue"):
                alert = ThreatAlert(
                    device_id=device_id,
                    alert_type="Rogue Device Detected",
                    severity="High" if device_info["risk_score"] > 70 else "Medium",
                    description=f"Potentially rogue device detected: {device_info['ip_address']} ({device_info['mac_address']})",
                    source_ip=device_info['ip_address']
                )
                alerts_to_create.append(self.prepare_for_mongo(alert.dict()))
            
            if device_info.get("is_wifi_threat"):
                alert = ThreatAlert(
                    device_id=device_id,
                    alert_type="WiFi Threat Detected",
                    severity="High",
                    description=f"WiFi threat detected: {', '.join(device_info.get('suspicious_activity', []))}",
                    source_ip=device_info['ip_address']
                )
                alerts_to_create.append(self.prepare_for_mongo(alert.dict()))
            
            # Batch insert alerts
            if alerts_to_create:
                await db.threat_alerts.insert_many(alerts_to_create)
                
        except Exception as e:
            logging.error(f"Alert creation error: {e}")

    async def update_device_database(self, device_info, is_new):
        """Update device information in database with threat alerts"""
        try:
            mac = device_info["mac_address"]
            
            if is_new:
                device = Device(**device_info)
                await db.devices.insert_one(self.prepare_for_mongo(device.dict()))
                
                # Create alerts for threats
                if device_info.get("is_rogue"):
                    alert = ThreatAlert(
                        device_id=device.id,
                        alert_type="Rogue Device Detected",
                        severity="High" if device_info["risk_score"] > 70 else "Medium",
                        description=f"Potentially rogue device detected: {device_info['ip_address']} ({mac})",
                        source_ip=device_info['ip_address']
                    )
                    await db.threat_alerts.insert_one(self.prepare_for_mongo(alert.dict()))
                
                if device_info.get("is_wifi_threat"):
                    alert = ThreatAlert(
                        device_id=device.id,
                        alert_type="WiFi Threat Detected",
                        severity="High",
                        description=f"WiFi threat detected: {', '.join(device_info.get('suspicious_activity', []))}",
                        source_ip=device_info['ip_address']
                    )
                    await db.threat_alerts.insert_one(self.prepare_for_mongo(alert.dict()))
            else:
                # Update existing device
                await db.devices.update_one(
                    {"mac_address": mac},
                    {
                        "$set": {
                            "last_seen": datetime.now(timezone.utc).isoformat(),
                            "ip_address": device_info["ip_address"],
                            "hostname": device_info["hostname"],
                            "open_ports": device_info["open_ports"],
                            "risk_score": device_info["risk_score"],
                            "is_wifi_threat": device_info["is_wifi_threat"],
                            "suspicious_activity": device_info["suspicious_activity"],
                            "connection_count": device_info["connection_count"]
                        }
                    }
                )
        except Exception as e:
            logging.error(f"Database update error: {e}")

# DoS Attack Monitor
class DOSMonitor:
    def __init__(self):
        self.monitoring = False
        self.packet_counts = defaultdict(int)
        self.connection_attempts = defaultdict(list)
        self.alerts = []

    def start_monitoring(self):
        """Start DoS monitoring"""
        self.monitoring = True
        self.packet_counts.clear()
        self.connection_attempts.clear()
        self.alerts.clear()

    def stop_monitoring(self):
        """Stop monitoring and return alerts"""
        self.monitoring = False
        return self.alerts

    def analyze_traffic_patterns(self, source_ip, packet_type):
        """Analyze traffic for DoS patterns"""
        current_time = time.time()
        
        # Count packets per IP
        self.packet_counts[source_ip] += 1
        
        # Track connection attempts
        self.connection_attempts[source_ip].append(current_time)
        
        # Remove old entries (older than 60 seconds)
        self.connection_attempts[source_ip] = [
            t for t in self.connection_attempts[source_ip] 
            if current_time - t <= 60
        ]
        
        # Check for DoS patterns
        packet_count = self.packet_counts[source_ip]
        recent_connections = len(self.connection_attempts[source_ip])
        
        # High packet rate detection
        if packet_count > 100:  # Threshold for suspicious activity
            alert = DOSAlert(
                source_ip=source_ip,
                target_ip="network",
                attack_type="High Packet Rate",
                severity="Medium" if packet_count < 500 else "High",
                packet_count=packet_count,
                duration_seconds=60.0
            )
            self.alerts.append(alert)
        
        # SYN flood detection (high connection attempts)
        if recent_connections > 50:
            alert = DOSAlert(
                source_ip=source_ip,
                target_ip="network",
                attack_type="SYN Flood",
                severity="High",
                packet_count=recent_connections,
                duration_seconds=60.0
            )
            self.alerts.append(alert)

# WiFi Threat Monitor
class WiFiThreatMonitor:
    def __init__(self):
        self.known_access_points = {}
        self.rogue_aps = []

    def detect_rogue_access_points(self, device_info):
        """Detect rogue access points"""
        threats = []
        
        # Check for access point indicators
        if device_info.get("device_type") == "Router":
            # Check if this is a known legitimate AP
            mac = device_info["mac_address"]
            if mac not in self.known_access_points:
                threats.append("Unknown Access Point")
        
        return threats

    def check_evil_twin(self, ssid, mac):
        """Check for evil twin attacks"""
        # Implementation for evil twin detection
        # This would compare SSIDs with different MAC addresses
        pass

# Enhanced Malware Scanner with VirusTotal Integration
class MalwareScanner:
    def __init__(self):
        self.vt_api_key = VIRUSTOTAL_API_KEY
        self.executor = ThreadPoolExecutor(max_workers=4)
        
    def get_vt_client(self):
        """Get a new VirusTotal client for thread-safe operations"""
        if self.vt_api_key:
            return vt.Client(self.vt_api_key)
        return None

    async def scan_file(self, file_path: str, filename: str) -> MalwareAnalysis:
        """Scan file with VirusTotal using thread-safe approach"""
        try:
            # Calculate file hashes
            file_hash = await self.calculate_file_hash(file_path)
            file_size = os.path.getsize(file_path)
            
            if not self.vt_api_key:
                # Fallback analysis without VirusTotal
                return MalwareAnalysis(
                    file_hash=file_hash,
                    filename=filename,
                    file_size=file_size,
                    threat_detected=False,
                    risk_level="Unknown",
                    detection_ratio="0/0",
                    scan_results={"error": "VirusTotal not available"}
                )
            
            # Check if file exists in VirusTotal database using thread-safe approach
            try:
                def get_file_object():
                    with vt.Client(self.vt_api_key) as client:
                        return client.get_object(f"/files/{file_hash}")
                
                file_obj = await asyncio.get_event_loop().run_in_executor(
                    self.executor, get_file_object
                )
                
                # Parse scan results
                analysis_result = self.parse_vt_results(file_obj, file_hash, filename, file_size)
                
            except vt.APIError as e:
                if e.code == "NotFoundError":
                    # File not in database, submit for scanning
                    analysis_result = await self.submit_file_for_scanning(file_path, file_hash, filename, file_size)
                else:
                    raise e
            
            return analysis_result
            
        except Exception as e:
            logging.error(f"File scan error: {e}")
            return MalwareAnalysis(
                file_hash=file_hash if 'file_hash' in locals() else "unknown",
                filename=filename,
                file_size=file_size if 'file_size' in locals() else 0,
                threat_detected=False,
                risk_level="Error",
                detection_ratio="0/0",
                scan_results={"error": str(e)}
            )

    async def submit_file_for_scanning(self, file_path: str, file_hash: str, filename: str, file_size: int):
        """Submit new file to VirusTotal for scanning using thread-safe approach"""
        try:
            # Submit file
            def submit_file():
                with vt.Client(self.vt_api_key) as client:
                    with open(file_path, "rb") as f:
                        return client.scan_file(f)
            
            analysis = await asyncio.get_event_loop().run_in_executor(
                self.executor, submit_file
            )
            
            # Wait for analysis to complete (with timeout)
            max_wait = 300  # 5 minutes
            wait_time = 0
            
            while wait_time < max_wait:
                try:
                    def get_file_object():
                        with vt.Client(self.vt_api_key) as client:
                            return client.get_object(f"/files/{file_hash}")
                    
                    file_obj = await asyncio.get_event_loop().run_in_executor(
                        self.executor, get_file_object
                    )
                    
                    if hasattr(file_obj, 'last_analysis_stats'):
                        return self.parse_vt_results(file_obj, file_hash, filename, file_size)
                    
                    await asyncio.sleep(10)
                    wait_time += 10
                    
                except vt.APIError:
                    await asyncio.sleep(10)
                    wait_time += 10
            
            # Timeout - return partial results
            return MalwareAnalysis(
                file_hash=file_hash,
                filename=filename,
                file_size=file_size,
                threat_detected=False,
                risk_level="Pending",
                detection_ratio="0/0",
                scan_results={"status": "Analysis in progress"},
                virustotal_link=f"https://www.virustotal.com/gui/file/{file_hash}"
            )
            
        except Exception as e:
            logging.error(f"File submission error: {e}")
            return MalwareAnalysis(
                file_hash=file_hash,
                filename=filename,
                file_size=file_size,
                threat_detected=False,
                risk_level="Error",
                detection_ratio="0/0",
                scan_results={"error": str(e)}
            )

    def parse_vt_results(self, file_obj, file_hash: str, filename: str, file_size: int) -> MalwareAnalysis:
        """Parse VirusTotal analysis results"""
        try:
            stats = file_obj.last_analysis_stats
            results = file_obj.last_analysis_results
            
            malicious_count = stats.get('malicious', 0)
            total_engines = sum(stats.values())
            
            threat_detected = malicious_count > 0
            detection_ratio = f"{malicious_count}/{total_engines}"
            
            # Determine risk level
            if malicious_count == 0:
                risk_level = "Clean"
            elif malicious_count <= 2:
                risk_level = "Low"
            elif malicious_count <= 5:
                risk_level = "Medium"
            else:
                risk_level = "High"
            
            # Extract threat type from results
            threat_type = None
            if threat_detected and results:
                for engine, result in results.items():
                    if result.get('category') == 'malicious' and result.get('result'):
                        threat_type = result['result']
                        break
            
            return MalwareAnalysis(
                file_hash=file_hash,
                filename=filename,
                file_size=file_size,
                threat_detected=threat_detected,
                threat_type=threat_type,
                detection_ratio=detection_ratio,
                risk_level=risk_level,
                scan_results={
                    'stats': stats,
                    'engines_detected': malicious_count,
                    'total_engines': total_engines
                },
                virustotal_link=f"https://www.virustotal.com/gui/file/{file_hash}"
            )
            
        except Exception as e:
            logging.error(f"Result parsing error: {e}")
            return MalwareAnalysis(
                file_hash=file_hash,
                filename=filename,
                file_size=file_size,
                threat_detected=False,
                risk_level="Error",
                detection_ratio="0/0",
                scan_results={"error": str(e)}
            )

    async def scan_url(self, url: str) -> URLAnalysis:
        """Scan URL with VirusTotal using thread-safe approach"""
        try:
            if not self.vt_api_key:
                return URLAnalysis(
                    url=url,
                    is_malicious=False,
                    risk_level="Unknown",
                    detection_ratio="0/0",
                    scan_results={"error": "VirusTotal not available"}
                )
            
            # Submit URL for analysis
            def submit_url():
                with vt.Client(self.vt_api_key) as client:
                    return client.scan_url(url)
            
            analysis = await asyncio.get_event_loop().run_in_executor(
                self.executor, submit_url
            )
            
            # Get URL ID for checking results
            url_id = vt.url_id(url)
            
            # Wait for analysis
            await asyncio.sleep(5)  # Give some time for analysis
            
            try:
                def get_url_object():
                    with vt.Client(self.vt_api_key) as client:
                        return client.get_object(f"/urls/{url_id}")
                
                url_obj = await asyncio.get_event_loop().run_in_executor(
                    self.executor, get_url_object
                )
                
                return self.parse_url_results(url_obj, url)
                
            except vt.APIError as e:
                if e.code == "NotFoundError":
                    # URL analysis not ready yet
                    return URLAnalysis(
                        url=url,
                        is_malicious=False,
                        risk_level="Pending",
                        detection_ratio="0/0",
                        scan_results={"status": "Analysis in progress"},
                        virustotal_link=f"https://www.virustotal.com/gui/url/{url_id}"
                    )
                else:
                    raise e
            
        except Exception as e:
            logging.error(f"URL scan error: {e}")
            return URLAnalysis(
                url=url,
                is_malicious=False,
                risk_level="Error",
                detection_ratio="0/0",
                scan_results={"error": str(e)}
            )

    def parse_url_results(self, url_obj, url: str) -> URLAnalysis:
        """Parse VirusTotal URL analysis results"""
        try:
            stats = url_obj.last_analysis_stats
            results = url_obj.last_analysis_results
            
            malicious_count = stats.get('malicious', 0)
            suspicious_count = stats.get('suspicious', 0)
            total_engines = sum(stats.values())
            
            is_malicious = malicious_count > 0 or suspicious_count > 2
            detection_ratio = f"{malicious_count + suspicious_count}/{total_engines}"
            
            # Extract threat categories
            threat_categories = []
            if results:
                for engine, result in results.items():
                    if result.get('category') in ['malicious', 'suspicious']:
                        if result.get('result') and result['result'] not in threat_categories:
                            threat_categories.append(result['result'])
            
            # Determine risk level
            if malicious_count > 5:
                risk_level = "High"
            elif malicious_count > 0 or suspicious_count > 3:
                risk_level = "Medium"
            elif suspicious_count > 0:
                risk_level = "Low"
            else:
                risk_level = "Clean"
            
            url_id = vt.url_id(url)
            
            return URLAnalysis(
                url=url,
                is_malicious=is_malicious,
                threat_categories=threat_categories,
                detection_ratio=detection_ratio,
                risk_level=risk_level,
                scan_results={
                    'stats': stats,
                    'malicious_count': malicious_count,
                    'suspicious_count': suspicious_count,
                    'total_engines': total_engines
                },
                virustotal_link=f"https://www.virustotal.com/gui/url/{url_id}"
            )
            
        except Exception as e:
            logging.error(f"URL result parsing error: {e}")
            return URLAnalysis(
                url=url,
                is_malicious=False,
                risk_level="Error",
                detection_ratio="0/0",
                scan_results={"error": str(e)}
            )

    async def calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of file"""
        hash_sha256 = hashlib.sha256()
        async with aiofiles.open(file_path, 'rb') as f:
            async for chunk in f:
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()

    def __del__(self):
        """Cleanup resources"""
        if hasattr(self, 'executor'):
            try:
                self.executor.shutdown(wait=False)
            except:
                pass

# Security Inbox for URL Management
class SecurityInbox:
    def __init__(self, malware_scanner):
        self.malware_scanner = malware_scanner
        self.inbox_cache = {}
        
    async def add_url_to_inbox(self, url: str, user_note: str = None):
        """Add URL to security inbox for analysis"""
        try:
            # Check if URL already exists in inbox
            existing = await db.security_inbox.find_one({"url": url})
            if existing:
                return {"status": "exists", "id": existing["id"]}
            
            # Create inbox entry
            inbox_entry = {
                "id": str(uuid.uuid4()),
                "url": url,
                "user_note": user_note,
                "added_date": datetime.now(timezone.utc).isoformat(),
                "scan_status": "pending",
                "scan_result": None,
                "threat_detected": False,
                "priority": "medium"
            }
            
            # Insert into database
            await db.security_inbox.insert_one(inbox_entry)
            
            return {"status": "added", "id": inbox_entry["id"]}
            
        except Exception as e:
            logging.error(f"Error adding URL to inbox: {e}")
            return {"status": "error", "message": str(e)}
    
    async def scan_inbox_url(self, inbox_id: str):
        """Scan a URL from the inbox"""
        try:
            # Get inbox entry
            entry = await db.security_inbox.find_one({"id": inbox_id})
            if not entry:
                return {"status": "not_found"}
            
            # Update scan status
            await db.security_inbox.update_one(
                {"id": inbox_id},
                {"$set": {"scan_status": "scanning"}}
            )
            
            # Perform URL scan
            scan_result = await self.malware_scanner.scan_url(entry["url"])
            
            # Update inbox entry with results
            await db.security_inbox.update_one(
                {"id": inbox_id},
                {
                    "$set": {
                        "scan_status": "completed",
                        "scan_result": self.prepare_for_mongo(scan_result.dict()),
                        "threat_detected": scan_result.is_malicious,
                        "scanned_date": datetime.now(timezone.utc).isoformat(),
                        "priority": "high" if scan_result.is_malicious else "low"
                    }
                }
            )
            
            # Also save to regular URL analyses
            await db.url_analyses.insert_one(self.prepare_for_mongo(scan_result.dict()))
            
            return {"status": "scanned", "result": scan_result.dict()}
            
        except Exception as e:
            logging.error(f"Error scanning inbox URL: {e}")
            return {"status": "error", "message": str(e)}
    
    async def get_inbox_entries(self, status: str = None, limit: int = 50):
        """Get inbox entries with optional filtering"""
        try:
            query = {}
            if status:
                query["scan_status"] = status
            
            entries = await db.security_inbox.find(query).sort("added_date", -1).limit(limit).to_list(limit)
            # Remove MongoDB ObjectId fields for JSON serialization
            for entry in entries:
                if '_id' in entry:
                    del entry['_id']
            return entries
            
        except Exception as e:
            logging.error(f"Error fetching inbox entries: {e}")
            return []
    
    async def batch_scan_urls(self, urls: list):
        """Batch scan multiple URLs"""
        results = []
        
        for url in urls:
            # Add to inbox
            add_result = await self.add_url_to_inbox(url, "Batch scan")
            if add_result["status"] in ["added", "exists"]:
                # Scan the URL
                scan_result = await self.scan_inbox_url(add_result["id"])
                results.append({
                    "url": url,
                    "status": scan_result["status"],
                    "threat_detected": scan_result.get("result", {}).get("is_malicious", False)
                })
        
        return results
    
    def prepare_for_mongo(self, data):
        """Prepare data for MongoDB storage"""
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, datetime):
                    data[key] = value.isoformat()
                elif isinstance(value, list) and value and isinstance(value[0], datetime):
                    data[key] = [v.isoformat() if isinstance(v, datetime) else v for v in value]
        return data

# Initialize enhanced scanners
network_scanner = EnhancedNetworkScanner()
malware_scanner = MalwareScanner()

# Initialize security inbox
security_inbox = SecurityInbox(malware_scanner)

# Enhanced API Routes
@api_router.get("/")
async def root():
    return {"message": "CryptoPulse Enhanced Network Security System", "features": ["Network Scanning", "Malware Analysis", "DoS Detection", "WiFi Threat Monitoring", "URL Scanning"]}

@api_router.post("/scan/network")
async def start_enhanced_network_scan():
    """Start enhanced network scan with threat detection"""
    result = await network_scanner.scan_network()
    return result

@api_router.get("/scan/progress")
async def get_scan_progress():
    """Get current scan progress"""
    return {
        "scanning": network_scanner.scanning,
        "progress": network_scanner.scan_progress
    }

@api_router.get("/wifi/networks")
async def get_wifi_networks():
    """Get discovered WiFi networks"""
    try:
        networks = network_scanner.scan_wifi_networks()
        threats = network_scanner.analyze_wifi_security(networks)
        return {
            "networks": networks,
            "threats_summary": threats,
            "total_networks": len(networks),
            "threat_count": len(threats)
        }
    except Exception as e:
        logging.error(f"WiFi networks fetch error: {e}")
        return {"networks": [], "threats_summary": [], "total_networks": 0, "threat_count": 0}

# Security Inbox API Endpoints
@api_router.post("/inbox/add-url")
async def add_url_to_inbox(url: str = Form(...), note: str = Form(None)):
    """Add URL to security inbox"""
    result = await security_inbox.add_url_to_inbox(url, note)
    return result

@api_router.get("/inbox/entries")
async def get_inbox_entries(status: str = None, limit: int = 50):
    """Get inbox entries"""
    entries = await security_inbox.get_inbox_entries(status, limit)
    return {"entries": entries, "total": len(entries)}

@api_router.post("/inbox/scan/{inbox_id}")
async def scan_inbox_url(inbox_id: str):
    """Scan URL from inbox"""
    result = await security_inbox.scan_inbox_url(inbox_id)
    return result

@api_router.post("/inbox/batch-scan")
async def batch_scan_urls(urls: List[str]):
    """Batch scan multiple URLs"""
    if len(urls) > 10:  # Limit batch size
        raise HTTPException(status_code=400, detail="Maximum 10 URLs per batch")
    
    results = await security_inbox.batch_scan_urls(urls)
    return {"results": results, "total_scanned": len(results)}

@api_router.delete("/inbox/entry/{inbox_id}")
async def delete_inbox_entry(inbox_id: str):
    """Delete entry from inbox"""
    try:
        result = await db.security_inbox.delete_one({"id": inbox_id})
        if result.deleted_count > 0:
            return {"status": "deleted"}
        else:
            raise HTTPException(status_code=404, detail="Entry not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.post("/scan/file")
async def scan_file_for_malware(file: UploadFile = File(...)):
    """Scan uploaded file for malware"""
    try:
        # Validate file size (32MB limit for VirusTotal free)
        max_size = 32 * 1024 * 1024  # 32MB
        
        # Save uploaded file temporarily
        file_path = UPLOAD_DIR / f"{uuid.uuid4()}_{file.filename}"
        
        async with aiofiles.open(file_path, 'wb') as f:
            content = await file.read()
            
            if len(content) > max_size:
                raise HTTPException(status_code=413, detail="File too large. Maximum size is 32MB.")
            
            await f.write(content)
        
        # Scan file with VirusTotal
        analysis_result = await malware_scanner.scan_file(str(file_path), file.filename)
        
        # Save analysis result to database
        await db.malware_analyses.insert_one(network_scanner.prepare_for_mongo(analysis_result.dict()))
        
        # Clean up temporary file
        try:
            os.unlink(file_path)
        except:
            pass
        
        # Broadcast result if threat detected
        if analysis_result.threat_detected:
            await manager.broadcast(json.dumps({
                "type": "malware_detected",
                "filename": file.filename,
                "threat_type": analysis_result.threat_type,
                "risk_level": analysis_result.risk_level,
                "detection_ratio": analysis_result.detection_ratio
            }))
        
        return analysis_result.dict()
        
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"File scan error: {e}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

@api_router.post("/scan/url")
async def scan_url_for_threats(url: str = Form(...)):
    """Scan URL for threats"""
    try:
        # Validate URL format
        parsed_url = urlparse(url)
        if not parsed_url.scheme or not parsed_url.netloc:
            raise HTTPException(status_code=400, detail="Invalid URL format")
        
        # Scan URL with VirusTotal
        analysis_result = await malware_scanner.scan_url(url)
        
        # Save analysis result to database
        await db.url_analyses.insert_one(network_scanner.prepare_for_mongo(analysis_result.dict()))
        
        # Broadcast result if threat detected
        if analysis_result.is_malicious:
            await manager.broadcast(json.dumps({
                "type": "malicious_url_detected",
                "url": url,
                "threat_categories": analysis_result.threat_categories,
                "risk_level": analysis_result.risk_level,
                "detection_ratio": analysis_result.detection_ratio
            }))
        
        return analysis_result.dict()
        
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"URL scan error: {e}")
        raise HTTPException(status_code=500, detail=f"URL scan failed: {str(e)}")

@api_router.get("/devices", response_model=List[Device])
async def get_devices():
    """Get all discovered devices"""
    devices = await db.devices.find().to_list(1000)
    return [Device(**device) for device in devices]

@api_router.get("/devices/active")
async def get_active_devices():
    """Get active devices for topology visualization"""
    devices = await db.devices.find({"status": "Active"}).to_list(1000)
    return devices

@api_router.get("/alerts", response_model=List[ThreatAlert])
async def get_threat_alerts():
    """Get all threat alerts"""
    alerts = await db.threat_alerts.find().sort("timestamp", -1).to_list(100)
    return [ThreatAlert(**alert) for alert in alerts]

@api_router.get("/alerts/unresolved")
async def get_unresolved_alerts():
    """Get unresolved threat alerts"""
    alerts = await db.threat_alerts.find({"resolved": False}).sort("timestamp", -1).to_list(50)
    return alerts

@api_router.get("/scans", response_model=List[NetworkScan])
async def get_network_scans():
    """Get scan history"""
    scans = await db.network_scans.find().sort("timestamp", -1).to_list(50)
    return [NetworkScan(**scan) for scan in scans]

@api_router.get("/malware/analyses")
async def get_malware_analyses():
    """Get malware analysis history"""
    analyses = await db.malware_analyses.find().sort("scan_date", -1).to_list(100)
    # Remove MongoDB ObjectId fields for JSON serialization
    for analysis in analyses:
        if '_id' in analysis:
            del analysis['_id']
    return analyses

@api_router.get("/url/analyses")
async def get_url_analyses():
    """Get URL analysis history"""
    analyses = await db.url_analyses.find().sort("scan_date", -1).to_list(100)
    # Remove MongoDB ObjectId fields for JSON serialization
    for analysis in analyses:
        if '_id' in analysis:
            del analysis['_id']
    return analyses

@api_router.get("/dashboard/stats")
async def get_enhanced_dashboard_stats():
    """Get enhanced dashboard statistics"""
    total_devices = await db.devices.count_documents({})
    active_devices = await db.devices.count_documents({"status": "Active"})
    rogue_devices = await db.devices.count_documents({"is_rogue": True})
    wifi_threats = await db.devices.count_documents({"is_wifi_threat": True})
    unresolved_alerts = await db.threat_alerts.count_documents({"resolved": False})
    malware_detected = await db.malware_analyses.count_documents({"threat_detected": True})
    malicious_urls = await db.url_analyses.count_documents({"is_malicious": True})
    
    # New inbox statistics
    pending_urls = await db.security_inbox.count_documents({"scan_status": "pending"})
    inbox_threats = await db.security_inbox.count_documents({"threat_detected": True})
    total_inbox_entries = await db.security_inbox.count_documents({})
    
    return {
        "total_devices": total_devices,
        "active_devices": active_devices,
        "rogue_devices": rogue_devices,
        "wifi_threats": wifi_threats,
        "unresolved_alerts": unresolved_alerts,
        "malware_detected": malware_detected,
        "malicious_urls": malicious_urls,
        "pending_urls": pending_urls,
        "inbox_threats": inbox_threats,
        "total_inbox_entries": total_inbox_entries
    }

@api_router.post("/alerts/{alert_id}/resolve")
async def resolve_alert(alert_id: str):
    """Resolve a threat alert"""
    result = await db.threat_alerts.update_one(
        {"id": alert_id},
        {"$set": {"resolved": True, "resolved_at": datetime.now(timezone.utc).isoformat()}}
    )
    
    if result.modified_count > 0:
        return {"status": "resolved"}
    else:
        raise HTTPException(status_code=404, detail="Alert not found")

# WebSocket endpoint
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # Handle incoming messages if needed
            pass
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# Include router
app.include_router(api_router)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Enhanced background task for continuous monitoring
async def enhanced_auto_scan_task():
    while True:
        try:
            await asyncio.sleep(300)  # 5 minutes
            if not network_scanner.scanning:
                await network_scanner.scan_network()
        except Exception as e:
            logger.error(f"Enhanced auto-scan error: {e}")

# Start enhanced background task
@app.on_event("startup")
async def startup_event():
    logger.info("Starting CryptoPulse Enhanced Security System...")
    asyncio.create_task(enhanced_auto_scan_task())

@app.on_event("shutdown")
async def shutdown_db_client():
    try:
        if malware_scanner.vt_client:
            malware_scanner.vt_client.close()
    except:
        pass
    client.close()