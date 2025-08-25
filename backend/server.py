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

# Enhanced Network Scanner with DoS Detection
class EnhancedNetworkScanner:
    def __init__(self):
        self.known_devices = {}
        self.scanning = False
        self.dos_monitor = DOSMonitor()
        self.wifi_monitor = WiFiThreatMonitor()
        self.malware_scanner = MalwareScanner()
        self.executor = ThreadPoolExecutor(max_workers=4)

    def get_network_interfaces(self):
        """Get available network interfaces"""
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
        return interfaces

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
        """Enhanced port scan with more ports"""
        open_ports = []
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            try:
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
            except:
                pass
            finally:
                sock.close()
        return open_ports

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
        """Enhanced network scanning with threat detection"""
        if self.scanning:
            return {"status": "already_scanning"}
        
        self.scanning = True
        scan_start = datetime.now(timezone.utc)
        
        try:
            # Get network interfaces
            interfaces = self.get_network_interfaces()
            if not interfaces:
                return {"status": "no_interfaces"}
            
            all_devices = []
            malware_count = 0
            threats_count = 0
            
            # Start DoS monitoring in background
            self.dos_monitor.start_monitoring()
            
            # Scan each interface
            for interface_info in interfaces[:1]:  # Scan first interface
                network_range = self.calculate_network_range(
                    interface_info['ip'], 
                    interface_info['netmask']
                )
                
                # Perform enhanced ARP scan
                devices = self.perform_arp_scan(network_range)
                
                # Process discovered devices
                for device_data in devices:
                    mac = device_data["mac"]
                    is_new_device = mac not in self.known_devices
                    
                    # Enhanced port scan
                    open_ports = self.quick_port_scan(device_data["ip"])
                    
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
                    
                    # Update device in database
                    await self.update_device_database(device_info, is_new_device)
                    
                    # Count threats
                    if device_info["is_rogue"] or device_info["is_wifi_threat"]:
                        threats_count += 1
                    
                    all_devices.append(device_info)
                    self.known_devices[mac] = device_info
            
            # Stop DoS monitoring
            dos_alerts = self.dos_monitor.stop_monitoring()
            
            # Create enhanced scan record
            scan_duration = (datetime.now(timezone.utc) - scan_start).total_seconds()
            scan_record = NetworkScan(
                scan_type="Enhanced_ARP_Discovery",
                target_network=network_range,
                devices_found=len(all_devices),
                malware_detected=malware_count,
                threats_found=threats_count,
                duration_seconds=scan_duration,
                status="Completed"
            )
            
            # Save scan to database
            await db.network_scans.insert_one(self.prepare_for_mongo(scan_record.dict()))
            
            # Broadcast results
            broadcast_data = {
                "type": "enhanced_scan_complete",
                "devices": all_devices,
                "threats_found": threats_count,
                "dos_alerts": len(dos_alerts),
                "scan_info": self.prepare_for_mongo(scan_record.dict())
            }
            await manager.broadcast(json.dumps(broadcast_data))
            
            return {
                "status": "completed",
                "devices_found": len(all_devices),
                "threats_found": threats_count,
                "scan_duration": scan_duration
            }
            
        except Exception as e:
            logging.error(f"Enhanced network scan error: {e}")
            return {"status": "error", "message": str(e)}
        finally:
            self.scanning = False

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
        self.vt_client = None
        self.init_virustotal_client()

    def init_virustotal_client(self):
        """Initialize VirusTotal client"""
        try:
            if VIRUSTOTAL_API_KEY:
                self.vt_client = vt.Client(VIRUSTOTAL_API_KEY)
                logging.info("VirusTotal client initialized successfully")
            else:
                logging.warning("VirusTotal API key not found")
        except Exception as e:
            logging.error(f"Failed to initialize VirusTotal client: {e}")

    async def scan_file(self, file_path: str, filename: str) -> MalwareAnalysis:
        """Scan file with VirusTotal"""
        try:
            # Calculate file hashes
            file_hash = await self.calculate_file_hash(file_path)
            file_size = os.path.getsize(file_path)
            
            if not self.vt_client:
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
            
            # Check if file exists in VirusTotal database
            try:
                file_obj = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: self.vt_client.get_object(f"/files/{file_hash}")
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
        """Submit new file to VirusTotal for scanning"""
        try:
            # Submit file
            with open(file_path, "rb") as f:
                analysis = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: self.vt_client.scan_file(f)
                )
            
            # Wait for analysis to complete (with timeout)
            max_wait = 300  # 5 minutes
            wait_time = 0
            
            while wait_time < max_wait:
                try:
                    file_obj = await asyncio.get_event_loop().run_in_executor(
                        None, lambda: self.vt_client.get_object(f"/files/{file_hash}")
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
        """Scan URL with VirusTotal"""
        try:
            if not self.vt_client:
                return URLAnalysis(
                    url=url,
                    is_malicious=False,
                    risk_level="Unknown",
                    detection_ratio="0/0",
                    scan_results={"error": "VirusTotal not available"}
                )
            
            # Submit URL for analysis
            analysis = await asyncio.get_event_loop().run_in_executor(
                None, lambda: self.vt_client.scan_url(url)
            )
            
            # Get URL ID for checking results
            url_id = vt.url_id(url)
            
            # Wait for analysis
            await asyncio.sleep(5)  # Give some time for analysis
            
            try:
                url_obj = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: self.vt_client.get_object(f"/urls/{url_id}")
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
        """Cleanup VirusTotal client"""
        if self.vt_client:
            try:
                self.vt_client.close()
            except:
                pass

# Initialize enhanced scanners
network_scanner = EnhancedNetworkScanner()
malware_scanner = MalwareScanner()

# Enhanced API Routes
@api_router.get("/")
async def root():
    return {"message": "CryptoPulse Enhanced Network Security System", "features": ["Network Scanning", "Malware Analysis", "DoS Detection", "WiFi Threat Monitoring", "URL Scanning"]}

@api_router.post("/scan/network")
async def start_enhanced_network_scan():
    """Start enhanced network scan with threat detection"""
    result = await network_scanner.scan_network()
    return result

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
    return analyses

@api_router.get("/url/analyses")
async def get_url_analyses():
    """Get URL analysis history"""
    analyses = await db.url_analyses.find().sort("scan_date", -1).to_list(100)
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
    
    return {
        "total_devices": total_devices,
        "active_devices": active_devices,
        "rogue_devices": rogue_devices,
        "wifi_threats": wifi_threats,
        "unresolved_alerts": unresolved_alerts,
        "malware_detected": malware_detected,
        "malicious_urls": malicious_urls
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