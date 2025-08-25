from fastapi import FastAPI, APIRouter, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
import asyncio
import json
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Dict, Optional
import uuid
from datetime import datetime, timezone
import scapy.all as scapy
import netifaces
import psutil
import socket
import re
from concurrent.futures import ThreadPoolExecutor
import threading

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

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

# Models
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
    authentication_attempts: int = 0
    open_ports: List[int] = Field(default_factory=list)

class NetworkScan(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scan_type: str
    target_network: str
    devices_found: int
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    duration_seconds: float
    status: str

class ThreatAlert(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    device_id: str
    alert_type: str
    severity: str
    description: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    resolved: bool = False

# Network Scanner Class
class NetworkScanner:
    def __init__(self):
        self.known_devices = {}
        self.scanning = False
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
            answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
            
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
        """Detect device type based on MAC, hostname, and open ports"""
        mac_vendors = {
            "Apple": ["00:03:93", "00:05:02", "00:0a:95", "00:0d:93", "a4:c3:61"],
            "Samsung": ["00:07:ab", "00:0d:e5", "00:12:fb", "00:15:b9"],
            "Router": ["00:1b:2f", "00:1e:58", "00:22:6b", "d8:50:e6"],
            "Printer": ["00:00:48", "00:01:e6", "00:04:76"]
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
            if any(term in hostname_lower for term in ["router", "gateway", "ap"]):
                return "Router"
            elif any(term in hostname_lower for term in ["printer", "canon", "hp", "epson"]):
                return "Printer"
            elif any(term in hostname_lower for term in ["iphone", "android", "mobile"]):
                return "Mobile"
        
        # Check open ports
        if 80 in open_ports or 443 in open_ports:
            return "Server/IoT"
        elif 22 in open_ports:
            return "Linux/Server"
        elif 135 in open_ports or 445 in open_ports:
            return "Windows"
        
        return "Unknown"

    def calculate_risk_score(self, device, is_new=False):
        """Calculate risk score for device"""
        risk_score = 0
        
        # New device penalty
        if is_new:
            risk_score += 30
        
        # Unknown device type penalty
        if device.get("device_type") == "Unknown":
            risk_score += 20
        
        # No hostname penalty
        if not device.get("hostname"):
            risk_score += 15
        
        # Multiple open ports penalty
        open_ports_count = len(device.get("open_ports", []))
        if open_ports_count > 5:
            risk_score += 25
        elif open_ports_count > 0:
            risk_score += 10
        
        # Ensure risk score is between 0 and 100
        return min(max(risk_score, 0), 100)

    async def scan_network(self):
        """Main network scanning function"""
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
            
            # Scan each interface
            for interface_info in interfaces[:1]:  # Scan first interface only for now
                network_range = self.calculate_network_range(
                    interface_info['ip'], 
                    interface_info['netmask']
                )
                
                # Perform ARP scan
                devices = self.perform_arp_scan(network_range)
                
                # Process discovered devices
                for device_data in devices:
                    # Check if device is new or known
                    mac = device_data["mac"]
                    is_new_device = mac not in self.known_devices
                    
                    # Basic port scan (limited to avoid being intrusive)
                    open_ports = self.quick_port_scan(device_data["ip"])
                    
                    # Detect device type
                    device_type = self.detect_device_type(
                        mac, device_data["hostname"], open_ports
                    )
                    
                    # Create device object
                    device_info = {
                        "mac_address": mac,
                        "ip_address": device_data["ip"],
                        "hostname": device_data["hostname"],
                        "device_type": device_type,
                        "open_ports": open_ports,
                        "is_rogue": is_new_device and self.is_suspicious_device(device_data, open_ports)
                    }
                    
                    # Calculate risk score
                    device_info["risk_score"] = self.calculate_risk_score(device_info, is_new_device)
                    
                    # Update device in database
                    await self.update_device_database(device_info, is_new_device)
                    
                    all_devices.append(device_info)
                    self.known_devices[mac] = device_info
            
            # Create scan record
            scan_duration = (datetime.now(timezone.utc) - scan_start).total_seconds()
            scan_record = NetworkScan(
                scan_type="ARP_Discovery",
                target_network=network_range,
                devices_found=len(all_devices),
                duration_seconds=scan_duration,
                status="Completed"
            )
            
            # Save scan to database
            await db.network_scans.insert_one(self.prepare_for_mongo(scan_record.dict()))
            
            # Broadcast results to connected clients
            broadcast_data = {
                "type": "scan_complete",
                "devices": all_devices,
                "scan_info": self.prepare_for_mongo(scan_record.dict())
            }
            await manager.broadcast(json.dumps(broadcast_data))
            
            return {
                "status": "completed",
                "devices_found": len(all_devices),
                "scan_duration": scan_duration
            }
            
        except Exception as e:
            logging.error(f"Network scan error: {e}")
            return {"status": "error", "message": str(e)}
        finally:
            self.scanning = False

    def quick_port_scan(self, ip, common_ports=[22, 23, 53, 80, 135, 139, 443, 445, 993, 995]):
        """Quick port scan for common services"""
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

    def is_suspicious_device(self, device_data, open_ports):
        """Determine if a device might be rogue"""
        # Simple heuristics for rogue device detection
        suspicious_indicators = 0
        
        # No hostname
        if not device_data.get("hostname"):
            suspicious_indicators += 1
        
        # Many open ports
        if len(open_ports) > 10:
            suspicious_indicators += 1
        
        # Unusual port combinations
        if 22 in open_ports and 80 in open_ports and 443 in open_ports:
            suspicious_indicators += 1
        
        return suspicious_indicators >= 2

    def prepare_for_mongo(self, data):
        """Prepare data for MongoDB storage"""
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, datetime):
                    data[key] = value.isoformat()
        return data

    async def update_device_database(self, device_info, is_new):
        """Update device information in database"""
        try:
            mac = device_info["mac_address"]
            
            if is_new:
                device = Device(**device_info)
                await db.devices.insert_one(self.prepare_for_mongo(device.dict()))
                
                # Create alert for new device
                if device_info.get("is_rogue"):
                    alert = ThreatAlert(
                        device_id=device.id,
                        alert_type="Rogue Device Detected",
                        severity="High" if device_info["risk_score"] > 70 else "Medium",
                        description=f"Potentially rogue device detected: {device_info['ip_address']} ({mac})"
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
                            "risk_score": device_info["risk_score"]
                        }
                    }
                )
        except Exception as e:
            logging.error(f"Database update error: {e}")

# Initialize scanner
network_scanner = NetworkScanner()

# API Routes
@api_router.get("/")
async def root():
    return {"message": "CryptoPulse Network Security System"}

@api_router.post("/scan/network")
async def start_network_scan():
    """Start a network scan"""
    result = await network_scanner.scan_network()
    return result

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

@api_router.get("/scans", response_model=List[NetworkScan])
async def get_network_scans():
    """Get scan history"""
    scans = await db.network_scans.find().sort("timestamp", -1).to_list(50)
    return [NetworkScan(**scan) for scan in scans]

@api_router.get("/dashboard/stats")
async def get_dashboard_stats():
    """Get dashboard statistics"""
    total_devices = await db.devices.count_documents({})
    active_devices = await db.devices.count_documents({"status": "Active"})
    rogue_devices = await db.devices.count_documents({"is_rogue": True})
    unresolved_alerts = await db.threat_alerts.count_documents({"resolved": False})
    
    return {
        "total_devices": total_devices,
        "active_devices": active_devices,
        "rogue_devices": rogue_devices,
        "unresolved_alerts": unresolved_alerts
    }

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

# Background task to auto-scan every 5 minutes
async def auto_scan_task():
    while True:
        try:
            await asyncio.sleep(300)  # 5 minutes
            if not network_scanner.scanning:
                await network_scanner.scan_network()
        except Exception as e:
            logger.error(f"Auto-scan error: {e}")

# Start background task
@app.on_event("startup")
async def startup_event():
    asyncio.create_task(auto_scan_task())

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()