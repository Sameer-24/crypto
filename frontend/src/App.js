import React, { useState, useEffect, useCallback } from "react";
import "./App.css";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import axios from "axios";
import { Button } from "./components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "./components/ui/card";
import { Badge } from "./components/ui/badge";
import { Alert, AlertDescription } from "./components/ui/alert";
import { 
  Shield, 
  Wifi, 
  Activity, 
  AlertTriangle, 
  Scan, 
  Monitor, 
  Network,
  Eye,
  RefreshCw
} from "lucide-react";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

const Dashboard = () => {
  const [devices, setDevices] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState({});
  const [scanning, setScanning] = useState(false);
  const [lastScan, setLastScan] = useState(null);
  const [wsConnected, setWsConnected] = useState(false);

  // WebSocket connection
  useEffect(() => {
    const wsUrl = BACKEND_URL.replace('https://', 'wss://').replace('http://', 'ws://');
    const ws = new WebSocket(`${wsUrl}/ws`);
    
    ws.onopen = () => {
      setWsConnected(true);
      console.log('WebSocket connected');
    };
    
    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.type === 'scan_complete') {
        setScanning(false);
        setLastScan(new Date().toLocaleTimeString());
        fetchDevices();
        fetchStats();
        fetchAlerts();
      }
    };
    
    ws.onclose = () => {
      setWsConnected(false);
      console.log('WebSocket disconnected');
    };
    
    return () => ws.close();
  }, []);

  const fetchDevices = useCallback(async () => {
    try {
      const response = await axios.get(`${API}/devices`);
      setDevices(response.data);
    } catch (error) {
      console.error('Error fetching devices:', error);
    }
  }, []);

  const fetchAlerts = useCallback(async () => {
    try {
      const response = await axios.get(`${API}/alerts`);
      setAlerts(response.data.slice(0, 5)); // Show latest 5 alerts
    } catch (error) {
      console.error('Error fetching alerts:', error);
    }
  }, []);

  const fetchStats = useCallback(async () => {
    try {
      const response = await axios.get(`${API}/dashboard/stats`);
      setStats(response.data);
    } catch (error) {
      console.error('Error fetching stats:', error);
    }
  }, []);

  const startScan = async () => {
    try {
      setScanning(true);
      await axios.post(`${API}/scan/network`);
      // Scanning state will be updated via WebSocket
    } catch (error) {
      console.error('Error starting scan:', error);
      setScanning(false);
    }
  };

  useEffect(() => {
    fetchDevices();
    fetchAlerts();
    fetchStats();
  }, [fetchDevices, fetchAlerts, fetchStats]);

  const getRiskColor = (risk) => {
    if (risk >= 70) return "bg-red-500";
    if (risk >= 40) return "bg-yellow-500";
    return "bg-green-500";
  };

  const getDeviceIcon = (type) => {
    switch (type.toLowerCase()) {
      case 'router': return <Wifi className="w-4 h-4" />;
      case 'mobile': case 'iphone': case 'android': return <Monitor className="w-4 h-4" />;
      default: return <Network className="w-4 h-4" />;
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900">
      {/* Header */}
      <div className="border-b border-gray-800 bg-black/20 backdrop-blur-lg">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-4">
            <div className="flex items-center space-x-3">
              <Shield className="w-8 h-8 text-cyan-400" />
              <h1 className="text-2xl font-bold text-white tracking-tight">CryptoPulse</h1>
              <Badge variant="outline" className="text-cyan-400 border-cyan-400/30">
                Network Security
              </Badge>
            </div>
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-2">
                <div className={`w-2 h-2 rounded-full ${wsConnected ? 'bg-green-400' : 'bg-red-400'}`} />
                <span className="text-sm text-gray-300">
                  {wsConnected ? 'Connected' : 'Disconnected'}
                </span>
              </div>
              <Button
                onClick={startScan}
                disabled={scanning}
                className="bg-cyan-600 hover:bg-cyan-700 text-white border-none"
              >
                {scanning ? (
                  <>
                    <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                    Scanning...
                  </>
                ) : (
                  <>
                    <Scan className="w-4 h-4 mr-2" />
                    Network Scan
                  </>
                )}
              </Button>
            </div>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <Card className="bg-black/30 border-gray-700 backdrop-blur-lg">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-gray-300">Total Devices</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-white">{stats.total_devices || 0}</div>
            </CardContent>
          </Card>
          
          <Card className="bg-black/30 border-gray-700 backdrop-blur-lg">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-gray-300">Active Devices</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-green-400">{stats.active_devices || 0}</div>
            </CardContent>
          </Card>
          
          <Card className="bg-black/30 border-gray-700 backdrop-blur-lg">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-gray-300">Rogue Devices</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-red-400">{stats.rogue_devices || 0}</div>
            </CardContent>
          </Card>
          
          <Card className="bg-black/30 border-gray-700 backdrop-blur-lg">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-gray-300">Active Alerts</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-yellow-400">{stats.unresolved_alerts || 0}</div>
            </CardContent>
          </Card>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Network Topology */}
          <div className="lg:col-span-2">
            <Card className="bg-black/30 border-gray-700 backdrop-blur-lg">
              <CardHeader>
                <CardTitle className="text-white flex items-center">
                  <Network className="w-5 h-5 mr-2" />
                  Live Network Topology
                </CardTitle>
              </CardHeader>
              <CardContent>
                <NetworkTopology devices={devices} />
              </CardContent>
            </Card>
          </div>

          {/* Device List & Alerts */}
          <div className="space-y-6">
            {/* Recent Alerts */}
            <Card className="bg-black/30 border-gray-700 backdrop-blur-lg">
              <CardHeader>
                <CardTitle className="text-white flex items-center">
                  <AlertTriangle className="w-5 h-5 mr-2" />
                  Recent Alerts
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {alerts.length > 0 ? alerts.map((alert) => (
                  <Alert key={alert.id} className="border-yellow-600/30 bg-yellow-900/20">
                    <AlertTriangle className="h-4 w-4" />
                    <AlertDescription className="text-yellow-200">
                      <div className="flex justify-between items-start">
                        <div>
                          <p className="font-medium">{alert.alert_type}</p>
                          <p className="text-sm opacity-80">{alert.description}</p>
                        </div>
                        <Badge variant="outline" className={
                          alert.severity === 'High' ? 'text-red-400 border-red-400/30' :
                          alert.severity === 'Medium' ? 'text-yellow-400 border-yellow-400/30' :
                          'text-green-400 border-green-400/30'
                        }>
                          {alert.severity}
                        </Badge>
                      </div>
                    </AlertDescription>
                  </Alert>
                )) : (
                  <p className="text-gray-400 text-center py-4">No recent alerts</p>
                )}
              </CardContent>
            </Card>

            {/* Device List */}
            <Card className="bg-black/30 border-gray-700 backdrop-blur-lg">
              <CardHeader>
                <CardTitle className="text-white flex items-center">
                  <Eye className="w-5 h-5 mr-2" />
                  Discovered Devices ({devices.length})
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 max-h-96 overflow-y-auto">
                {devices.map((device) => (
                  <div key={device.id} className="flex items-center justify-between p-3 rounded-lg bg-black/20 border border-gray-700/50">
                    <div className="flex items-center space-x-3">
                      {getDeviceIcon(device.device_type)}
                      <div>
                        <p className="text-white font-medium text-sm">
                          {device.hostname || 'Unknown Host'}
                        </p>
                        <p className="text-gray-400 text-xs">{device.ip_address}</p>
                      </div>
                    </div>
                    <div className="flex items-center space-x-2">
                      <div className={`w-3 h-3 rounded-full ${getRiskColor(device.risk_score)}`} />
                      <span className="text-xs text-gray-300">{device.risk_score}</span>
                      {device.is_rogue && (
                        <Badge className="bg-red-600 text-white text-xs">ROGUE</Badge>
                      )}
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>
          </div>
        </div>

        {lastScan && (
          <div className="mt-6 text-center">
            <p className="text-gray-400 text-sm">
              Last scan: {lastScan}
            </p>
          </div>
        )}
      </div>
    </div>
  );
};

const NetworkTopology = ({ devices }) => {
  const [selectedDevice, setSelectedDevice] = useState(null);

  // Simple grid-based topology for now
  const renderDevices = () => {
    return devices.map((device, index) => {
      const x = (index % 6) * 120 + 60;
      const y = Math.floor(index / 6) * 100 + 60;
      const riskColor = device.risk_score >= 70 ? '#ef4444' : 
                       device.risk_score >= 40 ? '#f59e0b' : '#22c55e';

      return (
        <g key={device.id}>
          {/* Connection line to center hub */}
          <line
            x1={300}
            y1={200}
            x2={x}
            y2={y}
            stroke="#374151"
            strokeWidth="2"
            opacity="0.5"
          />
          
          {/* Device node */}
          <circle
            cx={x}
            cy={y}
            r="20"
            fill={riskColor}
            stroke="#1f2937"
            strokeWidth="3"
            className="cursor-pointer transition-all hover:r-25"
            onClick={() => setSelectedDevice(device)}
          />
          
          {/* Device label */}
          <text
            x={x}
            y={y + 35}
            textAnchor="middle"
            className="fill-gray-300 text-xs"
          >
            {device.hostname?.substring(0, 8) || device.ip_address.split('.').pop()}
          </text>
          
          {device.is_rogue && (
            <circle
              cx={x + 15}
              cy={y - 15}
              r="5"
              fill="#ef4444"
              className="animate-pulse"
            />
          )}
        </g>
      );
    });
  };

  return (
    <div className="relative">
      <svg width="600" height="400" className="border border-gray-700 rounded-lg bg-black/10">
        {/* Central hub */}
        <circle
          cx="300"
          cy="200"
          r="30"
          fill="#0891b2"
          stroke="#1f2937"
          strokeWidth="4"
        />
        <text
          x="300"
          y="205"
          textAnchor="middle"
          className="fill-white font-bold text-sm"
        >
          HUB
        </text>
        
        {/* Device connections and nodes */}
        {renderDevices()}
      </svg>
      
      {/* Device info tooltip */}
      {selectedDevice && (
        <div className="absolute top-4 right-4 bg-black/80 p-4 rounded-lg border border-gray-600 backdrop-blur-lg">
          <h4 className="text-white font-bold">{selectedDevice.hostname || 'Unknown Device'}</h4>
          <p className="text-gray-300 text-sm">IP: {selectedDevice.ip_address}</p>
          <p className="text-gray-300 text-sm">MAC: {selectedDevice.mac_address}</p>
          <p className="text-gray-300 text-sm">Type: {selectedDevice.device_type}</p>
          <p className="text-gray-300 text-sm">Risk Score: {selectedDevice.risk_score}</p>
          <div className="flex items-center space-x-2 mt-2">
            <div className={`w-3 h-3 rounded-full ${selectedDevice.risk_score >= 70 ? 'bg-red-500' : selectedDevice.risk_score >= 40 ? 'bg-yellow-500' : 'bg-green-500'}`} />
            <span className="text-xs text-gray-400">
              {selectedDevice.risk_score >= 70 ? 'High Risk' : selectedDevice.risk_score >= 40 ? 'Medium Risk' : 'Low Risk'}
            </span>
          </div>
          <button 
            onClick={() => setSelectedDevice(null)}
            className="mt-2 text-xs text-gray-400 hover:text-white"
          >
            Close
          </button>
        </div>
      )}
    </div>
  );
};

function App() {
  return (
    <div className="App">
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Dashboard />} />
        </Routes>
      </BrowserRouter>
    </div>
  );
}

export default App;