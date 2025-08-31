import React, { useState, useEffect, useCallback, useRef } from "react";
import "./App.css";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import axios from "axios";
import { Button } from "./components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "./components/ui/card";
import { Badge } from "./components/ui/badge";
import { Alert, AlertDescription } from "./components/ui/alert";
import { Input } from "./components/ui/input";
import { Textarea } from "./components/ui/textarea";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "./components/ui/tabs";
import { 
  Shield, 
  Wifi, 
  Activity, 
  AlertTriangle, 
  Scan, 
  Monitor, 
  Network,
  Eye,
  RefreshCw,
  Upload,
  Globe,
  Bug,
  Zap,
  ShieldAlert,
  FileText,
  ExternalLink,
  CheckCircle,
  XCircle,
  Clock,
  Download,
  Trash2,
  Plus,
  Mail
} from "lucide-react";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

const Dashboard = () => {
  const [devices, setDevices] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState({});
  const [scanning, setScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [lastScan, setLastScan] = useState(null);
  const [wsConnected, setWsConnected] = useState(false);
  const [malwareAnalyses, setMalwareAnalyses] = useState([]);
  const [urlAnalyses, setUrlAnalyses] = useState([]);
  const [fileScanning, setFileScanning] = useState(false);
  const [urlScanning, setUrlScanning] = useState(false);
  const [urlToScan, setUrlToScan] = useState("");
  const [inboxEntries, setInboxEntries] = useState([]);
  const [inboxUrl, setInboxUrl] = useState("");
  const [inboxNote, setInboxNote] = useState("");
  const [wifiNetworks, setWifiNetworks] = useState([]);
  const [currentWifiConnection, setCurrentWifiConnection] = useState(null);
  const [wifiEnvironmentAnalysis, setWifiEnvironmentAnalysis] = useState({});
  const [wifiScanning, setWifiScanning] = useState(false);
  const [addingToInbox, setAddingToInbox] = useState(false);
  const fileInputRef = useRef(null);

  // WebSocket connection with enhanced message handling
  useEffect(() => {
    const wsUrl = BACKEND_URL.replace('https://', 'wss://').replace('http://', 'ws://');
    const ws = new WebSocket(`${wsUrl}/ws`);
    
    ws.onopen = () => {
      setWsConnected(true);
      console.log('Enhanced WebSocket connected');
    };
    
    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      console.log('WebSocket message:', data);
      
      switch(data.type) {
        case 'scan_started':
          setScanning(true);
          setScanProgress(0);
          break;
        case 'scan_progress':
          setScanProgress(data.progress);
          break;
        case 'enhanced_scan_complete':
          setScanning(false);
          setScanProgress(100);
          setLastScan(new Date().toLocaleTimeString());
          fetchDevices();
          fetchStats();
          fetchAlerts();
          if (data.wifi_networks) {
            setWifiNetworks(data.wifi_networks);
          }
          break;
        case 'scan_error':
          setScanning(false);
          setScanProgress(0);
          console.error('Scan error:', data.error);
          break;
        case 'malware_detected':
          fetchMalwareAnalyses();
          fetchStats();
          fetchAlerts();
          break;
        case 'malicious_url_detected':
          fetchUrlAnalyses();
          fetchStats();
          fetchAlerts();
          fetchInboxEntries();
          break;
        default:
          // Handle legacy scan_complete messages
          if (data.type === 'scan_complete') {
            setScanning(false);
            setScanProgress(100);
            setLastScan(new Date().toLocaleTimeString());
            fetchDevices();
            fetchStats();
            fetchAlerts();
          }
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
      setAlerts(response.data.slice(0, 10)); // Show latest 10 alerts
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

  const fetchMalwareAnalyses = useCallback(async () => {
    try {
      const response = await axios.get(`${API}/malware/analyses`);
      setMalwareAnalyses(response.data.slice(0, 5)); // Show latest 5
    } catch (error) {
      console.error('Error fetching malware analyses:', error);
    }
  }, []);

  const fetchUrlAnalyses = useCallback(async () => {
    try {
      const response = await axios.get(`${API}/url/analyses`);
      setUrlAnalyses(response.data.slice(0, 5)); // Show latest 5
    } catch (error) {
      console.error('Error fetching URL analyses:', error);
    }
  }, []);

  const fetchInboxEntries = useCallback(async () => {
    try {
      const response = await axios.get(`${API}/inbox/entries?limit=20`);
      setInboxEntries(response.data.entries || []);
    } catch (error) {
      console.error('Error fetching inbox entries:', error);
    }
  }, []);

  const fetchWifiNetworks = useCallback(async () => {
    try {
      const response = await axios.get(`${API}/wifi/networks`);
      setWifiNetworks(response.data.networks || []);
    } catch (error) {
      console.error('Error fetching WiFi networks:', error);
    }
  }, []);

  const startNetworkScan = async () => {
    try {
      setScanning(true);
      await axios.post(`${API}/scan/network`);
      // Scanning state will be updated via WebSocket
    } catch (error) {
      console.error('Error starting scan:', error);
      setScanning(false);
    }
  };

  const handleFileUpload = async (event) => {
    const file = event.target.files[0];
    if (!file) return;

    try {
      setFileScanning(true);
      const formData = new FormData();
      formData.append('file', file);

      const response = await axios.post(`${API}/scan/file`, formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });

      console.log('File scan result:', response.data);
      await fetchMalwareAnalyses();
      await fetchStats();

      // Reset file input
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
    } catch (error) {
      console.error('Error scanning file:', error);
      alert('Error scanning file: ' + (error.response?.data?.detail || error.message));
    } finally {
      setFileScanning(false);
    }
  };

  const handleUrlScan = async () => {
    if (!urlToScan.trim()) return;

    try {
      setUrlScanning(true);
      const formData = new FormData();
      formData.append('url', urlToScan);

      const response = await axios.post(`${API}/scan/url`, formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });

      console.log('URL scan result:', response.data);
      await fetchUrlAnalyses();
      await fetchStats();
      setUrlToScan('');
    } catch (error) {
      console.error('Error scanning URL:', error);
      alert('Error scanning URL: ' + (error.response?.data?.detail || error.message));
    } finally {
      setUrlScanning(false);
    }
  };

  const handleAddToInbox = async () => {
    if (!inboxUrl.trim()) return;

    try {
      setAddingToInbox(true);
      const formData = new FormData();
      formData.append('url', inboxUrl);
      formData.append('note', inboxNote);

      const response = await axios.post(`${API}/inbox/add-url`, formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });

      console.log('Added to inbox:', response.data);
      await fetchInboxEntries();
      await fetchStats();
      setInboxUrl('');
      setInboxNote('');
    } catch (error) {
      console.error('Error adding to inbox:', error);
      alert('Error adding to inbox: ' + (error.response?.data?.detail || error.message));
    } finally {
      setAddingToInbox(false);
    }
  };

  const handleScanFromInbox = async (inboxId) => {
    try {
      await axios.post(`${API}/inbox/scan/${inboxId}`);
      await fetchInboxEntries();
      await fetchStats();
      await fetchUrlAnalyses();
    } catch (error) {
      console.error('Error scanning from inbox:', error);
      alert('Error scanning URL: ' + (error.response?.data?.detail || error.message));
    }
  };

  const handleDeleteInboxEntry = async (inboxId) => {
    try {
      await axios.delete(`${API}/inbox/entry/${inboxId}`);
      await fetchInboxEntries();
      await fetchStats();
    } catch (error) {
      console.error('Error deleting inbox entry:', error);
    }
  };

  const resolveAlert = async (alertId) => {
    try {
      await axios.post(`${API}/alerts/${alertId}/resolve`);
      await fetchAlerts();
      await fetchStats();
    } catch (error) {
      console.error('Error resolving alert:', error);
    }
  };

  useEffect(() => {
    fetchDevices();
    fetchAlerts();
    fetchStats();
    fetchMalwareAnalyses();
    fetchUrlAnalyses();
    fetchInboxEntries();
    fetchWifiNetworks();
  }, [fetchDevices, fetchAlerts, fetchStats, fetchMalwareAnalyses, fetchUrlAnalyses, fetchInboxEntries, fetchWifiNetworks]);

  const getRiskColor = (risk) => {
    if (risk >= 70) return "bg-red-500";
    if (risk >= 40) return "bg-yellow-500";
    return "bg-green-500";
  };

  const getRiskBadgeColor = (riskLevel) => {
    switch(riskLevel?.toLowerCase()) {
      case 'high': return 'bg-red-600 text-white';
      case 'medium': return 'bg-yellow-600 text-white';
      case 'low': return 'bg-blue-600 text-white';
      case 'clean': return 'bg-green-600 text-white';
      default: return 'bg-gray-600 text-white';
    }
  };

  const getDeviceIcon = (type) => {
    switch (type?.toLowerCase()) {
      case 'router': return <Wifi className="w-4 h-4" />;
      case 'mobile': case 'iphone': case 'android': return <Monitor className="w-4 h-4" />;
      case 'iot': case 'camera': return <Activity className="w-4 h-4" />;
      case 'server': case 'linux': return <Monitor className="w-4 h-4" />;
      default: return <Network className="w-4 h-4" />;
    }
  };

  const formatTimestamp = (timestamp) => {
    return new Date(timestamp).toLocaleString();
  };

  const getInboxStatusColor = (status) => {
    switch(status) {
      case 'completed': return 'bg-green-600 text-white';
      case 'scanning': return 'bg-blue-600 text-white animate-pulse';
      case 'pending': return 'bg-gray-600 text-white';
      default: return 'bg-gray-600 text-white';
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900">
      {/* Enhanced Header */}
      <div className="border-b border-gray-800 bg-black/20 backdrop-blur-lg">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-4">
            <div className="flex items-center space-x-3">
              <Shield className="w-8 h-8 text-cyan-400" />
              <div>
                <h1 className="text-2xl font-bold text-white tracking-tight">CryptoPulse</h1>
                <p className="text-xs text-gray-400">Enhanced Network Security & Threat Detection</p>
              </div>
              <Badge variant="outline" className="text-cyan-400 border-cyan-400/30">
                v2.0 Enhanced
              </Badge>
            </div>
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-2">
                <div className={`w-2 h-2 rounded-full ${wsConnected ? 'bg-green-400' : 'bg-red-400'}`} />
                <span className="text-sm text-gray-300">
                  {wsConnected ? 'Real-time Connected' : 'Disconnected'}
                </span>
              </div>
              <Button
                onClick={startNetworkScan}
                disabled={scanning}
                className="bg-cyan-600 hover:bg-cyan-700 text-white border-none"
              >
                {scanning ? (
                  <>
                    <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                    Scanning... {scanProgress}%
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
        {/* Enhanced Stats Cards */}
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-4 mb-8">
          <Card className="bg-black/30 border-gray-700 backdrop-blur-lg">
            <CardHeader className="pb-2">
              <CardTitle className="text-xs font-medium text-gray-300 flex items-center">
                <Network className="w-3 h-3 mr-1" />
                Total Devices
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-xl font-bold text-white">{stats.total_devices || 0}</div>
            </CardContent>
          </Card>
          
          <Card className="bg-black/30 border-gray-700 backdrop-blur-lg">
            <CardHeader className="pb-2">
              <CardTitle className="text-xs font-medium text-gray-300 flex items-center">
                <Activity className="w-3 h-3 mr-1" />
                Active
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-xl font-bold text-green-400">{stats.active_devices || 0}</div>
            </CardContent>
          </Card>
          
          <Card className="bg-black/30 border-gray-700 backdrop-blur-lg">
            <CardHeader className="pb-2">
              <CardTitle className="text-xs font-medium text-gray-300 flex items-center">
                <ShieldAlert className="w-3 h-3 mr-1" />
                Rogue
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-xl font-bold text-red-400">{stats.rogue_devices || 0}</div>
            </CardContent>
          </Card>

          <Card className="bg-black/30 border-gray-700 backdrop-blur-lg">
            <CardHeader className="pb-2">
              <CardTitle className="text-xs font-medium text-gray-300 flex items-center">
                <Wifi className="w-3 h-3 mr-1" />
                WiFi Threats
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-xl font-bold text-orange-400">{stats.wifi_threats || 0}</div>
            </CardContent>
          </Card>
          
          <Card className="bg-black/30 border-gray-700 backdrop-blur-lg">
            <CardHeader className="pb-2">
              <CardTitle className="text-xs font-medium text-gray-300 flex items-center">
                <AlertTriangle className="w-3 h-3 mr-1" />
                Alerts
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-xl font-bold text-yellow-400">{stats.unresolved_alerts || 0}</div>
            </CardContent>
          </Card>

          <Card className="bg-black/30 border-gray-700 backdrop-blur-lg">
            <CardHeader className="pb-2">
              <CardTitle className="text-xs font-medium text-gray-300 flex items-center">
                <Bug className="w-3 h-3 mr-1" />
                Malware
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-xl font-bold text-red-500">{stats.malware_detected || 0}</div>
            </CardContent>
          </Card>

          <Card className="bg-black/30 border-gray-700 backdrop-blur-lg">
            <CardHeader className="pb-2">
              <CardTitle className="text-xs font-medium text-gray-300 flex items-center">
                <Globe className="w-3 h-3 mr-1" />
                Bad URLs
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-xl font-bold text-purple-400">{stats.malicious_urls || 0}</div>
            </CardContent>
          </Card>

          <Card className="bg-black/30 border-gray-700 backdrop-blur-lg">
            <CardHeader className="pb-2">
              <CardTitle className="text-xs font-medium text-gray-300 flex items-center">
                <FileText className="w-3 h-3 mr-1" />
                Inbox
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-xl font-bold text-cyan-400">{stats.total_inbox_entries || 0}</div>
            </CardContent>
          </Card>
        </div>

        {/* Tabbed Interface for Different Features */}
        <Tabs defaultValue="network" className="space-y-6">
          <TabsList className="grid w-full grid-cols-6 bg-black/30 border-gray-700">
            <TabsTrigger value="network" className="text-white data-[state=active]:bg-cyan-600">
              <Network className="w-4 h-4 mr-2" />
              Network Monitor
            </TabsTrigger>
            <TabsTrigger value="wifi" className="text-white data-[state=active]:bg-orange-600">
              <Wifi className="w-4 h-4 mr-2" />
              WiFi Scanner
            </TabsTrigger>
            <TabsTrigger value="malware" className="text-white data-[state=active]:bg-red-600">
              <Bug className="w-4 h-4 mr-2" />
              Malware Analysis
            </TabsTrigger>
            <TabsTrigger value="url" className="text-white data-[state=active]:bg-purple-600">
              <Globe className="w-4 h-4 mr-2" />
              URL Scanner
            </TabsTrigger>
            <TabsTrigger value="inbox" className="text-white data-[state=active]:bg-cyan-500">
              <FileText className="w-4 h-4 mr-2" />
              Security Inbox
            </TabsTrigger>
            <TabsTrigger value="alerts" className="text-white data-[state=active]:bg-yellow-600">
              <AlertTriangle className="w-4 h-4 mr-2" />
              Threat Alerts
            </TabsTrigger>
          </TabsList>

          {/* Network Monitor Tab */}
          <TabsContent value="network" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Network Topology */}
              <div className="lg:col-span-2">
                <Card className="bg-black/30 border-gray-700 backdrop-blur-lg">
                  <CardHeader>
                    <CardTitle className="text-white flex items-center">
                      <Network className="w-5 h-5 mr-2" />
                      Live Network Topology
                      {scanning && <RefreshCw className="w-4 h-4 ml-2 animate-spin" />}
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <NetworkTopology devices={devices} />
                  </CardContent>
                </Card>
              </div>

              {/* Device List */}
              <div>
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
                            <p className="text-gray-500 text-xs">{device.device_type}</p>
                          </div>
                        </div>
                        <div className="flex items-center space-x-2">
                          <div className={`w-3 h-3 rounded-full ${getRiskColor(device.risk_score)}`} />
                          <span className="text-xs text-gray-300">{device.risk_score}</span>
                          {device.is_rogue && (
                            <Badge className="bg-red-600 text-white text-xs">ROGUE</Badge>
                          )}
                          {device.is_wifi_threat && (
                            <Badge className="bg-orange-600 text-white text-xs">WiFi</Badge>
                          )}
                        </div>
                      </div>
                    ))}
                    {devices.length === 0 && (
                      <div className="text-center py-8 text-gray-400">
                        <Network className="w-12 h-12 mx-auto mb-4 opacity-50" />
                        <p>No devices discovered yet</p>
                        <p className="text-sm">Run a network scan to detect devices</p>
                      </div>
                    )}
                  </CardContent>
                </Card>
              </div>
            </div>
          </TabsContent>

          {/* WiFi Scanner Tab */}
          <TabsContent value="wifi" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* WiFi Network Discovery */}
              <Card className="bg-black/30 border-gray-700 backdrop-blur-lg">
                <CardHeader>
                  <CardTitle className="text-white flex items-center justify-between">
                    <div className="flex items-center">
                      <Wifi className="w-5 h-5 mr-2" />
                      Discovered WiFi Networks ({wifiNetworks.length})
                    </div>
                    <Button
                      onClick={fetchWifiNetworks}
                      size="sm"
                      className="bg-orange-600 hover:bg-orange-700 text-white"
                    >
                      <RefreshCw className="w-4 h-4 mr-1" />
                      Refresh
                    </Button>
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3 max-h-96 overflow-y-auto">
                  {wifiNetworks.map((network, index) => (
                    <div key={index} className="p-3 rounded-lg bg-black/20 border border-gray-700/50">
                      <div className="flex justify-between items-start mb-2">
                        <div className="flex-1">
                          <p className="text-white font-medium">{network.ssid}</p>
                          <p className="text-gray-400 text-sm">{network.bssid}</p>
                          <p className="text-gray-500 text-xs">{network.security} • {network.frequency}</p>
                        </div>
                        <div className="flex items-center space-x-2">
                          <Badge className={
                            network.threat_level === 'Critical' ? 'bg-red-700 text-white' :
                            network.threat_level === 'High' ? 'bg-red-600 text-white' :
                            network.threat_level === 'Medium' ? 'bg-yellow-600 text-white' :
                            'bg-green-600 text-white'
                          }>
                            {network.threat_level}
                          </Badge>
                          <div className={`w-3 h-3 rounded-full ${
                            network.signal_strength > -50 ? 'bg-green-500' :
                            network.signal_strength > -70 ? 'bg-yellow-500' : 'bg-red-500'
                          }`} title={`Signal: ${network.signal_strength} dBm`} />
                        </div>
                      </div>
                      {network.threats && network.threats.length > 0 && (
                        <div className="mt-2 flex flex-wrap gap-1">
                          {network.threats.map((threat, idx) => (
                            <Badge key={idx} className="bg-red-800 text-white text-xs">
                              {threat}
                            </Badge>
                          ))}
                        </div>
                      )}
                      <div className="mt-2 text-xs text-gray-400">
                        Channel {network.channel} • Signal: {network.signal_strength} dBm
                      </div>
                    </div>
                  ))}
                  {wifiNetworks.length === 0 && (
                    <div className="text-center py-8 text-gray-400">
                      <Wifi className="w-12 h-12 mx-auto mb-4 opacity-50" />
                      <p>No WiFi networks detected</p>
                      <p className="text-sm">Click refresh to scan for networks</p>
                    </div>
                  )}
                </CardContent>
              </Card>

              {/* WiFi Security Tips */}
              <Card className="bg-black/30 border-gray-700 backdrop-blur-lg">
                <CardHeader>
                  <CardTitle className="text-white flex items-center">
                    <ShieldAlert className="w-5 h-5 mr-2" />
                    WiFi Security Assessment
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="space-y-3">
                    <div className="flex items-center justify-between p-3 rounded-lg bg-red-900/20 border border-red-600/30">
                      <div>
                        <p className="text-white font-medium">Open Networks</p>
                        <p className="text-gray-400 text-sm">Unencrypted connections</p>
                      </div>
                      <Badge className="bg-red-600 text-white">
                        {wifiNetworks.filter(n => n.security === 'Open').length}
                      </Badge>
                    </div>
                    
                    <div className="flex items-center justify-between p-3 rounded-lg bg-yellow-900/20 border border-yellow-600/30">
                      <div>
                        <p className="text-white font-medium">Weak Encryption</p>
                        <p className="text-gray-400 text-sm">WEP/WPA networks</p>
                      </div>
                      <Badge className="bg-yellow-600 text-white">
                        {wifiNetworks.filter(n => ['WEP', 'WPA'].includes(n.security)).length}
                      </Badge>
                    </div>
                    
                    <div className="flex items-center justify-between p-3 rounded-lg bg-green-900/20 border border-green-600/30">
                      <div>
                        <p className="text-white font-medium">Secure Networks</p>
                        <p className="text-gray-400 text-sm">WPA2/WPA3 encryption</p>
                      </div>
                      <Badge className="bg-green-600 text-white">
                        {wifiNetworks.filter(n => ['WPA2-PSK', 'WPA3', 'WPA2'].includes(n.security)).length}
                      </Badge>
                    </div>
                  </div>

                  <div className="pt-4 border-t border-gray-600">
                    <h4 className="text-white font-medium mb-2">Security Recommendations</h4>
                    <ul className="space-y-1 text-sm text-gray-300">
                      <li>• Avoid connecting to open WiFi networks</li>
                      <li>• Use VPN on public networks</li>
                      <li>• Verify network names with venue staff</li>
                      <li>• Disable auto-connect features</li>
                      <li>• Use mobile hotspot when possible</li>
                    </ul>
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          {/* Malware Analysis Tab */}
          <TabsContent value="malware" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* File Upload Section */}
              <Card className="bg-black/30 border-gray-700 backdrop-blur-lg">
                <CardHeader>
                  <CardTitle className="text-white flex items-center">
                    <Upload className="w-5 h-5 mr-2" />
                    File Malware Scanner
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="border-2 border-dashed border-gray-600 rounded-lg p-8 text-center">
                    <Upload className="w-12 h-12 mx-auto mb-4 text-gray-400" />
                    <p className="text-white mb-2">Upload file for malware analysis</p>
                    <p className="text-gray-400 text-sm mb-4">Maximum file size: 32MB</p>
                    <input
                      ref={fileInputRef}
                      type="file"
                      onChange={handleFileUpload}
                      className="hidden"
                      disabled={fileScanning}
                    />
                    <Button
                      onClick={() => fileInputRef.current?.click()}
                      disabled={fileScanning}
                      className="bg-red-600 hover:bg-red-700 text-white"
                    >
                      {fileScanning ? (
                        <>
                          <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                          Scanning...
                        </>
                      ) : (
                        <>
                          <Upload className="w-4 h-4 mr-2" />
                          Choose File
                        </>
                      )}
                    </Button>
                  </div>
                </CardContent>
              </Card>

              {/* Recent Malware Analysis Results */}
              <Card className="bg-black/30 border-gray-700 backdrop-blur-lg">
                <CardHeader>
                  <CardTitle className="text-white flex items-center">
                    <FileText className="w-5 h-5 mr-2" />
                    Recent File Analysis
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3 max-h-96 overflow-y-auto">
                  {malwareAnalyses.map((analysis) => (
                    <div key={analysis.id} className="p-3 rounded-lg bg-black/20 border border-gray-700/50">
                      <div className="flex justify-between items-start mb-2">
                        <div className="flex-1">
                          <p className="text-white font-medium text-sm truncate">{analysis.filename}</p>
                          <p className="text-gray-400 text-xs">{formatTimestamp(analysis.scan_date)}</p>
                        </div>
                        <Badge className={getRiskBadgeColor(analysis.risk_level)}>
                          {analysis.risk_level}
                        </Badge>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-gray-300 text-sm">{analysis.detection_ratio}</span>
                        {analysis.virustotal_link && (
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => window.open(analysis.virustotal_link, '_blank')}
                            className="text-xs border-gray-600 text-gray-300 hover:bg-gray-700"
                          >
                            <ExternalLink className="w-3 h-3" />
                          </Button>
                        )}
                      </div>
                      {analysis.threat_detected && analysis.threat_type && (
                        <p className="text-red-400 text-xs mt-1">{analysis.threat_type}</p>
                      )}
                    </div>
                  ))}
                  {malwareAnalyses.length === 0 && (
                    <div className="text-center py-8 text-gray-400">
                      <Bug className="w-12 h-12 mx-auto mb-4 opacity-50" />
                      <p>No file analyses yet</p>
                      <p className="text-sm">Upload a file to start analysis</p>
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          {/* URL Scanner Tab */}
          <TabsContent value="url" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* URL Input Section */}
              <Card className="bg-black/30 border-gray-700 backdrop-blur-lg">
                <CardHeader>
                  <CardTitle className="text-white flex items-center">
                    <Globe className="w-5 h-5 mr-2" />
                    Website Threat Scanner
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="space-y-3">
                    <Input
                      placeholder="Enter URL to scan (e.g., https://example.com)"
                      value={urlToScan}
                      onChange={(e) => setUrlToScan(e.target.value)}
                      className="bg-black/20 border-gray-600 text-white placeholder-gray-400"
                      disabled={urlScanning}
                    />
                    <Button
                      onClick={handleUrlScan}
                      disabled={urlScanning || !urlToScan.trim()}
                      className="w-full bg-purple-600 hover:bg-purple-700 text-white"
                    >
                      {urlScanning ? (
                        <>
                          <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                          Analyzing URL...
                        </>
                      ) : (
                        <>
                          <Globe className="w-4 h-4 mr-2" />
                          Scan URL
                        </>
                      )}
                    </Button>
                  </div>
                  <div className="text-sm text-gray-400">
                    <p>• Detects malicious websites</p>
                    <p>• Identifies phishing attempts</p>
                    <p>• Checks for malware distribution</p>
                    <p>• Powered by VirusTotal</p>
                  </div>
                </CardContent>
              </Card>

              {/* Recent URL Analysis Results */}
              <Card className="bg-black/30 border-gray-700 backdrop-blur-lg">
                <CardHeader>
                  <CardTitle className="text-white flex items-center">
                    <FileText className="w-5 h-5 mr-2" />
                    Recent URL Analysis
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3 max-h-96 overflow-y-auto">
                  {urlAnalyses.map((analysis) => (
                    <div key={analysis.id} className="p-3 rounded-lg bg-black/20 border border-gray-700/50">
                      <div className="flex justify-between items-start mb-2">
                        <div className="flex-1">
                          <p className="text-white font-medium text-sm truncate">{analysis.url}</p>
                          <p className="text-gray-400 text-xs">{formatTimestamp(analysis.scan_date)}</p>
                        </div>
                        <Badge className={getRiskBadgeColor(analysis.risk_level)}>
                          {analysis.risk_level}
                        </Badge>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-gray-300 text-sm">{analysis.detection_ratio}</span>
                        {analysis.virustotal_link && (
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => window.open(analysis.virustotal_link, '_blank')}
                            className="text-xs border-gray-600 text-gray-300 hover:bg-gray-700"
                          >
                            <ExternalLink className="w-3 h-3" />
                          </Button>
                        )}
                      </div>
                      {analysis.threat_categories && analysis.threat_categories.length > 0 && (
                        <div className="mt-2 flex flex-wrap gap-1">
                          {analysis.threat_categories.slice(0, 3).map((category, idx) => (
                            <Badge key={idx} className="bg-red-800 text-white text-xs">
                              {category}
                            </Badge>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                  {urlAnalyses.length === 0 && (
                    <div className="text-center py-8 text-gray-400">
                      <Globe className="w-12 h-12 mx-auto mb-4 opacity-50" />
                      <p>No URL analyses yet</p>
                      <p className="text-sm">Enter a URL to start analysis</p>
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          {/* Security Inbox Tab */}
          <TabsContent value="inbox" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Add URL to Inbox */}
              <Card className="bg-black/30 border-gray-700 backdrop-blur-lg">
                <CardHeader>
                  <CardTitle className="text-white flex items-center">
                    <Plus className="w-5 h-5 mr-2" />
                    Add Website to Check
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="space-y-3">
                    <Input
                      placeholder="Enter website URL to check"
                      value={inboxUrl}
                      onChange={(e) => setInboxUrl(e.target.value)}
                      className="bg-black/20 border-gray-600 text-white placeholder-gray-400"
                      disabled={addingToInbox}
                    />
                    <Textarea
                      placeholder="Add note (optional)"
                      value={inboxNote}
                      onChange={(e) => setInboxNote(e.target.value)}
                      className="bg-black/20 border-gray-600 text-white placeholder-gray-400 min-h-[80px]"
                      disabled={addingToInbox}
                    />
                    <Button
                      onClick={handleAddToInbox}
                      disabled={addingToInbox || !inboxUrl.trim()}
                      className="w-full bg-cyan-600 hover:bg-cyan-700 text-white"
                    >
                      {addingToInbox ? (
                        <>
                          <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                          Adding...
                        </>
                      ) : (
                        <>
                          <Plus className="w-4 h-4 mr-2" />
                          Add to Security Inbox
                        </>
                      )}
                    </Button>
                  </div>
                  
                  <div className="pt-4 border-t border-gray-600">
                    <h4 className="text-white font-medium mb-2">Security Inbox Features</h4>
                    <ul className="space-y-1 text-sm text-gray-300">
                      <li>• Queue URLs for security analysis</li>
                      <li>• Track scanning status and results</li>
                      <li>• Batch scan multiple websites</li>
                      <li>• Manage threat detection history</li>
                      <li>• Export security reports</li>
                    </ul>
                  </div>
                </CardContent>
              </Card>

              {/* Inbox Status Summary */}
              <Card className="bg-black/30 border-gray-700 backdrop-blur-lg">
                <CardHeader>
                  <CardTitle className="text-white flex items-center">
                    <Mail className="w-5 h-5 mr-2" />
                    Inbox Summary
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid grid-cols-1 gap-3">
                    <div className="flex items-center justify-between p-3 rounded-lg bg-blue-900/20 border border-blue-600/30">
                      <div>
                        <p className="text-white font-medium">Pending Scans</p>
                        <p className="text-gray-400 text-sm">Waiting for analysis</p>
                      </div>
                      <Badge className="bg-blue-600 text-white">
                        {inboxEntries.filter(entry => entry.scan_status === 'pending').length}
                      </Badge>
                    </div>
                    
                    <div className="flex items-center justify-between p-3 rounded-lg bg-green-900/20 border border-green-600/30">
                      <div>
                        <p className="text-white font-medium">Clean URLs</p>
                        <p className="text-gray-400 text-sm">Safe websites</p>
                      </div>
                      <Badge className="bg-green-600 text-white">
                        {inboxEntries.filter(entry => entry.scan_status === 'completed' && !entry.threat_detected).length}
                      </Badge>
                    </div>
                    
                    <div className="flex items-center justify-between p-3 rounded-lg bg-red-900/20 border border-red-600/30">
                      <div>
                        <p className="text-white font-medium">Threats Found</p>
                        <p className="text-gray-400 text-sm">Malicious websites</p>
                      </div>
                      <Badge className="bg-red-600 text-white">
                        {inboxEntries.filter(entry => entry.threat_detected).length}
                      </Badge>
                    </div>
                  </div>

                  <div className="pt-4 border-t border-gray-600">
                    <Button
                      onClick={fetchInboxEntries}
                      size="sm"
                      className="w-full bg-gray-600 hover:bg-gray-700 text-white"
                    >
                      <RefreshCw className="w-4 h-4 mr-2" />
                      Refresh Inbox
                    </Button>
                  </div>
                </CardContent>
              </Card>

              {/* Inbox Entries List */}
              <Card className="bg-black/30 border-gray-700 backdrop-blur-lg">
                <CardHeader>
                  <CardTitle className="text-white flex items-center">
                    <FileText className="w-5 h-5 mr-2" />
                    Security Inbox ({inboxEntries.length})
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3 max-h-96 overflow-y-auto">
                  {inboxEntries.map((entry) => (
                    <div key={entry.id} className="p-3 rounded-lg bg-black/20 border border-gray-700/50">
                      <div className="flex justify-between items-start mb-2">
                        <div className="flex-1">
                          <p className="text-white font-medium text-sm truncate">{entry.url}</p>
                          <p className="text-gray-400 text-xs">{formatTimestamp(entry.added_date)}</p>
                          {entry.user_note && (
                            <p className="text-gray-500 text-xs mt-1 italic">"{entry.user_note}"</p>
                          )}
                        </div>
                        <div className="flex items-center space-x-2">
                          <Badge className={getInboxStatusColor(entry.scan_status)}>
                            {entry.scan_status}
                          </Badge>
                          {entry.threat_detected && (
                            <Badge className="bg-red-600 text-white text-xs">THREAT</Badge>
                          )}
                        </div>
                      </div>
                      
                      <div className="flex justify-between items-center">
                        <div className="flex space-x-2">
                          {entry.scan_status === 'pending' && (
                            <Button
                              size="sm"
                              onClick={() => handleScanFromInbox(entry.id)}
                              className="bg-blue-600 hover:bg-blue-700 text-white text-xs"
                            >
                              <Scan className="w-3 h-3 mr-1" />
                              Scan Now
                            </Button>
                          )}
                          {entry.scan_result && entry.scan_result.virustotal_link && (
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => window.open(entry.scan_result.virustotal_link, '_blank')}
                              className="text-xs border-gray-600 text-gray-300 hover:bg-gray-700"
                            >
                              <ExternalLink className="w-3 h-3" />
                            </Button>
                          )}
                        </div>
                        <Button
                          size="sm"
                          onClick={() => handleDeleteInboxEntry(entry.id)}
                          className="bg-red-600 hover:bg-red-700 text-white text-xs"
                        >
                          <Trash2 className="w-3 h-3" />
                        </Button>
                      </div>
                      
                      {entry.scan_result && (
                        <div className="mt-2 pt-2 border-t border-gray-600/50">
                          <div className="flex justify-between items-center text-xs">
                            <span className="text-gray-400">Detection Ratio:</span>
                            <span className="text-white">{entry.scan_result.detection_ratio}</span>
                          </div>
                          <div className="flex justify-between items-center text-xs">
                            <span className="text-gray-400">Risk Level:</span>
                            <Badge className={getRiskBadgeColor(entry.scan_result.risk_level)} size="xs">
                              {entry.scan_result.risk_level}
                            </Badge>
                          </div>
                        </div>
                      )}
                    </div>
                  ))}
                  
                  {inboxEntries.length === 0 && (
                    <div className="text-center py-8 text-gray-400">
                      <Mail className="w-12 h-12 mx-auto mb-4 opacity-50" />
                      <p>No entries in security inbox</p>
                      <p className="text-sm">Add a website URL to start checking</p>
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          {/* Threat Alerts Tab */}
          <TabsContent value="alerts" className="space-y-6">
            <Card className="bg-black/30 border-gray-700 backdrop-blur-lg">
              <CardHeader>
                <CardTitle className="text-white flex items-center">
                  <AlertTriangle className="w-5 h-5 mr-2" />
                  Security Threat Alerts
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3 max-h-96 overflow-y-auto">
                {alerts.map((alert) => (
                  <Alert key={alert.id} className={`border-gray-600/30 ${
                    alert.severity === 'High' ? 'bg-red-900/20 border-red-600/30' :
                    alert.severity === 'Medium' ? 'bg-yellow-900/20 border-yellow-600/30' :
                    'bg-blue-900/20 border-blue-600/30'
                  }`}>
                    <AlertTriangle className="h-4 w-4" />
                    <AlertDescription className="text-gray-200">
                      <div className="flex justify-between items-start">
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-1">
                            <p className="font-medium">{alert.alert_type}</p>
                            <Badge variant="outline" className={
                              alert.severity === 'High' ? 'text-red-400 border-red-400/30' :
                              alert.severity === 'Medium' ? 'text-yellow-400 border-yellow-400/30' :
                              'text-blue-400 border-blue-400/30'
                            }>
                              {alert.severity}
                            </Badge>
                          </div>
                          <p className="text-sm opacity-80">{alert.description}</p>
                          <div className="flex items-center gap-4 mt-2 text-xs text-gray-400">
                            <span>{formatTimestamp(alert.timestamp)}</span>
                            {alert.source_ip && <span>Source: {alert.source_ip}</span>}
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          {alert.resolved ? (
                            <Badge className="bg-green-600 text-white text-xs">
                              <CheckCircle className="w-3 h-3 mr-1" />
                              Resolved
                            </Badge>
                          ) : (
                            <Button
                              size="sm"
                              onClick={() => resolveAlert(alert.id)}
                              className="bg-green-600 hover:bg-green-700 text-white text-xs"
                            >
                              <CheckCircle className="w-3 h-3 mr-1" />
                              Resolve
                            </Button>
                          )}
                        </div>
                      </div>
                    </AlertDescription>
                  </Alert>
                ))}
                {alerts.length === 0 && (
                  <div className="text-center py-8 text-gray-400">
                    <CheckCircle className="w-12 h-12 mx-auto mb-4 opacity-50" />
                    <p>No security alerts</p>
                    <p className="text-sm">Your network appears to be secure</p>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>

        {lastScan && (
          <div className="mt-6 text-center">
            <p className="text-gray-400 text-sm flex items-center justify-center">
              <Clock className="w-4 h-4 mr-1" />
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

  // Enhanced grid-based topology with better positioning
  const renderDevices = () => {
    return devices.map((device, index) => {
      // Create a more spread out layout
      const cols = 8;
      const x = (index % cols) * 90 + 80;
      const y = Math.floor(index / cols) * 80 + 80;
      
      let riskColor = '#22c55e'; // Default green
      if (device.risk_score >= 70) riskColor = '#ef4444';
      else if (device.risk_score >= 40) riskColor = '#f59e0b';
      
      // Enhanced device representation
      let strokeColor = '#374151';
      if (device.is_rogue) strokeColor = '#ef4444';
      if (device.is_wifi_threat) strokeColor = '#f59e0b';

      return (
        <g key={device.id}>
          {/* Connection line to center hub */}
          <line
            x1={350}
            y1={200}
            x2={x}
            y2={y}
            stroke={strokeColor}
            strokeWidth={device.is_rogue || device.is_wifi_threat ? "3" : "2"}
            opacity={device.is_rogue || device.is_wifi_threat ? "0.8" : "0.4"}
            strokeDasharray={device.is_wifi_threat ? "5,5" : "none"}
          />
          
          {/* Device node */}
          <circle
            cx={x}
            cy={y}
            r={device.is_rogue || device.is_wifi_threat ? "25" : "20"}
            fill={riskColor}
            stroke={strokeColor}
            strokeWidth="3"
            className="cursor-pointer transition-all hover:opacity-80"
            onClick={() => setSelectedDevice(device)}
          />
          
          {/* Device type icon representation */}
          <circle
            cx={x}
            cy={y}
            r="8"
            fill="white"
            opacity="0.9"
          />
          
          {/* Device label */}
          <text
            x={x}
            y={y + 40}
            textAnchor="middle"
            className="fill-gray-300 text-xs"
          >
            {device.hostname?.substring(0, 10) || device.ip_address.split('.').pop()}
          </text>
          
          {/* Threat indicators */}
          {device.is_rogue && (
            <circle
              cx={x + 20}
              cy={y - 20}
              r="6"
              fill="#ef4444"
              className="animate-pulse"
            >
              <title>Rogue Device</title>
            </circle>
          )}
          
          {device.is_wifi_threat && (
            <circle
              cx={x - 20}
              cy={y - 20}
              r="6"
              fill="#f59e0b"
              className="animate-pulse"
            >
              <title>WiFi Threat</title>
            </circle>
          )}
        </g>
      );
    });
  };

  return (
    <div className="relative">
      <svg width="700" height="400" className="border border-gray-700 rounded-lg bg-black/10">
        {/* Enhanced central hub */}
        <circle
          cx="350"
          cy="200"
          r="35"
          fill="#0891b2"
          stroke="#1f2937"
          strokeWidth="4"
        />
        <text
          x="350"
          y="205"
          textAnchor="middle"
          className="fill-white font-bold text-sm"
        >
          NETWORK
        </text>
        <text
          x="350"
          y="218"
          textAnchor="middle"
          className="fill-white font-normal text-xs"
        >
          HUB
        </text>
        
        {/* Device connections and nodes */}
        {renderDevices()}
        
        {/* Legend */}
        <g transform="translate(10, 10)">
          <rect width="150" height="80" fill="black" fillOpacity="0.7" stroke="#374151" rx="5" />
          <text x="10" y="20" className="fill-white text-xs font-bold">Legend:</text>
          <circle cx="20" cy="35" r="5" fill="#22c55e" />
          <text x="35" y="40" className="fill-gray-300 text-xs">Safe Device</text>
          <circle cx="20" cy="50" r="5" fill="#f59e0b" />
          <text x="35" y="55" className="fill-gray-300 text-xs">Medium Risk</text>
          <circle cx="20" cy="65" r="5" fill="#ef4444" />
          <text x="35" y="70" className="fill-gray-300 text-xs">High Risk</text>
        </g>
      </svg>
      
      {/* Enhanced device info tooltip */}
      {selectedDevice && (
        <div className="absolute top-4 right-4 bg-black/90 p-4 rounded-lg border border-gray-600 backdrop-blur-lg max-w-xs">
          <div className="flex justify-between items-start mb-2">
            <h4 className="text-white font-bold">{selectedDevice.hostname || 'Unknown Device'}</h4>
            <button 
              onClick={() => setSelectedDevice(null)}
              className="text-gray-400 hover:text-white text-sm"
            >
              ✕
            </button>
          </div>
          
          <div className="space-y-2 text-sm">
            <div className="grid grid-cols-2 gap-2">
              <span className="text-gray-400">IP:</span>
              <span className="text-white">{selectedDevice.ip_address}</span>
              
              <span className="text-gray-400">MAC:</span>
              <span className="text-white text-xs">{selectedDevice.mac_address}</span>
              
              <span className="text-gray-400">Type:</span>
              <span className="text-white">{selectedDevice.device_type}</span>
              
              <span className="text-gray-400">Risk Score:</span>
              <span className="text-white">{selectedDevice.risk_score}/100</span>
              
              {selectedDevice.open_ports && selectedDevice.open_ports.length > 0 && (
                <>
                  <span className="text-gray-400">Open Ports:</span>
                  <span className="text-white">{selectedDevice.open_ports.length} ports</span>
                </>
              )}
            </div>
            
            <div className="flex items-center space-x-2 pt-2 border-t border-gray-600">
              <div className={`w-3 h-3 rounded-full ${
                selectedDevice.risk_score >= 70 ? 'bg-red-500' : 
                selectedDevice.risk_score >= 40 ? 'bg-yellow-500' : 'bg-green-500'
              }`} />
              <span className="text-xs text-gray-400">
                {selectedDevice.risk_score >= 70 ? 'High Risk' : 
                 selectedDevice.risk_score >= 40 ? 'Medium Risk' : 'Low Risk'}
              </span>
            </div>
            
            {(selectedDevice.is_rogue || selectedDevice.is_wifi_threat) && (
              <div className="pt-2 border-t border-gray-600">
                {selectedDevice.is_rogue && (
                  <Badge className="bg-red-600 text-white text-xs mr-1">ROGUE DEVICE</Badge>
                )}
                {selectedDevice.is_wifi_threat && (
                  <Badge className="bg-orange-600 text-white text-xs">WiFi THREAT</Badge>
                )}
              </div>
            )}
            
            {selectedDevice.suspicious_activity && selectedDevice.suspicious_activity.length > 0 && (
              <div className="pt-2 border-t border-gray-600">
                <p className="text-gray-400 text-xs mb-1">Suspicious Activity:</p>
                {selectedDevice.suspicious_activity.map((activity, idx) => (
                  <p key={idx} className="text-red-400 text-xs">• {activity}</p>
                ))}
              </div>
            )}
          </div>
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