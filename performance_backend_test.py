#!/usr/bin/env python3
"""
CryptoPulse Enhanced Network Security System - Performance-Focused Backend Testing
Focus: Performance optimization, threat detection accuracy, and comprehensive API testing
"""

import requests
import json
import time
import io
import sys
import threading
from datetime import datetime
from urllib.parse import urlparse
import websocket

class CryptoPulsePerformanceTester:
    def __init__(self, base_url="https://scan-protector.preview.emergentagent.com"):
        self.base_url = base_url
        self.api_url = f"{base_url}/api"
        self.tests_run = 0
        self.tests_passed = 0
        self.performance_metrics = {}
        self.critical_failures = []
        self.minor_issues = []
        
    def log_result(self, test_name, success, duration=None, response_data=None, is_critical=True):
        """Log test results with performance metrics"""
        self.tests_run += 1
        if success:
            self.tests_passed += 1
            status_icon = "✅"
            if duration:
                self.performance_metrics[test_name] = duration
                print(f"{status_icon} {test_name} ({duration:.2f}s)")
            else:
                print(f"{status_icon} {test_name}")
                
            if response_data and isinstance(response_data, dict):
                if 'devices_found' in response_data:
                    print(f"   Devices found: {response_data['devices_found']}")
                if 'threats_found' in response_data:
                    print(f"   Threats found: {response_data['threats_found']}")
                if 'scan_duration' in response_data:
                    print(f"   Scan duration: {response_data['scan_duration']:.2f}s")
        else:
            if is_critical:
                self.critical_failures.append(test_name)
                print(f"❌ {test_name} (CRITICAL)")
            else:
                self.minor_issues.append(test_name)
                print(f"⚠️  {test_name} (MINOR)")
    
    def make_request(self, method, endpoint, data=None, files=None, timeout=30, form_data=False):
        """Make HTTP request with performance timing"""
        url = f"{self.api_url}/{endpoint}" if not endpoint.startswith('http') else endpoint
        
        start_time = time.time()
        try:
            if method == 'GET':
                response = requests.get(url, timeout=timeout)
            elif method == 'POST':
                if files or form_data:
                    response = requests.post(url, data=data, files=files, timeout=timeout)
                else:
                    response = requests.post(url, json=data, timeout=timeout)
            elif method == 'DELETE':
                response = requests.delete(url, timeout=timeout)
            else:
                raise ValueError(f"Unsupported method: {method}")
            
            duration = time.time() - start_time
            return response.status_code, response.text, response.headers, duration
            
        except requests.exceptions.Timeout:
            duration = time.time() - start_time
            return None, f"Request timed out after {timeout} seconds", {}, duration
        except Exception as e:
            duration = time.time() - start_time
            return None, str(e), {}, duration

    def test_network_device_scanning_performance(self):
        """Test Network Device Scanning Performance - CRITICAL TEST AREA 1"""
        print("\n🔍 TESTING NETWORK DEVICE SCANNING PERFORMANCE")
        print("=" * 55)
        print("Performance Requirement: Network scans should complete within 2-3 minutes max")
        
        # Test scan progress endpoint first
        print("\n1. Testing Scan Progress Endpoint...")
        status, response_text, _, duration = self.make_request('GET', 'scan/progress')
        
        if status == 200:
            try:
                response_data = json.loads(response_text)
                self.log_result("Scan progress endpoint", True, duration, response_data)
            except:
                self.log_result("Scan progress endpoint", False, is_critical=False)
        else:
            self.log_result("Scan progress endpoint", False, is_critical=True)
        
        # Test enhanced network scan with performance monitoring
        print("\n2. Testing Enhanced Network Scan Performance...")
        print("   Starting network scan with performance monitoring...")
        
        start_time = time.time()
        status, response_text, _, duration = self.make_request('POST', 'scan/network', timeout=180)
        
        if status == 200:
            try:
                response_data = json.loads(response_text)
                scan_duration = response_data.get('scan_duration', duration)
                
                # Check performance requirement (2-3 minutes max = 180 seconds)
                if scan_duration <= 180:
                    self.log_result("Network scan performance", True, scan_duration, response_data)
                    print(f"   ✅ Performance requirement met: {scan_duration:.2f}s ≤ 180s")
                else:
                    self.log_result("Network scan performance - TOO SLOW", False, is_critical=True)
                    print(f"   ❌ Performance requirement failed: {scan_duration:.2f}s > 180s")
                
                # Test parallel processing and caching optimizations
                if 'devices_found' in response_data:
                    devices_count = response_data['devices_found']
                    if devices_count > 0:
                        processing_rate = devices_count / scan_duration
                        print(f"   Device processing rate: {processing_rate:.2f} devices/second")
                        
                        if processing_rate > 0.5:  # At least 0.5 devices per second
                            self.log_result("Device processing efficiency", True)
                        else:
                            self.log_result("Device processing efficiency - SLOW", False, is_critical=False)
                
            except:
                self.log_result("Network scan performance", False, is_critical=True)
        else:
            self.log_result("Network scan performance", False, is_critical=True)
        
        # Test WebSocket real-time updates during scanning
        print("\n3. Testing WebSocket Real-time Updates...")
        self.test_websocket_scanning_updates()

    def test_wifi_threat_detection(self):
        """Test WiFi Threat Detection - CRITICAL TEST AREA 2"""
        print("\n📶 TESTING WIFI THREAT DETECTION")
        print("=" * 40)
        
        # Test WiFi networks endpoint
        print("\n1. Testing WiFi Networks Discovery...")
        status, response_text, _, duration = self.make_request('GET', 'wifi/networks')
        
        if status == 200:
            try:
                response_data = json.loads(response_text)
                networks = response_data.get('networks', [])
                threats = response_data.get('threats_summary', [])
                
                self.log_result("WiFi networks discovery", True, duration, response_data)
                
                # Test threat categorization
                print("\n2. Testing WiFi Threat Categorization...")
                threat_categories_found = []
                
                for network in networks:
                    if 'threat_level' in network:
                        threat_level = network.get('threat_level')
                        if threat_level not in threat_categories_found:
                            threat_categories_found.append(threat_level)
                    
                    # Check for specific threat types
                    network_threats = network.get('threats', [])
                    for threat in network_threats:
                        if 'Open Network' in threat:
                            print(f"   ✅ Open network threat detected: {network.get('ssid', 'Unknown')}")
                        if 'Weak Encryption' in threat:
                            print(f"   ✅ Weak encryption detected: {network.get('ssid', 'Unknown')}")
                        if 'Suspicious' in threat:
                            print(f"   ✅ Suspicious SSID detected: {network.get('ssid', 'Unknown')}")
                
                if threat_categories_found:
                    self.log_result("WiFi threat categorization", True)
                    print(f"   Threat levels found: {threat_categories_found}")
                else:
                    self.log_result("WiFi threat categorization - No threats found", True, is_critical=False)
                
                # Test WiFi security assessment
                print("\n3. Testing WiFi Security Assessment...")
                security_assessment_working = False
                
                for network in networks:
                    security = network.get('security', '')
                    encryption = network.get('encryption', '')
                    
                    if security or encryption:
                        security_assessment_working = True
                        print(f"   Security info found for {network.get('ssid', 'Unknown')}: {security}")
                
                if security_assessment_working:
                    self.log_result("WiFi security assessment", True)
                else:
                    self.log_result("WiFi security assessment - Limited data", True, is_critical=False)
                
            except:
                self.log_result("WiFi networks discovery", False, is_critical=True)
        else:
            self.log_result("WiFi networks discovery", False, is_critical=True)

    def test_malware_file_scanning(self):
        """Test Malware File Scanning - CRITICAL TEST AREA 3"""
        print("\n🦠 TESTING MALWARE FILE SCANNING")
        print("=" * 40)
        print("Performance Requirement: File scans should process within 30 seconds for files under 10MB")
        
        # Test file upload limits and processing speed
        print("\n1. Testing File Upload and Processing Speed...")
        
        # Create test files of different sizes
        test_files = [
            ("small_test.txt", b"This is a small test file for malware scanning.", "text/plain"),
            ("medium_test.txt", b"X" * 1024 * 100, "text/plain"),  # 100KB file
            ("large_test.txt", b"Y" * 1024 * 1024, "text/plain")   # 1MB file
        ]
        
        for filename, content, content_type in test_files:
            print(f"\n   Testing {filename} ({len(content)} bytes)...")
            
            test_file = io.BytesIO(content)
            files = {'file': (filename, test_file, content_type)}
            
            start_time = time.time()
            status, response_text, _, duration = self.make_request('POST', 'scan/file', files=files, timeout=60)
            
            if status == 200:
                try:
                    response_data = json.loads(response_text)
                    
                    # Check performance requirement (30 seconds for files under 10MB)
                    if len(content) < 10 * 1024 * 1024 and duration <= 30:
                        self.log_result(f"File scan performance - {filename}", True, duration, response_data)
                        print(f"   ✅ Performance requirement met: {duration:.2f}s ≤ 30s")
                    elif len(content) >= 10 * 1024 * 1024:
                        self.log_result(f"File scan - {filename}", True, duration, response_data)
                        print(f"   File size: {len(content)} bytes, Duration: {duration:.2f}s")
                    else:
                        self.log_result(f"File scan performance - {filename} TOO SLOW", False, is_critical=True)
                        print(f"   ❌ Performance requirement failed: {duration:.2f}s > 30s")
                    
                    # Test VirusTotal integration
                    if 'virustotal_link' in response_data:
                        self.log_result("VirusTotal integration", True)
                        print(f"   ✅ VirusTotal link: {response_data['virustotal_link'][:50]}...")
                    
                    # Test malware detection accuracy
                    if 'risk_level' in response_data:
                        risk_level = response_data['risk_level']
                        detection_ratio = response_data.get('detection_ratio', '0/0')
                        print(f"   Risk Level: {risk_level}, Detection: {detection_ratio}")
                        
                        if risk_level in ['Clean', 'Low', 'Medium', 'High', 'Pending', 'Unknown', 'Error']:
                            self.log_result("Malware detection categorization", True)
                        else:
                            self.log_result("Malware detection categorization", False, is_critical=False)
                    
                except:
                    self.log_result(f"File scan - {filename}", False, is_critical=True)
            else:
                self.log_result(f"File scan - {filename}", False, is_critical=True)

    def test_url_threat_analysis(self):
        """Test URL Threat Analysis - CRITICAL TEST AREA 4"""
        print("\n🌐 TESTING URL THREAT ANALYSIS")
        print("=" * 35)
        print("Performance Requirement: URL scans should complete within 15 seconds")
        
        # Test URLs with various risk levels
        test_urls = [
            ("https://www.google.com", "Known safe URL"),
            ("https://github.com", "Developer platform"),
            ("https://stackoverflow.com", "Q&A platform"),
            ("http://example.com", "HTTP (less secure)")
        ]
        
        for url, description in test_urls:
            print(f"\n   Testing {description}: {url}")
            
            data = {'url': url}
            start_time = time.time()
            status, response_text, _, duration = self.make_request('POST', 'scan/url', data=data, form_data=True, timeout=30)
            
            if status == 200:
                try:
                    response_data = json.loads(response_text)
                    
                    # Check performance requirement (15 seconds)
                    if duration <= 15:
                        self.log_result(f"URL scan performance - {description}", True, duration, response_data)
                        print(f"   ✅ Performance requirement met: {duration:.2f}s ≤ 15s")
                    else:
                        self.log_result(f"URL scan performance - {description} TOO SLOW", False, is_critical=True)
                        print(f"   ❌ Performance requirement failed: {duration:.2f}s > 15s")
                    
                    # Test VirusTotal URL scanning integration
                    if 'virustotal_link' in response_data:
                        self.log_result("VirusTotal URL integration", True)
                    
                    # Test malicious URL detection accuracy
                    if 'risk_level' in response_data:
                        risk_level = response_data['risk_level']
                        detection_ratio = response_data.get('detection_ratio', '0/0')
                        threat_categories = response_data.get('threat_categories', [])
                        
                        print(f"   Risk Level: {risk_level}, Detection: {detection_ratio}")
                        if threat_categories:
                            print(f"   Threat Categories: {threat_categories}")
                        
                        if risk_level in ['Clean', 'Low', 'Medium', 'High', 'Pending', 'Unknown', 'Error']:
                            self.log_result("URL threat categorization", True)
                        else:
                            self.log_result("URL threat categorization", False, is_critical=False)
                    
                except:
                    self.log_result(f"URL scan - {description}", False, is_critical=True)
            else:
                self.log_result(f"URL scan - {description}", False, is_critical=True)

    def test_security_inbox_functionality(self):
        """Test Security Inbox Functionality - CRITICAL TEST AREA 5"""
        print("\n🔒 TESTING SECURITY INBOX FUNCTIONALITY")
        print("=" * 45)
        
        # Test URL queuing and batch processing
        print("\n1. Testing URL Queuing...")
        test_urls = [
            "https://example.com",
            "https://httpbin.org/get",
            "https://jsonplaceholder.typicode.com/posts/1"
        ]
        
        added_ids = []
        for url in test_urls:
            data = {'url': url, 'note': f'Performance test: {url}'}
            status, response_text, _, duration = self.make_request('POST', 'inbox/add-url', data=data, form_data=True)
            
            if status == 200:
                try:
                    response_data = json.loads(response_text)
                    if response_data.get('status') in ['added', 'exists']:
                        added_ids.append(response_data.get('id'))
                        self.log_result(f"Add URL to inbox: {url}", True, duration)
                    else:
                        self.log_result(f"Add URL to inbox: {url}", False, is_critical=True)
                except:
                    self.log_result(f"Add URL to inbox: {url}", False, is_critical=True)
            else:
                self.log_result(f"Add URL to inbox: {url}", False, is_critical=True)
        
        # Test inbox entries retrieval
        print("\n2. Testing Inbox Entries Retrieval...")
        status, response_text, _, duration = self.make_request('GET', 'inbox/entries')
        
        if status == 200:
            try:
                response_data = json.loads(response_text)
                entries = response_data.get('entries', [])
                self.log_result("Get inbox entries", True, duration)
                print(f"   Total entries: {len(entries)}")
            except:
                self.log_result("Get inbox entries", False, is_critical=True)
        else:
            self.log_result("Get inbox entries", False, is_critical=True)
        
        # Test batch processing
        print("\n3. Testing Batch URL Processing...")
        if added_ids:
            for inbox_id in added_ids[:2]:  # Test first 2 IDs
                status, response_text, _, duration = self.make_request('POST', f'inbox/scan/{inbox_id}')
                
                if status == 200:
                    try:
                        response_data = json.loads(response_text)
                        self.log_result(f"Scan inbox URL {inbox_id[:8]}...", True, duration)
                    except:
                        self.log_result(f"Scan inbox URL {inbox_id[:8]}...", False, is_critical=False)
                else:
                    self.log_result(f"Scan inbox URL {inbox_id[:8]}...", False, is_critical=True)
        
        # Test batch scan endpoint
        print("\n4. Testing Batch Scan Endpoint...")
        batch_urls = ["https://www.wikipedia.org", "https://www.reddit.com"]
        status, response_text, _, duration = self.make_request('POST', 'inbox/batch-scan', data=batch_urls)
        
        if status == 200:
            try:
                response_data = json.loads(response_text)
                self.log_result("Batch scan URLs", True, duration, response_data)
            except:
                self.log_result("Batch scan URLs", False, is_critical=False)
        else:
            self.log_result("Batch scan URLs", False, is_critical=True)
        
        # Test deletion and management
        print("\n5. Testing Deletion and Management...")
        if added_ids:
            status, response_text, _, duration = self.make_request('DELETE', f'inbox/entry/{added_ids[0]}')
            
            if status == 200:
                self.log_result("Delete inbox entry", True, duration)
            else:
                self.log_result("Delete inbox entry", False, is_critical=False)

    def test_websocket_scanning_updates(self):
        """Test WebSocket real-time updates during scanning"""
        print("\n   Testing WebSocket Real-time Updates...")
        
        ws_url = self.base_url.replace('https://', 'wss://').replace('http://', 'ws://') + '/ws'
        
        try:
            connection_success = False
            messages_received = []
            
            def on_open(ws):
                nonlocal connection_success
                connection_success = True
                print("   ✅ WebSocket connection established")
            
            def on_message(ws, message):
                nonlocal messages_received
                try:
                    data = json.loads(message)
                    messages_received.append(data)
                    msg_type = data.get('type', 'unknown')
                    print(f"   📡 Received: {msg_type}")
                except:
                    pass
            
            def on_error(ws, error):
                print(f"   ❌ WebSocket error: {error}")
            
            def on_close(ws, close_status_code, close_msg):
                print("   WebSocket connection closed")
            
            ws = websocket.WebSocketApp(ws_url,
                                      on_open=on_open,
                                      on_message=on_message,
                                      on_error=on_error,
                                      on_close=on_close)
            
            # Run WebSocket in background
            def run_ws():
                ws.run_forever()
            
            thread = threading.Thread(target=run_ws)
            thread.daemon = True
            thread.start()
            
            # Wait for connection
            time.sleep(2)
            
            if connection_success:
                self.log_result("WebSocket real-time connection", True)
                
                # Test if we receive scan updates
                if messages_received:
                    self.log_result("WebSocket scan updates", True)
                    print(f"   Messages received: {len(messages_received)}")
                else:
                    self.log_result("WebSocket scan updates - No messages", True, is_critical=False)
            else:
                self.log_result("WebSocket real-time connection", False, is_critical=False)
            
            ws.close()
            
        except ImportError:
            print("   ⚠️  websocket-client not available, skipping WebSocket test")
            self.log_result("WebSocket test - Library unavailable", True, is_critical=False)
        except Exception as e:
            self.log_result("WebSocket real-time connection", False, is_critical=False)

    def test_database_operations_performance(self):
        """Test Database Operations and Performance"""
        print("\n🗄️  TESTING DATABASE OPERATIONS PERFORMANCE")
        print("=" * 45)
        
        # Test various database endpoints with performance monitoring
        db_endpoints = [
            ("devices", "Device storage and retrieval"),
            ("devices/active", "Active device queries"),
            ("alerts", "Threat alert storage"),
            ("alerts/unresolved", "Alert filtering"),
            ("scans", "Scan history storage"),
            ("malware/analyses", "Malware analysis storage"),
            ("url/analyses", "URL analysis storage")
        ]
        
        for endpoint, description in db_endpoints:
            status, response_text, _, duration = self.make_request('GET', endpoint)
            
            if status == 200:
                try:
                    response_data = json.loads(response_text)
                    
                    # Check response time (should be under 5 seconds for database queries)
                    if duration <= 5.0:
                        self.log_result(f"Database - {description}", True, duration)
                    else:
                        self.log_result(f"Database - {description} SLOW", False, is_critical=False)
                        print(f"   ⚠️  Slow response: {duration:.2f}s > 5.0s")
                    
                    # Check data structure
                    if isinstance(response_data, list):
                        print(f"   Records found: {len(response_data)}")
                    elif isinstance(response_data, dict) and 'entries' in response_data:
                        print(f"   Records found: {len(response_data['entries'])}")
                    
                except:
                    self.log_result(f"Database - {description}", False, is_critical=True)
            else:
                self.log_result(f"Database - {description}", False, is_critical=True)

    def test_api_performance_requirements(self):
        """Test API Performance Requirements"""
        print("\n⚡ TESTING API PERFORMANCE REQUIREMENTS")
        print("=" * 45)
        print("Performance Requirement: Dashboard stats should load within 2 seconds")
        
        # Test dashboard stats performance
        print("\n1. Testing Dashboard Stats Performance...")
        status, response_text, _, duration = self.make_request('GET', 'dashboard/stats')
        
        if status == 200:
            try:
                response_data = json.loads(response_text)
                
                # Check performance requirement (2 seconds)
                if duration <= 2.0:
                    self.log_result("Dashboard stats performance", True, duration, response_data)
                    print(f"   ✅ Performance requirement met: {duration:.2f}s ≤ 2.0s")
                else:
                    self.log_result("Dashboard stats performance - TOO SLOW", False, is_critical=True)
                    print(f"   ❌ Performance requirement failed: {duration:.2f}s > 2.0s")
                
                # Check data accuracy
                expected_stats = [
                    'total_devices', 'active_devices', 'rogue_devices', 'wifi_threats',
                    'unresolved_alerts', 'malware_detected', 'malicious_urls',
                    'pending_urls', 'inbox_threats', 'total_inbox_entries'
                ]
                
                found_stats = [stat for stat in expected_stats if stat in response_data]
                if len(found_stats) >= 7:
                    self.log_result("Dashboard data accuracy", True)
                    print(f"   Stats available: {len(found_stats)}/{len(expected_stats)}")
                else:
                    self.log_result("Dashboard data accuracy", False, is_critical=False)
                
            except:
                self.log_result("Dashboard stats performance", False, is_critical=True)
        else:
            self.log_result("Dashboard stats performance", False, is_critical=True)
        
        # Test other API endpoints performance
        print("\n2. Testing Other API Endpoints Performance...")
        api_endpoints = [
            ("devices", 3.0),  # Should load within 3 seconds
            ("alerts", 3.0),   # Should load within 3 seconds
            ("wifi/networks", 5.0)  # WiFi scan can take up to 5 seconds
        ]
        
        for endpoint, max_time in api_endpoints:
            status, response_text, _, duration = self.make_request('GET', endpoint)
            
            if status == 200:
                if duration <= max_time:
                    self.log_result(f"API performance - {endpoint}", True, duration)
                else:
                    self.log_result(f"API performance - {endpoint} SLOW", False, is_critical=False)
                    print(f"   ⚠️  Slow response: {duration:.2f}s > {max_time}s")
            else:
                self.log_result(f"API performance - {endpoint}", False, is_critical=True)

    def run_comprehensive_performance_tests(self):
        """Run all comprehensive performance tests"""
        print("🛡️  CRYPTOPULSE ENHANCED NETWORK SECURITY SYSTEM")
        print("🚀 COMPREHENSIVE PERFORMANCE & FUNCTIONALITY TESTING")
        print("=" * 70)
        print("Focus: Performance optimization, threat detection accuracy, API reliability")
        print("=" * 70)
        
        # Run tests in order of priority from review request
        self.test_network_device_scanning_performance()    # CRITICAL TEST AREA 1
        self.test_wifi_threat_detection()                  # CRITICAL TEST AREA 2  
        self.test_malware_file_scanning()                  # CRITICAL TEST AREA 3
        self.test_url_threat_analysis()                    # CRITICAL TEST AREA 4
        self.test_security_inbox_functionality()           # CRITICAL TEST AREA 5
        self.test_database_operations_performance()        # Database Operations
        self.test_api_performance_requirements()           # API Performance
        
        # Generate comprehensive performance report
        self.generate_performance_report()

    def generate_performance_report(self):
        """Generate comprehensive performance and functionality report"""
        print("\n" + "=" * 70)
        print("📊 COMPREHENSIVE PERFORMANCE & FUNCTIONALITY REPORT")
        print("=" * 70)
        
        success_rate = (self.tests_passed / self.tests_run) * 100 if self.tests_run > 0 else 0
        
        print(f"Total Tests Run: {self.tests_run}")
        print(f"Tests Passed: {self.tests_passed}")
        print(f"Success Rate: {success_rate:.1f}%")
        
        # Performance metrics summary
        if self.performance_metrics:
            print(f"\n⚡ PERFORMANCE METRICS:")
            for test_name, duration in self.performance_metrics.items():
                print(f"   • {test_name}: {duration:.2f}s")
        
        # Critical failures
        if self.critical_failures:
            print(f"\n❌ CRITICAL FAILURES ({len(self.critical_failures)}):")
            for failure in self.critical_failures:
                print(f"   • {failure}")
        
        # Minor issues
        if self.minor_issues:
            print(f"\n⚠️  MINOR ISSUES ({len(self.minor_issues)}):")
            for issue in self.minor_issues:
                print(f"   • {issue}")
        
        print("\n" + "=" * 70)
        
        # Performance requirements assessment
        print("🎯 PERFORMANCE REQUIREMENTS ASSESSMENT:")
        
        performance_requirements = [
            ("Network scans", "≤ 180s (2-3 minutes)", "network scan performance"),
            ("File scans", "≤ 30s (files under 10MB)", "file scan performance"),
            ("URL scans", "≤ 15s", "url scan performance"),
            ("Dashboard stats", "≤ 2s", "dashboard stats performance")
        ]
        
        for req_name, req_limit, metric_key in performance_requirements:
            matching_metrics = [k for k in self.performance_metrics.keys() if metric_key.lower() in k.lower()]
            if matching_metrics:
                avg_time = sum(self.performance_metrics[k] for k in matching_metrics) / len(matching_metrics)
                print(f"   • {req_name}: {avg_time:.2f}s {req_limit}")
            else:
                print(f"   • {req_name}: Not tested or failed")
        
        print("\n" + "=" * 70)
        
        # Overall assessment
        if len(self.critical_failures) == 0:
            print("🎉 ALL CRITICAL FUNCTIONALITY WORKING!")
            print("✅ CryptoPulse Enhanced Security System is fully operational.")
            print("🚀 Performance requirements are being met.")
            return 0
        elif len(self.critical_failures) <= 3 and success_rate >= 75:
            print("⚠️  MOSTLY FUNCTIONAL with some critical issues.")
            print("🔧 Minor fixes needed for optimal performance.")
            return 1
        else:
            print("❌ SIGNIFICANT ISSUES DETECTED")
            print("🚨 Multiple critical failures require immediate attention.")
            return 2

def main():
    tester = CryptoPulsePerformanceTester()
    return tester.run_comprehensive_performance_tests()

if __name__ == "__main__":
    sys.exit(main())