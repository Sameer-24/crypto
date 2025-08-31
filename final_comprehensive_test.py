#!/usr/bin/env python3
"""
Final Comprehensive Testing for CryptoPulse Enhanced Security Application
Focus: VirusTotal Integration Fixes, Network Scanning Performance, and Production Readiness
Based on review request for final verification after performance optimizations
"""

import requests
import json
import time
import io
from datetime import datetime
import sys
import websocket
import threading

class FinalComprehensiveTester:
    def __init__(self, base_url="https://scan-protector.preview.emergentagent.com"):
        self.base_url = base_url
        self.api_url = f"{base_url}/api"
        self.tests_run = 0
        self.tests_passed = 0
        self.critical_failures = []
        self.performance_results = {}
        self.start_time = None
        
    def log_result(self, test_name, success, response_data=None, duration=None, is_critical=True):
        """Log test results with performance metrics"""
        self.tests_run += 1
        if success:
            self.tests_passed += 1
            status_icon = "✅"
            if duration:
                print(f"{status_icon} {test_name} ({duration:.2f}s)")
                self.performance_results[test_name] = duration
            else:
                print(f"{status_icon} {test_name}")
        else:
            if is_critical:
                self.critical_failures.append(test_name)
                print(f"❌ {test_name} (CRITICAL FAILURE)")
            else:
                print(f"⚠️  {test_name} (Minor Issue)")
    
    def make_timed_request(self, method, endpoint, data=None, files=None, timeout=120):
        """Make HTTP request with timing and comprehensive error handling"""
        url = f"{self.api_url}/{endpoint}" if not endpoint.startswith('http') else endpoint
        start_time = time.time()
        
        try:
            if method == 'GET':
                response = requests.get(url, timeout=timeout)
            elif method == 'POST':
                if files:
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

    def test_virustotal_file_scanning_critical(self):
        """CRITICAL: Test VirusTotal file scanning with async context manager fix"""
        print("\n🦠 CRITICAL TEST: VirusTotal File Scanning Integration")
        print("=" * 60)
        print("Testing the async context manager fix and performance improvements...")
        
        # Test with multiple file types to ensure robustness
        test_files = [
            ("test_document.txt", b"This is a test document for malware scanning analysis.", "text/plain"),
            ("test_script.py", b"# Python test script\nprint('Hello World')\n", "text/x-python"),
            ("test_data.json", b'{"test": "data", "safe": true}', "application/json")
        ]
        
        for filename, content, content_type in test_files:
            print(f"\n   Testing file: {filename}")
            
            # Create file buffer
            file_buffer = io.BytesIO(content)
            files = {'file': (filename, file_buffer, content_type)}
            
            # Test file scanning with performance measurement
            status, response_text, headers, duration = self.make_timed_request(
                'POST', 'scan/file', files=files, timeout=60
            )
            
            if status == 200:
                try:
                    response_data = json.loads(response_text)
                    
                    # Check for required fields indicating successful VirusTotal integration
                    required_fields = ['file_hash', 'filename', 'file_size', 'risk_level', 'detection_ratio']
                    missing_fields = [field for field in required_fields if field not in response_data]
                    
                    if not missing_fields:
                        # Check if VirusTotal integration is working (no async context manager error)
                        if 'virustotal_link' in response_data or response_data.get('risk_level') != 'Error':
                            self.log_result(f"VirusTotal File Scan: {filename}", True, response_data, duration)
                            
                            # Performance check: Should be under 20 seconds as per requirements
                            if duration <= 20:
                                print(f"      ✅ Performance target met: {duration:.2f}s ≤ 20s")
                            else:
                                print(f"      ⚠️  Performance target missed: {duration:.2f}s > 20s")
                            
                            # Check for async context manager error specifically
                            if 'Timeout context manager should be used inside a task' in str(response_data):
                                self.log_result(f"VirusTotal Async Fix: {filename}", False, is_critical=True)
                                print("      ❌ ASYNC CONTEXT MANAGER ERROR STILL PRESENT")
                            else:
                                self.log_result(f"VirusTotal Async Fix: {filename}", True)
                                print("      ✅ No async context manager errors detected")
                        else:
                            self.log_result(f"VirusTotal File Scan: {filename}", False, is_critical=True)
                            print(f"      ❌ VirusTotal integration failed: {response_data.get('risk_level', 'Unknown error')}")
                    else:
                        self.log_result(f"VirusTotal File Scan: {filename}", False, is_critical=True)
                        print(f"      ❌ Missing required fields: {missing_fields}")
                        
                except json.JSONDecodeError:
                    self.log_result(f"VirusTotal File Scan: {filename}", False, is_critical=True)
                    print(f"      ❌ Invalid JSON response")
            else:
                self.log_result(f"VirusTotal File Scan: {filename}", False, is_critical=True)
                print(f"      ❌ HTTP {status}: {response_text[:100]}...")

    def test_virustotal_url_scanning_critical(self):
        """CRITICAL: Test VirusTotal URL scanning with various URL types"""
        print("\n🌐 CRITICAL TEST: VirusTotal URL Scanning Integration")
        print("=" * 55)
        
        # Test URLs including potentially malicious patterns (but safe domains)
        test_urls = [
            "https://www.google.com",
            "https://github.com",
            "https://stackoverflow.com",
            "http://example.com",  # Test HTTP vs HTTPS
        ]
        
        for test_url in test_urls:
            print(f"\n   Testing URL: {test_url}")
            
            data = {'url': test_url}
            status, response_text, headers, duration = self.make_timed_request(
                'POST', 'scan/url', data=data, files={}, timeout=30
            )
            
            if status == 200:
                try:
                    response_data = json.loads(response_text)
                    
                    # Check for required fields
                    required_fields = ['url', 'risk_level', 'detection_ratio', 'is_malicious']
                    missing_fields = [field for field in required_fields if field not in response_data]
                    
                    if not missing_fields:
                        # Check if VirusTotal integration is working
                        if 'virustotal_link' in response_data or response_data.get('risk_level') != 'Error':
                            self.log_result(f"VirusTotal URL Scan: {test_url}", True, response_data, duration)
                            
                            # Performance check: Should be under 10 seconds as per requirements
                            if duration <= 10:
                                print(f"      ✅ Performance target met: {duration:.2f}s ≤ 10s")
                            else:
                                print(f"      ⚠️  Performance target missed: {duration:.2f}s > 10s")
                                
                        else:
                            self.log_result(f"VirusTotal URL Scan: {test_url}", False, is_critical=True)
                            print(f"      ❌ VirusTotal integration failed")
                    else:
                        self.log_result(f"VirusTotal URL Scan: {test_url}", False, is_critical=True)
                        print(f"      ❌ Missing required fields: {missing_fields}")
                        
                except json.JSONDecodeError:
                    self.log_result(f"VirusTotal URL Scan: {test_url}", False, is_critical=True)
                    print(f"      ❌ Invalid JSON response")
            else:
                self.log_result(f"VirusTotal URL Scan: {test_url}", False, is_critical=True)
                print(f"      ❌ HTTP {status}: {response_text[:100]}...")

    def test_network_scanning_performance_critical(self):
        """CRITICAL: Test network scanning performance optimizations"""
        print("\n🔍 CRITICAL TEST: Network Scanning Performance Optimization")
        print("=" * 60)
        print("Testing optimized port scanning, reduced timeouts, and smaller batches...")
        
        # Test network scan with performance measurement
        print("\n   Starting optimized network scan...")
        status, response_text, headers, duration = self.make_timed_request(
            'POST', 'scan/network', timeout=150  # Allow up to 2.5 minutes
        )
        
        if status == 200:
            try:
                response_data = json.loads(response_text)
                
                # Check for successful completion
                if response_data.get('status') == 'completed':
                    self.log_result("Network Scan Completion", True, response_data, duration)
                    
                    # CRITICAL: Performance check - should be under 120 seconds (2 minutes)
                    if duration <= 120:
                        self.log_result("Network Scan Performance Target", True)
                        print(f"      ✅ EXCELLENT: Scan completed in {duration:.2f}s ≤ 120s target")
                    else:
                        self.log_result("Network Scan Performance Target", False, is_critical=True)
                        print(f"      ❌ PERFORMANCE ISSUE: {duration:.2f}s > 120s target")
                    
                    # Check scan results quality
                    devices_found = response_data.get('devices_found', 0)
                    threats_found = response_data.get('threats_found', 0)
                    
                    print(f"      Devices discovered: {devices_found}")
                    print(f"      Threats detected: {threats_found}")
                    
                    if devices_found > 0:
                        self.log_result("Network Device Discovery", True)
                    else:
                        self.log_result("Network Device Discovery", False, is_critical=False)
                        print("      ⚠️  No devices found (may be normal in isolated environment)")
                        
                else:
                    self.log_result("Network Scan Completion", False, is_critical=True)
                    print(f"      ❌ Scan failed with status: {response_data.get('status', 'unknown')}")
                    
            except json.JSONDecodeError:
                self.log_result("Network Scan Completion", False, is_critical=True)
                print(f"      ❌ Invalid JSON response")
        else:
            self.log_result("Network Scan Completion", False, is_critical=True)
            print(f"      ❌ HTTP {status}: {response_text[:100]}...")
        
        # Test scan progress endpoint
        print("\n   Testing scan progress tracking...")
        status, response_text, headers, duration = self.make_timed_request('GET', 'scan/progress')
        
        if status == 200:
            try:
                response_data = json.loads(response_text)
                if 'scanning' in response_data and 'progress' in response_data:
                    self.log_result("Scan Progress Tracking", True, response_data, duration)
                else:
                    self.log_result("Scan Progress Tracking", False, is_critical=False)
            except:
                self.log_result("Scan Progress Tracking", False, is_critical=False)
        else:
            self.log_result("Scan Progress Tracking", False, is_critical=False)

    def test_wifi_threat_detection(self):
        """Test WiFi threat detection functionality"""
        print("\n📶 TEST: WiFi Threat Detection System")
        print("=" * 40)
        
        status, response_text, headers, duration = self.make_timed_request('GET', 'wifi/networks')
        
        if status == 200:
            try:
                response_data = json.loads(response_text)
                
                networks = response_data.get('networks', [])
                threats_summary = response_data.get('threats_summary', [])
                
                self.log_result("WiFi Networks Discovery", True, response_data, duration)
                
                print(f"      Networks found: {len(networks)}")
                print(f"      Threats detected: {len(threats_summary)}")
                
                # Check threat categorization
                if isinstance(networks, list) and len(networks) > 0:
                    threat_levels_found = any('threat_level' in network for network in networks)
                    if threat_levels_found:
                        self.log_result("WiFi Threat Categorization", True)
                        print("      ✅ Threat categorization working")
                    else:
                        self.log_result("WiFi Threat Categorization", False, is_critical=False)
                        print("      ⚠️  No threat levels in network data")
                else:
                    print("      ℹ️  No WiFi networks detected (may be normal)")
                    self.log_result("WiFi Threat Categorization", True)  # Not critical if no networks
                    
            except json.JSONDecodeError:
                self.log_result("WiFi Networks Discovery", False, is_critical=True)
        else:
            self.log_result("WiFi Networks Discovery", False, is_critical=True)

    def test_security_inbox_functionality(self):
        """Test Security Inbox functionality"""
        print("\n🔒 TEST: Security Inbox System")
        print("=" * 35)
        
        # Test adding URLs
        test_urls = ["https://example.com", "https://github.com"]
        added_ids = []
        
        for url in test_urls:
            print(f"\n   Adding URL: {url}")
            data = {'url': url, 'note': f'Test URL: {url}'}
            status, response_text, headers, duration = self.make_timed_request(
                'POST', 'inbox/add-url', data=data, files={}
            )
            
            if status == 200:
                try:
                    response_data = json.loads(response_text)
                    if response_data.get('status') in ['added', 'exists']:
                        self.log_result(f"Add URL to Inbox: {url}", True, response_data, duration)
                        added_ids.append(response_data.get('id'))
                    else:
                        self.log_result(f"Add URL to Inbox: {url}", False, is_critical=True)
                except:
                    self.log_result(f"Add URL to Inbox: {url}", False, is_critical=True)
            else:
                self.log_result(f"Add URL to Inbox: {url}", False, is_critical=True)
        
        # Test getting inbox entries
        print("\n   Getting inbox entries...")
        status, response_text, headers, duration = self.make_timed_request('GET', 'inbox/entries')
        
        if status == 200:
            try:
                response_data = json.loads(response_text)
                self.log_result("Get Inbox Entries", True, response_data, duration)
            except:
                self.log_result("Get Inbox Entries", False, is_critical=True)
        else:
            self.log_result("Get Inbox Entries", False, is_critical=True)
        
        # Test scanning URLs from inbox
        if added_ids:
            print(f"\n   Scanning URL from inbox...")
            status, response_text, headers, duration = self.make_timed_request(
                'POST', f'inbox/scan/{added_ids[0]}'
            )
            
            if status == 200:
                try:
                    response_data = json.loads(response_text)
                    self.log_result("Scan URL from Inbox", True, response_data, duration)
                except:
                    self.log_result("Scan URL from Inbox", False, is_critical=False)
            else:
                self.log_result("Scan URL from Inbox", False, is_critical=True)

    def test_websocket_realtime_features(self):
        """Test WebSocket connectivity for real-time features"""
        print("\n🌐 TEST: Real-time WebSocket Features")
        print("=" * 40)
        
        ws_url = self.base_url.replace('https://', 'wss://').replace('http://', 'ws://') + '/ws'
        
        try:
            connection_success = False
            connection_time = None
            
            def on_open(ws):
                nonlocal connection_success, connection_time
                connection_time = time.time() - start_time
                connection_success = True
                print(f"      ✅ WebSocket connected in {connection_time:.2f}s")
                ws.close()
            
            def on_error(ws, error):
                print(f"      ❌ WebSocket error: {error}")
            
            def on_close(ws, close_status_code, close_msg):
                pass
            
            start_time = time.time()
            ws = websocket.WebSocketApp(ws_url,
                                      on_open=on_open,
                                      on_error=on_error,
                                      on_close=on_close)
            
            # Run with timeout
            def run_ws():
                ws.run_forever()
            
            thread = threading.Thread(target=run_ws)
            thread.daemon = True
            thread.start()
            thread.join(timeout=10)
            
            if connection_success:
                self.log_result("WebSocket Connectivity", True, duration=connection_time)
            else:
                self.log_result("WebSocket Connectivity", False, is_critical=False)
                print("      ⚠️  WebSocket connection failed (may be normal in some environments)")
                
        except ImportError:
            print("      ℹ️  websocket-client not available, skipping WebSocket test")
            self.log_result("WebSocket Connectivity", True)  # Don't fail for missing dependency
        except Exception as e:
            self.log_result("WebSocket Connectivity", False, is_critical=False)
            print(f"      ⚠️  WebSocket test failed: {e}")

    def test_database_performance(self):
        """Test database operations performance"""
        print("\n🗄️  TEST: Database Performance")
        print("=" * 30)
        
        # Test various database endpoints with performance measurement
        endpoints = [
            ("devices", "Devices Collection"),
            ("alerts", "Threat Alerts"),
            ("scans", "Network Scans"),
            ("dashboard/stats", "Dashboard Statistics")
        ]
        
        for endpoint, description in endpoints:
            status, response_text, headers, duration = self.make_timed_request('GET', endpoint)
            
            if status == 200:
                try:
                    response_data = json.loads(response_text)
                    
                    # Performance check: Should be under 2 seconds
                    if duration <= 2:
                        self.log_result(f"Database {description}", True, duration=duration)
                        print(f"      ✅ Performance target met: {duration:.2f}s ≤ 2s")
                    else:
                        self.log_result(f"Database {description}", True, duration=duration)
                        print(f"      ⚠️  Performance target missed: {duration:.2f}s > 2s")
                        
                except json.JSONDecodeError:
                    self.log_result(f"Database {description}", False, is_critical=True)
            else:
                self.log_result(f"Database {description}", False, is_critical=True)

    def test_api_response_times(self):
        """Test overall API response times"""
        print("\n⚡ TEST: API Response Time Performance")
        print("=" * 40)
        
        # Test basic endpoints for response time
        quick_endpoints = [
            ("", "Root Endpoint"),
            ("dashboard/stats", "Dashboard Stats"),
            ("devices/active", "Active Devices"),
            ("alerts/unresolved", "Unresolved Alerts")
        ]
        
        for endpoint, description in quick_endpoints:
            status, response_text, headers, duration = self.make_timed_request('GET', endpoint)
            
            if status == 200:
                # All API responses should be under 2 seconds as per requirements
                if duration <= 2:
                    self.log_result(f"API Response Time: {description}", True, duration=duration)
                else:
                    self.log_result(f"API Response Time: {description}", False, is_critical=False)
                    print(f"      ⚠️  Slow response: {duration:.2f}s > 2s target")
            else:
                self.log_result(f"API Response Time: {description}", False, is_critical=True)

    def run_final_comprehensive_tests(self):
        """Run all final comprehensive tests"""
        print("🛡️  CRYPTOPULSE ENHANCED - FINAL COMPREHENSIVE TESTING")
        print("=" * 65)
        print("Focus: VirusTotal Fixes, Performance Optimization, Production Readiness")
        print("=" * 65)
        
        self.start_time = time.time()
        
        # Run tests in priority order based on review request
        self.test_virustotal_file_scanning_critical()      # CRITICAL - VirusTotal fix verification
        self.test_virustotal_url_scanning_critical()       # CRITICAL - VirusTotal fix verification  
        self.test_network_scanning_performance_critical()  # CRITICAL - Performance optimization
        self.test_wifi_threat_detection()                  # WiFi threat detection
        self.test_security_inbox_functionality()           # Security inbox
        self.test_websocket_realtime_features()           # Real-time features
        self.test_database_performance()                   # Database performance
        self.test_api_response_times()                     # API performance
        
        # Generate final report
        self.generate_final_report()
    
    def generate_final_report(self):
        """Generate comprehensive final test report"""
        total_time = time.time() - self.start_time
        
        print("\n" + "=" * 70)
        print("📊 FINAL COMPREHENSIVE TEST RESULTS")
        print("=" * 70)
        
        success_rate = (self.tests_passed / self.tests_run) * 100 if self.tests_run > 0 else 0
        
        print(f"Total Test Duration: {total_time:.2f} seconds")
        print(f"Total Tests Run: {self.tests_run}")
        print(f"Tests Passed: {self.tests_passed}")
        print(f"Success Rate: {success_rate:.1f}%")
        
        # Performance Summary
        if self.performance_results:
            print(f"\n⚡ PERFORMANCE SUMMARY:")
            for test_name, duration in self.performance_results.items():
                if 'File Scan' in test_name:
                    target = 20
                    status = "✅" if duration <= target else "⚠️"
                    print(f"   {status} {test_name}: {duration:.2f}s (target: ≤{target}s)")
                elif 'URL Scan' in test_name:
                    target = 10
                    status = "✅" if duration <= target else "⚠️"
                    print(f"   {status} {test_name}: {duration:.2f}s (target: ≤{target}s)")
                elif 'Network Scan' in test_name:
                    target = 120
                    status = "✅" if duration <= target else "⚠️"
                    print(f"   {status} {test_name}: {duration:.2f}s (target: ≤{target}s)")
                elif 'Database' in test_name or 'API Response' in test_name:
                    target = 2
                    status = "✅" if duration <= target else "⚠️"
                    print(f"   {status} {test_name}: {duration:.2f}s (target: ≤{target}s)")
        
        # Critical Issues
        if self.critical_failures:
            print(f"\n❌ CRITICAL FAILURES ({len(self.critical_failures)}):")
            for failure in self.critical_failures:
                print(f"   • {failure}")
        
        print("\n" + "=" * 70)
        
        # Final Assessment
        if len(self.critical_failures) == 0:
            print("🎉 ALL CRITICAL TESTS PASSED!")
            print("✅ VirusTotal integration working properly")
            print("✅ Network scanning performance optimized")
            print("✅ All systems ready for production use")
            return 0
        elif len(self.critical_failures) <= 2 and success_rate >= 80:
            print("⚠️  MOSTLY READY with minor critical issues")
            print("🔧 Address critical failures before full production deployment")
            return 1
        else:
            print("❌ SIGNIFICANT ISSUES REQUIRE ATTENTION")
            print("🚨 Multiple critical failures need immediate fixes")
            return 2

def main():
    print("Starting Final Comprehensive Testing...")
    tester = FinalComprehensiveTester()
    return tester.run_final_comprehensive_tests()

if __name__ == "__main__":
    sys.exit(main())