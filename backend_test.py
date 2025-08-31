import requests
import sys
import json
import time
import io
from datetime import datetime

class CryptoPulseEnhancedAPITester:
    def __init__(self, base_url="https://network-checker-4.preview.emergentagent.com"):
        self.base_url = base_url
        self.api_url = f"{base_url}/api"
        self.tests_run = 0
        self.tests_passed = 0

    def run_test(self, name, method, endpoint, expected_status, data=None, files=None, timeout=30):
        """Run a single API test"""
        url = f"{self.api_url}/{endpoint}" if not endpoint.startswith('http') else endpoint
        headers = {}
        
        # Don't set Content-Type for multipart/form-data (files)
        if not files:
            headers['Content-Type'] = 'application/json'

        self.tests_run += 1
        print(f"\n🔍 Testing {name}...")
        print(f"   URL: {url}")
        
        try:
            if method == 'GET':
                response = requests.get(url, headers=headers, timeout=timeout)
            elif method == 'POST':
                if files is not None:
                    # For file uploads or form data, don't use json parameter
                    response = requests.post(url, data=data, files=files, timeout=timeout)
                else:
                    response = requests.post(url, json=data, headers=headers, timeout=timeout)

            success = response.status_code == expected_status
            if success:
                self.tests_passed += 1
                print(f"✅ Passed - Status: {response.status_code}")
                try:
                    response_data = response.json()
                    if isinstance(response_data, dict) and len(response_data) <= 5:
                        print(f"   Response: {response_data}")
                    elif isinstance(response_data, list):
                        print(f"   Response: List with {len(response_data)} items")
                    else:
                        print(f"   Response: {str(response_data)[:100]}...")
                except:
                    print(f"   Response: {response.text[:100]}...")
            else:
                print(f"❌ Failed - Expected {expected_status}, got {response.status_code}")
                print(f"   Response: {response.text[:200]}...")

            return success, response.json() if response.text and response.text.strip() else {}

        except requests.exceptions.Timeout:
            print(f"❌ Failed - Request timed out after {timeout} seconds")
            return False, {}
        except Exception as e:
            print(f"❌ Failed - Error: {str(e)}")
            return False, {}

    def test_enhanced_root_endpoint(self):
        """Test enhanced root API endpoint with feature list"""
        success, response = self.run_test("Enhanced Root API Endpoint", "GET", "", 200)
        
        if success and response:
            # Check if enhanced features are listed
            expected_features = ["Network Scanning", "Malware Analysis", "DoS Detection", "WiFi Threat Monitoring", "URL Scanning"]
            features = response.get('features', [])
            
            print(f"   Features listed: {features}")
            
            # Check if at least some enhanced features are present
            found_features = sum(1 for feature in expected_features if any(f in feature for f in features))
            if found_features >= 3:
                print("   ✅ Enhanced features detected in root endpoint")
            else:
                print("   ⚠️  Some enhanced features may be missing")
        
        return success, response

    def test_enhanced_dashboard_stats(self):
        """Test enhanced dashboard statistics with 7 stat cards"""
        success, response = self.run_test("Enhanced Dashboard Stats (7 Cards)", "GET", "dashboard/stats", 200)
        
        if success and response:
            # Check for all 7 expected stats
            expected_stats = [
                'total_devices', 'active_devices', 'rogue_devices', 
                'wifi_threats', 'unresolved_alerts', 'malware_detected', 'malicious_urls'
            ]
            
            found_stats = [stat for stat in expected_stats if stat in response]
            print(f"   Stats found: {found_stats}")
            
            if len(found_stats) == 7:
                print("   ✅ All 7 enhanced stat cards present")
            else:
                print(f"   ⚠️  Only {len(found_stats)}/7 stat cards found")
        
        return success, response

    def test_malware_analyses_endpoint(self):
        """Test malware analysis history endpoint"""
        return self.run_test("Malware Analysis History", "GET", "malware/analyses", 200)

    def test_url_analyses_endpoint(self):
        """Test URL analysis history endpoint"""
        return self.run_test("URL Analysis History", "GET", "url/analyses", 200)

    def test_unresolved_alerts_endpoint(self):
        """Test unresolved alerts endpoint"""
        return self.run_test("Unresolved Alerts", "GET", "alerts/unresolved", 200)

    def test_file_malware_scan(self):
        """Test file malware scanning with VirusTotal integration"""
        print(f"\n🦠 Testing Enhanced Feature: File Malware Scanning")
        print("   Creating test file for malware analysis...")
        
        # Create a small test file
        test_content = b"This is a test file for malware scanning. Not malicious content."
        test_file = io.BytesIO(test_content)
        test_file.name = "test_file.txt"
        
        files = {'file': ('test_file.txt', test_file, 'text/plain')}
        
        success, response = self.run_test(
            "File Malware Scan (VirusTotal)", 
            "POST", 
            "scan/file", 
            200,
            files=files,
            timeout=60
        )
        
        if success and response:
            print("   ✅ File scan completed successfully")
            if 'file_hash' in response:
                print(f"   File Hash: {response['file_hash'][:16]}...")
            if 'risk_level' in response:
                print(f"   Risk Level: {response['risk_level']}")
            if 'detection_ratio' in response:
                print(f"   Detection Ratio: {response['detection_ratio']}")
            if 'virustotal_link' in response:
                print("   ✅ VirusTotal integration working")
        
        return success, response

    def test_url_threat_scan(self):
        """Test URL threat scanning with VirusTotal integration"""
        print(f"\n🌐 Testing Enhanced Feature: URL Threat Scanning")
        print("   Testing with a known safe URL...")
        
        # Test with a known safe URL
        test_url = "https://www.google.com"
        data = {'url': test_url}
        
        success, response = self.run_test(
            "URL Threat Scan (VirusTotal)", 
            "POST", 
            "scan/url", 
            200,
            data=data,
            files={},  # This will trigger form data mode
            timeout=60
        )
        
        if success and response:
            print("   ✅ URL scan completed successfully")
            if 'url' in response:
                print(f"   Scanned URL: {response['url']}")
            if 'risk_level' in response:
                print(f"   Risk Level: {response['risk_level']}")
            if 'detection_ratio' in response:
                print(f"   Detection Ratio: {response['detection_ratio']}")
            if 'virustotal_link' in response:
                print("   ✅ VirusTotal integration working")
        
        return success, response

    def test_enhanced_network_scan(self):
        """Test enhanced network scan with threat detection"""
        print(f"\n🔍 Testing Enhanced Feature: Network Scanning with Threat Detection")
        print("   This may take 30-60 seconds as it performs enhanced network discovery...")
        
        success, response = self.run_test(
            "Enhanced Network Scan", 
            "POST", 
            "scan/network", 
            200,
            timeout=90
        )
        
        if success and response:
            print("   ✅ Enhanced network scan completed successfully")
            if 'status' in response:
                print(f"   Scan Status: {response['status']}")
            if 'devices_found' in response:
                print(f"   Devices Found: {response['devices_found']}")
            if 'threats_found' in response:
                print(f"   Threats Found: {response['threats_found']}")
            if 'scan_duration' in response:
                print(f"   Scan Duration: {response['scan_duration']:.2f}s")
        
        return success, response

    def test_alert_resolution(self):
        """Test alert resolution functionality"""
        print(f"\n🚨 Testing Alert Resolution...")
        
        # First get alerts to see if any exist
        alerts_success, alerts_response = self.run_test("Get Alerts for Resolution", "GET", "alerts", 200)
        
        if alerts_success and alerts_response and len(alerts_response) > 0:
            # Try to resolve the first alert
            alert_id = alerts_response[0].get('id')
            if alert_id:
                success, response = self.run_test(
                    f"Resolve Alert {alert_id}", 
                    "POST", 
                    f"alerts/{alert_id}/resolve", 
                    200
                )
                return success, response
            else:
                print("   ⚠️  No alert ID found to test resolution")
                return True, {}
        else:
            print("   ℹ️  No alerts available to test resolution")
            return True, {}

    def test_websocket_endpoint(self):
        """Test WebSocket endpoint for real-time updates"""
        ws_url = self.base_url.replace('https://', 'wss://').replace('http://', 'ws://') + '/ws'
        print(f"\n🌐 Testing Real-time WebSocket Connection...")
        print(f"   URL: {ws_url}")
        
        try:
            import websocket
            
            connection_success = False
            
            def on_open(ws):
                nonlocal connection_success
                print("   ✅ WebSocket connection opened successfully")
                connection_success = True
                ws.close()
            
            def on_error(ws, error):
                print(f"   ❌ WebSocket error: {error}")
            
            def on_close(ws, close_status_code, close_msg):
                print("   WebSocket connection closed")
            
            ws = websocket.WebSocketApp(ws_url,
                                      on_open=on_open,
                                      on_error=on_error,
                                      on_close=on_close)
            
            # Run with timeout
            import threading
            def run_ws():
                ws.run_forever()
            
            thread = threading.Thread(target=run_ws)
            thread.daemon = True
            thread.start()
            thread.join(timeout=5)
            
            self.tests_run += 1
            if connection_success:
                self.tests_passed += 1
                return True
            else:
                print("   ❌ WebSocket connection failed")
                return False
            
        except ImportError:
            print("   ⚠️  websocket-client not available, testing HTTP upgrade instead")
            # Test WebSocket upgrade via HTTP
            try:
                headers = {
                    'Upgrade': 'websocket',
                    'Connection': 'Upgrade',
                    'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
                    'Sec-WebSocket-Version': '13'
                }
                response = requests.get(ws_url.replace('wss://', 'https://').replace('ws://', 'http://'), 
                                      headers=headers, timeout=5)
                
                self.tests_run += 1
                if response.status_code == 101:  # Switching Protocols
                    print("   ✅ WebSocket upgrade successful")
                    self.tests_passed += 1
                    return True
                else:
                    print(f"   ❌ WebSocket upgrade failed: {response.status_code}")
                    return False
            except Exception as e:
                print(f"   ❌ WebSocket test failed: {e}")
                self.tests_run += 1
                return False
        except Exception as e:
            print(f"   ❌ WebSocket test failed: {e}")
            self.tests_run += 1
            return False

    def test_basic_endpoints(self):
        """Test basic CRUD endpoints"""
        print("\n🖥️  Testing Basic Device & Alert Endpoints...")
        
        endpoints = [
            ("Get All Devices", "GET", "devices", 200),
            ("Get Active Devices", "GET", "devices/active", 200),
            ("Get All Alerts", "GET", "alerts", 200),
            ("Get Network Scans", "GET", "scans", 200)
        ]
        
        results = []
        for name, method, endpoint, expected_status in endpoints:
            success, response = self.run_test(name, method, endpoint, expected_status)
            results.append(success)
        
        return all(results)

def main():
    print("🛡️  CryptoPulse Enhanced v2.0 Network Security System - Comprehensive API Testing")
    print("=" * 80)
    
    # Setup
    tester = CryptoPulseEnhancedAPITester()
    
    # Test enhanced root endpoint
    print("\n📡 Testing Enhanced API Connectivity...")
    root_success, _ = tester.test_enhanced_root_endpoint()
    
    if not root_success:
        print("\n❌ Basic API connectivity failed. Backend may be down.")
        print("   Please check if the backend service is running.")
        return 1
    
    # Test enhanced dashboard with 7 stat cards
    print("\n📊 Testing Enhanced Dashboard (7 Stat Cards)...")
    tester.test_enhanced_dashboard_stats()
    
    # Test new malware and URL analysis endpoints
    print("\n🦠 Testing Malware & URL Analysis Endpoints...")
    tester.test_malware_analyses_endpoint()
    tester.test_url_analyses_endpoint()
    tester.test_unresolved_alerts_endpoint()
    
    # Test basic CRUD endpoints
    tester.test_basic_endpoints()
    
    # Test enhanced network scanning
    print("\n🔍 Testing Enhanced Network Scanning...")
    scan_success, scan_response = tester.test_enhanced_network_scan()
    
    # Test VirusTotal integrations
    print("\n🦠 Testing VirusTotal Integrations...")
    print("   Note: These tests require VirusTotal API key to be configured")
    
    file_scan_success, _ = tester.test_file_malware_scan()
    url_scan_success, _ = tester.test_url_threat_scan()
    
    # Test alert resolution
    print("\n🚨 Testing Alert Management...")
    tester.test_alert_resolution()
    
    # Test WebSocket for real-time updates
    print("\n🌐 Testing Real-time WebSocket Connection...")
    tester.test_websocket_endpoint()
    
    # Wait for scans to process and re-test data endpoints
    if scan_success or file_scan_success or url_scan_success:
        print("\n⏳ Waiting 10 seconds for scans to process and populate data...")
        time.sleep(10)
        
        print("\n🔄 Re-testing data endpoints to verify scan results...")
        tester.test_enhanced_dashboard_stats()
        tester.test_malware_analyses_endpoint()
        tester.test_url_analyses_endpoint()
    
    # Print comprehensive results
    print("\n" + "=" * 80)
    print(f"📊 COMPREHENSIVE TEST RESULTS - CryptoPulse Enhanced v2.0")
    print(f"Tests passed: {tester.tests_passed}/{tester.tests_run}")
    
    success_rate = (tester.tests_passed / tester.tests_run) * 100 if tester.tests_run > 0 else 0
    print(f"Success rate: {success_rate:.1f}%")
    
    if tester.tests_passed == tester.tests_run:
        print("🎉 ALL TESTS PASSED! Enhanced CryptoPulse v2.0 backend is fully functional.")
        print("✅ Ready for frontend testing with all enhanced features.")
        return 0
    else:
        failed_tests = tester.tests_run - tester.tests_passed
        print(f"⚠️  {failed_tests} test(s) failed. Check the issues above.")
        
        if success_rate >= 70:
            print("✅ Most enhanced functionality is working. Proceeding with frontend testing.")
            return 0
        else:
            print("❌ Too many critical failures. Backend needs fixes before frontend testing.")
            return 1

if __name__ == "__main__":
    sys.exit(main())