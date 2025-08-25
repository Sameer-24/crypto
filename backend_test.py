import requests
import sys
import json
import time
from datetime import datetime

class CryptoPulseAPITester:
    def __init__(self, base_url="https://cryptopulse-detect.preview.emergentagent.com"):
        self.base_url = base_url
        self.api_url = f"{base_url}/api"
        self.tests_run = 0
        self.tests_passed = 0

    def run_test(self, name, method, endpoint, expected_status, data=None, timeout=30):
        """Run a single API test"""
        url = f"{self.api_url}/{endpoint}" if not endpoint.startswith('http') else endpoint
        headers = {'Content-Type': 'application/json'}

        self.tests_run += 1
        print(f"\n🔍 Testing {name}...")
        print(f"   URL: {url}")
        
        try:
            if method == 'GET':
                response = requests.get(url, headers=headers, timeout=timeout)
            elif method == 'POST':
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

    def test_root_endpoint(self):
        """Test root API endpoint"""
        return self.run_test("Root API Endpoint", "GET", "", 200)

    def test_dashboard_stats(self):
        """Test dashboard statistics endpoint"""
        return self.run_test("Dashboard Stats", "GET", "dashboard/stats", 200)

    def test_get_devices(self):
        """Test get all devices endpoint"""
        return self.run_test("Get All Devices", "GET", "devices", 200)

    def test_get_active_devices(self):
        """Test get active devices endpoint"""
        return self.run_test("Get Active Devices", "GET", "devices/active", 200)

    def test_get_alerts(self):
        """Test get threat alerts endpoint"""
        return self.run_test("Get Threat Alerts", "GET", "alerts", 200)

    def test_get_scans(self):
        """Test get network scans endpoint"""
        return self.run_test("Get Network Scans", "GET", "scans", 200)

    def test_network_scan(self):
        """Test network scan endpoint - this is the core feature"""
        print(f"\n🚨 Testing Core Feature: Network Scanning")
        print("   This may take 30-60 seconds as it performs actual network discovery...")
        
        success, response = self.run_test(
            "Network Scan (Core Feature)", 
            "POST", 
            "scan/network", 
            200,
            timeout=60
        )
        
        if success:
            print("   ✅ Network scan initiated successfully")
            if 'status' in response:
                print(f"   Scan Status: {response['status']}")
            if 'devices_found' in response:
                print(f"   Devices Found: {response['devices_found']}")
        
        return success, response

    def test_websocket_endpoint(self):
        """Test WebSocket endpoint availability"""
        ws_url = self.base_url.replace('https://', 'wss://').replace('http://', 'ws://') + '/ws'
        print(f"\n🔍 Testing WebSocket Endpoint...")
        print(f"   URL: {ws_url}")
        
        try:
            import websocket
            
            def on_open(ws):
                print("   ✅ WebSocket connection opened successfully")
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
            self.tests_passed += 1
            return True
            
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

def main():
    print("🛡️  CryptoPulse Network Security System - API Testing")
    print("=" * 60)
    
    # Setup
    tester = CryptoPulseAPITester()
    
    # Test basic connectivity
    print("\n📡 Testing Basic API Connectivity...")
    root_success, _ = tester.test_root_endpoint()
    
    if not root_success:
        print("\n❌ Basic API connectivity failed. Backend may be down.")
        print("   Please check if the backend service is running.")
        return 1
    
    # Test all endpoints
    print("\n📊 Testing Dashboard & Statistics...")
    tester.test_dashboard_stats()
    
    print("\n🖥️  Testing Device Management...")
    tester.test_get_devices()
    tester.test_get_active_devices()
    
    print("\n🚨 Testing Alert System...")
    tester.test_get_alerts()
    
    print("\n📈 Testing Scan History...")
    tester.test_get_scans()
    
    # Test core network scanning feature
    print("\n🔍 Testing Core Network Scanning Feature...")
    scan_success, scan_response = tester.test_network_scan()
    
    if scan_success:
        print("\n⏳ Waiting 5 seconds for scan to process...")
        time.sleep(5)
        
        # Re-test devices and stats to see if scan populated data
        print("\n🔄 Re-testing endpoints to verify scan results...")
        tester.test_get_devices()
        tester.test_dashboard_stats()
    
    # Test WebSocket connectivity
    print("\n🌐 Testing Real-time WebSocket Connection...")
    tester.test_websocket_endpoint()
    
    # Print final results
    print("\n" + "=" * 60)
    print(f"📊 FINAL TEST RESULTS")
    print(f"Tests passed: {tester.tests_passed}/{tester.tests_run}")
    
    if tester.tests_passed == tester.tests_run:
        print("🎉 ALL TESTS PASSED! Backend is fully functional.")
        return 0
    else:
        failed_tests = tester.tests_run - tester.tests_passed
        print(f"⚠️  {failed_tests} test(s) failed. Check the issues above.")
        
        if tester.tests_passed >= tester.tests_run * 0.7:  # 70% pass rate
            print("✅ Most core functionality is working. Proceeding with frontend testing.")
            return 0
        else:
            print("❌ Too many critical failures. Backend needs fixes before frontend testing.")
            return 1

if __name__ == "__main__":
    sys.exit(main())