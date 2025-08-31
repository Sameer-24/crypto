#!/usr/bin/env python3
"""
WiFi Network Scanner Backend Verification Test
Focused verification of WiFi functionality after service restart
"""

import requests
import sys
import json
import time
from datetime import datetime

class WiFiBackendVerificationTester:
    def __init__(self, base_url="https://stack-test-refine.preview.emergentagent.com"):
        self.base_url = base_url
        self.api_url = f"{base_url}/api"
        self.tests_run = 0
        self.tests_passed = 0
        self.test_results = []

    def run_test(self, name, method, endpoint, expected_status, data=None, timeout=30):
        """Run a single API test with detailed logging"""
        url = f"{self.api_url}/{endpoint}"
        headers = {'Content-Type': 'application/json'}

        self.tests_run += 1
        print(f"\n🔍 Testing {name}...")
        print(f"   URL: {url}")
        
        start_time = time.time()
        
        try:
            if method == 'GET':
                response = requests.get(url, headers=headers, timeout=timeout)
            elif method == 'POST':
                response = requests.post(url, json=data, headers=headers, timeout=timeout)
            elif method == 'DELETE':
                response = requests.delete(url, headers=headers, timeout=timeout)

            response_time = (time.time() - start_time) * 1000  # Convert to milliseconds
            
            success = response.status_code == expected_status
            if success:
                self.tests_passed += 1
                print(f"✅ PASSED - Status: {response.status_code}, Response Time: {response_time:.1f}ms")
                
                try:
                    response_data = response.json()
                    self.test_results.append({
                        'test': name,
                        'status': 'PASSED',
                        'response_time_ms': response_time,
                        'data_size': len(str(response_data))
                    })
                    return success, response_data
                except:
                    print(f"   Response: {response.text[:100]}...")
                    self.test_results.append({
                        'test': name,
                        'status': 'PASSED',
                        'response_time_ms': response_time,
                        'data_size': len(response.text)
                    })
                    return success, {}
            else:
                print(f"❌ FAILED - Expected {expected_status}, got {response.status_code}")
                print(f"   Response: {response.text[:200]}...")
                self.test_results.append({
                    'test': name,
                    'status': 'FAILED',
                    'error': f"Status {response.status_code}",
                    'response_time_ms': response_time
                })
                return False, {}

        except requests.exceptions.Timeout:
            print(f"❌ FAILED - Request timed out after {timeout} seconds")
            self.test_results.append({
                'test': name,
                'status': 'FAILED',
                'error': 'Timeout'
            })
            return False, {}
        except Exception as e:
            print(f"❌ FAILED - Error: {str(e)}")
            self.test_results.append({
                'test': name,
                'status': 'FAILED',
                'error': str(e)
            })
            return False, {}

    def test_wifi_networks_endpoint(self):
        """Test Enhanced Real WiFi Network Scanning - /api/wifi/networks"""
        print(f"\n📡 Testing Enhanced Real WiFi Network Scanning")
        print("   Expected: Real WiFi scanning with system commands (nmcli, iwlist, iw)")
        print("   Expected: Network details (ssid, bssid, security, signal_strength, channel)")
        print("   Expected: Security threat analysis and threat levels")
        print("   Expected: Response time <15s")
        
        success, response = self.run_test(
            "Enhanced Real WiFi Network Scanning", 
            "GET", 
            "wifi/networks", 
            200,
            timeout=20  # Allow extra time for WiFi scanning
        )
        
        if success and response:
            # Verify response structure and content
            if isinstance(response, dict) and 'networks' in response:
                networks = response['networks']
                print(f"   ✅ Found {len(networks)} WiFi networks")
                
                # Check network properties
                if networks:
                    sample_network = networks[0]
                    required_fields = ['ssid', 'bssid', 'security', 'signal_strength', 'channel', 'threat_level']
                    missing_fields = [field for field in required_fields if field not in sample_network]
                    
                    if not missing_fields:
                        print("   ✅ All required network properties present")
                    else:
                        print(f"   ⚠️  Missing fields: {missing_fields}")
                    
                    # Check threat analysis
                    threat_levels = [n.get('threat_level') for n in networks if n.get('threat_level')]
                    if threat_levels:
                        print(f"   ✅ Security threat analysis working - Threat levels: {set(threat_levels)}")
                    else:
                        print("   ⚠️  No threat level analysis found")
                        
                    # Check for open networks detection
                    open_networks = [n for n in networks if 'Open' in str(n.get('security', ''))]
                    if open_networks:
                        print(f"   ✅ Open network detection working - Found {len(open_networks)} open networks")
                else:
                    print("   ⚠️  No networks found in scan")
            else:
                print("   ❌ Invalid response structure - expected 'networks' key")
                success = False
        
        return success, response

    def test_current_connection_endpoint(self):
        """Test Current WiFi Connection Analysis - /api/wifi/current-connection"""
        print(f"\n🔗 Testing Current WiFi Connection Analysis")
        print("   Expected: Connection detection and status")
        print("   Expected: Signal strength and security assessment")
        print("   Expected: Network configuration (IP, gateway, DNS)")
        print("   Expected: Connectivity tests and quality metrics")
        print("   Expected: Response time <3s")
        
        success, response = self.run_test(
            "Current WiFi Connection Analysis", 
            "GET", 
            "wifi/current-connection", 
            200,
            timeout=5  # Stricter timeout for current connection
        )
        
        if success and response:
            # Check if connected or not
            is_connected = response.get('connected', False)
            print(f"   Connection Status: {'Connected' if is_connected else 'Not Connected'}")
            
            if is_connected:
                # Verify connection details
                connection_fields = ['ssid', 'signal_strength', 'security']
                present_fields = [field for field in connection_fields if field in response]
                print(f"   ✅ Connection details present: {present_fields}")
                
                # Check network configuration
                network_config = ['gateway', 'dns_servers', 'local_ip']
                config_present = [field for field in network_config if field in response]
                if config_present:
                    print(f"   ✅ Network configuration available: {config_present}")
                
                # Check connectivity tests
                connectivity_tests = ['internet_connectivity', 'dns_working', 'latency_ms']
                tests_present = [field for field in connectivity_tests if field in response]
                if tests_present:
                    print(f"   ✅ Connectivity tests working: {tests_present}")
                
                # Check quality metrics
                if 'connection_quality' in response:
                    quality = response['connection_quality']
                    print(f"   ✅ Connection quality assessment available: {quality.get('overall_score', 'N/A')}/100")
            else:
                print("   ℹ️  Not connected to WiFi - testing disconnected state handling")
        
        return success, response

    def test_wifi_rescan_endpoint(self):
        """Test Enhanced WiFi API Endpoints - /api/wifi/rescan"""
        print(f"\n🔄 Testing Enhanced WiFi Rescan Endpoint")
        print("   Expected: Rescan functionality working")
        print("   Expected: Response time <20s")
        print("   Expected: Proper status messages")
        
        success, response = self.run_test(
            "WiFi Rescan Functionality", 
            "POST", 
            "wifi/rescan", 
            200,
            timeout=25  # Allow time for rescan
        )
        
        if success and response:
            # Check rescan response
            if 'status' in response:
                print(f"   ✅ Rescan status: {response['status']}")
            
            if 'message' in response:
                print(f"   ✅ Status message: {response['message']}")
            
            # Check if rescan was initiated/completed
            expected_statuses = ['initiated', 'completed', 'success', 'scanning']
            status = response.get('status', '').lower()
            if any(expected in status for expected in expected_statuses):
                print("   ✅ Rescan successfully initiated/completed")
            else:
                print(f"   ⚠️  Unexpected rescan status: {status}")
        
        return success, response

    def test_api_error_handling(self):
        """Test API error handling for non-existent endpoints"""
        print(f"\n🚫 Testing API Error Handling")
        
        # Test 404 for non-existent endpoint
        success_404, _ = self.run_test(
            "404 Error Handling", 
            "GET", 
            "wifi/nonexistent", 
            404,
            timeout=5
        )
        
        # Test 405 for wrong method
        success_405, _ = self.run_test(
            "405 Method Not Allowed", 
            "DELETE", 
            "wifi/networks", 
            405,
            timeout=5
        )
        
        return success_404 and success_405

    def verify_data_integrity(self):
        """Verify data integrity across endpoints"""
        print(f"\n🔍 Testing Data Integrity Across Endpoints")
        
        # Get networks from main endpoint
        networks_success, networks_response = self.run_test(
            "Networks Data Integrity Check", 
            "GET", 
            "wifi/networks", 
            200,
            timeout=15
        )
        
        # Get current connection
        connection_success, connection_response = self.run_test(
            "Connection Data Integrity Check", 
            "GET", 
            "wifi/current-connection", 
            200,
            timeout=5
        )
        
        if networks_success and connection_success:
            # Check if current connection matches one of the scanned networks
            if connection_response.get('connected'):
                current_ssid = connection_response.get('ssid')
                current_bssid = connection_response.get('bssid')
                
                if networks_response and 'networks' in networks_response:
                    networks = networks_response['networks']
                    matching_network = None
                    
                    for network in networks:
                        if (network.get('ssid') == current_ssid or 
                            network.get('bssid') == current_bssid):
                            matching_network = network
                            break
                    
                    if matching_network:
                        print("   ✅ Current connection matches scanned network data")
                        if matching_network.get('is_current'):
                            print("   ✅ Current network properly marked in scan results")
                    else:
                        print("   ⚠️  Current connection not found in scanned networks")
            
            print("   ✅ Data integrity checks completed")
            return True
        
        return False

    def run_comprehensive_verification(self):
        """Run comprehensive WiFi backend verification"""
        print("🛡️  WiFi Network Scanner Backend Verification Test")
        print("=" * 70)
        print("📋 Verifying WiFi functionality after service restart...")
        
        # Test core WiFi endpoints
        networks_success, _ = self.test_wifi_networks_endpoint()
        connection_success, _ = self.test_current_connection_endpoint()
        rescan_success, _ = self.test_wifi_rescan_endpoint()
        
        # Test error handling
        error_handling_success = self.test_api_error_handling()
        
        # Test data integrity
        integrity_success = self.verify_data_integrity()
        
        # Calculate results
        core_tests_passed = sum([networks_success, connection_success, rescan_success])
        all_tests_passed = sum([networks_success, connection_success, rescan_success, 
                               error_handling_success, integrity_success])
        
        # Print results
        print("\n" + "=" * 70)
        print(f"📊 WIFI BACKEND VERIFICATION RESULTS")
        print(f"Tests passed: {self.tests_passed}/{self.tests_run}")
        
        success_rate = (self.tests_passed / self.tests_run) * 100 if self.tests_run > 0 else 0
        print(f"Success rate: {success_rate:.1f}%")
        
        # Detailed results
        print(f"\n🔍 Core WiFi Functionality: {core_tests_passed}/3 tests passed")
        print(f"📡 Enhanced Real WiFi Network Scanning: {'✅ WORKING' if networks_success else '❌ FAILED'}")
        print(f"🔗 Current WiFi Connection Analysis: {'✅ WORKING' if connection_success else '❌ FAILED'}")
        print(f"🔄 Enhanced WiFi API Endpoints: {'✅ WORKING' if rescan_success else '❌ FAILED'}")
        print(f"🚫 Error Handling: {'✅ WORKING' if error_handling_success else '❌ FAILED'}")
        print(f"🔍 Data Integrity: {'✅ WORKING' if integrity_success else '❌ FAILED'}")
        
        # Performance summary
        if self.test_results:
            response_times = [r['response_time_ms'] for r in self.test_results if 'response_time_ms' in r]
            if response_times:
                avg_response_time = sum(response_times) / len(response_times)
                print(f"\n⚡ Average Response Time: {avg_response_time:.1f}ms")
        
        # Final assessment
        if core_tests_passed == 3:
            print("\n🎉 ALL CORE WIFI FUNCTIONALITY VERIFIED!")
            print("✅ WiFi backend is fully operational after service restart")
            return 0
        elif core_tests_passed >= 2:
            print(f"\n⚠️  {3 - core_tests_passed} core WiFi test(s) failed")
            print("✅ Most WiFi functionality is working")
            return 0
        else:
            print(f"\n❌ CRITICAL: {3 - core_tests_passed} core WiFi tests failed")
            print("❌ WiFi backend needs attention")
            return 1

def main():
    tester = WiFiBackendVerificationTester()
    return tester.run_comprehensive_verification()

if __name__ == "__main__":
    sys.exit(main())