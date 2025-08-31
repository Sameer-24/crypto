import requests
import sys
import json
import time
from datetime import datetime

class WiFiEnhancedAPITester:
    def __init__(self, base_url="https://network-checker-4.preview.emergentagent.com"):
        self.base_url = base_url
        self.api_url = f"{base_url}/api"
        self.tests_run = 0
        self.tests_passed = 0
        self.critical_failures = []
        self.minor_issues = []

    def run_test(self, name, method, endpoint, expected_status, data=None, timeout=30):
        """Run a single API test with detailed response analysis"""
        url = f"{self.api_url}/{endpoint}" if not endpoint.startswith('http') else endpoint
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

            response_time = round((time.time() - start_time) * 1000, 2)
            
            success = response.status_code == expected_status
            if success:
                self.tests_passed += 1
                print(f"✅ Passed - Status: {response.status_code} | Response Time: {response_time}ms")
                try:
                    response_data = response.json()
                    return True, response_data, response_time
                except:
                    print(f"   Response: {response.text[:100]}...")
                    return True, {}, response_time
            else:
                print(f"❌ Failed - Expected {expected_status}, got {response.status_code}")
                print(f"   Response: {response.text[:200]}...")
                self.critical_failures.append(f"{name}: Expected {expected_status}, got {response.status_code}")
                return False, {}, response_time

        except requests.exceptions.Timeout:
            print(f"❌ Failed - Request timed out after {timeout} seconds")
            self.critical_failures.append(f"{name}: Timeout after {timeout}s")
            return False, {}, timeout * 1000
        except Exception as e:
            print(f"❌ Failed - Error: {str(e)}")
            self.critical_failures.append(f"{name}: {str(e)}")
            return False, {}, 0

    def test_wifi_networks_endpoint(self):
        """Test Enhanced WiFi Network Scanning (/api/wifi/networks)"""
        print(f"\n📡 Testing Enhanced WiFi Network Scanning")
        print("   This endpoint should discover real WiFi networks using system commands")
        
        success, response, response_time = self.run_test(
            "WiFi Networks Discovery", 
            "GET", 
            "wifi/networks", 
            200,
            timeout=20  # WiFi scanning can take time
        )
        
        if success and response:
            print("   ✅ WiFi networks endpoint working")
            
            # Validate response structure
            if isinstance(response, dict):
                networks = response.get('networks', [])
                environment = response.get('environment', {})
                current_connection = response.get('current_connection', {})
                
                print(f"   Networks Found: {len(networks)}")
                print(f"   Environment Analysis: {'✅' if environment else '❌'}")
                print(f"   Current Connection: {'✅' if current_connection else '❌'}")
                
                # Validate network properties
                if networks:
                    sample_network = networks[0]
                    required_fields = ['ssid', 'bssid', 'security', 'signal_strength', 'channel', 'threat_level']
                    missing_fields = [field for field in required_fields if field not in sample_network]
                    
                    if missing_fields:
                        self.minor_issues.append(f"WiFi Networks: Missing fields {missing_fields}")
                        print(f"   ⚠️  Missing fields in network data: {missing_fields}")
                    else:
                        print("   ✅ All required network properties present")
                    
                    # Check threat analysis
                    threats_found = sum(1 for network in networks if network.get('threats'))
                    print(f"   Networks with Threats: {threats_found}")
                    
                    # Check security analysis
                    security_levels = set(network.get('threat_level', 'Unknown') for network in networks)
                    print(f"   Security Levels Found: {list(security_levels)}")
                    
                    # Check for current connection marking
                    current_networks = [n for n in networks if n.get('is_current')]
                    print(f"   Current Connection Marked: {'✅' if current_networks else '❌'}")
                
                # Validate environment analysis
                if environment:
                    env_fields = ['total_networks', 'open_networks', 'threat_summary', 'channel_analysis']
                    env_present = [field for field in env_fields if field in environment]
                    print(f"   Environment Fields: {env_present}")
                
                # Performance check
                if response_time > 15000:  # 15 seconds
                    self.minor_issues.append(f"WiFi Networks: Slow response time {response_time}ms")
                    print(f"   ⚠️  Slow response time: {response_time}ms (expected < 15s)")
                else:
                    print(f"   ✅ Good response time: {response_time}ms")
                    
            else:
                self.critical_failures.append("WiFi Networks: Invalid response format")
                print("   ❌ Invalid response format - expected dict with networks array")
        
        return success, response

    def test_current_connection_endpoint(self):
        """Test Current WiFi Connection Analysis (/api/wifi/current-connection)"""
        print(f"\n🔗 Testing Current WiFi Connection Analysis")
        print("   This endpoint should analyze the currently connected WiFi network")
        
        success, response, response_time = self.run_test(
            "Current WiFi Connection Analysis", 
            "GET", 
            "wifi/current-connection", 
            200,
            timeout=10
        )
        
        if success and response:
            print("   ✅ Current connection endpoint working")
            
            # Validate response structure
            if isinstance(response, dict):
                connected = response.get('connected', False)
                print(f"   Connection Status: {'Connected' if connected else 'Not Connected'}")
                
                if connected:
                    # Check connection details
                    connection_fields = ['ssid', 'signal_strength', 'security', 'gateway', 'dns_servers', 'local_ip']
                    present_fields = [field for field in connection_fields if field in response]
                    missing_fields = [field for field in connection_fields if field not in response]
                    
                    print(f"   Connection Details Present: {present_fields}")
                    if missing_fields:
                        self.minor_issues.append(f"Current Connection: Missing fields {missing_fields}")
                        print(f"   ⚠️  Missing connection fields: {missing_fields}")
                    
                    # Check quality assessment
                    quality = response.get('connection_quality', {})
                    if quality:
                        print(f"   Quality Score: {quality.get('overall_score', 'N/A')}")
                        print(f"   Signal Quality: {quality.get('signal_quality', 'N/A')}")
                        print(f"   Security Quality: {quality.get('security_quality', 'N/A')}")
                    else:
                        self.minor_issues.append("Current Connection: No quality assessment")
                    
                    # Check connectivity tests
                    internet = response.get('internet_connectivity', False)
                    dns = response.get('dns_working', False)
                    latency = response.get('latency_ms')
                    
                    print(f"   Internet Connectivity: {'✅' if internet else '❌'}")
                    print(f"   DNS Working: {'✅' if dns else '❌'}")
                    print(f"   Latency: {latency}ms" if latency else "   Latency: Not measured")
                    
                    # Check security recommendations
                    recommendations = response.get('recommendations', {})
                    if recommendations:
                        security_recs = len(recommendations.get('security', []))
                        performance_recs = len(recommendations.get('performance', []))
                        print(f"   Security Recommendations: {security_recs}")
                        print(f"   Performance Recommendations: {performance_recs}")
                    else:
                        self.minor_issues.append("Current Connection: No recommendations provided")
                
                # Performance check
                if response_time > 3000:  # 3 seconds
                    self.minor_issues.append(f"Current Connection: Slow response time {response_time}ms")
                    print(f"   ⚠️  Slow response time: {response_time}ms (expected < 3s)")
                else:
                    print(f"   ✅ Good response time: {response_time}ms")
                    
            else:
                self.critical_failures.append("Current Connection: Invalid response format")
                print("   ❌ Invalid response format")
        
        return success, response

    def test_wifi_rescan_endpoint(self):
        """Test WiFi Network Rescanning (/api/wifi/rescan)"""
        print(f"\n🔄 Testing WiFi Network Rescanning")
        print("   This endpoint should force a fresh WiFi scan and broadcast updates")
        
        success, response, response_time = self.run_test(
            "WiFi Network Rescan", 
            "POST", 
            "wifi/rescan", 
            200,
            timeout=25  # Rescanning can take longer
        )
        
        if success and response:
            print("   ✅ WiFi rescan endpoint working")
            
            # Validate response structure
            if isinstance(response, dict):
                status = response.get('status')
                message = response.get('message')
                
                print(f"   Rescan Status: {status}")
                print(f"   Message: {message}")
                
                # Check if scan was initiated
                if status in ['completed', 'initiated', 'success']:
                    print("   ✅ Rescan successfully initiated/completed")
                else:
                    self.minor_issues.append(f"WiFi Rescan: Unexpected status '{status}'")
                
                # Check for updated data
                networks = response.get('networks', [])
                if networks:
                    print(f"   Updated Networks: {len(networks)}")
                else:
                    print("   ⚠️  No updated networks in response")
                
                # Performance check
                if response_time > 20000:  # 20 seconds
                    self.minor_issues.append(f"WiFi Rescan: Slow response time {response_time}ms")
                    print(f"   ⚠️  Slow response time: {response_time}ms (expected < 20s)")
                else:
                    print(f"   ✅ Good response time: {response_time}ms")
                    
            else:
                self.critical_failures.append("WiFi Rescan: Invalid response format")
                print("   ❌ Invalid response format")
        
        return success, response

    def test_wifi_security_analysis(self, networks_response):
        """Test WiFi Security Analysis functionality"""
        print(f"\n🔒 Testing WiFi Security Analysis")
        
        if not networks_response or not isinstance(networks_response, dict):
            print("   ⚠️  No networks data available for security analysis")
            return False
        
        networks = networks_response.get('networks', [])
        if not networks:
            print("   ⚠️  No networks found for security analysis")
            return False
        
        print(f"   Analyzing security for {len(networks)} networks...")
        
        # Test threat detection
        threat_levels = {}
        networks_with_threats = 0
        open_networks = 0
        weak_encryption = 0
        
        for network in networks:
            threat_level = network.get('threat_level', 'Unknown')
            threat_levels[threat_level] = threat_levels.get(threat_level, 0) + 1
            
            if network.get('threats'):
                networks_with_threats += 1
            
            security = network.get('security', '').upper()
            if 'OPEN' in security or not security:
                open_networks += 1
            elif 'WEP' in security:
                weak_encryption += 1
        
        print(f"   Threat Levels Distribution: {threat_levels}")
        print(f"   Networks with Threats: {networks_with_threats}")
        print(f"   Open Networks: {open_networks}")
        print(f"   Weak Encryption (WEP): {weak_encryption}")
        
        # Test evil twin detection
        ssid_counts = {}
        for network in networks:
            ssid = network.get('ssid', '')
            if ssid:
                ssid_counts[ssid] = ssid_counts.get(ssid, 0) + 1
        
        potential_evil_twins = sum(1 for count in ssid_counts.values() if count > 1)
        print(f"   Potential Evil Twins: {potential_evil_twins}")
        
        # Test environment analysis
        environment = networks_response.get('environment', {})
        if environment:
            print("   ✅ Environment analysis present")
            threat_summary = environment.get('threat_summary', {})
            if threat_summary:
                print(f"   Environment Threat Summary: {threat_summary}")
        else:
            self.minor_issues.append("WiFi Security: No environment analysis")
        
        return True

    def test_wifi_performance_requirements(self):
        """Test WiFi endpoints meet performance requirements"""
        print(f"\n⚡ Testing WiFi Performance Requirements")
        
        # Test networks endpoint performance
        print("   Testing /wifi/networks performance...")
        start_time = time.time()
        success1, _, _ = self.run_test("WiFi Networks Performance", "GET", "wifi/networks", 200, timeout=15)
        networks_time = time.time() - start_time
        
        # Test current connection performance
        print("   Testing /wifi/current-connection performance...")
        start_time = time.time()
        success2, _, _ = self.run_test("Current Connection Performance", "GET", "wifi/current-connection", 200, timeout=3)
        connection_time = time.time() - start_time
        
        # Test rescan performance
        print("   Testing /wifi/rescan performance...")
        start_time = time.time()
        success3, _, _ = self.run_test("WiFi Rescan Performance", "POST", "wifi/rescan", 200, timeout=20)
        rescan_time = time.time() - start_time
        
        # Evaluate performance
        print(f"\n   Performance Results:")
        print(f"   WiFi Networks: {networks_time:.2f}s (target: <15s)")
        print(f"   Current Connection: {connection_time:.2f}s (target: <3s)")
        print(f"   Rescan: {rescan_time:.2f}s (target: <20s)")
        
        performance_issues = []
        if networks_time > 15:
            performance_issues.append(f"WiFi Networks slow: {networks_time:.2f}s")
        if connection_time > 3:
            performance_issues.append(f"Current Connection slow: {connection_time:.2f}s")
        if rescan_time > 20:
            performance_issues.append(f"Rescan slow: {rescan_time:.2f}s")
        
        if performance_issues:
            self.minor_issues.extend(performance_issues)
            print(f"   ⚠️  Performance issues: {performance_issues}")
        else:
            print("   ✅ All endpoints meet performance requirements")
        
        return success1 and success2 and success3

    def test_wifi_data_integrity(self, networks_response, connection_response):
        """Test WiFi data integrity and consistency"""
        print(f"\n🔍 Testing WiFi Data Integrity")
        
        integrity_issues = []
        
        # Test networks data integrity
        if networks_response and isinstance(networks_response, dict):
            networks = networks_response.get('networks', [])
            
            for i, network in enumerate(networks):
                # Check required fields
                required_fields = ['ssid', 'bssid', 'security', 'signal_strength', 'threat_level']
                for field in required_fields:
                    if field not in network:
                        integrity_issues.append(f"Network {i}: Missing {field}")
                
                # Check data types
                if 'signal_strength' in network:
                    try:
                        int(network['signal_strength'])
                    except (ValueError, TypeError):
                        integrity_issues.append(f"Network {i}: Invalid signal_strength type")
                
                if 'channel' in network:
                    try:
                        int(network['channel'])
                    except (ValueError, TypeError):
                        integrity_issues.append(f"Network {i}: Invalid channel type")
                
                # Check threat level values
                valid_threat_levels = ['Very Low', 'Low', 'Medium', 'High', 'Critical', 'Unknown']
                if network.get('threat_level') not in valid_threat_levels:
                    integrity_issues.append(f"Network {i}: Invalid threat_level")
        
        # Test current connection data integrity
        if connection_response and isinstance(connection_response, dict):
            if connection_response.get('connected'):
                # Check IP address format
                local_ip = connection_response.get('local_ip')
                if local_ip:
                    import re
                    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
                    if not re.match(ip_pattern, local_ip):
                        integrity_issues.append("Current Connection: Invalid IP address format")
                
                # Check DNS servers format
                dns_servers = connection_response.get('dns_servers', [])
                if dns_servers:
                    for dns in dns_servers:
                        if not re.match(ip_pattern, dns):
                            integrity_issues.append(f"Current Connection: Invalid DNS server format: {dns}")
        
        if integrity_issues:
            self.minor_issues.extend(integrity_issues)
            print(f"   ⚠️  Data integrity issues found: {len(integrity_issues)}")
            for issue in integrity_issues[:5]:  # Show first 5 issues
                print(f"      - {issue}")
            if len(integrity_issues) > 5:
                print(f"      ... and {len(integrity_issues) - 5} more")
        else:
            print("   ✅ All data integrity checks passed")
        
        return len(integrity_issues) == 0

    def test_wifi_error_handling(self):
        """Test WiFi endpoints error handling"""
        print(f"\n🚫 Testing WiFi Error Handling")
        
        # Test invalid endpoints
        error_tests = [
            ("Invalid WiFi Endpoint", "GET", "wifi/invalid", 404),
            ("Invalid Method on Networks", "POST", "wifi/networks", 405),
            ("Invalid Method on Current Connection", "POST", "wifi/current-connection", 405),
        ]
        
        error_handling_success = True
        for name, method, endpoint, expected_status in error_tests:
            success, _, _ = self.run_test(name, method, endpoint, expected_status, timeout=5)
            if not success:
                error_handling_success = False
        
        return error_handling_success

def main():
    print("🛡️  Enhanced WiFi Functionality - Comprehensive Testing Suite")
    print("=" * 80)
    
    # Setup
    tester = WiFiEnhancedAPITester()
    
    # Test basic connectivity first
    print("\n📡 Testing Basic API Connectivity...")
    try:
        response = requests.get(f"{tester.api_url}", timeout=10)
        if response.status_code != 200:
            print("❌ Basic API connectivity failed. Backend may be down.")
            return 1
        print("✅ Basic API connectivity working")
    except Exception as e:
        print(f"❌ Cannot connect to backend: {e}")
        return 1
    
    # Test Enhanced WiFi Network Scanning
    print("\n" + "="*50)
    print("TESTING: Enhanced WiFi Network Scanning")
    print("="*50)
    networks_success, networks_response = tester.test_wifi_networks_endpoint()
    
    # Test Current WiFi Connection Analysis  
    print("\n" + "="*50)
    print("TESTING: Current WiFi Connection Analysis")
    print("="*50)
    connection_success, connection_response = tester.test_current_connection_endpoint()
    
    # Test WiFi Network Rescanning
    print("\n" + "="*50)
    print("TESTING: WiFi Network Rescanning")
    print("="*50)
    rescan_success, rescan_response = tester.test_wifi_rescan_endpoint()
    
    # Test WiFi Security Analysis
    print("\n" + "="*50)
    print("TESTING: WiFi Security Analysis")
    print("="*50)
    security_success = tester.test_wifi_security_analysis(networks_response)
    
    # Test Performance Requirements
    print("\n" + "="*50)
    print("TESTING: Performance Requirements")
    print("="*50)
    performance_success = tester.test_wifi_performance_requirements()
    
    # Test Data Integrity
    print("\n" + "="*50)
    print("TESTING: Data Integrity")
    print("="*50)
    integrity_success = tester.test_wifi_data_integrity(networks_response, connection_response)
    
    # Test Error Handling
    print("\n" + "="*50)
    print("TESTING: Error Handling")
    print("="*50)
    error_handling_success = tester.test_wifi_error_handling()
    
    # Print comprehensive results
    print("\n" + "=" * 80)
    print(f"📊 ENHANCED WiFi FUNCTIONALITY TEST RESULTS")
    print("=" * 80)
    print(f"Tests passed: {tester.tests_passed}/{tester.tests_run}")
    
    success_rate = (tester.tests_passed / tester.tests_run) * 100 if tester.tests_run > 0 else 0
    print(f"Success rate: {success_rate:.1f}%")
    
    # Critical failures
    if tester.critical_failures:
        print(f"\n❌ CRITICAL FAILURES ({len(tester.critical_failures)}):")
        for failure in tester.critical_failures:
            print(f"   - {failure}")
    
    # Minor issues
    if tester.minor_issues:
        print(f"\n⚠️  MINOR ISSUES ({len(tester.minor_issues)}):")
        for issue in tester.minor_issues[:10]:  # Show first 10
            print(f"   - {issue}")
        if len(tester.minor_issues) > 10:
            print(f"   ... and {len(tester.minor_issues) - 10} more minor issues")
    
    # Overall assessment
    print(f"\n🎯 OVERALL ASSESSMENT:")
    
    core_endpoints_working = networks_success and connection_success and rescan_success
    
    if core_endpoints_working and len(tester.critical_failures) == 0:
        print("✅ ALL CORE WiFi FUNCTIONALITY WORKING")
        print("✅ Enhanced WiFi scanning system is fully operational")
        print("✅ Ready for production use")
        return 0
    elif core_endpoints_working:
        print("✅ CORE WiFi FUNCTIONALITY WORKING")
        print("⚠️  Some minor issues detected but system is functional")
        return 0
    else:
        print("❌ CRITICAL WiFi FUNCTIONALITY ISSUES")
        print("❌ System requires fixes before production use")
        return 1

if __name__ == "__main__":
    sys.exit(main())