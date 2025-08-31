#!/usr/bin/env python3
"""
Comprehensive Backend Testing for CryptoPulse Enhanced Security Application
Focus: Security Inbox, WiFi Security, Network Scanning, and Database Integration
"""

import requests
import json
import time
import io
from datetime import datetime
import sys

class CryptoPulseComprehensiveTester:
    def __init__(self, base_url="https://stack-test-refine.preview.emergentagent.com"):
        self.base_url = base_url
        self.api_url = f"{base_url}/api"
        self.tests_run = 0
        self.tests_passed = 0
        self.critical_failures = []
        self.minor_issues = []
        
    def log_result(self, test_name, success, response_data=None, is_critical=True):
        """Log test results and categorize failures"""
        self.tests_run += 1
        if success:
            self.tests_passed += 1
            print(f"✅ {test_name}")
            if response_data and isinstance(response_data, dict):
                # Show key metrics for successful tests
                if 'total' in response_data:
                    print(f"   Total items: {response_data['total']}")
                elif 'status' in response_data:
                    print(f"   Status: {response_data['status']}")
        else:
            if is_critical:
                self.critical_failures.append(test_name)
                print(f"❌ {test_name} (CRITICAL)")
            else:
                self.minor_issues.append(test_name)
                print(f"⚠️  {test_name} (MINOR)")
    
    def make_request(self, method, endpoint, data=None, files=None, timeout=30):
        """Make HTTP request with error handling"""
        url = f"{self.api_url}/{endpoint}" if not endpoint.startswith('http') else endpoint
        
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
            
            return response.status_code, response.text, response.headers
            
        except requests.exceptions.Timeout:
            return None, f"Request timed out after {timeout} seconds", {}
        except Exception as e:
            return None, str(e), {}
    
    def test_security_inbox_functionality(self):
        """Test all Security Inbox endpoints - MAIN FOCUS"""
        print("\n🔒 TESTING SECURITY INBOX FUNCTIONALITY (MAIN FOCUS)")
        print("=" * 60)
        
        # Test 1: Add URL to inbox
        print("\n1. Testing Add URL to Security Inbox...")
        test_urls = [
            "https://example.com",
            "https://google.com", 
            "https://github.com"
        ]
        
        added_ids = []
        for url in test_urls:
            data = {'url': url, 'note': f'Test URL: {url}'}
            status, response_text, _ = self.make_request('POST', 'inbox/add-url', data=data, files={})
            
            if status == 200:
                try:
                    response_data = json.loads(response_text)
                    if response_data.get('status') in ['added', 'exists']:  # Both are valid responses
                        if response_data.get('status') == 'exists':
                            print(f"   URL already exists: {url}")
                        added_ids.append(response_data.get('id'))
                        self.log_result(f"Add URL to inbox: {url}", True, response_data)
                    else:
                        self.log_result(f"Add URL to inbox: {url}", False, is_critical=True)
                except:
                    self.log_result(f"Add URL to inbox: {url}", False, is_critical=True)
            else:
                self.log_result(f"Add URL to inbox: {url}", False, is_critical=True)
        
        # Test 2: Get inbox entries (with error handling for ObjectId issue)
        print("\n2. Testing Get Inbox Entries...")
        status, response_text, _ = self.make_request('GET', 'inbox/entries')
        
        if status == 200:
            try:
                response_data = json.loads(response_text)
                self.log_result("Get inbox entries", True, response_data)
            except json.JSONDecodeError:
                # This is likely the ObjectId serialization issue
                self.log_result("Get inbox entries - JSON serialization issue", False, is_critical=True)
        elif status == 500:
            self.log_result("Get inbox entries - Server error (likely ObjectId issue)", False, is_critical=True)
        else:
            self.log_result("Get inbox entries", False, is_critical=True)
        
        # Test 3: Scan URLs from inbox
        print("\n3. Testing Scan URLs from Inbox...")
        for inbox_id in added_ids[:2]:  # Test first 2 IDs
            status, response_text, _ = self.make_request('POST', f'inbox/scan/{inbox_id}')
            
            if status == 200:
                try:
                    response_data = json.loads(response_text)
                    self.log_result(f"Scan inbox URL {inbox_id[:8]}...", True, response_data)
                except:
                    self.log_result(f"Scan inbox URL {inbox_id[:8]}...", False, is_critical=False)
            else:
                self.log_result(f"Scan inbox URL {inbox_id[:8]}...", False, is_critical=True)
        
        # Test 4: Batch scan URLs
        print("\n4. Testing Batch URL Scanning...")
        batch_urls = ["https://stackoverflow.com", "https://reddit.com"]
        status, response_text, _ = self.make_request('POST', 'inbox/batch-scan', data=batch_urls)
        
        if status == 200:
            try:
                response_data = json.loads(response_text)
                self.log_result("Batch scan URLs", True, response_data)
            except:
                self.log_result("Batch scan URLs", False, is_critical=False)
        else:
            self.log_result("Batch scan URLs", False, is_critical=True)
        
        # Test 5: Delete inbox entry
        print("\n5. Testing Delete Inbox Entry...")
        if added_ids:
            status, response_text, _ = self.make_request('DELETE', f'inbox/entry/{added_ids[0]}')
            
            if status == 200:
                try:
                    response_data = json.loads(response_text)
                    self.log_result("Delete inbox entry", True, response_data)
                except:
                    self.log_result("Delete inbox entry", True)  # DELETE might not return JSON
            else:
                self.log_result("Delete inbox entry", False, is_critical=False)
    
    def test_enhanced_wifi_security(self):
        """Test WiFi security features"""
        print("\n📶 TESTING ENHANCED WIFI SECURITY FEATURES")
        print("=" * 50)
        
        # Test WiFi networks discovery
        print("\n1. Testing WiFi Networks Discovery...")
        status, response_text, _ = self.make_request('GET', 'wifi/networks')
        
        if status == 200:
            try:
                response_data = json.loads(response_text)
                networks = response_data.get('networks', [])
                threats = response_data.get('threats_summary', [])
                
                print(f"   Networks found: {len(networks)}")
                print(f"   Threats detected: {len(threats)}")
                
                # Check if WiFi threat detection is working
                if isinstance(networks, list):
                    self.log_result("WiFi networks discovery", True, response_data)
                    
                    # Test threat analysis
                    if any('threat_level' in network for network in networks):
                        self.log_result("WiFi threat analysis", True)
                    else:
                        self.log_result("WiFi threat analysis - No threat levels found", False, is_critical=False)
                else:
                    self.log_result("WiFi networks discovery", False, is_critical=True)
            except:
                self.log_result("WiFi networks discovery", False, is_critical=True)
        else:
            self.log_result("WiFi networks discovery", False, is_critical=True)
    
    def test_performance_optimized_scanning(self):
        """Test performance-optimized network scanning"""
        print("\n🚀 TESTING PERFORMANCE-OPTIMIZED NETWORK SCANNING")
        print("=" * 55)
        
        # Test 1: Network scan with progress tracking
        print("\n1. Testing Network Scan with Progress Tracking...")
        
        # Start scan
        start_time = time.time()
        status, response_text, _ = self.make_request('POST', 'scan/network', timeout=90)
        scan_duration = time.time() - start_time
        
        if status == 200:
            try:
                response_data = json.loads(response_text)
                self.log_result("Enhanced network scan", True, response_data)
                
                print(f"   Scan completed in {scan_duration:.2f} seconds")
                if 'devices_found' in response_data:
                    print(f"   Devices found: {response_data['devices_found']}")
                if 'threats_found' in response_data:
                    print(f"   Threats found: {response_data['threats_found']}")
                    
            except:
                self.log_result("Enhanced network scan", False, is_critical=True)
        else:
            self.log_result("Enhanced network scan", False, is_critical=True)
        
        # Test 2: Scan progress endpoint
        print("\n2. Testing Scan Progress Tracking...")
        status, response_text, _ = self.make_request('GET', 'scan/progress')
        
        if status == 200:
            try:
                response_data = json.loads(response_text)
                if 'scanning' in response_data and 'progress' in response_data:
                    self.log_result("Scan progress tracking", True, response_data)
                else:
                    self.log_result("Scan progress tracking", False, is_critical=False)
            except:
                self.log_result("Scan progress tracking", False, is_critical=False)
        else:
            self.log_result("Scan progress tracking", False, is_critical=True)
    
    def test_enhanced_dashboard_stats(self):
        """Test enhanced dashboard with inbox metrics"""
        print("\n📊 TESTING ENHANCED DASHBOARD & STATISTICS")
        print("=" * 45)
        
        status, response_text, _ = self.make_request('GET', 'dashboard/stats')
        
        if status == 200:
            try:
                response_data = json.loads(response_text)
                
                # Check for all expected stats including new inbox metrics
                expected_stats = [
                    'total_devices', 'active_devices', 'rogue_devices', 'wifi_threats',
                    'unresolved_alerts', 'malware_detected', 'malicious_urls',
                    'pending_urls', 'inbox_threats', 'total_inbox_entries'
                ]
                
                found_stats = [stat for stat in expected_stats if stat in response_data]
                missing_stats = [stat for stat in expected_stats if stat not in response_data]
                
                print(f"   Stats found: {len(found_stats)}/{len(expected_stats)}")
                if missing_stats:
                    print(f"   Missing stats: {missing_stats}")
                
                if len(found_stats) >= 7:  # At least the basic 7 stats
                    self.log_result("Enhanced dashboard stats", True, response_data)
                    
                    # Check for new inbox metrics specifically
                    inbox_stats = ['pending_urls', 'inbox_threats', 'total_inbox_entries']
                    inbox_found = [stat for stat in inbox_stats if stat in response_data]
                    
                    if len(inbox_found) == 3:
                        self.log_result("Inbox metrics in dashboard", True)
                    else:
                        self.log_result("Inbox metrics in dashboard", False, is_critical=False)
                else:
                    self.log_result("Enhanced dashboard stats", False, is_critical=True)
                    
            except:
                self.log_result("Enhanced dashboard stats", False, is_critical=True)
        else:
            self.log_result("Enhanced dashboard stats", False, is_critical=True)
    
    def test_database_integration(self):
        """Test database integration and data persistence"""
        print("\n🗄️  TESTING DATABASE INTEGRATION")
        print("=" * 35)
        
        # Test various data endpoints to verify database operations
        endpoints_to_test = [
            ("devices", "Devices collection"),
            ("devices/active", "Active devices query"),
            ("alerts", "Threat alerts collection"),
            ("scans", "Network scans collection"),
        ]
        
        for endpoint, description in endpoints_to_test:
            status, response_text, _ = self.make_request('GET', endpoint)
            
            if status == 200:
                try:
                    response_data = json.loads(response_text)
                    if isinstance(response_data, list):
                        self.log_result(f"Database - {description}", True)
                    else:
                        self.log_result(f"Database - {description}", False, is_critical=False)
                except:
                    self.log_result(f"Database - {description}", False, is_critical=True)
            else:
                self.log_result(f"Database - {description}", False, is_critical=True)
        
        # Test malware and URL analyses (these had issues earlier)
        print("\n   Testing Analysis Collections...")
        
        analysis_endpoints = [
            ("malware/analyses", "Malware analyses"),
            ("url/analyses", "URL analyses")
        ]
        
        for endpoint, description in analysis_endpoints:
            status, response_text, _ = self.make_request('GET', endpoint)
            
            if status == 200:
                try:
                    response_data = json.loads(response_text)
                    self.log_result(f"Database - {description}", True)
                except:
                    self.log_result(f"Database - {description} (JSON error)", False, is_critical=True)
            elif status == 500:
                self.log_result(f"Database - {description} (Server error)", False, is_critical=True)
            else:
                self.log_result(f"Database - {description}", False, is_critical=True)
    
    def test_api_error_handling(self):
        """Test API error handling and validation"""
        print("\n🛡️  TESTING API ERROR HANDLING & VALIDATION")
        print("=" * 45)
        
        # Test 1: Invalid URL format
        print("\n1. Testing Invalid URL Validation...")
        invalid_urls = ["not-a-url", "ftp://invalid", ""]
        
        for invalid_url in invalid_urls:
            data = {'url': invalid_url}
            status, response_text, _ = self.make_request('POST', 'inbox/add-url', data=data)
            
            # Should either reject (400) or handle gracefully (200 with error status)
            if status in [400, 422]:  # Proper validation
                self.log_result(f"Invalid URL rejection: {invalid_url}", True)
            elif status == 200:
                try:
                    response_data = json.loads(response_text)
                    if response_data.get('status') == 'error':
                        self.log_result(f"Invalid URL handling: {invalid_url}", True)
                    else:
                        self.log_result(f"Invalid URL handling: {invalid_url}", False, is_critical=False)
                except:
                    self.log_result(f"Invalid URL handling: {invalid_url}", False, is_critical=False)
            else:
                self.log_result(f"Invalid URL handling: {invalid_url}", False, is_critical=False)
        
        # Test 2: File size limits
        print("\n2. Testing File Size Validation...")
        # Create a small test file (should pass)
        small_file_content = b"Small test file"
        small_file = io.BytesIO(small_file_content)
        files = {'file': ('small_test.txt', small_file, 'text/plain')}
        
        status, response_text, _ = self.make_request('POST', 'scan/file', files=files)
        
        if status == 200:
            self.log_result("File upload validation (small file)", True)
        else:
            self.log_result("File upload validation (small file)", False, is_critical=False)
        
        # Test 3: Non-existent endpoints
        print("\n3. Testing Non-existent Endpoints...")
        status, response_text, _ = self.make_request('GET', 'nonexistent/endpoint')
        
        if status == 404:
            self.log_result("404 handling for non-existent endpoints", True)
        else:
            self.log_result("404 handling for non-existent endpoints", False, is_critical=False)
    
    def run_comprehensive_tests(self):
        """Run all comprehensive tests"""
        print("🛡️  CRYPTOPULSE ENHANCED SECURITY - COMPREHENSIVE BACKEND TESTING")
        print("=" * 70)
        print("Focus: Security Inbox, WiFi Security, Performance Optimization")
        print("=" * 70)
        
        # Test in priority order based on review request
        self.test_security_inbox_functionality()  # MAIN FOCUS
        self.test_enhanced_wifi_security()
        self.test_performance_optimized_scanning()
        self.test_enhanced_dashboard_stats()
        self.test_database_integration()
        self.test_api_error_handling()
        
        # Generate comprehensive report
        self.generate_final_report()
    
    def generate_final_report(self):
        """Generate comprehensive test report"""
        print("\n" + "=" * 70)
        print("📊 COMPREHENSIVE TEST RESULTS")
        print("=" * 70)
        
        success_rate = (self.tests_passed / self.tests_run) * 100 if self.tests_run > 0 else 0
        
        print(f"Total Tests Run: {self.tests_run}")
        print(f"Tests Passed: {self.tests_passed}")
        print(f"Success Rate: {success_rate:.1f}%")
        
        if self.critical_failures:
            print(f"\n❌ CRITICAL FAILURES ({len(self.critical_failures)}):")
            for failure in self.critical_failures:
                print(f"   • {failure}")
        
        if self.minor_issues:
            print(f"\n⚠️  MINOR ISSUES ({len(self.minor_issues)}):")
            for issue in self.minor_issues:
                print(f"   • {issue}")
        
        print("\n" + "=" * 70)
        
        # Determine overall status
        if len(self.critical_failures) == 0:
            print("🎉 ALL CRITICAL FUNCTIONALITY WORKING!")
            print("✅ Security Inbox and enhanced features are operational.")
            return 0
        elif len(self.critical_failures) <= 3 and success_rate >= 70:
            print("⚠️  MOSTLY FUNCTIONAL with some critical issues.")
            print("🔧 Requires fixes for critical failures before production.")
            return 1
        else:
            print("❌ SIGNIFICANT ISSUES DETECTED")
            print("🚨 Multiple critical failures require immediate attention.")
            return 2

def main():
    tester = CryptoPulseComprehensiveTester()
    return tester.run_comprehensive_tests()

if __name__ == "__main__":
    sys.exit(main())