"""
XSS Testing Module for DV-WebScanPro
Tests for Cross-Site Scripting vulnerabilities
"""

from urllib.parse import quote
from utils.helpers import print_info, print_vuln, print_success, print_error
from utils.http_client import HttpClient
from bs4 import BeautifulSoup

class XSSTester:
    """XSS vulnerability tester"""
    
    def __init__(self):
        self.http = HttpClient()
        self.vulnerabilities = []
        
        # XSS payloads that work with DVWA
        self.payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "\" onmouseover=\"alert('XSS')\"",
            "javascript:alert('XSS')",
            "<ScRiPt>alert('XSS')</ScRiPt>",
        ]
    
    def login_first(self):
        """Login to DVWA"""
        print_info("Logging into DVWA...")
        return self.http.login_dvwa()
    
    def test_reflected_xss(self):
        """Test Reflected XSS on xss_r page"""
        print_info("\n" + "="*60)
        print_info("TESTING REFLECTED XSS")
        print_info("="*60)
        
        xss_url = "http://localhost/DVWA/vulnerabilities/xss_r/"
        
        # Check if page exists
        response = self.http.get(xss_url)
        if not response or response.status_code != 200:
            print_error("XSS reflected page not accessible!")
            return
        
        print_success("XSS reflected page accessible")
        
        # Test each payload
        for payload in self.payloads:
            test_url = f"{xss_url}?name={quote(payload)}"
            print_info(f"\nTrying: {payload[:30]}...")
            
            response = self.http.get(test_url)
            if not response:
                continue
            
            # Check if payload is reflected in response
            if payload in response.text:
                print_vuln("  ✓ XSS VULNERABILITY FOUND!")
                print_info(f"    Payload reflected in page")
                
                vuln = {
                    'type': 'Reflected XSS',
                    'url': xss_url,
                    'parameter': 'name',
                    'payload': payload,
                    'risk': 'High',
                    'evidence': 'Payload reflected in response'
                }
                self.vulnerabilities.append(vuln)
                break
    
    def test_stored_xss(self):
        """Test Stored XSS on xss_s page"""
        print_info("\n" + "="*60)
        print_info("TESTING STORED XSS")
        print_info("="*60)
        
        xss_url = "http://localhost/DVWA/vulnerabilities/xss_s/"
        
        # Check if page exists
        response = self.http.get(xss_url)
        if not response or response.status_code != 200:
            print_error("XSS stored page not accessible!")
            return
        
        print_success("XSS stored page accessible")
        
        # Test guestbook entry with XSS payload
        for payload in self.payloads[:3]:  # Test first 3 payloads
            print_info(f"\nTrying stored XSS with: {payload[:30]}...")
            
            # Post the payload to guestbook
            data = {
                'txtName': 'Hacker',
                'mtxMessage': payload,
                'btnSign': 'Sign Guestbook'
            }
            
            response = self.http.post(xss_url, data=data)
            
            if not response:
                continue
            
            # Check if payload is stored and displayed
            response = self.http.get(xss_url)
            if response and payload in response.text:
                print_vuln("  ✓ STORED XSS VULNERABILITY FOUND!")
                
                vuln = {
                    'type': 'Stored XSS',
                    'url': xss_url,
                    'input': 'message',
                    'payload': payload,
                    'risk': 'High',
                    'evidence': 'Payload stored and displayed'
                }
                self.vulnerabilities.append(vuln)
                break
    
    def test_dom_xss(self):
        """Test DOM XSS on xss_d page"""
        print_info("\n" + "="*60)
        print_info("TESTING DOM XSS")
        print_info("="*60)
        
        xss_url = "http://localhost/DVWA/vulnerabilities/xss_d/"
        
        # Check if page exists
        response = self.http.get(xss_url)
        if not response or response.status_code != 200:
            print_error("XSS DOM page not accessible!")
            return
        
        print_success("XSS DOM page accessible")
        
        # Test DOM-based XSS payloads
        dom_payloads = [
            "#<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
        ]
        
        for payload in dom_payloads:
            test_url = f"{xss_url}?default={quote(payload)}"
            print_info(f"\nTrying DOM XSS: {payload}")
            
            response = self.http.get(test_url)
            if not response:
                continue
            
            # Check for DOM-based XSS indicators
            if "script" in response.text.lower() or "alert" in response.text.lower():
                print_vuln("  ✓ DOM XSS POSSIBLE")
                
                vuln = {
                    'type': 'DOM XSS',
                    'url': xss_url,
                    'parameter': 'default',
                    'payload': payload,
                    'risk': 'Medium',
                    'evidence': 'DOM manipulation possible'
                }
                self.vulnerabilities.append(vuln)
    
    def run_tests(self):
        """Run all XSS tests"""
        if self.login_first():
            self.test_reflected_xss()
            self.test_stored_xss()
            self.test_dom_xss()
            
            print_info("\n" + "="*60)
            print_info("XSS TEST RESULTS SUMMARY")
            print_info("="*60)
            
            if self.vulnerabilities:
                print_vuln(f"Found {len(self.vulnerabilities)} XSS vulnerabilities!")
                for i, vuln in enumerate(self.vulnerabilities, 1):
                    print_info(f"{i}. {vuln['type']} - {vuln['url']}")
            else:
                print_info("No XSS vulnerabilities found")
            
            return self.vulnerabilities
        else:
            print_error("Login failed")
            return []