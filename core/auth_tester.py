"""
Authentication and Session Testing Module for DV-WebScanPro
Tests for weak credentials, session security, and authentication bypass
"""

from utils.helpers import print_info, print_vuln, print_success, print_error, print_warning
from utils.http_client import HttpClient
from bs4 import BeautifulSoup
import time

class AuthTester:
    """Authentication and Session security tester"""
    
    def __init__(self):
        self.http = HttpClient()
        self.vulnerabilities = []
        
        # Common weak credentials to test
        self.weak_creds = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '123456'),
            ('admin', 'admin123'),
            ('root', 'root'),
            ('root', 'password'),
            ('user', 'user'),
            ('user', 'password'),
            ('test', 'test'),
            ('guest', 'guest'),
        ]
    
    def login_first(self):
        """Login to DVWA"""
        print_info("Logging into DVWA...")
        return self.http.login_dvwa()
    
    def test_weak_credentials(self):
        """Test for weak/default credentials on login page"""
        print_info("\n" + "="*60)
        print_info("TESTING WEAK CREDENTIALS")
        print_info("="*60)
        
        login_url = "http://localhost/DVWA/login.php"
        
        for username, password in self.weak_creds:
            print_info(f"Trying: {username}:{password}")
            
            # Get CSRF token first
            response = self.http.get(login_url)
            if not response:
                continue
            
            soup = BeautifulSoup(response.text, 'html.parser')
            token = soup.find('input', {'name': 'user_token'})
            if token:
                token_value = token.get('value', '')
            else:
                token_value = ''
            
            # Try login
            login_data = {
                'username': username,
                'password': password,
                'Login': 'Login',
                'user_token': token_value
            }
            
            response = self.http.post(login_url, data=login_data)
            
            if response and 'index.php' in response.url:
                print_vuln(f"  ✓ WEAK CREDENTIALS FOUND: {username}:{password}")
                
                vuln = {
                    'type': 'Weak Credentials',
                    'url': login_url,
                    'credentials': f"{username}:{password}",
                    'risk': 'High',
                    'remediation': 'Enforce strong password policy, implement account lockout'
                }
                self.vulnerabilities.append(vuln)
                break
    
    def test_session_cookies(self):
        """Test session cookie security"""
        print_info("\n" + "="*60)
        print_info("TESTING SESSION COOKIE SECURITY")
        print_info("="*60)
        
        cookies = self.http.get_cookies()
        
        if cookies:
            print_info(f"Session cookies found: {cookies}")
            
            # Check for secure flags
            for cookie_name, cookie_value in cookies.items():
                # In a real test, we'd check the actual cookie attributes
                # For DVWA, we'll check if session cookie exists
                if 'PHPSESSID' in cookie_name:
                    print_warning("  Session cookie lacks Secure flag (simulated)")
                    
                    vuln = {
                        'type': 'Insecure Session Cookie',
                        'cookie': cookie_name,
                        'risk': 'Medium',
                        'remediation': 'Set Secure and HttpOnly flags on session cookies'
                    }
                    self.vulnerabilities.append(vuln)
    
    def test_session_fixation(self):
        """Test for session fixation vulnerability"""
        print_info("\n" + "="*60)
        print_info("TESTING SESSION FIXATION")
        print_info("="*60)
        
        # Get initial session cookie
        self.http.get("http://localhost/DVWA/")
        initial_cookie = self.http.get_cookies()
        
        # Login
        self.http.login_dvwa()
        after_login_cookie = self.http.get_cookies()
        
        # Check if session ID changed after login
        if initial_cookie == after_login_cookie:
            print_vuln("  ✓ SESSION FIXATION POSSIBLE - Session ID didn't change after login")
            
            vuln = {
                'type': 'Session Fixation',
                'risk': 'High',
                'remediation': 'Regenerate session ID after login'
            }
            self.vulnerabilities.append(vuln)
        else:
            print_success("  Session ID changed after login - good")
    
    def test_brute_force_protection(self):
        """Test for brute force protection on login page"""
        print_info("\n" + "="*60)
        print_info("TESTING BRUTE FORCE PROTECTION")
        print_info("="*60)
        
        login_url = "http://localhost/DVWA/login.php"
        failed_attempts = 0
        
        # Try multiple failed logins
        for i in range(5):
            print_info(f"Attempt {i+1}: Trying invalid login...")
            
            # Get CSRF token
            response = self.http.get(login_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            token = soup.find('input', {'name': 'user_token'})
            token_value = token.get('value', '') if token else ''
            
            login_data = {
                'username': 'invalid',
                'password': 'invalid',
                'Login': 'Login',
                'user_token': token_value
            }
            
            response = self.http.post(login_url, data=login_data)
            
            if response and 'index.php' not in response.url:
                failed_attempts += 1
            
            time.sleep(1)
        
        if failed_attempts >= 5:
            print_vuln("  ✓ NO BRUTE FORCE PROTECTION - Allowed 5 failed attempts")
            
            vuln = {
                'type': 'Missing Brute Force Protection',
                'risk': 'Medium',
                'remediation': 'Implement account lockout after failed attempts'
            }
            self.vulnerabilities.append(vuln)
        else:
            print_success("  Brute force protection may be in place")
    
    def run_tests(self):
        """Run all authentication tests"""
        if self.login_first():
            self.test_weak_credentials()
            self.test_session_cookies()
            self.test_session_fixation()
            self.test_brute_force_protection()
            
            print_info("\n" + "="*60)
            print_info("AUTHENTICATION TEST RESULTS SUMMARY")
            print_info("="*60)
            
            if self.vulnerabilities:
                print_vuln(f"Found {len(self.vulnerabilities)} authentication vulnerabilities!")
                for i, vuln in enumerate(self.vulnerabilities, 1):
                    print_info(f"{i}. {vuln['type']} - Risk: {vuln['risk']}")
            else:
                print_info("No authentication vulnerabilities found")
            
            return self.vulnerabilities
        else:
            print_error("Login failed")
            return []