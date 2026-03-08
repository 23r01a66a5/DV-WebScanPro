#!/usr/bin/env python3
"""
Test DVWA login separately
"""

from utils.helpers import print_banner, print_info, print_success, print_error, print_warning
from utils.http_client import HttpClient

def test_login():
    """Test only the login functionality"""
    print_banner()
    
    client = HttpClient()
    
    print_info("="*60)
    print_info("TESTING DVWA LOGIN")
    print_info("="*60)
    
    # First check if DVWA is reachable
    print_info("\nStep 1: Checking if DVWA is accessible...")
    try:
        response = client.get("http://localhost/DVWA/")
        if response and response.status_code == 200:
            print_success("DVWA is accessible!")
        else:
            print_error("Cannot access DVWA. Make sure XAMPP is running.")
            print_info("Try opening http://localhost/DVWA/ in your browser")
            return
    except Exception as e:
        print_error(f"Error accessing DVWA: {str(e)}")
        return
    
    # Check login status
    print_info("\nStep 2: Checking login status...")
    status = client.check_dvwa_status()
    print_info(f"Status: {status}")
    
    # Try to login
    print_info("\nStep 3: Attempting to login...")
    if client.login_dvwa():
        print_success("\n✓✓✓ LOGIN SUCCESSFUL! ✓✓✓")
        print_info(f"Cookies: {client.get_cookies()}")
        
        # Try to access a protected page
        print_info("\nStep 4: Testing access to protected page...")
        response = client.get("http://localhost/DVWA/vulnerabilities/sqli/")
        if response and response.status_code == 200:
            print_success("Successfully accessed SQLi page!")
            if 'Surname' in response.text:
                print_success("Found SQL injection form - Ready for testing!")
            else:
                print_warning("Page loaded but SQL form not found")
        else:
            print_error("Could not access SQLi page")
    else:
        print_error("\n✗✗✗ LOGIN FAILED ✗✗✗")
        
        # Manual troubleshooting instructions
        print_info("\n" + "="*60)
        print_info("TROUBLESHOOTING STEPS")
        print_info("="*60)
        print_info("1. Open your browser and go to: http://localhost/DVWA/setup.php")
        print_info("2. Click 'Create/Reset Database' button at the bottom")
        print_info("3. Then go to: http://localhost/DVWA/login.php")
        print_info("4. Try to login manually with:")
        print_info("   Username: admin")
        print_info("   Password: password")
        print_info("5. If manual login works but script doesn't, check:")
        print_info("   - Is XAMPP running? (Apache & MySQL)")
        print_info("   - Any firewall blocking?")
        print_info("   - Try accessing http://127.0.0.1/DVWA/ instead of localhost")

if __name__ == "__main__":
    test_login()#!/usr/bin/env python3
"""
Test DVWA login separately
"""

from utils.helpers import print_banner, print_info, print_success, print_error, print_warning
from utils.http_client import HttpClient

def test_login():
    """Test only the login functionality"""
    print_banner()
    
    client = HttpClient()
    
    print_info("="*60)
    print_info("TESTING DVWA LOGIN")
    print_info("="*60)
    
    # First check if DVWA is reachable
    print_info("\nStep 1: Checking if DVWA is accessible...")
    try:
        response = client.get("http://localhost/DVWA/")
        if response and response.status_code == 200:
            print_success("DVWA is accessible!")
        else:
            print_error("Cannot access DVWA. Make sure XAMPP is running.")
            print_info("Try opening http://localhost/DVWA/ in your browser")
            return
    except Exception as e:
        print_error(f"Error accessing DVWA: {str(e)}")
        return
    
    # Check login status
    print_info("\nStep 2: Checking login status...")
    status = client.check_dvwa_status()
    print_info(f"Status: {status}")
    
    # Try to login
    print_info("\nStep 3: Attempting to login...")
    if client.login_dvwa():
        print_success("\n✓✓✓ LOGIN SUCCESSFUL! ✓✓✓")
        print_info(f"Cookies: {client.get_cookies()}")
        
        # Try to access a protected page
        print_info("\nStep 4: Testing access to protected page...")
        response = client.get("http://localhost/DVWA/vulnerabilities/sqli/")
        if response and response.status_code == 200:
            print_success("Successfully accessed SQLi page!")
            if 'Surname' in response.text:
                print_success("Found SQL injection form - Ready for testing!")
            else:
                print_warning("Page loaded but SQL form not found")
        else:
            print_error("Could not access SQLi page")
    else:
        print_error("\n✗✗✗ LOGIN FAILED ✗✗✗")
        
        # Manual troubleshooting instructions
        print_info("\n" + "="*60)
        print_info("TROUBLESHOOTING STEPS")
        print_info("="*60)
        print_info("1. Open your browser and go to: http://localhost/DVWA/setup.php")
        print_info("2. Click 'Create/Reset Database' button at the bottom")
        print_info("3. Then go to: http://localhost/DVWA/login.php")
        print_info("4. Try to login manually with:")
        print_info("   Username: admin")
        print_info("   Password: password")
        print_info("5. If manual login works but script doesn't, check:")
        print_info("   - Is XAMPP running? (Apache & MySQL)")
        print_info("   - Any firewall blocking?")
        print_info("   - Try accessing http://127.0.0.1/DVWA/ instead of localhost")

if __name__ == "__main__":
    test_login()#!/usr/bin/env python3
"""
Test DVWA login separately
"""

from utils.helpers import print_banner, print_info, print_success, print_error, print_warning
from utils.http_client import HttpClient

def test_login():
    """Test only the login functionality"""
    print_banner()
    
    client = HttpClient()
    
    print_info("="*60)
    print_info("TESTING DVWA LOGIN")
    print_info("="*60)
    
    # First check if DVWA is reachable
    print_info("\nStep 1: Checking if DVWA is accessible...")
    try:
        response = client.get("http://localhost/DVWA/")
        if response and response.status_code == 200:
            print_success("DVWA is accessible!")
        else:
            print_error("Cannot access DVWA. Make sure XAMPP is running.")
            print_info("Try opening http://localhost/DVWA/ in your browser")
            return
    except Exception as e:
        print_error(f"Error accessing DVWA: {str(e)}")
        return
    
    # Check login status
    print_info("\nStep 2: Checking login status...")
    status = client.check_dvwa_status()
    print_info(f"Status: {status}")
    
    # Try to login
    print_info("\nStep 3: Attempting to login...")
    if client.login_dvwa():
        print_success("\n✓✓✓ LOGIN SUCCESSFUL! ✓✓✓")
        print_info(f"Cookies: {client.get_cookies()}")
        
        # Try to access a protected page
        print_info("\nStep 4: Testing access to protected page...")
        response = client.get("http://localhost/DVWA/vulnerabilities/sqli/")
        if response and response.status_code == 200:
            print_success("Successfully accessed SQLi page!")
            if 'Surname' in response.text:
                print_success("Found SQL injection form - Ready for testing!")
            else:
                print_warning("Page loaded but SQL form not found")
        else:
            print_error("Could not access SQLi page")
    else:
        print_error("\n✗✗✗ LOGIN FAILED ✗✗✗")
        
        # Manual troubleshooting instructions
        print_info("\n" + "="*60)
        print_info("TROUBLESHOOTING STEPS")
        print_info("="*60)
        print_info("1. Open your browser and go to: http://localhost/DVWA/setup.php")
        print_info("2. Click 'Create/Reset Database' button at the bottom")
        print_info("3. Then go to: http://localhost/DVWA/login.php")
        print_info("4. Try to login manually with:")
        print_info("   Username: admin")
        print_info("   Password: password")
        print_info("5. If manual login works but script doesn't, check:")
        print_info("   - Is XAMPP running? (Apache & MySQL)")
        print_info("   - Any firewall blocking?")
        print_info("   - Try accessing http://127.0.0.1/DVWA/ instead of localhost")

if __name__ == "__main__":
    test_login()