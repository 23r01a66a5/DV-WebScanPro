#!/usr/bin/env python3
"""
Test HTTP client with DVWA
"""

from utils.helpers import print_banner, print_info, print_success, print_error
from utils.http_client import HttpClient

def test_dvwa_connection():
    """Test connecting to DVWA"""
    print_banner()
    
    # Create HTTP client
    client = HttpClient()
    
    # Test 1: Check if DVWA is accessible
    print_info("Test 1: Checking if DVWA is accessible...")
    response = client.get("http://localhost/DVWA")
    
    if response and response.status_code == 200:
        print_success("DVWA is accessible!")
        print_info(f"Status code: {response.status_code}")
        print_info(f"Page title: {response.text.split('<title>')[1].split('</title>')[0] if '<title>' in response.text else 'Not found'}")
    else:
        print_error("Cannot access DVWA. Make sure XAMPP is running.")
        return
    
    # Test 2: Try to login
    print_info("\nTest 2: Attempting to login to DVWA...")
    if client.login_dvwa():
        print_success("Login successful!")
        print_info(f"Cookies: {client.get_cookies()}")
    else:
        print_error("Login failed")
    
    # Test 3: Access a protected page
    print_info("\nTest 3: Accessing a protected page...")
    response = client.get("http://localhost/DVWA/vulnerabilities/sqli/")
    if response and response.status_code == 200:
        print_success("Successfully accessed SQLi page!")
        if 'Surname' in response.text:
            print_success("Found SQL injection test form")
    else:
        print_error("Could not access SQLi page")
    
    print_success("\nHTTP Client tests completed!")

if __name__ == "__main__":
    test_dvwa_connection()