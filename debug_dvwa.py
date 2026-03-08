#!/usr/bin/env python3
"""
Debug DVWA connection and login
"""

import requests
from bs4 import BeautifulSoup

print("="*60)
print("DVWA DEBUGGING TOOL")
print("="*60)

# Test 1: Basic connection
print("\n[1] Testing connection to localhost...")
try:
    r = requests.get("http://localhost", timeout=5)
    print(f"✓ Localhost responded with status: {r.status_code}")
    print(f"  Page title: {r.text.split('<title>')[1].split('</title>')[0] if '<title>' in r.text else 'No title'}")
except Exception as e:
    print(f"✗ Failed: {e}")

# Test 2: DVWA homepage
print("\n[2] Testing DVWA homepage...")
try:
    r = requests.get("http://localhost/DVWA/", timeout=5)
    print(f"✓ DVWA responded with status: {r.status_code}")
    print(f"  Page title: {r.text.split('<title>')[1].split('</title>')[0] if '<title>' in r.text else 'No title'}")
    print(f"  URL after redirect: {r.url}")
except Exception as e:
    print(f"✗ Failed: {e}")

# Test 3: DVWA login page
print("\n[3] Checking login page...")
try:
    r = requests.get("http://localhost/DVWA/login.php", timeout=5)
    print(f"✓ Login page status: {r.status_code}")
    
    # Parse the form
    soup = BeautifulSoup(r.text, 'html.parser')
    form = soup.find('form')
    if form:
        print(f"  Found form with action: {form.get('action', 'N/A')}")
        print(f"  Form method: {form.get('method', 'N/A')}")
        
        # Find all input fields
        inputs = form.find_all('input')
        print(f"  Found {len(inputs)} input fields:")
        for i, inp in enumerate(inputs):
            name = inp.get('name', 'NO_NAME')
            type_ = inp.get('type', 'text')
            print(f"    {i+1}. name='{name}', type='{type_}'")
    else:
        print("  No form found on login page!")
        
except Exception as e:
    print(f"✗ Failed: {e}")

# Test 4: Try direct login
print("\n[4] Attempting direct login...")
session = requests.Session()

# Try different login combinations
login_attempts = [
    {'username': 'admin', 'password': 'password', 'Login': 'Login'},
    {'username': 'admin', 'password': 'password', 'login': 'Login'},
    {'user': 'admin', 'pass': 'password', 'submit': 'Login'},
]

for i, login_data in enumerate(login_attempts, 1):
    print(f"\n  Attempt {i} with data: {login_data}")
    try:
        r = session.post("http://localhost/DVWA/login.php", data=login_data, allow_redirects=True)
        print(f"    Response status: {r.status_code}")
        print(f"    Final URL: {r.url}")
        
        if 'index.php' in r.url:
            print("    ✓✓✓ LOGIN SUCCESSFUL! ✓✓✓")
            print(f"    Cookies: {session.cookies.get_dict()}")
            break
        else:
            print("    ✗ Login failed - still on login page")
    except Exception as e:
        print(f"    ✗ Error: {e}")

print("\n" + "="*60)
print("DEBUGGING COMPLETE")
print("="*60)