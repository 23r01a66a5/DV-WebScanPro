#!/usr/bin/env python3
"""
Test Authentication module with DVWA
"""

from utils.helpers import print_banner, print_info, print_success
from core.auth_tester import AuthTester

def test_auth():
    """Test authentication vulnerabilities on DVWA"""
    print_banner()
    
    print_info("Testing Authentication vulnerabilities on DVWA")
    
    # Create and run auth tester
    tester = AuthTester()
    vulnerabilities = tester.run_tests()
    
    print_success("\nAuthentication test completed!")

if __name__ == "__main__":
    test_auth()