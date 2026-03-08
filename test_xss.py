#!/usr/bin/env python3
"""
Test XSS module with DVWA
"""

from utils.helpers import print_banner
from core.xss_tester import XSSTester

def test_xss():
    """Test XSS detection on DVWA"""
    print_banner()
    
    print_info("Testing XSS vulnerabilities on DVWA")
    
    # Create and run XSS tester
    tester = XSSTester()
    vulnerabilities = tester.run_tests()
    
    print_success("\nXSS test completed!")

if __name__ == "__main__":
    from utils.helpers import print_info, print_success
    test_xss()