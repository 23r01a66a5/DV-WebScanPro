#!/usr/bin/env python3
"""
Test SQL Injection module with DVWA - SIMPLE VERSION
"""

from utils.helpers import print_banner, print_info, print_success, print_error
from core.simple_sqli import SimpleSQLiTester

def test_sqli():
    """Test SQL injection detection on DVWA"""
    print_banner()
    
    print_info("Testing SQL injection on DVWA")
    print_info("Using simple, proven method")
    
    # Create and run the simple tester
    tester = SimpleSQLiTester()
    vulnerabilities = tester.run_tests()
    
    print_success("\nTest completed!")

if __name__ == "__main__":
    test_sqli()