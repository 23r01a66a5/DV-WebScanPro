#!/usr/bin/env python3
"""
Test IDOR module with DVWA
"""

from utils.helpers import print_banner, print_info, print_success
from core.idor_tester import IDORTester

def test_idor():
    """Test IDOR vulnerabilities on DVWA"""
    print_banner()
    
    print_info("Testing IDOR vulnerabilities on DVWA")
    
    # Create and run IDOR tester
    tester = IDORTester()
    vulnerabilities = tester.run_tests()
    
    print_success("\nIDOR test completed!")

if __name__ == "__main__":
    test_idor()