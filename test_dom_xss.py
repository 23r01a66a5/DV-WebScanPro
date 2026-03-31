#!/usr/bin/env python3
"""
Test only DOM-based XSS
"""

from utils.helpers import print_banner, print_info
from core.xss_tester import XSSTester

def test_dom_only():
    print_banner()
    print_info("Testing ONLY DOM-based XSS")
    
    tester = XSSTester()
    if tester.login_first():
        tester.test_dom_xss()
        
        if tester.vulnerabilities:
            print_vuln(f"Found {len(tester.vulnerabilities)} DOM XSS vulnerabilities!")
            for v in tester.vulnerabilities:
                print_info(f"  - {v['payload']}")

if __name__ == "__main__":
    from utils.helpers import print_vuln
    test_dom_only()