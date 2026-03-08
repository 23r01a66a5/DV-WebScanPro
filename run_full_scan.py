#!/usr/bin/env python3
"""
Full security scan of DVWA using all modules
Generates comprehensive HTML report
"""

from utils.helpers import print_banner, print_info, print_success, print_error, get_timestamp
from core.simple_sqli import SimpleSQLiTester
from core.xss_tester import XSSTester
from core.auth_tester import AuthTester
from core.idor_tester import IDORTester
from core.reporter import ReportGenerator

def run_full_scan():
    """Run all security tests and generate report"""
    print_banner()
    
    target = "http://localhost/DVWA"
    scan_id = get_timestamp()
    
    print_info("="*60)
    print_info(f"STARTING FULL SECURITY SCAN")
    print_info(f"Target: {target}")
    print_info(f"Scan ID: {scan_id}")
    print_info("="*60)
    
    # Initialize report generator
    report = ReportGenerator(target, scan_id)
    
    # Test 1: SQL Injection
    print_info("\n" + "="*60)
    print_info("MODULE 1: SQL INJECTION TESTING")
    print_info("="*60)
    sqli_tester = SimpleSQLiTester()
    sqli_vulns = sqli_tester.run_tests()
    report.add_vulnerabilities(sqli_vulns)
    
    # Test 2: XSS
    print_info("\n" + "="*60)
    print_info("MODULE 2: XSS TESTING")
    print_info("="*60)
    xss_tester = XSSTester()
    xss_vulns = xss_tester.run_tests()
    report.add_vulnerabilities(xss_vulns)
    
    # Test 3: Authentication
    print_info("\n" + "="*60)
    print_info("MODULE 3: AUTHENTICATION TESTING")
    print_info("="*60)
    auth_tester = AuthTester()
    auth_vulns = auth_tester.run_tests()
    report.add_vulnerabilities(auth_vulns)
    
    # Test 4: IDOR
    print_info("\n" + "="*60)
    print_info("MODULE 4: IDOR TESTING")
    print_info("="*60)
    idor_tester = IDORTester()
    idor_vulns = idor_tester.run_tests()
    report.add_vulnerabilities(idor_vulns)
    
    # Generate final report
    print_info("\n" + "="*60)
    print_info("GENERATING FINAL REPORT")
    print_info("="*60)
    
    report_file = report.save_report()
    
    # Print summary
    print_success("\n" + "="*60)
    print_success("SCAN COMPLETE - SUMMARY")
    print_success("="*60)
    print_success(f"Total vulnerabilities found: {len(report.vulnerabilities)}")
    
    risk_counts = report.count_by_risk()
    print_info(f"  High Risk: {risk_counts['High']}")
    print_info(f"  Medium Risk: {risk_counts['Medium']}")
    print_info(f"  Low Risk: {risk_counts['Low']}")
    
    print_success(f"\nReport saved to: {report_file}")
    print_success("Open this file in your browser to view the results!")

if __name__ == "__main__":
    run_full_scan()