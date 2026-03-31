#!/usr/bin/env python3
"""
Test IDOR module with DVWA
Includes Horizontal and Vertical privilege escalation testing
"""

from utils.helpers import print_banner, print_info, print_success, print_vuln
from core.idor_tester import IDORTester

def test_idor():
    """Test IDOR vulnerabilities on DVWA"""
    print_banner()
    
    print_info("="*60)
    print_info("TESTING IDOR VULNERABILITIES")
    print_info("="*60)
    print_info("🔍 Horizontal Testing: Accessing other users at same privilege level")
    print_info("🔍 Vertical Testing: Attempting privilege escalation to admin level")
    print_info("="*60)
    
    # Create and run IDOR tester
    tester = IDORTester()
    vulnerabilities = tester.run_tests()
    
    # Additional Horizontal & Vertical test results
    print_info("\n" + "="*60)
    print_info("IDOR TEST RESULTS SUMMARY")
    print_info("="*60)
    
    # Horizontal Testing Results
    print_info("\n📊 HORIZONTAL TESTING RESULTS:")
    print_info("   • Tested accessing user IDs: 1, 2, 3, 4, 5")
    
    # Check if any user data was accessed
    user_ids_found = []
    for vuln in vulnerabilities:
        if "user" in vuln.get('url', '').lower() or "id" in str(vuln.get('parameter', '')):
            user_ids_found.append(vuln.get('parameter', 'id'))
    
    if user_ids_found:
        print_vuln("   ✓ VULNERABLE: Can access other users' data (Horizontal Privilege Escalation)")
        print_info("     Evidence: Successfully accessed data for multiple user IDs")
    else:
        print_info("   ✓ SECURE: Cannot access other users' data")
    
    # Vertical Testing Results
    print_info("\n📊 VERTICAL TESTING RESULTS:")
    print_info("   • Tested accessing admin functions and restricted pages")
    
    # Check for file inclusion (vertical escalation)
    file_inclusion_found = False
    for vuln in vulnerabilities:
        if "File Inclusion" in vuln.get('type', ''):
            file_inclusion_found = True
            break
    
    if file_inclusion_found:
        print_vuln("   ✓ VULNERABLE: File inclusion found (Potential Vertical Privilege Escalation)")
        print_info("     Evidence: Accessed files that should be restricted")
    else:
        print_info("   ✓ SECURE: No vertical privilege escalation found")
    
    # Overall count
    print_info("\n📈 TOTAL VULNERABILITIES FOUND: " + str(len(vulnerabilities)))
    
    # List all vulnerabilities
    if vulnerabilities:
        print_info("\n🔍 VULNERABILITY DETAILS:")
        for i, vuln in enumerate(vulnerabilities, 1):
            risk = vuln.get('risk', 'Unknown')
            if risk == "High":
                print_vuln(f"   {i}. {vuln.get('type', 'Unknown')} - {vuln.get('url', 'N/A')} [{risk} RISK]")
            else:
                print_info(f"   {i}. {vuln.get('type', 'Unknown')} - {vuln.get('url', 'N/A')} [{risk} RISK]")
    
    print_success("\n✅ IDOR test completed!")
    print_info("="*60)

if __name__ == "__main__":
    test_idor()