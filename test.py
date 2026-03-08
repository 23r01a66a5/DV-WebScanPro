#!/usr/bin/env python3
"""
Test script for DV-WebScanPro helpers
"""

from utils.helpers import (
    print_banner, print_info, print_success, 
    print_warning, print_error, print_vuln,
    ensure_dir, get_timestamp, save_to_file
)

# Test the banner
print_banner()

# Test different message types
print_info("This is an info message")
print_success("This is a success message") 
print_warning("This is a warning message")
print_error("This is an error message")
print_vuln("This is a vulnerability message")

# Test directory creation
ensure_dir("test_folder")

# Test timestamp
timestamp = get_timestamp()
print_info(f"Current timestamp: {timestamp}")

# Test file saving
save_to_file("This is a test", f"test_{timestamp}.txt", "test_folder")

print_success("All tests completed!")