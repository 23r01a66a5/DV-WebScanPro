"""
Helper functions for DV-WebScanPro
"""

import os
import sys
from datetime import datetime
from colorama import init, Fore, Style

# Initialize colorama for colored terminal output
init(autoreset=True)

class Colors:
    """Color codes for terminal output"""
    HEADER = Fore.MAGENTA
    INFO = Fore.BLUE
    SUCCESS = Fore.GREEN
    WARNING = Fore.YELLOW
    ERROR = Fore.RED
    VULN = Fore.RED + Style.BRIGHT
    RESET = Style.RESET_ALL

def print_banner():
    """Display tool banner"""
    banner = f"""
{Colors.HEADER}╔══════════════════════════════════════════════════════════════╗
{Colors.HEADER}║     {Colors.SUCCESS}DV-WebScanPro - Web Application Security Scanner{Colors.HEADER}        ║
{Colors.HEADER}║         {Colors.WARNING}Developed for Educational Purposes{Colors.HEADER}                    ║
{Colors.HEADER}║              {Colors.INFO}Tested on DVWA - XAMPP Edition{Colors.HEADER}                      ║
{Colors.HEADER}╚══════════════════════════════════════════════════════════════╝{Colors.RESET}
    
    {Colors.INFO}Target:{Colors.RESET} OWASP Top 10 Vulnerabilities
    {Colors.INFO}Modules:{Colors.RESET} SQLi | XSS | Auth | IDOR
    """
    print(banner)

def print_info(message):
    """Print info message in blue"""
    print(f"{Colors.INFO}[*] {message}{Colors.RESET}")

def print_success(message):
    """Print success message in green"""
    print(f"{Colors.SUCCESS}[+] {message}{Colors.RESET}")

def print_warning(message):
    """Print warning message in yellow"""
    print(f"{Colors.WARNING}[!] {message}{Colors.RESET}")

def print_error(message):
    """Print error message in red"""
    print(f"{Colors.ERROR}[x] {message}{Colors.RESET}")

def print_vuln(message):
    """Print vulnerability message in bright red"""
    print(f"{Colors.VULN}[VULNERABLE] {message}{Colors.RESET}")

def ensure_dir(directory):
    """Create directory if it doesn't exist"""
    if not os.path.exists(directory):
        os.makedirs(directory)
        print_success(f"Created directory: {directory}")
        return True
    return False

def get_timestamp():
    """Get current timestamp for filenames"""
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def save_to_file(content, filename, directory="reports"):
    """Save content to a file"""
    ensure_dir(directory)
    filepath = os.path.join(directory, filename)
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        print_success(f"Saved to {filepath}")
        return filepath
    except Exception as e:
        print_error(f"Failed to save file: {str(e)}")
        return None

def read_file(filepath):
    """Read content from a file"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception as e:
        print_error(f"Failed to read file: {str(e)}")
        return None