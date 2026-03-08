#!/usr/bin/env python3
"""
Test the web crawler with DVWA
"""

from utils.helpers import print_banner, print_info, print_success, print_error
from utils.crawler import WebCrawler

def test_crawler():
    """Test crawling DVWA"""
    print_banner()
    
    # Target DVWA
    target = "http://localhost/DVWA"
    print_info(f"Testing crawler on: {target}")
    
    # Create crawler instance (limit to 10 pages for quick test)
    crawler = WebCrawler(target, max_pages=10)
    
    # First login to DVWA to access protected pages
    print_info("\nLogging into DVWA first...")
    if crawler.http.login_dvwa():
        print_success("Logged in successfully!")
    else:
        print_error("Failed to login. Some pages may not be accessible.")
    
    # Run the crawler
    print_info("\nStarting crawler...")
    results = crawler.crawl()
    
    # Display results
    print_success("\n" + "="*60)
    print_success("CRAWLER TEST RESULTS")
    print_success("="*60)
    
    print_info(f"Base URL: {results['base_url']}")
    print_info(f"Pages crawled: {len(results['pages'])}")
    print_info(f"Forms found: {len(results['forms'])}")
    print_info(f"Input fields: {len(results['inputs'])}")
    print_info(f"URL parameters: {len(results['parameters'])}")
    
    # Show first few pages
    print_info("\nFirst 5 pages crawled:")
    for i, page in enumerate(results['pages'][:5]):
        print_info(f"  {i+1}. {page}")
    
    # Show forms if any
    if results['forms']:
        print_info("\nForms found:")
        for i, form in enumerate(results['forms'][:3]):  # Show first 3 forms
            print_info(f"  Form {i+1}:")
            print_info(f"    Action: {form['action']}")
            print_info(f"    Method: {form['method']}")
            print_info(f"    Inputs: {', '.join([inp['name'] for inp in form['inputs']])}")
    
    print_success("\nCrawler test completed!")

if __name__ == "__main__":
    test_crawler()