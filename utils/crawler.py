"""
Web Crawler for DV-WebScanPro
Discovers pages, forms, and input fields on target website
"""

from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from collections import deque
import re
from .http_client import HttpClient
from .helpers import print_info, print_success, print_warning, print_error

class WebCrawler:
    """Crawls website to discover pages, forms, and inputs"""
    
    def __init__(self, base_url, max_pages=30):
        self.base_url = base_url.rstrip('/')
        self.max_pages = max_pages
        self.http = HttpClient()
        self.visited = set()
        self.to_visit = deque([base_url + '/', base_url + '/index.php'])  # Add both
        self.results = {
            'base_url': base_url,
            'pages': [],
            'forms': [],
            'inputs': [],
            'parameters': []
        }
        
    def normalize_url(self, url):
        """Normalize URL to avoid duplicates"""
        try:
            parsed = urlparse(url)
            # Remove fragments and normalize path
            path = parsed.path.rstrip('/') or '/'
            query = '?' + parsed.query if parsed.query else ''
            return f"{parsed.scheme}://{parsed.netloc}{path}{query}"
        except:
            return url
    
    def is_same_domain(self, url):
        """Check if URL belongs to same domain as base_url"""
        try:
            base_domain = urlparse(self.base_url).netloc
            url_domain = urlparse(url).netloc
            return base_domain == url_domain
        except:
            return False
    
    def is_within_dvwa(self, url):
        """Check if URL is within DVWA directory"""
        try:
            # Only crawl URLs that start with the base URL
            return url.startswith(self.base_url)
        except:
            return False
    
    def extract_forms(self, url, html):
        """Extract all forms from HTML"""
        soup = BeautifulSoup(html, 'html.parser')
        forms_found = []
        
        for form in soup.find_all('form'):
            form_info = {
                'page_url': url,
                'action': urljoin(url, form.get('action', '')),
                'method': form.get('method', 'get').upper(),
                'inputs': []
            }
            
            # Extract all input fields
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_name = input_tag.get('name')
                if input_name:  # Only add if has name attribute
                    input_info = {
                        'name': input_name,
                        'type': input_tag.get('type', 'text'),
                        'value': input_tag.get('value', '')
                    }
                    form_info['inputs'].append(input_info)
                    
                    # Also add to global inputs list
                    self.results['inputs'].append({
                        'url': url,
                        'form_action': form_info['action'],
                        'name': input_name,
                        'type': input_info['type'],
                        'method': form_info['method']
                    })
            
            # Only add forms that have inputs
            if form_info['inputs']:
                forms_found.append(form_info)
                self.results['forms'].append(form_info)
        
        return forms_found
    
    def extract_links(self, url, html):
        """Extract all links from HTML - IMPROVED VERSION"""
        soup = BeautifulSoup(html, 'html.parser')
        links = []
        
        # Find all links
        for link in soup.find_all('a', href=True):
            href = link['href']
            absolute_url = urljoin(url, href)
            
            # Only follow links within DVWA
            if self.is_within_dvwa(absolute_url):
                normalized = self.normalize_url(absolute_url)
                
                # Skip logout and other unwanted pages
                skip_patterns = ['.jpg', '.jpeg', '.png', '.gif', '.css', '.js', '.pdf', '.doc', '.zip', 'logout.php']
                should_skip = False
                for pattern in skip_patterns:
                    if pattern in normalized.lower():
                        should_skip = True
                        break
                
                if not should_skip:
                    if normalized not in self.visited and normalized not in self.to_visit:
                        links.append(normalized)
                        print_info(f"    Found link: {normalized}")
        
        return links
    
    def extract_parameters(self, url):
        """Extract parameters from URL query string"""
        parsed = urlparse(url)
        if parsed.query:
            # Parse query parameters
            params = re.findall(r'[?&]([^=]+)=', url)
            for param in params:
                param_info = {
                    'url': self.normalize_url(url.split('?')[0]),
                    'parameter': param,
                    'full_url': url
                }
                
                # Check if already added
                exists = False
                for existing in self.results['parameters']:
                    if existing['url'] == param_info['url'] and existing['parameter'] == param:
                        exists = True
                        break
                
                if not exists:
                    self.results['parameters'].append(param_info)
            
            return params
        return []
    
    def is_login_page(self, url, html):
        """Check if page is a login page"""
        login_indicators = ['login', 'signin', 'log in', 'sign in', 'username', 'password']
        url_lower = url.lower()
        html_lower = html.lower()
        
        for indicator in login_indicators:
            if indicator in url_lower or indicator in html_lower:
                return True
        return False
    
    def crawl(self):
        """Main crawling function - IMPROVED VERSION"""
        print_info(f"Starting crawl of {self.base_url}")
        print_info(f"Max pages to crawl: {self.max_pages}")
        print_info(f"Staying within: {self.base_url}")
        
        pages_crawled = 0
        
        # First, make sure we're logged in by visiting the homepage
        print_info("Ensuring we're logged in...")
        self.http.get(self.base_url + '/index.php')
        
        while self.to_visit and pages_crawled < self.max_pages:
            url = self.to_visit.popleft()
            normalized_url = self.normalize_url(url)
            
            if normalized_url in self.visited:
                continue
            
            # Skip if not within DVWA
            if not self.is_within_dvwa(normalized_url):
                print_info(f"Skipping (outside DVWA): {url}")
                continue
            
            print_info(f"Crawling ({pages_crawled + 1}/{self.max_pages}): {url}")
            
            response = self.http.get(url)
            if response and response.status_code == 200:
                self.visited.add(normalized_url)
                self.results['pages'].append(normalized_url)
                pages_crawled += 1
                
                # Check if HTML content
                content_type = response.headers.get('Content-Type', '')
                if 'text/html' in content_type:
                    # Check if it's a login page
                    if self.is_login_page(url, response.text):
                        self.results['is_login'] = True
                        self.results['login_url'] = url
                        print_success(f"  Found login page: {url}")
                    
                    # Extract forms
                    forms = self.extract_forms(url, response.text)
                    if forms:
                        print_success(f"  Found {len(forms)} form(s) on this page")
                        
                        # Print form details
                        for form in forms:
                            print_info(f"    Form action: {form['action']}")
                            print_info(f"    Method: {form['method']}")
                            print_info(f"    Inputs: {[i['name'] for i in form['inputs']]}")
                    
                    # Extract links for further crawling
                    new_links = self.extract_links(url, response.text)
                    if new_links:
                        print_info(f"  Found {len(new_links)} new links to crawl")
                        self.to_visit.extend(new_links)
                    
                    # Extract URL parameters
                    params = self.extract_parameters(url)
                    if params:
                        print_success(f"  Found URL parameters: {params}")
                else:
                    print_info(f"  Skipping non-HTML content: {content_type}")
            else:
                print_warning(f"  Failed to crawl {url} (Status: {response.status_code if response else 'No response'})")
        
        # If we didn't find many pages, try adding common DVWA paths manually
        if len(self.results['pages']) < 3:
            print_info("Adding common DVWA paths manually...")
            common_paths = [
                '/vulnerabilities/sqli/',
                '/vulnerabilities/sqli_blind/',
                '/vulnerabilities/xss_r/',
                '/vulnerabilities/xss_s/',
                '/vulnerabilities/brute/',
                '/vulnerabilities/exec/',
                '/vulnerabilities/csrf/',
                '/vulnerabilities/fi/',
                '/vulnerabilities/upload/',
            ]
            
            for path in common_paths:
                test_url = self.base_url + path
                if test_url not in self.visited:
                    print_info(f"Testing: {test_url}")
                    response = self.http.get(test_url)
                    if response and response.status_code == 200:
                        self.visited.add(test_url)
                        self.results['pages'].append(test_url)
                        print_success(f"  Found page: {test_url}")
                        
                        # Check for forms on this page
                        if 'text/html' in response.headers.get('Content-Type', ''):
                            forms = self.extract_forms(test_url, response.text)
                            if forms:
                                print_success(f"  Found {len(forms)} form(s) on this page")
        
        # Print summary
        print_success("\n" + "="*60)
        print_success("CRAWLING COMPLETE - SUMMARY")
        print_success("="*60)
        print_success(f"Total pages crawled: {len(self.results['pages'])}")
        print_success(f"Total forms found: {len(self.results['forms'])}")
        print_success(f"Total input fields: {len(self.results['inputs'])}")
        print_success(f"Total URL parameters: {len(self.results['parameters'])}")
        
        # List all pages found
        print_info("\nPages found:")
        for page in self.results['pages']:
            print_info(f"  - {page}")
        
        return self.results
    
    def get_target_metadata(self):
        """Return structured target metadata for testing modules"""
        return self.results