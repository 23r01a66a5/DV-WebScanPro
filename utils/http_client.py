"""
HTTP Client for DV-WebScanPro
Handles all web requests with session management
"""

import requests
from urllib.parse import urljoin, urlparse
import time
from bs4 import BeautifulSoup
from .helpers import print_warning, print_error, print_success, print_info

class HttpClient:
    """Handles HTTP requests with session management"""
    
    def __init__(self, timeout=10, retries=2):
        self.session = requests.Session()
        self.timeout = timeout
        self.retries = retries
        self.set_default_headers()
        
    def set_default_headers(self):
        """Set default headers to look like a real browser"""
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
    
    def request(self, method, url, **kwargs):
        """Make HTTP request with retry logic"""
        kwargs.setdefault('timeout', self.timeout)
        kwargs.setdefault('allow_redirects', True)
        
        for attempt in range(self.retries + 1):
            try:
                response = self.session.request(method, url, **kwargs)
                return response
            except requests.exceptions.ConnectionError:
                if attempt < self.retries:
                    time.sleep(1)
                    continue
                print_error(f"Connection error: {url}")
            except requests.exceptions.Timeout:
                if attempt < self.retries:
                    time.sleep(1)
                    continue
                print_error(f"Timeout: {url}")
            except requests.exceptions.RequestException as e:
                if attempt < self.retries:
                    time.sleep(1)
                    continue
                print_error(f"Request failed: {str(e)}")
            except Exception as e:
                print_error(f"Unexpected error: {str(e)}")
                return None
        return None
    
    def get(self, url, **kwargs):
        """GET request"""
        return self.request('GET', url, **kwargs)
    
    def post(self, url, data=None, json=None, **kwargs):
        """POST request"""
        return self.request('POST', url, data=data, json=json, **kwargs)
    
    def is_same_domain(self, url1, url2):
        """Check if two URLs are from same domain"""
        try:
            domain1 = urlparse(url1).netloc
            domain2 = urlparse(url2).netloc
            return domain1 == domain2
        except:
            return False
    
    def get_domain(self, url):
        """Extract domain from URL"""
        try:
            parsed = urlparse(url)
            return f"{parsed.scheme}://{parsed.netloc}"
        except:
            return None
    
    def extract_csrf_token(self, html):
        """Extract CSRF token from login page"""
        try:
            soup = BeautifulSoup(html, 'html.parser')
            # Look for hidden input with name 'user_token'
            token_input = soup.find('input', {'name': 'user_token'})
            if token_input:
                token = token_input.get('value', '')
                print_info(f"Found CSRF token: {token[:10]}...")
                return token
            return None
        except Exception as e:
            print_error(f"Error extracting CSRF token: {str(e)}")
            return None
    
    def login_dvwa(self, url="http://localhost/DVWA/login.php"):
        """Login to DVWA with CSRF token support"""
        print_info("Attempting to login to DVWA with CSRF token...")
        
        try:
            # Step 1: Get the login page to extract CSRF token
            print_info("Fetching login page to get CSRF token...")
            response = self.get(url)
            if not response:
                print_error("Could not access DVWA login page")
                return False
            
            # Step 2: Extract CSRF token
            csrf_token = self.extract_csrf_token(response.text)
            if not csrf_token:
                print_error("Could not find CSRF token on login page")
                return False
            
            # Step 3: Prepare login data with CSRF token
            login_data = {
                'username': 'admin',
                'password': 'password',
                'Login': 'Login',
                'user_token': csrf_token
            }
            
            print_info("Sending login request with CSRF token...")
            
            # Step 4: Send login request
            response = self.post(url, data=login_data, allow_redirects=True)
            
            if response:
                # Check if login successful (redirected to index.php)
                if 'index.php' in response.url:
                    print_success("✓✓✓ SUCCESSFULLY LOGGED INTO DVWA! ✓✓✓")
                    
                    # Verify login by checking session cookies
                    cookies = self.get_cookies()
                    print_info(f"Session cookies: {cookies}")
                    
                    # Set security level to low
                    self.set_dvwa_security('low')
                    return True
                else:
                    print_error(f"Login failed. Still on: {response.url}")
                    
                    # Check for error message
                    if 'Login failed' in response.text:
                        print_error("Login failed message detected - wrong credentials?")
                    
                    # Try one more time with a fresh token
                    print_info("Retrying with fresh token...")
                    return self.login_dvwa_retry(url)
            else:
                print_error("No response from login attempt")
                return False
                
        except Exception as e:
            print_error(f"Login error: {str(e)}")
            return False
    
    def login_dvwa_retry(self, url="http://localhost/DVWA/login.php"):
        """Retry login with fresh token"""
        try:
            # Get fresh login page
            response = self.get(url)
            if not response:
                return False
            
            # Extract new token
            csrf_token = self.extract_csrf_token(response.text)
            if not csrf_token:
                return False
            
            # Try login again
            login_data = {
                'username': 'admin',
                'password': 'password',
                'Login': 'Login',
                'user_token': csrf_token
            }
            
            response = self.post(url, data=login_data, allow_redirects=True)
            
            if response and 'index.php' in response.url:
                print_success("✓✓✓ LOGIN SUCCESSFUL ON RETRY! ✓✓✓")
                self.set_dvwa_security('low')
                return True
            
            return False
        except:
            return False
    
    def set_dvwa_security(self, level='low'):
        """Set DVWA security level"""
        try:
            security_url = "http://localhost/DVWA/security.php"
            
            # Get the security page first
            self.get(security_url)
            
            # Post the security level
            data = {
                'security': level,
                'seclev_submit': 'Submit'
            }
            
            response = self.post(security_url, data=data)
            if response:
                print_success(f"DVWA security level set to: {level}")
                return True
            return False
        except Exception as e:
            print_error(f"Failed to set security level: {str(e)}")
            return False
    
    def get_cookies(self):
        """Get current session cookies"""
        return self.session.cookies.get_dict()
    
    def clear_cookies(self):
        """Clear all cookies"""
        self.session.cookies.clear()
    
    def check_dvwa_status(self):
        """Check if DVWA is accessible and login is needed"""
        try:
            response = self.get("http://localhost/DVWA/index.php")
            if response:
                if 'login.php' in response.url:
                    print_info("DVWA requires login")
                    return 'login_required'
                elif 'index.php' in response.url:
                    print_success("DVWA is already logged in")
                    return 'logged_in'
            return 'unknown'
        except:
            return 'unreachable'"""
HTTP Client for DV-WebScanPro
Handles all web requests with session management
"""

import requests
from urllib.parse import urljoin, urlparse
import time
from bs4 import BeautifulSoup
from .helpers import print_warning, print_error, print_success, print_info

class HttpClient:
    """Handles HTTP requests with session management"""
    
    def __init__(self, timeout=10, retries=2):
        self.session = requests.Session()
        self.timeout = timeout
        self.retries = retries
        self.set_default_headers()
        
    def set_default_headers(self):
        """Set default headers to look like a real browser"""
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
    
    def request(self, method, url, **kwargs):
        """Make HTTP request with retry logic"""
        kwargs.setdefault('timeout', self.timeout)
        kwargs.setdefault('allow_redirects', True)
        
        for attempt in range(self.retries + 1):
            try:
                response = self.session.request(method, url, **kwargs)
                return response
            except requests.exceptions.ConnectionError:
                if attempt < self.retries:
                    time.sleep(1)
                    continue
                print_error(f"Connection error: {url}")
            except requests.exceptions.Timeout:
                if attempt < self.retries:
                    time.sleep(1)
                    continue
                print_error(f"Timeout: {url}")
            except requests.exceptions.RequestException as e:
                if attempt < self.retries:
                    time.sleep(1)
                    continue
                print_error(f"Request failed: {str(e)}")
            except Exception as e:
                print_error(f"Unexpected error: {str(e)}")
                return None
        return None
    
    def get(self, url, **kwargs):
        """GET request"""
        return self.request('GET', url, **kwargs)
    
    def post(self, url, data=None, json=None, **kwargs):
        """POST request"""
        return self.request('POST', url, data=data, json=json, **kwargs)
    
    def is_same_domain(self, url1, url2):
        """Check if two URLs are from same domain"""
        try:
            domain1 = urlparse(url1).netloc
            domain2 = urlparse(url2).netloc
            return domain1 == domain2
        except:
            return False
    
    def get_domain(self, url):
        """Extract domain from URL"""
        try:
            parsed = urlparse(url)
            return f"{parsed.scheme}://{parsed.netloc}"
        except:
            return None
    
    def extract_csrf_token(self, html):
        """Extract CSRF token from login page"""
        try:
            soup = BeautifulSoup(html, 'html.parser')
            # Look for hidden input with name 'user_token'
            token_input = soup.find('input', {'name': 'user_token'})
            if token_input:
                token = token_input.get('value', '')
                print_info(f"Found CSRF token: {token[:10]}...")
                return token
            return None
        except Exception as e:
            print_error(f"Error extracting CSRF token: {str(e)}")
            return None
    
    def login_dvwa(self, url="http://localhost/DVWA/login.php"):
        """Login to DVWA with CSRF token support"""
        print_info("Attempting to login to DVWA with CSRF token...")
        
        try:
            # Step 1: Get the login page to extract CSRF token
            print_info("Fetching login page to get CSRF token...")
            response = self.get(url)
            if not response:
                print_error("Could not access DVWA login page")
                return False
            
            # Step 2: Extract CSRF token
            csrf_token = self.extract_csrf_token(response.text)
            if not csrf_token:
                print_error("Could not find CSRF token on login page")
                return False
            
            # Step 3: Prepare login data with CSRF token
            login_data = {
                'username': 'admin',
                'password': 'password',
                'Login': 'Login',
                'user_token': csrf_token
            }
            
            print_info("Sending login request with CSRF token...")
            
            # Step 4: Send login request
            response = self.post(url, data=login_data, allow_redirects=True)
            
            if response:
                # Check if login successful (redirected to index.php)
                if 'index.php' in response.url:
                    print_success("✓✓✓ SUCCESSFULLY LOGGED INTO DVWA! ✓✓✓")
                    
                    # Verify login by checking session cookies
                    cookies = self.get_cookies()
                    print_info(f"Session cookies: {cookies}")
                    
                    # Set security level to low
                    self.set_dvwa_security('low')
                    return True
                else:
                    print_error(f"Login failed. Still on: {response.url}")
                    
                    # Check for error message
                    if 'Login failed' in response.text:
                        print_error("Login failed message detected - wrong credentials?")
                    
                    # Try one more time with a fresh token
                    print_info("Retrying with fresh token...")
                    return self.login_dvwa_retry(url)
            else:
                print_error("No response from login attempt")
                return False
                
        except Exception as e:
            print_error(f"Login error: {str(e)}")
            return False
    
    def login_dvwa_retry(self, url="http://localhost/DVWA/login.php"):
        """Retry login with fresh token"""
        try:
            # Get fresh login page
            response = self.get(url)
            if not response:
                return False
            
            # Extract new token
            csrf_token = self.extract_csrf_token(response.text)
            if not csrf_token:
                return False
            
            # Try login again
            login_data = {
                'username': 'admin',
                'password': 'password',
                'Login': 'Login',
                'user_token': csrf_token
            }
            
            response = self.post(url, data=login_data, allow_redirects=True)
            
            if response and 'index.php' in response.url:
                print_success("✓✓✓ LOGIN SUCCESSFUL ON RETRY! ✓✓✓")
                self.set_dvwa_security('low')
                return True
            
            return False
        except:
            return False
    
    def set_dvwa_security(self, level='low'):
        """Set DVWA security level"""
        try:
            security_url = "http://localhost/DVWA/security.php"
            
            # Get the security page first
            self.get(security_url)
            
            # Post the security level
            data = {
                'security': level,
                'seclev_submit': 'Submit'
            }
            
            response = self.post(security_url, data=data)
            if response:
                print_success(f"DVWA security level set to: {level}")
                return True
            return False
        except Exception as e:
            print_error(f"Failed to set security level: {str(e)}")
            return False
    
    def get_cookies(self):
        """Get current session cookies"""
        return self.session.cookies.get_dict()
    
    def clear_cookies(self):
        """Clear all cookies"""
        self.session.cookies.clear()
    
    def check_dvwa_status(self):
        """Check if DVWA is accessible and login is needed"""
        try:
            response = self.get("http://localhost/DVWA/index.php")
            if response:
                if 'login.php' in response.url:
                    print_info("DVWA requires login")
                    return 'login_required'
                elif 'index.php' in response.url:
                    print_success("DVWA is already logged in")
                    return 'logged_in'
            return 'unknown'
        except:
            return 'unreachable'"""
HTTP Client for DV-WebScanPro
Handles all web requests with session management
"""

import requests
from urllib.parse import urljoin, urlparse
import time
from bs4 import BeautifulSoup
from .helpers import print_warning, print_error, print_success, print_info

class HttpClient:
    """Handles HTTP requests with session management"""
    
    def __init__(self, timeout=10, retries=2):
        self.session = requests.Session()
        self.timeout = timeout
        self.retries = retries
        self.set_default_headers()
        
    def set_default_headers(self):
        """Set default headers to look like a real browser"""
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
    
    def request(self, method, url, **kwargs):
        """Make HTTP request with retry logic"""
        kwargs.setdefault('timeout', self.timeout)
        kwargs.setdefault('allow_redirects', True)
        
        for attempt in range(self.retries + 1):
            try:
                response = self.session.request(method, url, **kwargs)
                return response
            except requests.exceptions.ConnectionError:
                if attempt < self.retries:
                    time.sleep(1)
                    continue
                print_error(f"Connection error: {url}")
            except requests.exceptions.Timeout:
                if attempt < self.retries:
                    time.sleep(1)
                    continue
                print_error(f"Timeout: {url}")
            except requests.exceptions.RequestException as e:
                if attempt < self.retries:
                    time.sleep(1)
                    continue
                print_error(f"Request failed: {str(e)}")
            except Exception as e:
                print_error(f"Unexpected error: {str(e)}")
                return None
        return None
    
    def get(self, url, **kwargs):
        """GET request"""
        return self.request('GET', url, **kwargs)
    
    def post(self, url, data=None, json=None, **kwargs):
        """POST request"""
        return self.request('POST', url, data=data, json=json, **kwargs)
    
    def is_same_domain(self, url1, url2):
        """Check if two URLs are from same domain"""
        try:
            domain1 = urlparse(url1).netloc
            domain2 = urlparse(url2).netloc
            return domain1 == domain2
        except:
            return False
    
    def get_domain(self, url):
        """Extract domain from URL"""
        try:
            parsed = urlparse(url)
            return f"{parsed.scheme}://{parsed.netloc}"
        except:
            return None
    
    def extract_csrf_token(self, html):
        """Extract CSRF token from login page"""
        try:
            soup = BeautifulSoup(html, 'html.parser')
            # Look for hidden input with name 'user_token'
            token_input = soup.find('input', {'name': 'user_token'})
            if token_input:
                token = token_input.get('value', '')
                print_info(f"Found CSRF token: {token[:10]}...")
                return token
            return None
        except Exception as e:
            print_error(f"Error extracting CSRF token: {str(e)}")
            return None
    
    def login_dvwa(self, url="http://localhost/DVWA/login.php"):
        """Login to DVWA with CSRF token support"""
        print_info("Attempting to login to DVWA with CSRF token...")
        
        try:
            # Step 1: Get the login page to extract CSRF token
            print_info("Fetching login page to get CSRF token...")
            response = self.get(url)
            if not response:
                print_error("Could not access DVWA login page")
                return False
            
            # Step 2: Extract CSRF token
            csrf_token = self.extract_csrf_token(response.text)
            if not csrf_token:
                print_error("Could not find CSRF token on login page")
                return False
            
            # Step 3: Prepare login data with CSRF token
            login_data = {
                'username': 'admin',
                'password': 'password',
                'Login': 'Login',
                'user_token': csrf_token
            }
            
            print_info("Sending login request with CSRF token...")
            
            # Step 4: Send login request
            response = self.post(url, data=login_data, allow_redirects=True)
            
            if response:
                # Check if login successful (redirected to index.php)
                if 'index.php' in response.url:
                    print_success("✓✓✓ SUCCESSFULLY LOGGED INTO DVWA! ✓✓✓")
                    
                    # Verify login by checking session cookies
                    cookies = self.get_cookies()
                    print_info(f"Session cookies: {cookies}")
                    
                    # Set security level to low
                    self.set_dvwa_security('low')
                    return True
                else:
                    print_error(f"Login failed. Still on: {response.url}")
                    
                    # Check for error message
                    if 'Login failed' in response.text:
                        print_error("Login failed message detected - wrong credentials?")
                    
                    # Try one more time with a fresh token
                    print_info("Retrying with fresh token...")
                    return self.login_dvwa_retry(url)
            else:
                print_error("No response from login attempt")
                return False
                
        except Exception as e:
            print_error(f"Login error: {str(e)}")
            return False
    
    def login_dvwa_retry(self, url="http://localhost/DVWA/login.php"):
        """Retry login with fresh token"""
        try:
            # Get fresh login page
            response = self.get(url)
            if not response:
                return False
            
            # Extract new token
            csrf_token = self.extract_csrf_token(response.text)
            if not csrf_token:
                return False
            
            # Try login again
            login_data = {
                'username': 'admin',
                'password': 'password',
                'Login': 'Login',
                'user_token': csrf_token
            }
            
            response = self.post(url, data=login_data, allow_redirects=True)
            
            if response and 'index.php' in response.url:
                print_success("✓✓✓ LOGIN SUCCESSFUL ON RETRY! ✓✓✓")
                self.set_dvwa_security('low')
                return True
            
            return False
        except:
            return False
    
    def set_dvwa_security(self, level='low'):
        """Set DVWA security level"""
        try:
            security_url = "http://localhost/DVWA/security.php"
            
            # Get the security page first
            self.get(security_url)
            
            # Post the security level
            data = {
                'security': level,
                'seclev_submit': 'Submit'
            }
            
            response = self.post(security_url, data=data)
            if response:
                print_success(f"DVWA security level set to: {level}")
                return True
            return False
        except Exception as e:
            print_error(f"Failed to set security level: {str(e)}")
            return False
    
    def get_cookies(self):
        """Get current session cookies"""
        return self.session.cookies.get_dict()
    
    def clear_cookies(self):
        """Clear all cookies"""
        self.session.cookies.clear()
    
    def check_dvwa_status(self):
        """Check if DVWA is accessible and login is needed"""
        try:
            response = self.get("http://localhost/DVWA/index.php")
            if response:
                if 'login.php' in response.url:
                    print_info("DVWA requires login")
                    return 'login_required'
                elif 'index.php' in response.url:
                    print_success("DVWA is already logged in")
                    return 'logged_in'
            return 'unknown'
        except:
            return 'unreachable'"""
HTTP Client for DV-WebScanPro
Handles all web requests with session management
"""

import requests
from urllib.parse import urljoin, urlparse
import time
from bs4 import BeautifulSoup
from .helpers import print_warning, print_error, print_success, print_info

class HttpClient:
    """Handles HTTP requests with session management"""
    
    def __init__(self, timeout=10, retries=2):
        self.session = requests.Session()
        self.timeout = timeout
        self.retries = retries
        self.set_default_headers()
        
    def set_default_headers(self):
        """Set default headers to look like a real browser"""
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
    
    def request(self, method, url, **kwargs):
        """Make HTTP request with retry logic"""
        kwargs.setdefault('timeout', self.timeout)
        kwargs.setdefault('allow_redirects', True)
        
        for attempt in range(self.retries + 1):
            try:
                response = self.session.request(method, url, **kwargs)
                return response
            except requests.exceptions.ConnectionError:
                if attempt < self.retries:
                    time.sleep(1)
                    continue
                print_error(f"Connection error: {url}")
            except requests.exceptions.Timeout:
                if attempt < self.retries:
                    time.sleep(1)
                    continue
                print_error(f"Timeout: {url}")
            except requests.exceptions.RequestException as e:
                if attempt < self.retries:
                    time.sleep(1)
                    continue
                print_error(f"Request failed: {str(e)}")
            except Exception as e:
                print_error(f"Unexpected error: {str(e)}")
                return None
        return None
    
    def get(self, url, **kwargs):
        """GET request"""
        return self.request('GET', url, **kwargs)
    
    def post(self, url, data=None, json=None, **kwargs):
        """POST request"""
        return self.request('POST', url, data=data, json=json, **kwargs)
    
    def is_same_domain(self, url1, url2):
        """Check if two URLs are from same domain"""
        try:
            domain1 = urlparse(url1).netloc
            domain2 = urlparse(url2).netloc
            return domain1 == domain2
        except:
            return False
    
    def get_domain(self, url):
        """Extract domain from URL"""
        try:
            parsed = urlparse(url)
            return f"{parsed.scheme}://{parsed.netloc}"
        except:
            return None
    
    def extract_csrf_token(self, html):
        """Extract CSRF token from login page"""
        try:
            soup = BeautifulSoup(html, 'html.parser')
            # Look for hidden input with name 'user_token'
            token_input = soup.find('input', {'name': 'user_token'})
            if token_input:
                token = token_input.get('value', '')
                print_info(f"Found CSRF token: {token[:10]}...")
                return token
            return None
        except Exception as e:
            print_error(f"Error extracting CSRF token: {str(e)}")
            return None
    
    def login_dvwa(self, url="http://localhost/DVWA/login.php"):
        """Login to DVWA with CSRF token support"""
        print_info("Attempting to login to DVWA with CSRF token...")
        
        try:
            # Step 1: Get the login page to extract CSRF token
            print_info("Fetching login page to get CSRF token...")
            response = self.get(url)
            if not response:
                print_error("Could not access DVWA login page")
                return False
            
            # Step 2: Extract CSRF token
            csrf_token = self.extract_csrf_token(response.text)
            if not csrf_token:
                print_error("Could not find CSRF token on login page")
                return False
            
            # Step 3: Prepare login data with CSRF token
            login_data = {
                'username': 'admin',
                'password': 'password',
                'Login': 'Login',
                'user_token': csrf_token
            }
            
            print_info("Sending login request with CSRF token...")
            
            # Step 4: Send login request
            response = self.post(url, data=login_data, allow_redirects=True)
            
            if response:
                # Check if login successful (redirected to index.php)
                if 'index.php' in response.url:
                    print_success("✓✓✓ SUCCESSFULLY LOGGED INTO DVWA! ✓✓✓")
                    
                    # Verify login by checking session cookies
                    cookies = self.get_cookies()
                    print_info(f"Session cookies: {cookies}")
                    
                    # Set security level to low
                    self.set_dvwa_security('low')
                    return True
                else:
                    print_error(f"Login failed. Still on: {response.url}")
                    
                    # Check for error message
                    if 'Login failed' in response.text:
                        print_error("Login failed message detected - wrong credentials?")
                    
                    # Try one more time with a fresh token
                    print_info("Retrying with fresh token...")
                    return self.login_dvwa_retry(url)
            else:
                print_error("No response from login attempt")
                return False
                
        except Exception as e:
            print_error(f"Login error: {str(e)}")
            return False
    
    def login_dvwa_retry(self, url="http://localhost/DVWA/login.php"):
        """Retry login with fresh token"""
        try:
            # Get fresh login page
            response = self.get(url)
            if not response:
                return False
            
            # Extract new token
            csrf_token = self.extract_csrf_token(response.text)
            if not csrf_token:
                return False
            
            # Try login again
            login_data = {
                'username': 'admin',
                'password': 'password',
                'Login': 'Login',
                'user_token': csrf_token
            }
            
            response = self.post(url, data=login_data, allow_redirects=True)
            
            if response and 'index.php' in response.url:
                print_success("✓✓✓ LOGIN SUCCESSFUL ON RETRY! ✓✓✓")
                self.set_dvwa_security('low')
                return True
            
            return False
        except:
            return False
    
    def set_dvwa_security(self, level='low'):
        """Set DVWA security level"""
        try:
            security_url = "http://localhost/DVWA/security.php"
            
            # Get the security page first
            self.get(security_url)
            
            # Post the security level
            data = {
                'security': level,
                'seclev_submit': 'Submit'
            }
            
            response = self.post(security_url, data=data)
            if response:
                print_success(f"DVWA security level set to: {level}")
                return True
            return False
        except Exception as e:
            print_error(f"Failed to set security level: {str(e)}")
            return False
    
    def get_cookies(self):
        """Get current session cookies"""
        return self.session.cookies.get_dict()
    
    def clear_cookies(self):
        """Clear all cookies"""
        self.session.cookies.clear()
    
    def check_dvwa_status(self):
        """Check if DVWA is accessible and login is needed"""
        try:
            response = self.get("http://localhost/DVWA/index.php")
            if response:
                if 'login.php' in response.url:
                    print_info("DVWA requires login")
                    return 'login_required'
                elif 'index.php' in response.url:
                    print_success("DVWA is already logged in")
                    return 'logged_in'
            return 'unknown'
        except:
            return 'unreachable'"""
HTTP Client for DV-WebScanPro
Handles all web requests with session management
"""

import requests
from urllib.parse import urljoin, urlparse
import time
from bs4 import BeautifulSoup
from .helpers import print_warning, print_error, print_success, print_info

class HttpClient:
    """Handles HTTP requests with session management"""
    
    def __init__(self, timeout=10, retries=2):
        self.session = requests.Session()
        self.timeout = timeout
        self.retries = retries
        self.set_default_headers()
        
    def set_default_headers(self):
        """Set default headers to look like a real browser"""
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
    
    def request(self, method, url, **kwargs):
        """Make HTTP request with retry logic"""
        kwargs.setdefault('timeout', self.timeout)
        kwargs.setdefault('allow_redirects', True)
        
        for attempt in range(self.retries + 1):
            try:
                response = self.session.request(method, url, **kwargs)
                return response
            except requests.exceptions.ConnectionError:
                if attempt < self.retries:
                    time.sleep(1)
                    continue
                print_error(f"Connection error: {url}")
            except requests.exceptions.Timeout:
                if attempt < self.retries:
                    time.sleep(1)
                    continue
                print_error(f"Timeout: {url}")
            except requests.exceptions.RequestException as e:
                if attempt < self.retries:
                    time.sleep(1)
                    continue
                print_error(f"Request failed: {str(e)}")
            except Exception as e:
                print_error(f"Unexpected error: {str(e)}")
                return None
        return None
    
    def get(self, url, **kwargs):
        """GET request"""
        return self.request('GET', url, **kwargs)
    
    def post(self, url, data=None, json=None, **kwargs):
        """POST request"""
        return self.request('POST', url, data=data, json=json, **kwargs)
    
    def is_same_domain(self, url1, url2):
        """Check if two URLs are from same domain"""
        try:
            domain1 = urlparse(url1).netloc
            domain2 = urlparse(url2).netloc
            return domain1 == domain2
        except:
            return False
    
    def get_domain(self, url):
        """Extract domain from URL"""
        try:
            parsed = urlparse(url)
            return f"{parsed.scheme}://{parsed.netloc}"
        except:
            return None
    
    def extract_csrf_token(self, html):
        """Extract CSRF token from login page"""
        try:
            soup = BeautifulSoup(html, 'html.parser')
            # Look for hidden input with name 'user_token'
            token_input = soup.find('input', {'name': 'user_token'})
            if token_input:
                token = token_input.get('value', '')
                print_info(f"Found CSRF token: {token[:10]}...")
                return token
            return None
        except Exception as e:
            print_error(f"Error extracting CSRF token: {str(e)}")
            return None
    
    def login_dvwa(self, url="http://localhost/DVWA/login.php"):
        """Login to DVWA with CSRF token support"""
        print_info("Attempting to login to DVWA with CSRF token...")
        
        try:
            # Step 1: Get the login page to extract CSRF token
            print_info("Fetching login page to get CSRF token...")
            response = self.get(url)
            if not response:
                print_error("Could not access DVWA login page")
                return False
            
            # Step 2: Extract CSRF token
            csrf_token = self.extract_csrf_token(response.text)
            if not csrf_token:
                print_error("Could not find CSRF token on login page")
                return False
            
            # Step 3: Prepare login data with CSRF token
            login_data = {
                'username': 'admin',
                'password': 'password',
                'Login': 'Login',
                'user_token': csrf_token
            }
            
            print_info("Sending login request with CSRF token...")
            
            # Step 4: Send login request
            response = self.post(url, data=login_data, allow_redirects=True)
            
            if response:
                # Check if login successful (redirected to index.php)
                if 'index.php' in response.url:
                    print_success("✓✓✓ SUCCESSFULLY LOGGED INTO DVWA! ✓✓✓")
                    
                    # Verify login by checking session cookies
                    cookies = self.get_cookies()
                    print_info(f"Session cookies: {cookies}")
                    
                    # Set security level to low
                    self.set_dvwa_security('low')
                    return True
                else:
                    print_error(f"Login failed. Still on: {response.url}")
                    
                    # Check for error message
                    if 'Login failed' in response.text:
                        print_error("Login failed message detected - wrong credentials?")
                    
                    # Try one more time with a fresh token
                    print_info("Retrying with fresh token...")
                    return self.login_dvwa_retry(url)
            else:
                print_error("No response from login attempt")
                return False
                
        except Exception as e:
            print_error(f"Login error: {str(e)}")
            return False
    
    def login_dvwa_retry(self, url="http://localhost/DVWA/login.php"):
        """Retry login with fresh token"""
        try:
            # Get fresh login page
            response = self.get(url)
            if not response:
                return False
            
            # Extract new token
            csrf_token = self.extract_csrf_token(response.text)
            if not csrf_token:
                return False
            
            # Try login again
            login_data = {
                'username': 'admin',
                'password': 'password',
                'Login': 'Login',
                'user_token': csrf_token
            }
            
            response = self.post(url, data=login_data, allow_redirects=True)
            
            if response and 'index.php' in response.url:
                print_success("✓✓✓ LOGIN SUCCESSFUL ON RETRY! ✓✓✓")
                self.set_dvwa_security('low')
                return True
            
            return False
        except:
            return False
    
    def set_dvwa_security(self, level='low'):
        """Set DVWA security level"""
        try:
            security_url = "http://localhost/DVWA/security.php"
            
            # Get the security page first
            self.get(security_url)
            
            # Post the security level
            data = {
                'security': level,
                'seclev_submit': 'Submit'
            }
            
            response = self.post(security_url, data=data)
            if response:
                print_success(f"DVWA security level set to: {level}")
                return True
            return False
        except Exception as e:
            print_error(f"Failed to set security level: {str(e)}")
            return False
    
    def get_cookies(self):
        """Get current session cookies"""
        return self.session.cookies.get_dict()
    
    def clear_cookies(self):
        """Clear all cookies"""
        self.session.cookies.clear()
    
    def check_dvwa_status(self):
        """Check if DVWA is accessible and login is needed"""
        try:
            response = self.get("http://localhost/DVWA/index.php")
            if response:
                if 'login.php' in response.url:
                    print_info("DVWA requires login")
                    return 'login_required'
                elif 'index.php' in response.url:
                    print_success("DVWA is already logged in")
                    return 'logged_in'
            return 'unknown'
        except:
            return 'unreachable'