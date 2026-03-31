
# **DV-WebScanPro**
## **What is WebScanPro?**

WebScanPro is an automated security testing tool I developed that simulates real-world hacker attacks on web applications. Instead of manually testing each vulnerability one by one, the tool handles everything automatically — logging into the target, discovering all pages and forms, injecting attack payloads, analyzing responses, and generating a comprehensive security report.

---

## **The Problem It Solves**

Manual security testing is extremely time-consuming. A tester must discover every page on a website, identify all input fields, test different attack vectors on each field, document successful exploits, and write remediation recommendations. This process can take days or weeks and is prone to human error. WebScanPro automates this entire workflow, completing in minutes what would take a security professional hours or days to do manually.

---

## **Testing Environment — DVWA**

I tested WebScanPro on DVWA (Damn Vulnerable Web Application), a deliberately insecure web application designed for security training. DVWA contains known vulnerabilities across multiple categories including SQL injection, XSS, command injection, and broken authentication. I installed it locally using XAMPP — starting Apache and MySQL services, downloading DVWA to the htdocs folder, running the setup script to create the database, and logging in with the default credentials (admin:password). The security level was set to "low" to ensure all vulnerabilities were exposed for testing.

---

## **Project Architecture**

The tool follows a modular pipeline architecture:

**Core Modules:**
- `sqli_tester.py` — Handles all SQL injection detection
- `xss_tester.py` — Tests for cross-site scripting vulnerabilities
- `auth_tester.py` — Evaluates authentication and session security
- `idor_tester.py` — Checks for access control flaws
- `reporter.py` — Compiles findings into an HTML report

**Utility Modules:**
- `crawler.py` — Discovers all pages, forms, and input fields
- `http_client.py` — Manages HTTP sessions, cookies, and authentication
- `helpers.py` — Provides colored console output and file utilities

**Test Runners:**
- Separate test files for each module that can be run independently
- `run_full_scan.py` — Orchestrates the complete testing workflow

---

## **The Complete Workflow**

### **Phase 1: Target Discovery**

The process begins when I provide the target URL. The `http_client` establishes a session and handles DVWA's CSRF protection by extracting the `user_token` from the login page before submitting credentials. Once authenticated, the `crawler` starts at the homepage and recursively follows all links, parsing each page with BeautifulSoup to extract forms, input fields, and URL parameters. It records every form's action URL, HTTP method, and all input names and types. This discovery phase creates a complete map of the application's attack surface, which is stored as JSON metadata and passed to all testing modules.

### **Phase 2: SQL Injection Testing**

The SQL injection module reads the discovered forms and tests each input field using multiple detection techniques. For error-based detection, it injects a single quote `'` and watches for database error messages like "mysql_error" or "syntax error" in the response. For union-based detection, it injects `' UNION SELECT user,password FROM users--` and checks if the response contains extracted data like "First name:" or "Surname:". For time-based blind injection, it uses `' OR SLEEP(5)--` and measures response time — a delay of 4+ seconds confirms the vulnerability. For boolean-based detection, it compares responses between `' AND 1=1--` and `' AND 1=2--` to detect differences in returned content. Each successful injection is recorded with the payload used, the parameter exploited, and the evidence collected.

### **Phase 3: Cross-Site Scripting Testing**

The XSS module tests for three distinct types of injection attacks. For reflected XSS, it injects payloads like `<script>alert('XSS')</script>` into URL parameters and checks if the payload appears unmodified in the response. For stored XSS, it submits the same payloads to forms like the guestbook and verifies if they persist and display to subsequent visitors. For DOM-based XSS, it appends payloads like `#<script>alert('XSS')</script>` to the URL and checks if the page's JavaScript reads from the URL hash and writes it to the DOM unsafely. The module maintains a library of 7 payloads designed to bypass common filters, including mixed-case variations and event handler injections.

### **Phase 4: Authentication Security Testing**

The authentication module performs four distinct security checks. First, it attempts login with a dictionary of 10 common weak credentials like admin/admin and admin/password. Second, it analyzes session cookies for missing security flags — specifically checking if the `Secure` flag (prevents transmission over HTTP) and `HttpOnly` flag (prevents JavaScript access) are present. Third, it tests for session fixation by comparing the session ID before and after login — a secure application regenerates the session ID upon authentication, while a vulnerable one keeps the same ID. Fourth, it tests brute force protection by making multiple failed login attempts and checking if the application implements account lockout or rate limiting. Each vulnerability is logged with its risk level and evidence.

### **Phase 5: IDOR and Access Control Testing**

The IDOR module tests horizontal and vertical privilege escalation. For horizontal testing, it modifies URL parameters like `?id=1` to access other users' data by trying values 2 through 5 and checking if the response contains user information that shouldn't be accessible. For vertical testing, it attempts to access admin-only pages like `/setup.php` and `/security.php` directly. It also tests file inclusion vulnerabilities by manipulating the `page` parameter to access restricted files like `file1.php` and attempting path traversal with `../../../../etc/passwd`. Any successful access to unauthorized resources is flagged as an IDOR vulnerability.

### **Phase 6: Report Generation**

The final phase compiles all findings from the four testing modules into a professional HTML report. The report generator collects vulnerabilities from each module, counts them by risk level (High/Medium/Low), and organizes them by type. For each vulnerability, it displays the URL, the parameter or input field, the exact payload used, the evidence of exploitation, and specific remediation recommendations. The report uses color-coded risk badges and a clean, professional layout. A critical security measure was implemented — all user-supplied payloads are escaped before being written to the HTML to prevent the report itself from executing JavaScript code. This ensures that when I open the report, I see the payloads as text rather than having them run as actual scripts.

---

## **Installation and Execution**

The tool requires Python 3.7+ and two core libraries — `requests` for HTTP communication and `beautifulsoup4` for HTML parsing. After installing dependencies with `pip install -r requirements.txt`, I activate the virtual environment and run `python run_full_scan.py`. This single command executes the entire pipeline — logging in, crawling, running all four test modules sequentially, and generating the final report in the `reports` folder.

---

## **Results Achieved**

The tool successfully identified 11 vulnerabilities across all tested categories:

- **SQL Injection:** 5 vulnerabilities including error-based and time-based types. The payload `1' OR '1'='1` successfully extracted all user data including admin credentials.

- **XSS:** 2 DOM-based XSS vulnerabilities found using `#<script>alert('XSS')</script>` and `javascript:alert('XSS')` payloads.

- **Authentication:** 3 vulnerabilities — weak credentials (`admin:password`), insecure session cookies missing Secure and HttpOnly flags, and no brute force protection allowing unlimited login attempts.

- **IDOR:** 1 file inclusion vulnerability allowing access to restricted files through parameter manipulation.

---

## **Key Learnings**

Developing WebScanPro taught me several important lessons about web application security. Understanding SQL injection became tangible when I saw actual MySQL error messages appearing in the terminal after injecting a single quote. Session fixation made sense when I printed the session IDs before and after login and saw they were identical — confirming the application didn't regenerate tokens. Perhaps most memorably, when I first generated the HTML report, the XSS payloads executed in my own browser, popping up alert boxes. This reinforced the critical importance of output encoding — the same lesson applies whether you're securing a web application or generating security reports.

The modular architecture proved valuable throughout development. Because each test module reads from the same discovered data and writes findings in a consistent JSON format, adding new vulnerability tests doesn't require modifying existing modules. This pipeline design makes the tool extensible — new security checks can be added as independent modules without disrupting the core workflow.
