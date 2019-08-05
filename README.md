<h2 align="center">:skull: <br> <br>Web Vulnerabilities Checklist<br><h4 align="center"><a href="https://www.linkedin.com/in/shubhampy" style="text-decoration:none;">:zap: @nullb0t :zap:</a></h4>

#### Recon & Source Code Analysis
- [x] Dynamic Analysis of Web Application Source Code
- [x] Dynamic Analysis of Complete JavaScript Source
- [x] Enumeration of Publicly Accessible Cloud Storage
- [x] Common Crawling & Sensitive Directory Enumeration
- [x] Manual & Automated Subdomain Analysis | Discovery
- [x] Identifying & Testing for Subdomain Takeover Issues
#### Information gathering part
- [x] Fingerprint Web Server - `Find the version and type of a running web server to determine known vulnerabilities and the appropriate exploits.Using "HTTP header field ordering" and "Malformed requests test"`.
- [x] Review Webserver Metafiles for Information Leakage - `Analyze robots.txt and identify Tags from website.`
- [x] Enumerate Applications on Webserver- `Find applications hosted in the webserver (Virtual hosts/Subdomain), non-standard ports.`
- [x] Find sensitive information `from webpage comments and Metadata on source code.`
- [x] Map the target application and understand the principal workflows.
- [x] Find the type of web application framework/CMS - `Identify application architecture including Web language, WAF, Reverse proxy, Application Server, Backend Database.`
- [x] Identify HTTP allowed methods on Web server` with OPTIONS. Arbitrary HTTP Methods, HEAD access control bypass and XST.`
- [x] Check JS source code, comments, cache file, backup file (.old, .bak, .inc, .src) and guessing of filename
- [x] Find important file, information `(.asa , .inc , .sql ,zip, tar, pdf, txt, etc).`
- [x] Verify that the identity requirements for user registration are aligned with business and security requirements.
- [x] Testing for bypassing authentication schema `Force browsing (/admin/main.php, /page.asp?authenticated=yes), Parameter Modification, Session ID prediction, SQL Injection`
- [x] If multiple files can be uploaded at once, there must be tests in place to verify that each file is properly evaluated.`PS. file.phtml, shell.phPWND, SHELL~1.PHP`
#### Testing for Authentication Issues
- [x] Improper Authorization
- [x] Improper Authentication
- [x] Weak Login Function Issues
- [x] Bypass Single factor Authentication
- [x] Bypass Two factor (2FA) Authentication
- [x] Execution with Unnecessary Privileges
- [x] Insecure Direct Object Reference (IDOR)
- [x] Account Takeover related Logical Issues
- [x] Exploiting Forgot Password Functionality
- [x] Bypass Authentication on Critical Functions
- [x] Session Expiration & Session Fixation Issue
- [x] OAuth Redirect_URI Issues (Token Hijacking)
- [x] User Impersonation vulnerability | Exploitation
- [x] Authorization Bypass Through User-Controlled Key
- [x] OAuth Permission Models Issues (Account Takeover)
- [x] Improper Permission Assignment for Critical Resource
#### Testing for Web Application Encryptions
- [x] Missing Required Cryptographic Step
- [x] Cleartext Transmission of Session Token
- [x] Exploitaing Encrypted Cookies | Sessions
- [x] Cleartext Storage of Sensitive Information
- [x] Exploiting Encrypted Password Reset Tokens
- [x] Exploiting Encrypted Coupon Codes from Source
- [x] Use of a Broken or Risky Cryptographic Algorithm
#### Testing for Arbitrary Injections
- [x] CSV Injection
- [x] CSS Injections
- [x] CRLF Injections
- [x] Iframe Injection
- [x] SMTP Injection
- [x] Cookie Injections
- [x] LDAP Query Injections
- [x] Host Header Injections
- [x] Apache Struts Vulnerability
- [x] Remote Code Executions (RCE)
- [x] XML External Entity Injection
- [x] HTML5 Security & HTML Injections
- [x] Argument Injection or Modification
- [x] XPath Injection & Data Query Logic
- [x] Server Side Template Injections (SSTI)
#### Testing for Sensitive Data Exposure
- [x] Password Disclosure
- [x] Full Path Disclosure
- [x] Sensitive Token in URL
- [x] Internal IP Disclosure
- [x] Token Leakage via Referer
- [x] Directory Listing Enabled
- [x] Default Credentials Issues
- [x] Disclosure Private API Keys
- [x] Default/Config Files Testing
- [x] Detailed Server Configuration
- [x] Exposed Internal Admin Portal
- [x] Disclosure Private Git Repository
- [x] User Enumeration (Sensitive Data Leaks)
- [x] DBMS Misconfiguration Excessively Privileged User
- [x] EXIF Geolocation Data Not Stripped From Uploaded Images
#### Testing for Traditional Security Issues
- [x] Directory Traversal Attacks
- [x] Remote File Inclusion Vulnerability
- [x] Cross-Site Request Forgery (CSRF) Attacks
- [x] Server-Side Request Forgery (SSRF) Attacks
- [x] Cross-Origin Resource Sharing (CORS) Attacks
- [x] SSL Attack (BREACH, POODLE, HEARTBLEED)
- [x] Unrestricted File Upload with Dangerous Type
- [x] URL Redirection to Untrusted Site (Open Redirect)
#### Testing for Dos / Buffer Overflow Issues
- [x] XML-RPC Pingback DoS Attack
- [x] Incorrect Calculation of Buffer Size
- [x] XML External Entity (DTD) DoS attacks
- [x] Buffer Copy without Checking Size of Input
#### Testing for Common Issues
- [x] Captcha Bypass Attacks
- [x] Clickjacking (UI Readdressing)
- [x] Deserialization of Untrusted Data
- [x] Missing Authentication for Critical Function
- [x] Parameter Pollution in Social Sharing Buttons
#### Testing for Low Priority issues
- [x] JSON Hijacking
- [x] Lack of Verification Email
- [x] Mail Server Misconfiguration
- [x] No Rate Limiting on Login | Registration
- [x] No Rate Limiting on SMS | Email-Triggering
- [x] Race Conditions Enabled on Applications Functions
#### Vulnerability Analysis Tools
- [x] API Testing with Telerik Fiddler
- [x] Bug Hunting | Behaviour Analysis with Burpsuite
#### Penetration Testing Methodology & Standard I covered
- [x] Bugcrowd Vulnerability Rating Taxonomy (VRT)
- [x] SANS Top 25 Most Dangerous Applications Errors
- [x] Owasp Top 10 Vulnerabilities in Modern Web Applications
- [x] Common Attack Pattern Enumeration and Classification (CAPEC)
