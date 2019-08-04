### <h2 align="center">:skull: <br> <br>Web Vulnerabilities Checklist<br><h4 align="center"><a href="https://www.twitter.com/nullb0t">nullb0t</a></h1>

#### Recon & Source Code Analysis
- [x] Dynamic Analysis of Web Application Source Code
- [x] Dynamic Analysis of Complete JavaScript Source
- [x] Enumeration of Publicly Accessible Cloud Storage
- [x] Common Crawling & Sensitive Directory Enumeration
- [x] Manual & Automated Subdomain Analysis | Discovery
- [x] Identifying & Testing for Subdomain Takeover Issues
#### Information gathering part
- [ ] Fingerprint Web Server - `Find the version and type of a running web server to determine known vulnerabilities and the appropriate exploits.Using "HTTP header field ordering" and "Malformed requests test"`.
- [ ] Review Webserver Metafiles for Information Leakage - `Analyze robots.txt and identify Tags from website.`
- [ ] Enumerate Applications on Webserver- `Find applications hosted in the webserver (Virtual hosts/Subdomain), non-standard ports.`
- [ ] Find sensitive information `from webpage comments and Metadata on source code.`
- [ ] Map the target application and understand the principal workflows.
- [ ] Find the type of web application framework/CMS - `Identify application architecture including Web language, WAF, Reverse proxy, Application Server, Backend Database.`
- [ ] Identify HTTP allowed methods on Web server` with OPTIONS. Arbitrary HTTP Methods, HEAD access control bypass and XST.`
- [ ] Check JS source code, comments, cache file, backup file (.old, .bak, .inc, .src) and guessing of filename
- [ ] Find important file, information `(.asa , .inc , .sql ,zip, tar, pdf, txt, etc).`
- [ ] Verify that the identity requirements for user registration are aligned with business and security requirements.
- [ ] Testing for bypassing authentication schema `Force browsing (/admin/main.php, /page.asp?authenticated=yes), Parameter Modification, Session ID prediction, SQL Injection`
- [ ] If multiple files can be uploaded at once, there must be tests in place to verify that each file is properly evaluated.`PS. file.phtml, shell.phPWND, SHELL~1.PHP`
#### Testing for Authentication Issues
- [ ] Improper Authorization
- [x] Improper Authentication
- [x] Weak Login Function Issues
- [ ] Bypass Single factor Authentication
- [x] Bypass Two factor (2FA) Authentication
- [ ] Execution with Unnecessary Privileges
- [x] Insecure Direct Object Reference (IDOR)
- [ ] Account Takeover related Logical Issues
- [x] Exploiting Forgot Password Functionality
- [ ] Bypass Authentication on Critical Functions
- [x] Session Expiration & Session Fixation Issue
- [x] OAuth Redirect_URI Issues (Token Hijacking)
- [ ] User Impersonation vulnerability | Exploitation
- [ ] Authorization Bypass Through User-Controlled Key
- [ ] OAuth Permission Models Issues (Account Takeover)
- [ ] Improper Permission Assignment for Critical Resource
#### Testing for Web Application Encryptions
- [ ] Missing Required Cryptographic Step
- [x] Cleartext Transmission of Session Token
- [ ] Exploitaing Encrypted Cookies | Sessions
- [x] Cleartext Storage of Sensitive Information
- [x] Exploiting Encrypted Password Reset Tokens
- [ ] Exploiting Encrypted Coupon Codes from Source
- [ ] Use of a Broken or Risky Cryptographic Algorithm
#### Testing for Arbitrary Injections
- [ ] CSV Injection
- [ ] CSS Injections
- [ ] CRLF Injections
- [x] Iframe Injection
- [ ] Cookie Injections
- [ ] LDAP Query Injections
- [x] Host Header Injections
- [ ] Apache Struts Vulnerability
- [ ] Remote Code Executions (RCE)
- [ ] XML External Entity Injection
- [x] HTML5 Security & HTML Injections
- [ ] Argument Injection or Modification
- [ ] XPath Injection & Data Query Logic
- [x] Server Side Template Injections (SSTI)
#### Testing for Sensitive Data Exposure
- [ ] Password Disclosure
- [ ] Full Path Disclosure
- [x] Sensitive Token in URL
- [x] Internal IP Disclosure
- [ ] Token Leakage via Referer
- [x] Directory Listing Enabled
- [x] Default Credentials Issues
- [x] Disclosure Private API Keys
- [x] Default/Config Files Testing
- [x] Detailed Server Configuration
- [x] Exposed Internal Admin Portal
- [x] Disclosure Private Git Repository
- [x] User Enumeration (Sensitive Data Leaks)
- [ ] DBMS Misconfiguration Excessively Privileged User
- [ ] EXIF Geolocation Data Not Stripped From Uploaded Images
#### Testing for Traditional Security Issues
- [ ] Directory Traversal Attacks
- [ ] Remote File Inclusion Vulnerability
- [ ] Cross-Site Request Forgery (CSRF) Attacks
- [ ] Server-Side Request Forgery (SSRF) Attacks
- [x] Cross-Origin Resource Sharing (CORS) Attacks
- [x] SSL Attack (BREACH, POODLE, HEARTBLEED)
- [x] Unrestricted File Upload with Dangerous Type
- [x] URL Redirection to Untrusted Site (Open Redirect)
#### Testing for Dos / Buffer Overflow Issues
- [x] XML-RPC Pingback DoS Attack
- [x] Incorrect Calculation of Buffer Size
- [ ] XML External Entity (DTD) DoS attacks
- [x] Buffer Copy without Checking Size of Input
#### Testing for Common Issues
- [x] Captcha Bypass Attacks
- [x] Clickjacking (UI Readdressing)
- [ ] Deserialization of Untrusted Data
- [ ] Missing Authentication for Critical Function
- [ ] Parameter Pollution in Social Sharing Buttons
#### Testing for Low Priority issues
- [x] JSON Hijacking
- [x] Lack of Verification Email
- [x] Mail Server Misconfiguration
- [x] No Rate Limiting on Login | Registration
- [x] No Rate Limiting on SMS | Email-Triggering
- [ ] Race Conditions Enabled on Applications Functions
#### Vulnerability Analysis Tools
- [ ] API Testing with Telerik Fiddler
- [ ] Bug Hunting | Behaviour Analysis with Burpsuite
#### Penetration Testing Methodology & Standard I covered
- [x] Bugcrowd Vulnerability Rating Taxonomy (VRT)
- [x] SANS Top 25 Most Dangerous Applications Errors
- [x] Owasp Top 10 Vulnerabilities in Modern Web Applications
- [x] Common Attack Pattern Enumeration and Classification (CAPEC)
