### <h2 align="center">:skull: <br> <br> Vulnerabilities Checklist <hr></h1>
Reconnaissance & Source Code Analysis
- [ ] Dynamic Analysis of Web Application Source Code
- [ ] Dynamic Analysis of Complete JavaScript Source
- [ ] Enumeration of Publicly Accessible Cloud Storage
- [ ] Common Crawling & Sensitive Directory Enumeration
- [ ] Manual & Automated Subdomain Analysis | Discovery
- [ ] Identifying & Testing for Subdomain Takeover Issues
#### Testing for Authentication Issues
- [ ] Improper Authorization
- [ ] Improper Authentication
- [ ] Weak Login Function Issues
- [ ] Bypass Single factor Authentication
- [ ] Bypass Two factor (2FA) Authentication
- [ ] Execution with Unnecessary Privileges
- [ ] Insecure Direct Object Reference (IDOR)
- [ ] Account Takeover related Logical Issues
- [ ] Exploiting Forgot Password Functionality
- [ ] Bypass Authentication on Critical Functions
- [ ] Session Expiration & Session Fixation Issue
- [ ] OAuth Redirect_URI Issues (Token Hijacking)
- [ ] User Impersonation vulnerability | Exploitation
- [ ] Authorization Bypass Through User-Controlled Key
- [ ] OAuth Permission Models Issues (Account Takeover)
- [ ] Improper Permission Assignment for Critical Resource
#### Testing for Web Application Encryptions
- [ ] Missing Required Cryptographic Step
- [ ] Cleartext Transmission of Session Token
- [ ] Exploitaing Encrypted Cookies | Sessions
- [ ] Cleartext Storage of Sensitive Information
- [ ] Exploiting Encrypted Password Reset Tokens
- [ ] Exploiting Encrypted Coupon Codes from Source
- [ ] Use of a Broken or Risky Cryptographic Algorithm
#### Testing for Arbitrary Injections
- [ ] CSV Injection
- [ ] CSS Injections
- [ ] CRLF Injections
- [ ] Iframe Injection
- [ ] Cookie Injections
- [ ] LDAP Query Injections
- [ ] Host Header Injections
- [ ] Apache Struts Vulnerability
- [ ] Remote Code Executions (RCE)
- [ ] XML External Entity Injection
- [ ] HTML5 Security & HTML Injections
- [ ] Argument Injection or Modification
- [ ] XPath Injection & Data Query Logic
- [ ] Server Side Template Injections (SSTI)
#### Testing for Sensitive Data Exposure
- [ ] Password Disclosure
- [ ] Full Path Disclosure
- [ ] Sensitive Token in URL
- [ ] Internal IP Disclosure
- [ ] Token Leakage via Referer
- [ ] Directory Listing Enabled
- [ ] Default Credentials Issues
- [ ] Disclosure Private API Keys
- [ ] Default/Config Files Testing
- [ ] Detailed Server Configuration
- [ ] Exposed Internal Admin Portal
- [ ] Disclosure Private Git Repository
- [ ] Mixed Content (HTTPS Sourcing HTTP)
- [ ] User Enumeration (Sensitive Data Leaks)
- [ ] DBMS Misconfiguration Excessively Privileged User
- [ ] EXIF Geolocation Data Not Stripped From Uploaded Images
#### Testing for Traditional Security Issues
- [ ] Directory Traversal Attacks
- [ ] Remote File Inclusion Vulnerability
- [ ] Cross-Site Request Forgery (CSRF) Attacks
- [ ] Server-Side Request Forgery (SSRF) Attacks
- [ ] Cross-Origin Resource Sharing (CORS) Attacks
- [ ] SSL Attack (BREACH, POODLE, HEARTBLEED)
- [ ] Unrestricted File Upload with Dangerous Type
- [ ] URL Redirection to Untrusted Site (Open Redirect)
#### Testing for Dos / Buffer Overflow Issues
- [ ] XML-RPC Pingback DoS Attack
- [ ] Incorrect Calculation of Buffer Size
- [ ] XML External Entity (DTD) DoS attacks
- [ ] Buffer Copy without Checking Size of Input
#### Testing for Common Issues
- [ ] Captcha Bypass Attacks
- [ ] DNS Zone Transfer Issues
- [ ] Clickjacking (UI Readdressing)
- [ ] Deserialization of Untrusted Data
- [ ] Missing Authentication for Critical Function
- [ ] Parameter Pollution in Social Sharing Buttons
#### Testing for Low Priority issues
- [ ] JSON Hijacking
- [ ] No Password Policy
- [ ] Same-Site Scripting Issues
- [ ] Lack of Notification Email
- [ ] Lack of Verification Email
- [ ] Mail Server Misconfiguration
- [ ] Reflected File Download (RFD)
- [ ] Weak Registration Implementation
- [ ] Missing Secure or HTTPOnly Cookie Flag
- [ ] No Rate Limiting on Login | Registration
- [ ] No Rate Limiting on SMS | Email-Triggering
- [ ] Race Conditions Enabled on Applications Functions
#### Vulnerability Analysis Tools
- [ ] API Testing with Telerik Fiddler
- [ ] Bug Hunting | Behaviour Analysis with Burpsuite
#### Penetration Testing Methodology & Standard we covered
- [ ] Bugcrowd Vulnerability Rating Taxonomy (VRT)
- [ ] SANS Top 25 Most Dangerous Applications Errors
- [ ] Owasp CWE : Vulnerabilities in Modern Web Applications
- [ ] Common Attack Pattern Enumeration and Classification (CAPEC)
