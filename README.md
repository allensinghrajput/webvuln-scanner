# 🔍 WebVuln Scanner

A browser-based web vulnerability scanner that performs **passive, non-destructive security assessments** on websites. It helps identify common security misconfigurations and potential vulnerabilities through safe, read-only analysis without exploiting or modifying the target system.

> ⚠️ **Disclaimer:** This project is intended **only** for websites you own or have explicit authorization to test. Unauthorized scanning may violate laws or terms of service.

---

## 📖 Overview

WebVuln Scanner analyzes a target website and generates a security report highlighting common vulnerabilities, configuration issues, and information disclosure risks. The scanner focuses on passive detection techniques, making it suitable for security assessments, educational purposes, and authorized penetration testing.

---

## ✨ Features

- 🛡️ Security Header Analysis
- 🍪 Cookie Security Checks
- 🔐 SSL/TLS Certificate Validation
- 🖥️ Server & CMS Fingerprinting
- 📂 Detection of Exposed Sensitive Files
- 📁 Directory Listing Detection
- 🤖 robots.txt Analysis
- ⚠️ Basic Reflected XSS Detection
- 💉 Error-Based SQL Injection Detection
- 📊 Risk Score Calculation
- 🗂️ Scan History Management
- 🌐 Browser-Based Dashboard

---

## 🔍 Security Checks

The scanner analyzes websites for:

- Missing HTTP Security Headers
- Weak Cookie Configurations
- SSL/TLS Certificate Issues
- Server & Technology Disclosure
- CMS Fingerprinting
- Publicly Accessible Sensitive Files
- Directory Listing Exposure
- Sensitive Paths in robots.txt
- Reflected XSS Indicators
- Error-Based SQL Injection Indicators

---

## 🖥️ Technology Stack

### Backend
- PHP 8
- Apache
- MySQL / MariaDB

### Frontend
- HTML5
- CSS3
- JavaScript

### Libraries
- cURL
- OpenSSL
- PDO

---

## 📂 Project Structure

```
webvuln-scanner/
│
├── api/
├── assets/
├── includes/
├── sql/
├── index.php
├── history.php
├── scan_detail.php
├── config.php
└── README.md
```

---

## 🚀 How It Works

1. User enters a target URL.
2. The scanner validates the target.
3. Passive security checks are performed.
4. Findings are analyzed and assigned severity levels.
5. An overall risk score is calculated.
6. Results are stored in the database.
7. The dashboard displays the complete security report.

---

## 📊 Risk Levels

| Severity | Description |
|-----------|-------------|
| 🟢 Info | Informational finding |
| 🟡 Low | Minor security issue |
| 🟠 Medium | Moderate security risk |
| 🔴 High | Significant security issue |
| ⚫ Critical | Immediate attention required |

---

## ⚡ Key Characteristics

- Passive scanning only
- No exploitation
- No data extraction
- No authentication bypass
- No denial-of-service testing
- Safe for authorized security assessments

---

## 📸 Screenshots

> Add screenshots of:

- Home Dashboard
- Scan Results
- Scan History
- Detailed Findings

---

## 🛠️ Installation

See the setup guide included in this repository for deployment using XAMPP, Apache, PHP, and MySQL.

---

## 🎯 Future Improvements

- Authentication System
- PDF Report Export
- Scheduled Scanning
- REST API
- CVSS Risk Scoring
- Multi-threaded Scanning
- OWASP Top 10 Mapping
- Docker Support

---

## 📜 License

This project is intended for educational purposes and authorized security testing only.

---

## 👨‍💻 Author

**Abhinav Kumar**

BCA (Cybersecurity)