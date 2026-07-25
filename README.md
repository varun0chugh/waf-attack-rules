# 🛡️ WAFProbe — The World's Most Comprehensive WAF Testing Suite

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://img.shields.io/badge/Attack_Tests-518-red)]()
[![Categories](https://img.shields.io/badge/Categories-20-blue)]()
[![Format](https://img.shields.io/badge/Format-OWASP_FTW_YAML-green)]()

**WAFProbe** is an open-source WAF (Web Application Firewall) efficacy testing tool with **518 unique attack test cases** across **20 attack categories**. It goes beyond OWASP CRS and Microsoft Azure DRS by covering modern attack vectors like Log4Shell, SSTI, Prototype Pollution, GraphQL attacks, JWT bypasses, and more.

> ⚠️ **Disclaimer**: These payloads are for **authorized security testing only**. Only scan systems you own or have explicit permission to test.

---

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/varun0chugh/wafprobe.git
cd wafprobe

# Create virtual environment & install dependencies
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run CLI scan
python -m wafprobe.cli http://your-waf-protected-url.com

# Run Web Dashboard
uvicorn wafprobe.api.main:app --reload --port 8000
# Then open http://localhost:8000
```

---

## 📊 Attack Coverage (543 Tests / 20 Categories)

| ID | Category | Tests | Description |
|----|----------|-------|-------------|
| **910** | XXE | 17 | XML External Entity Injection (classic, blind, OOB, SOAP, SVG, billion laughs) |
| **911** | Method Enforcement | 20 | Dangerous HTTP methods (TRACE, DEBUG, WebDAV, PUT uploads) |
| **912** | SSRF | 18 | Server-Side Request Forgery (AWS/GCP/Azure metadata, IP obfuscation, DNS rebinding) |
| **913** | Scanner Detection | 30 | Known scanner signatures (Nmap, Nikto, SQLMap, Burp, ZAP, WPScan, etc.) |
| **920** | Protocol Violations | 40 | HTTP protocol anomalies (smuggling, desync, CRLF, oversized requests) |
| **921** | Protocol Attack | 20 | Request smuggling (CL.TE, TE.CL), response splitting, cache poisoning |
| **930** | LFI | 26 | Local File Inclusion (path traversal, encoding bypasses, PHP wrappers, proc) |
| **931** | RFI | 21 | Remote File Inclusion (HTTP/FTP/SMB, wrappers, encoding bypasses) |
| **932** | RCE | 37 | Remote Code Execution (command injection, JNDI, Log4Shell, PowerShell) |
| **933** | PHP Attacks | 21 | Shellshock, object injection, wrappers, eval/assert, file upload bypass |
| **934** | Node.js | 20 | require() injection, prototype pollution, eval, child_process, vm escape |
| **935** | SSTI | 30 | Server-Side Template Injection (Jinja2, Twig, Freemarker, Thymeleaf, ERB, EJS, 14 engines) |
| **941** | XSS | 61 | Cross-Site Scripting (reflected, DOM, mutation, polyglot, 25+ bypass techniques) |
| **942** | SQLi | 54 | SQL Injection (UNION, blind, stacked, NoSQL, LDAP, GraphQL, XPath, ORM) |
| **943** | Session Fixation | 15 | Session hijacking (PHPSESSID, JSESSIONID, cookie tossing, donation) |
| **944** | Java Attacks | 37 | Log4Shell, Spring4Shell, OGNL, SpEL, deserialization, JNDI, ysoserial |
| **945** | CRLF Injection | 20 | Header injection, response splitting, log injection, SMTP injection |
| **946** | Open Redirect | 20 | URL redirect bypasses (protocol-relative, backslash, @-sign, encoding) |
| **947** | API Attacks | 16 | GraphQL abuse, JWT attacks, mass assignment, BOLA/IDOR, XML-RPC |
| **950** | Data Leakage | 20 | Sensitive data exposure (credit cards, stack traces, credentials, keys) |

---

## 🏗️ Architecture

```
wafprobe/
├── attacks/                    # 543 attack test cases in OWASP FTW YAML format
│   ├── REQUEST-910-*-XXE/      # XML External Entity
│   ├── REQUEST-911-*-METHOD/   # HTTP Method Enforcement
│   ├── REQUEST-912-*-SSRF/     # Server-Side Request Forgery
│   ├── REQUEST-913-*-SCANNER/  # Scanner/Bot Detection
│   ├── REQUEST-920-*-PROTOCOL/ # Protocol Violations
│   ├── REQUEST-921-*-ATTACK/   # Protocol Attacks (Smuggling)
│   ├── REQUEST-930-*-LFI/      # Local File Inclusion
│   ├── REQUEST-931-*-RFI/      # Remote File Inclusion
│   ├── REQUEST-932-*-RCE/      # Remote Code Execution
│   ├── REQUEST-933-*-PHP/      # PHP Attacks
│   ├── REQUEST-934-*-NODEJS/   # Node.js Attacks
│   ├── REQUEST-935-*-SSTI/     # Template Injection
│   ├── REQUEST-941-*-XSS/      # Cross-Site Scripting
│   ├── REQUEST-942-*-SQLI/     # SQL Injection
│   ├── REQUEST-943-*-SESSION/  # Session Fixation
│   ├── REQUEST-944-*-JAVA/     # Java Attacks
│   ├── REQUEST-945-*-CRLF/     # CRLF Injection
│   ├── REQUEST-946-*-REDIRECT/ # Open Redirect
│   ├── REQUEST-947-*-API/      # API Security
│   └── REQUEST-950-*-LEAKAGE/  # Data Leakage
├── engine/
│   ├── parser.py               # YAML test case parser
│   └── scanner.py              # HTTP request engine & detection logic
├── api/
│   └── main.py                 # FastAPI backend (async scanning)
├── ui/
│   └── index.html              # Web dashboard
├── cli.py                      # Command-line interface
├── test_server.py              # Local dummy WAF for testing
└── requirements.txt
```

---

## 🆚 How WAFProbe Compares

| Feature | OWASP CRS v4 | Microsoft DRS 2.2 | **WAFProbe** |
|---------|--------------|-------------------|-------------|
| Test format | ModSecurity rules | Azure-specific | **Universal YAML (FTW)** |
| SQLi tests | ✅ Classic | ✅ Classic | **✅ Classic + NoSQL + LDAP + GraphQL + XPath** |
| XSS tests | ✅ Standard | ✅ Standard | **✅ 61 tests incl. mutation, polyglot, framework-specific** |
| SSTI | ❌ Limited | ❌ None | **✅ 30 tests, 14 template engines** |
| Log4Shell | ✅ Basic | ✅ Basic | **✅ 10+ variants with obfuscation** |
| API Security | ❌ None | ❌ None | **✅ GraphQL, JWT, BOLA, mass assignment** |
| Prototype Pollution | ❌ None | ❌ None | **✅ Node.js + JSON merge** |
| SSRF (Cloud) | ✅ Basic | ✅ Basic | **✅ AWS/GCP/Azure/DO + IP obfuscation** |
| Scanner Detection | ✅ Standard | ✅ Standard | **✅ 30 scanner signatures** |
| Open Redirect | ❌ Limited | ❌ None | **✅ 20 bypass techniques** |
| Session Attacks | ✅ Basic | ✅ Basic | **✅ Cookie tossing, donation, cross-subdomain** |
| Total Tests | ~200 | ~150 | **518** |

---

## 🧪 Testing Against Your WAF

### Option 1: Test against a local dummy WAF
```bash
# Terminal 1: Start the dummy WAF server
python wafprobe/test_server.py

# Terminal 2: Run the scanner
python -m wafprobe.cli http://localhost:8080
```

### Option 2: Test against a real WAF
```bash
python -m wafprobe.cli https://your-waf-protected-app.com
```

### Option 3: Web Dashboard
```bash
uvicorn wafprobe.api.main:app --reload --port 8000
```

---

## 📝 YAML Format (OWASP FTW Compatible)

Each test file follows the standard FTW YAML schema:

```yaml
meta:
  author: "WAFProbe"
  description: "Attack Category Description"
  enabled: true
  name: "category-name"
tests:
  - test_id: 942100
    desc: "SQLi using UNION SELECT injection"
    stages:
      - stage:
          input:
            dest_addr: "127.0.0.1"
            method: "GET"
            port: 80
            headers:
              User-Agent: "WAF-Tester/1.0"
              Host: "localhost"
            uri: "/?id=1' UNION SELECT username,password FROM users--"
          output:
            log_contains: "id \"942"
```

---

## 🤝 Contributing

We welcome contributions! To add new attack tests:

1. Fork the repository
2. Create a YAML file in the appropriate `REQUEST-XXX-*` directory
3. Follow the FTW YAML format above
4. Ensure test IDs are unique within the category
5. Submit a pull request

---

## 📄 License

MIT License. See [LICENSE](LICENSE) for details.

---

## ⚠️ Legal

This tool is intended for **authorized security testing and WAF validation only**. Unauthorized scanning of systems you do not own is illegal. Always obtain proper authorization before testing.
