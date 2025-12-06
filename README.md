# WAF Attack Suite

This repository contains a collection of unique Web Application Firewall (WAF) attack test cases defined in YAML format. These tests are designed to evaluate the effectiveness of WAF rules, particularly against bypass attempts and non-standard payloads.

## Structure

The tests are organized by category, following the OWASP ModSecurity Core Rule Set (CRS) naming convention:

- **REQUEST-930-APPLICATION-ATTACK-LFI**: Local File Inclusion (LFI) attacks.
- **REQUEST-932-APPLICATION-ATTACK-RCE**: Remote Code Execution (RCE) attacks.
- **REQUEST-941-APPLICATION-ATTACK-XSS**: Cross-Site Scripting (XSS) attacks.
- **REQUEST-942-APPLICATION-ATTACK-SQLI**: SQL Injection (SQLi) attacks.

## Format

The tests use the [FTW (Framework for Testing WAFs)](https://github.com/coreruleset/ftw) YAML format. Each file contains a `meta` section and a list of `tests`.

### Example

```yaml
meta:
  author: "Antigravity"
  description: "Unique SQL Injection Bypass Attempt"
  enabled: true
  name: "942-sqli-unique-bypass"
tests:
  - test_id: 942001
    desc: "SQLi using JSON operator"
    stages:
      - stage:
          input:
            dest_addr: "127.0.0.1"
            method: "POST"
            port: 80
            headers:
              User-Agent: "OWASP CRS/3.3.0"
              Host: "localhost"
              Content-Type: "application/json"
            data: '{"user": "admin", "pass": {"@>": "SELECT * FROM users"}}'
          output:
            log_contains: "id \"942"
```

## Usage

These files can be used with tools like `go-ftw` or `ftw` to run regression tests against your WAF implementation.

## Disclaimer

These payloads are for educational and testing purposes only. Do not use them against systems you do not own or have explicit permission to test.
