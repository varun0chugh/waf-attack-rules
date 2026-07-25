import os

base_dir = "/Users/varunchugh/master_QA/wafprobe/attacks"

files = {
    "REQUEST-911-METHOD-ENFORCEMENT/911-method-enforcement.yaml": """meta:
  author: "Security Engineer"
  description: "Method Enforcement Tests"
  enabled: true
  name: "911-method-enforcement.yaml"
tests:
  - test_id: "911100"
    desc: "TRACE method (used for XST)"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "TRACE"
          port: 80
          headers:
            Host: "localhost"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "911101"
    desc: "DEBUG method"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "DEBUG"
          port: 80
          headers:
            Host: "localhost"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "911102"
    desc: "CONNECT method"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "CONNECT"
          port: 80
          headers:
            Host: "localhost"
          uri: "www.example.com:80"
        output:
          log_contains: "id"
  - test_id: "911103"
    desc: "PROPFIND method"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "PROPFIND"
          port: 80
          headers:
            Host: "localhost"
            Depth: "1"
          uri: "/webdav/"
        output:
          log_contains: "id"
  - test_id: "911104"
    desc: "PROPPATCH method"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "PROPPATCH"
          port: 80
          headers:
            Host: "localhost"
            Content-Type: "application/xml"
          uri: "/webdav/"
          data: "<?xml version=\\"1.0\\" encoding=\\"utf-8\\" ?>..."
        output:
          log_contains: "id"
  - test_id: "911105"
    desc: "MKCOL method"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "MKCOL"
          port: 80
          headers:
            Host: "localhost"
          uri: "/newfolder/"
        output:
          log_contains: "id"
  - test_id: "911106"
    desc: "COPY method"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "COPY"
          port: 80
          headers:
            Host: "localhost"
            Destination: "http://localhost/dest"
          uri: "/source"
        output:
          log_contains: "id"
  - test_id: "911107"
    desc: "MOVE method"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "MOVE"
          port: 80
          headers:
            Host: "localhost"
            Destination: "http://localhost/dest"
          uri: "/source"
        output:
          log_contains: "id"
  - test_id: "911108"
    desc: "LOCK method"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "LOCK"
          port: 80
          headers:
            Host: "localhost"
            Timeout: "Infinite, Second-4100000000"
          uri: "/resource"
        output:
          log_contains: "id"
  - test_id: "911109"
    desc: "UNLOCK method"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "UNLOCK"
          port: 80
          headers:
            Host: "localhost"
            Lock-Token: "<urn:uuid:a515cfa4-5da4-22e1-f5b5-00a0451e6bf7>"
          uri: "/resource"
        output:
          log_contains: "id"
  - test_id: "911110"
    desc: "PATCH with malicious body"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "PATCH"
          port: 80
          headers:
            Host: "localhost"
            Content-Type: "application/json-patch+json"
          uri: "/api/user/1"
          data: "[{\\"op\\": \\"replace\\", \\"path\\": \\"/role\\", \\"value\\": \\"admin\\"}]"
        output:
          log_contains: "id"
  - test_id: "911111"
    desc: "DELETE method abuse"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "DELETE"
          port: 80
          headers:
            Host: "localhost"
          uri: "/etc/passwd"
        output:
          log_contains: "id"
  - test_id: "911112"
    desc: "OPTIONS method enumeration"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "OPTIONS"
          port: 80
          headers:
            Host: "localhost"
          uri: "*"
        output:
          log_contains: "id"
  - test_id: "911113"
    desc: "Custom HTTP method JEFF"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "JEFF"
          port: 80
          headers:
            Host: "localhost"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "911114"
    desc: "Custom HTTP method HACK"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "HACK"
          port: 80
          headers:
            Host: "localhost"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "911115"
    desc: "PUT method for file upload"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "PUT"
          port: 80
          headers:
            Host: "localhost"
            Content-Type: "text/html"
          uri: "/shell.jsp"
          data: "<% Runtime.getRuntime().exec(request.getParameter(\\"cmd\\")); %>"
        output:
          log_contains: "id"
  - test_id: "911116"
    desc: "BCOPY method (WebDAV)"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "BCOPY"
          port: 80
          headers:
            Host: "localhost"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "911117"
    desc: "BDELETE method (WebDAV)"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "BDELETE"
          port: 80
          headers:
            Host: "localhost"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "911118"
    desc: "BMOVE method (WebDAV)"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "BMOVE"
          port: 80
          headers:
            Host: "localhost"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "911119"
    desc: "BPROPFIND method (WebDAV)"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "BPROPFIND"
          port: 80
          headers:
            Host: "localhost"
          uri: "/"
        output:
          log_contains: "id"
""",
    "REQUEST-913-SCANNER-DETECTION/913-scanner-detection.yaml": """meta:
  author: "Security Engineer"
  description: "Scanner Detection Tests"
  enabled: true
  name: "913-scanner-detection.yaml"
tests:
  - test_id: "913100"
    desc: "Nmap User-Agent"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
            User-Agent: "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "913101"
    desc: "Nikto User-Agent"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
            User-Agent: "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:004120)"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "913102"
    desc: "SQLMap User-Agent"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
            User-Agent: "sqlmap/1.5.8.5#dev (http://sqlmap.org)"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "913103"
    desc: "Burp Suite User-Agent"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
            User-Agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36"
            X-Burp-Collaborator: "foobar"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "913104"
    desc: "DirBuster User-Agent"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
            User-Agent: "DirBuster-0.1.3 (http://www.owasp.org/index.php/Category:OWASP_DirBuster_Project)"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "913105"
    desc: "Acunetix User-Agent"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
            User-Agent: "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.21 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.21"
            Acunetix-Product: "WVS/14.0"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "913106"
    desc: "w3af User-Agent"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
            User-Agent: "w3af.org"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "913107"
    desc: "Havij User-Agent"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
            User-Agent: "Havij"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "913108"
    desc: "OpenVAS User-Agent"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
            User-Agent: "Mozilla/5.0 [en] (X11, U; OpenVAS-VT 9.0.3)"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "913109"
    desc: "ZAP User-Agent"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
            User-Agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 OPR/77.0.4054.277 ZAP/2.11"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "913110"
    desc: "WPScan User-Agent"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
            User-Agent: "WPScan v3.8.22 (https://wpscan.com/wordpress-security-scanner)"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "913111"
    desc: "Masscan User-Agent"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
            User-Agent: "masscan/1.3 (https://github.com/robertdavidgraham/masscan)"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "913112"
    desc: "Gobuster patterns"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
            User-Agent: "gobuster/3.1.0"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "913113"
    desc: "Python-urllib crawler"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
            User-Agent: "python-urllib/3.9"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "913114"
    desc: "Go-http-client crawler"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
            User-Agent: "Go-http-client/1.1"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "913115"
    desc: "Script kiddie patterns"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
            X-Forwarded-For: "127.0.0.1"
            User-Agent: "curl/7.68.0"
          uri: "/admin.php"
        output:
          log_contains: "id"
  - test_id: "913116"
    desc: "Suspicious header combinations"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
            Accept: "*/*"
            User-Agent: "Mozilla/5.0"
            Connection: "Keep-Alive"
            Pragma: "no-cache"
          uri: "/login"
        output:
          log_contains: "id"
  - test_id: "913117"
    desc: "Arachni User-Agent"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
            User-Agent: "Arachni/v1.5.1"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "913118"
    desc: "JNDI Exploit Kit User-Agent"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
            User-Agent: "${jndi:ldap://127.0.0.1/a}"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "913119"
    desc: "ZmEu scanner"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
            User-Agent: "ZmEu"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "913120"
    desc: "Morfeus scanner"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
            User-Agent: "Morfeus Fucking Scanner"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "913121"
    desc: "Panscience scanner"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
            User-Agent: "panscience.org"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "913122"
    desc: "BFAC (Backup File Artifacts Checker)"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
            User-Agent: "BFAC"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "913123"
    desc: "Wfuzz User-Agent"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
            User-Agent: "Wfuzz/2.4"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "913124"
    desc: "Ffuf User-Agent"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
            User-Agent: "Fuzz Faster U Fool v1.3.1"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "913125"
    desc: "WhatWeb User-Agent"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
            User-Agent: "WhatWeb/0.5.5.3"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "913126"
    desc: "Wappalyzer User-Agent"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
            User-Agent: "Wappalyzer"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "913127"
    desc: "CensysInspect User-Agent"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
            User-Agent: "Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "913128"
    desc: "Shodan User-Agent"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
            User-Agent: "Shodan"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "913129"
    desc: "Netsparker User-Agent"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
            User-Agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.130 Safari/537.36 Netsparker"
          uri: "/"
        output:
          log_contains: "id"
""",
    "REQUEST-920-PROTOCOL-VIOLATIONS/920-protocol-violations.yaml": """meta:
  author: "Security Engineer"
  description: "Protocol Violations Tests"
  enabled: true
  name: "920-protocol-violations.yaml"
tests:
  - test_id: "920100"
    desc: "Missing Host header"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Accept: "*/*"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "920101"
    desc: "Duplicate Host header"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: 
              - "localhost"
              - "evil.com"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "920102"
    desc: "Host header with IP address"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "192.168.1.1"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "920103"
    desc: "Content-Length mismatch"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "POST"
          port: 80
          headers:
            Host: "localhost"
            Content-Length: "100"
          uri: "/"
          data: "short"
        output:
          log_contains: "id"
  - test_id: "920104"
    desc: "Transfer-Encoding with invalid value"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "POST"
          port: 80
          headers:
            Host: "localhost"
            Transfer-Encoding: "invalid"
          uri: "/"
          data: "test"
        output:
          log_contains: "id"
  - test_id: "920105"
    desc: "Chunked Transfer-Encoding abuse"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "POST"
          port: 80
          headers:
            Host: "localhost"
            Transfer-Encoding: "chunked"
          uri: "/"
          data: "4\\r\\ntest\\r\\n0\\r\\n\\r\\n"
        output:
          log_contains: "id"
  - test_id: "920106"
    desc: "Request smuggling (CL.TE)"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "POST"
          port: 80
          headers:
            Host: "localhost"
            Content-Length: "13"
            Transfer-Encoding: "chunked"
          uri: "/"
          data: "0\\r\\n\\r\\nGET /x HTTP/1.1\\r\\nHost: localhost\\r\\n\\r\\n"
        output:
          log_contains: "id"
  - test_id: "920107"
    desc: "Request smuggling (TE.CL)"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "POST"
          port: 80
          headers:
            Host: "localhost"
            Content-Length: "4"
            Transfer-Encoding: "chunked"
          uri: "/"
          data: "12\\r\\nGET /x HTTP/1.1\\r\\n0\\r\\n\\r\\n"
        output:
          log_contains: "id"
  - test_id: "920108"
    desc: "HTTP/0.9 request"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers: {}
          uri: "/"
          version: "HTTP/0.9"
        output:
          log_contains: "id"
  - test_id: "920109"
    desc: "Invalid HTTP version"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
          uri: "/"
          version: "HTTP/2.5"
        output:
          log_contains: "id"
  - test_id: "920110"
    desc: "Extremely long URI (>8192 chars)"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
          uri: "/?q=A"
        output:
          log_contains: "id"
  - test_id: "920111"
    desc: "Extremely long header value"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
            User-Agent: "A"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "920112"
    desc: "Null bytes in headers"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
            X-Custom: "foo\\0bar"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "920113"
    desc: "CRLF injection in headers"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
            X-Custom: "foo\\r\\nbar: baz"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "920114"
    desc: "Response splitting attempt"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
          uri: "/?lang=en\\r\\nSet-Cookie:%20session=hack"
        output:
          log_contains: "id"
  - test_id: "920115"
    desc: "Invalid Content-Type"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "POST"
          port: 80
          headers:
            Host: "localhost"
            Content-Type: "invalid/type"
          uri: "/"
          data: "test"
        output:
          log_contains: "id"
  - test_id: "920116"
    desc: "Multipart boundary abuse"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "POST"
          port: 80
          headers:
            Host: "localhost"
            Content-Type: "multipart/form-data; boundary=---------------------------malformed"
          uri: "/"
          data: "-----------------------------malformed\\r\\nContent-Disposition: form-data; name=\\"file\\"; filename=\\"test.txt\\"\\r\\n\\r\\ntest\\r\\n-----------------------------malformed--"
        output:
          log_contains: "id"
  - test_id: "920117"
    desc: "Multiple Content-Type headers"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "POST"
          port: 80
          headers:
            Host: "localhost"
            Content-Type:
              - "application/x-www-form-urlencoded"
              - "application/json"
          uri: "/"
          data: '{"a": 1}'
        output:
          log_contains: "id"
  - test_id: "920118"
    desc: "HTTP request smuggling via H2"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "POST"
          port: 80
          headers:
            Host: "localhost"
            x-forwarded-for: "127.0.0.1\\r\\nTransfer-Encoding: chunked"
          uri: "/"
          data: "0\\r\\n\\r\\nGET /admin HTTP/1.1\\r\\nHost: localhost\\r\\n\\r\\n"
        output:
          log_contains: "id"
  - test_id: "920119"
    desc: "Desync attacks"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "POST"
          port: 80
          headers:
            Host: "localhost"
            Content-Length: "4"
            Transfer-Encoding: " \\tchunked"
          uri: "/"
          data: "3\\r\\nabc\\r\\n0\\r\\n\\r\\n"
        output:
          log_contains: "id"
  - test_id: "920120"
    desc: "Empty Host header"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: ""
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "920121"
    desc: "Host header with port"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost:8080"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "920122"
    desc: "Multiple Transfer-Encoding headers"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "POST"
          port: 80
          headers:
            Host: "localhost"
            Transfer-Encoding:
              - "chunked"
              - "gzip"
          uri: "/"
          data: "test"
        output:
          log_contains: "id"
  - test_id: "920123"
    desc: "Transfer-Encoding with Content-Length"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "POST"
          port: 80
          headers:
            Host: "localhost"
            Content-Length: "10"
            Transfer-Encoding: "chunked"
          uri: "/"
          data: "test"
        output:
          log_contains: "id"
  - test_id: "920124"
    desc: "Invalid character in header name"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
            "X-Inv@lid": "test"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "920125"
    desc: "Missing Accept header"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "920126"
    desc: "Missing User-Agent header"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "920127"
    desc: "Non-ASCII characters in header"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
            X-Test: "é"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "920128"
    desc: "Line folding in headers"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
            X-Test: "foo\\r\\n bar"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "920129"
    desc: "Empty header name"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
            "": "value"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "920130"
    desc: "Whitespace before URI"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
          uri: " /"
        output:
          log_contains: "id"
  - test_id: "920131"
    desc: "Invalid character in URI"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
          uri: "/test<>"
        output:
          log_contains: "id"
  - test_id: "920132"
    desc: "Multiple Content-Length headers"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "POST"
          port: 80
          headers:
            Host: "localhost"
            Content-Length:
              - "5"
              - "5"
          uri: "/"
          data: "hello"
        output:
          log_contains: "id"
  - test_id: "920133"
    desc: "Content-Length with non-numeric value"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "POST"
          port: 80
          headers:
            Host: "localhost"
            Content-Length: "abc"
          uri: "/"
          data: "test"
        output:
          log_contains: "id"
  - test_id: "920134"
    desc: "Negative Content-Length"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "POST"
          port: 80
          headers:
            Host: "localhost"
            Content-Length: "-1"
          uri: "/"
          data: "test"
        output:
          log_contains: "id"
  - test_id: "920135"
    desc: "Body in GET request"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
            Content-Length: "4"
          uri: "/"
          data: "test"
        output:
          log_contains: "id"
  - test_id: "920136"
    desc: "Missing Content-Length in POST"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "POST"
          port: 80
          headers:
            Host: "localhost"
          uri: "/"
          data: "test"
        output:
          log_contains: "id"
  - test_id: "920137"
    desc: "Space before header name"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
            " X-Test": "value"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "920138"
    desc: "Double CRLF in header"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
            X-Test: "foo\\r\\n\\r\\nbar"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "920139"
    desc: "Tab character in URI"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
          uri: "/test\\t"
        output:
          log_contains: "id"
""",
    "REQUEST-921-PROTOCOL-ATTACK/921-protocol-attack.yaml": """meta:
  author: "Security Engineer"
  description: "Protocol Attack Tests"
  enabled: true
  name: "921-protocol-attack.yaml"
tests:
  - test_id: "921100"
    desc: "HTTP Response Splitting"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
          uri: "/?page=index%0d%0aSet-Cookie:%20session=hack"
        output:
          log_contains: "id"
  - test_id: "921101"
    desc: "CRLF Header Injection"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
          uri: "/?q=test%0d%0aX-Injected:%20header"
        output:
          log_contains: "id"
  - test_id: "921102"
    desc: "HTTP Request Smuggling CL.TE"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "POST"
          port: 80
          headers:
            Host: "localhost"
            Content-Length: "15"
            Transfer-Encoding: "chunked"
          uri: "/"
          data: "0\\r\\n\\r\\nPOST / HTTP/1.1\\r\\n\\r\\n"
        output:
          log_contains: "id"
  - test_id: "921103"
    desc: "HTTP Request Smuggling TE.CL"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "POST"
          port: 80
          headers:
            Host: "localhost"
            Content-Length: "4"
            Transfer-Encoding: "chunked"
          uri: "/"
          data: "5c\\r\\nPOST / HTTP/1.1\\r\\nHost: localhost\\r\\nContent-Length: 15\\r\\n\\r\\nx\\r\\n0\\r\\n\\r\\n"
        output:
          log_contains: "id"
  - test_id: "921104"
    desc: "Chunked encoding smuggling"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "POST"
          port: 80
          headers:
            Host: "localhost"
            Transfer-Encoding: "chunked"
          uri: "/"
          data: "1\\r\\nA\\r\\n0\\r\\n\\r\\nGET /admin HTTP/1.1\\r\\nHost: localhost\\r\\n\\r\\n"
        output:
          log_contains: "id"
  - test_id: "921105"
    desc: "H2 desync attack"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "POST"
          port: 80
          headers:
            Host: "localhost"
            X-Forwarded-For: "127.0.0.1\\r\\nTransfer-Encoding: chunked"
          uri: "/"
          data: "0\\r\\n\\r\\nGET /admin HTTP/1.1\\r\\nHost: localhost\\r\\n\\r\\n"
        output:
          log_contains: "id"
  - test_id: "921106"
    desc: "Header injection via newline"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
            X-Custom: "foo\\nbar"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "921107"
    desc: "Response header injection"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
          uri: "/redirect?url=http://example.com%0d%0aLocation:%20http://evil.com"
        output:
          log_contains: "id"
  - test_id: "921108"
    desc: "Cache poisoning headers"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
            X-Forwarded-Host: "evil.com"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "921109"
    desc: "Host header routing abuse"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "admin.local"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "921110"
    desc: "HTTP Request Smuggling TE.TE"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "POST"
          port: 80
          headers:
            Host: "localhost"
            Content-Length: "4"
            Transfer-Encoding:
              - "chunked"
              - "cow"
          uri: "/"
          data: "5\\r\\nhello\\r\\n0\\r\\n\\r\\n"
        output:
          log_contains: "id"
  - test_id: "921111"
    desc: "Cache poisoning via X-Original-URL"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
            X-Original-URL: "/admin"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "921112"
    desc: "Cache poisoning via X-Rewrite-URL"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
            X-Rewrite-URL: "/admin"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "921113"
    desc: "Cache poisoning via X-Forwarded-Scheme"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
            X-Forwarded-Scheme: "http"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "921114"
    desc: "Cache poisoning via X-Host"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
            X-Host: "evil.com"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "921115"
    desc: "Cache poisoning via Forwarded"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
            Forwarded: "host=evil.com"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "921116"
    desc: "Cache poisoning via X-HTTP-Host-Override"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
            X-HTTP-Host-Override: "evil.com"
          uri: "/"
        output:
          log_contains: "id"
  - test_id: "921117"
    desc: "Web Cache Deception"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "GET"
          port: 80
          headers:
            Host: "localhost"
          uri: "/myaccount/profile.css"
        output:
          log_contains: "id"
  - test_id: "921118"
    desc: "HTTP Request Smuggling with unusual whitespace"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "POST"
          port: 80
          headers:
            Host: "localhost"
            Content-Length: "4"
            Transfer-Encoding: "\\x0bchunked"
          uri: "/"
          data: "0\\r\\n\\r\\n"
        output:
          log_contains: "id"
  - test_id: "921119"
    desc: "HTTP Request Smuggling with tab in Transfer-Encoding"
    stages:
      - input:
          dest_addr: "127.0.0.1"
          method: "POST"
          port: 80
          headers:
            Host: "localhost"
            Content-Length: "4"
            Transfer-Encoding: "\\tchunked"
          uri: "/"
          data: "0\\r\\n\\r\\n"
        output:
          log_contains: "id"
"""
}

os.makedirs(base_dir, exist_ok=True)
for path, content in files.items():
    full_path = os.path.join(base_dir, path)
    os.makedirs(os.path.dirname(full_path), exist_ok=True)
    with open(full_path, "w") as f:
        f.write(content)

print("Created all files successfully.")
