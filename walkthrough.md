# WAFProbe Walkthrough

WAFProbe is a SaaS-ready tool for testing Web Application Firewall (WAF) efficacy. It uses a custom suite of attack payloads to validate if a WAF is correctly blocking malicious traffic.

## Features
- **Custom Attack Suite**: Includes unique SQLi, XSS, RCE, and LFI payloads.
- **CLI Tool**: Run scans from the terminal.
- **Web Dashboard**: A modern UI for running audits and viewing reports.
- **Scoring System**: Calculates a "WAF Health Score" based on blocked attacks.

## Installation

```bash
# Clone the repository
git clone <repo_url>
cd wafprobe

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

### CLI
Run a scan against a target URL:
```bash
python -m wafprobe.cli http://example.com
```

### Web Dashboard
Start the server:
```bash
uvicorn wafprobe.api.main:app --reload --port 8000
```
Navigate to `http://localhost:8000` in your browser.

## Safe Public Test Targets

> [!WARNING]
> **Do not scan websites you do not own or have permission to test.** It is illegal and unethical.

Use these authorized testbeds to verify the tool (expect mostly "BYPASSED" results as they are intentionally vulnerable):

1.  **HTTPBin** (`http://httpbin.org`)
    *   *Expected Result:* **0% Health Score** (Everything bypassed).
    *   *Use Case:* Verifying that WAFProbe is correctly sending requests.

2.  **OWASP Juice Shop** (`https://juice-shop.herokuapp.com`)
    *   *Expected Result:* Low Health Score.
    *   *Use Case:* Testing against a modern, complex web application.

3.  **Altoro Mutual** (`http://demo.testfire.net`)
    *   *Expected Result:* Low Health Score.
    *   *Use Case:* Legacy web app testing.

## Demo
![WAFProbe Dashboard](/Users/varunchugh/.gemini/antigravity/brain/e039d59b-8e7b-4d29-904a-9e7ab3fa1a94/wafprobe_demo_final_1763745124852.webp)

## Project Structure
- `wafprobe/engine`: Core scanning logic.
- `wafprobe/api`: FastAPI backend.
- `wafprobe/ui`: HTML/JS frontend.
- `wafprobe/attacks`: YAML attack definitions.
