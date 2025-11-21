# WAFProbe MVP Implementation Plan

## Goal
Build **WAFProbe**, a SaaS tool that automates WAF efficacy testing. It will use our custom `waf-attack-suite` to simulate attacks against a target URL and report which payloads bypassed the WAF. This addresses the critical industry need for continuous security validation and offers a clear monetization path (subscription-based security assurance).

## User Review Required
> [!IMPORTANT]
> **Target Validation**: The scanner will send actual attack payloads (safe, but flagged as malicious). Ensure you only scan domains you own or have permission to test.
> **Tech Stack**: Python (FastAPI) for the backend/engine, and a lightweight HTML/JS frontend.

## Proposed Changes

### 1. Project Structure
Create a new directory `wafprobe` with the following structure:
- `engine/`: Core logic to parse YAMLs and execute HTTP requests.
- `api/`: FastAPI backend to serve the UI and trigger scans.
- `ui/`: Simple dashboard to view results.
- `attacks/`: Symlink or copy of our `waf-attack-suite`.

### 2. Core Engine (`engine/scanner.py`)
- **YAML Parser**: Load test cases from the `waf-attack-suite`.
- **Request Sender**: Use `requests` library to construct precise HTTP requests (headers, methods, payloads).
- **Detection Logic**:
    - Check HTTP Status Code (e.g., 403 Forbidden = Blocked).
    - Check Response Body (e.g., "WAF Blocked" message).
    - **Pass/Fail Criteria**: If the WAF blocks it, it's a **PASS** (for the WAF). If the request goes through (200 OK) or triggers the expected application error (500), it's a **FAIL** (WAF Bypass).

### 3. CLI Interface (`cli.py`)
- Command: `python cli.py scan <target_url>`
- Output: Real-time console logs of attacks and a final summary table.

### 4. Web Dashboard (SaaS MVP)
- **Frontend**: A clean, "Dark Mode" UI using HTML5 and Tailwind CSS (via CDN).
    - **Input**: URL field.
    - **Action**: "Run Audit" button.
    - **Results**: A visual scorecard (e.g., "Grade: B", "85% Blocked") and a list of successful bypasses.
- **Backend**: FastAPI endpoints:
    - `POST /scan`: Initiates an async scan.
    - `GET /status/{scan_id}`: Polls for progress.
    - `GET /report/{scan_id}`: Returns final JSON results.

## Verification Plan

### Automated Tests
- Unit tests for the YAML parser.
- Mocked HTTP tests to ensure the engine correctly identifies "Blocked" vs "Bypassed" responses.

### Manual Verification
- Run `wafprobe` against a local test server (e.g., a simple Python server) to see "Bypassed" results (since there is no WAF).
- Run against a WAF-protected test endpoint (if available) or simulate WAF responses.
