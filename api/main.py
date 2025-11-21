from fastapi import FastAPI, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import List, Dict
import uuid
import os
from wafprobe.engine.parser import AttackParser
from wafprobe.engine.scanner import WAFScanner

app = FastAPI()

# Serve UI
app.mount("/ui", StaticFiles(directory="wafprobe/ui", html=True), name="ui")

class ScanRequest(BaseModel):
    url: str

class ScanResult(BaseModel):
    id: str
    status: str
    results: List[Dict] = []
    score: float = 0.0

# In-memory storage for simplicity
scans: Dict[str, ScanResult] = {}

def run_scan_task(scan_id: str, url: str):
    print(f"Starting scan {scan_id} for {url}")
    scans[scan_id].status = "running"
    
    try:
        # Path to attacks - assuming running from root of repo or wafprobe dir
        # Adjusting for running from /Users/varunchugh/master_QA
        attacks_path = os.path.join(os.getcwd(), "wafprobe", "attacks")
        parser = AttackParser(attacks_path)
        tests = parser.load_tests()
        
        scanner = WAFScanner(url)
        results = scanner.scan(tests)
        
        passed_count = sum(1 for r in results if r['passed'])
        score = (passed_count / len(tests)) * 100 if tests else 0
        
        scans[scan_id].results = results
        scans[scan_id].score = score
        scans[scan_id].status = "completed"
        print(f"Scan {scan_id} completed. Score: {score}")
        
    except Exception as e:
        print(f"Scan {scan_id} failed: {e}")
        scans[scan_id].status = "failed"

@app.post("/api/scan")
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    scan_id = str(uuid.uuid4())
    scans[scan_id] = ScanResult(id=scan_id, status="pending")
    background_tasks.add_task(run_scan_task, scan_id, request.url)
    return {"scan_id": scan_id}

@app.get("/api/scan/{scan_id}")
async def get_scan_status(scan_id: str):
    return scans.get(scan_id, {"error": "Scan not found"})

@app.get("/")
async def read_index():
    return FileResponse('wafprobe/ui/index.html')
