from fastapi import FastAPI, Request, Response
import uvicorn

app = FastAPI()

BLOCK_PATTERNS = [
    "SELECT", "UNION", "alert(", "etc/passwd", "base64", "system(", 
    "<script>", "1=1", "1!=2",
    "() { :; };", "O:8:\"stdClass\"", "php://input", # Shellshock & PHP
    "\xAC\xED\x00\x05", "ognl", # Java
    "<!ENTITY", "169.254.169.254", "127.0.0.1:22" # XXE & SSRF
]

@app.middleware("http")
async def waf_middleware(request: Request, call_next):
    # Read body to check for payloads
    body = await request.body()
    body_str = body.decode("utf-8", errors="ignore")
    query_params = str(request.query_params)
    
    # Check for attack patterns in query or body
    for pattern in BLOCK_PATTERNS:
        if pattern in body_str or pattern in query_params:
            return Response(content="WAF Blocked: Malicious Payload Detected", status_code=403)
            
    response = await call_next(request)
    return response

@app.get("/")
@app.post("/")
async def root():
    return {"message": "Hello, this is a protected app!"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)
