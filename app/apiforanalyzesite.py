from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse
from app.analyze_site import recon
from urllib.parse import urlparse

app = FastAPI(title="Recon API")

def clean_url(url: str) -> str:
    url = url.strip()
    if url.startswith('https//'):
        url = url.replace('https//', 'https://', 1)
    parsed = urlparse(url)
    if not parsed.scheme:
        url = 'http://' + url
    return url

@app.get("/recon")
def recon_endpoint(url: str = Query(..., description="Target URL to analyze")):
    try:
        url = clean_url(url)
        result = recon(url)
        return JSONResponse(content=result)
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})
