# session_logic.py

import httpx
import time
import asyncio
import atexit

# --- Global Instances ---
_client_instance = None

TRANSIENT_STATUS = {429, 500, 502, 503, 504}
TRANSIENT_EXCEPTIONS = (httpx.ConnectError, httpx.TimeoutException)

# ==========================================
# 1. SYNC LOGIC (For Vendor URLs)
# ==========================================
def _get_or_create_client():
    global _client_instance
    if _client_instance is None:
        _client_instance = httpx.Client(
            http2=True,
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
            timeout=httpx.Timeout(10.0),
            headers={"User-Agent": "VulnerabilityScanner/1.0"},
            follow_redirects=True
        )
        atexit.register(_client_instance.close)
    return _client_instance

def get_response(url: str):
    client = _get_or_create_client()
    max_retries = 3
    
    for attempt in range(max_retries + 1):
        try:
            response = client.get(url)
            if response.status_code not in TRANSIENT_STATUS:
                return response
        except TRANSIENT_EXCEPTIONS:
            response = None

        if attempt < max_retries:
            time.sleep(1 * (2 ** attempt))
            continue
            
    return response

# ==========================================
# 2. ASYNC LOGIC (For mitre.org CVEs)
# ==========================================

async def async_get_response(client: httpx.AsyncClient, url: str):
    """
    Stateless async retry utility. 
    It doesn't own the client; it just uses the one passed in.
    """
    max_retries = 3
    
    for attempt in range(max_retries + 1):
        try:
            response = await client.get(url)
            if response.status_code not in TRANSIENT_STATUS:
                return response
        except TRANSIENT_EXCEPTIONS:
            response = None

        if attempt < max_retries:
            await asyncio.sleep(1 * (2 ** attempt))
            continue
            
    return response