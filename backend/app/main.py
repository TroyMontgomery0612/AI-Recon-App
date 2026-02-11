from app.services.geo_tool import get_geo_info
from app.services.dns_deep_tool import get_advanced_dns
from app.services.port_scanner import scan_target_ports
from fastapi import FastAPI, Request, Query
from app.api.endpoints.scope import router as scope_router
from app.core.security import require_scope
from app.services.dns_tool import get_dns_records
from app.services.whois_tool import get_whois_info


app = FastAPI(title="ReconGuard Test", version="1.0")
from fastapi.middleware.cors import CORSMiddleware

# This allows your React app to "reach into" the backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(scope_router)



@app.get("/")
def read_root():
    return {"status": "online", "message": "System Ready"}


# --- THE TEST ZONE ---
@app.get("/test-scan")
@require_scope
async def test_scan(
    request: Request,
    target: str = Query(..., description="The IP to scan"),
):
    return {
        "status": "AUTHORIZED",
        "message": f"Target {target} is safe to scan.",
    }


@app.get("/scan/passive")
@require_scope
async def passive_scan(
    request: Request,
    target: str = Query(..., description="The domain name to scan"),
):
    """
    Passive reconnaissance endpoint that performs DNS and WHOIS lookups
    for the given target domain. Access is gated by @require_scope
    (The Kill Switch) to ensure only authorized targets are scanned.
    """
    dns_result = get_dns_records(target)
    whois_result = get_whois_info(target)

    return {
        "target": target,
        "dns": dns_result,
        "whois": whois_result,
    }

# --- ACTIVE RECON SECTION ---

@app.get("/scan/active", tags=["Active Recon"])
@require_scope
async def active_scan(
    request: Request, 
    target: str = Query(..., description="Target IP or Domain to probe")
):
    """
    Performs an ACTIVE Port Scan using Nmap.
    WARNING: This touches the target system. Ensure you have authorization.
    """
    # 1. Run the scan
    scan_results = scan_target_ports(target)
    
    return {
        "target": target,
        "scan_type": "Nmap Fast Scan (-F)",
        "open_ports": scan_results
    }
    # --- PASSIVE INTELLIGENCE TOOLS ---

@app.get("/tools/geo", tags=["Passive Intelligence"])
@require_scope
async def geo_lookup(request: Request, target: str):
    """Get location, ISP, and Map coordinates."""
    return {"target": target, "geo_data": get_geo_info(target)}

@app.get("/tools/dns-deep", tags=["Passive Intelligence"])
@require_scope
async def dns_deep_lookup(request: Request, target: str):
    """Find Mail Servers (MX) and Security Records (TXT)."""
    return {"target": target, "dns_records": get_advanced_dns(target)}