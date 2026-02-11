from fastapi import APIRouter, Query, HTTPException
from typing import Optional

# Import the service tools
from app.services.geo_tool import get_geo_info
from app.services.dns_tool import get_dns_records
from app.services.whois_tool import get_whois_info
from app.services.port_scanner import scan_target_ports

# 1. Define your Safety List right here
# Only targets in this list will be allowed for Active Nmap scanning
AUTHORIZED_LABS = ["scanme.nmap.org", "localhost", "127.0.0.1", "8.8.8.8"]

router = APIRouter(prefix="/tools", tags=["Intelligence Tools"])

@router.get("/geo")
async def geo_recon(target: str = Query(..., description="Target Domain or IP")):
    try:
        data = get_geo_info(target)
        return {"target": target, "geo_data": data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/dns")
async def dns_recon(target: str = Query(..., description="Target Domain")):
    try:
        return get_dns_records(target)
    except Exception as e:
        return {"error": f"DNS Lookup Failed: {str(e)}"}

@router.get("/whois")
async def whois_recon(target: str = Query(..., description="Target Domain")):
    try:
        return get_whois_info(target)
    except Exception as e:
        return {"error": f"Whois Lookup Failed: {str(e)}"}

@router.get("/scan")
async def port_scan(target: str = Query(..., description="Target Domain or IP")):
    # 2. The Ethical Check
    # This is what triggers the 403 Forbidden error you saw in Swagger
    if target.lower() not in [lab.lower() for lab in AUTHORIZED_LABS]:
        raise HTTPException(
            status_code=403, 
            detail=f"ETHICAL_GUARDRAIL: Target '{target}' is not in the authorized lab environment."
        )

    try:
        # If authorized, proceed to the Nmap engine
        return scan_target_ports(target)
    except Exception as e:
        return {"error": f"Port Scan Failed: {str(e)}"}