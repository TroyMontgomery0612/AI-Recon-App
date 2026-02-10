from fastapi import FastAPI, Request, Query

from app.api.endpoints.scope import router as scope_router
from app.core.security import require_scope
from app.services.dns_tool import get_dns_records
from app.services.whois_tool import get_whois_info


app = FastAPI(title="ReconGuard Test", version="1.0")
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
