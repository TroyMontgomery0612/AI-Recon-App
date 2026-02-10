from functools import wraps
from fastapi import HTTPException, Request

# 1. The Rules Engine
class ScopeEngine:
    def __init__(self):
        # We start with a simple set of safe IPs
        self.allowed_ips = {"127.0.0.1", "localhost", "google.com", "scanme.nmap.org"}

    def is_ip_allowed(self, ip: str) -> bool:
        return ip in self.allowed_ips

# Create the global engine instance
scope_engine = ScopeEngine()

# 2. The Kill Switch (Decorator)
def require_scope(func):
    @wraps(func)
    async def wrapper(request: Request, *args, **kwargs):
        # Grab target from the URL (e.g. ?target=127.0.0.1)
        target = request.query_params.get("target")
        
        if not target:
             raise HTTPException(status_code=400, detail="Target parameter required")

        if not scope_engine.is_ip_allowed(target):
            # BLOCK THE REQUEST
            raise HTTPException(status_code=403, detail=f"Target {target} is NOT authorized.")
            
        return await func(request, *args, **kwargs)
    return wrapper