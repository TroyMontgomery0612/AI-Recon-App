import asyncio
from functools import wraps

from fastapi import HTTPException, Request
from sqlalchemy.orm import Session

from app.db.models import ScopeTarget
from app.db.session import SessionLocal


class ScopeEngine:
    """
    Scope engine backed by the PostgreSQL database.

    Instead of relying on a hardcoded set of allowed targets, this engine
    queries the ScopeTarget table to determine whether a given target
    (IP or domain) is authorized.
    """

    def _is_target_in_db(self, target: str) -> bool:
        db: Session = SessionLocal()
        try:
            exists = db.query(ScopeTarget).filter(ScopeTarget.target == target).first()
            return exists is not None
        finally:
            db.close()

    def is_ip_allowed(self, ip: str) -> bool:
        """
        Backwards-compatible API for existing decorators.
        Internally this simply checks whether the given target exists
        in the ScopeTarget table.
        """
        return self._is_target_in_db(ip)


# Create the global engine instance
scope_engine = ScopeEngine()


def require_scope(func):
    """
    Kill Switch decorator.

    Ensures that every scan request first validates the requested target
    against the ScopeTarget table. If the target is not present, the
    request is blocked with an HTTP 403.
    """

    @wraps(func)
    async def wrapper(request: Request, *args, **kwargs):
        # Grab target from the URL (e.g. ?target=127.0.0.1 or ?target=example.com)
        target = request.query_params.get("target")

        if not target:
            raise HTTPException(status_code=400, detail="Target parameter required")

        # Run sync DB check in thread pool to avoid blocking the event loop
        allowed = await asyncio.to_thread(scope_engine.is_ip_allowed, target)
        if not allowed:
            raise HTTPException(
                status_code=403,
                detail=f"Target {target} is NOT authorized.",
            )

        # Inject the validated target so the decorated function receives the actual
        # string instead of relying on FastAPI's injection (which runs after the
        # decorator and would otherwise leave target as the Query default).
        return await func(request, *args, **kwargs)

    return wrapper
