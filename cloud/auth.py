"""FastAPI dependency that validates X-API-Key and returns the Customer."""

from __future__ import annotations

from fastapi import HTTPException, Security
from fastapi.security import APIKeyHeader

from cloud import db

_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def get_customer(api_key: str | None = Security(_key_header)) -> db.Customer:
    if not api_key:
        raise HTTPException(status_code=401, detail="Missing X-API-Key header")
    customer = await db.get_customer(api_key)
    if customer is None:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return customer
