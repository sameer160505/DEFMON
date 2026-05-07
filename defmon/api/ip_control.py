"""DefMon admin IP access-control endpoints."""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from defmon.api.auth import RoleChecker
from defmon.database import get_db
from defmon.models import AuditLog, BlockedIP, User, UserRole

ip_control_router = APIRouter(prefix="/ip-control", tags=["IP Control"])
allow_admin = RoleChecker([UserRole.ADMIN])


class BlockIPRequest(BaseModel):
    ip: str = Field(min_length=3, max_length=45)
    reason: str = Field(default="Blocked by admin", max_length=500)


def _serialize_blocked_ip(row: BlockedIP) -> dict:
    return {
        "id": row.id,
        "ip": row.ip,
        "reason": row.reason,
        "blocked_by": row.blocked_by,
        "blocked_at": row.blocked_at.isoformat() if row.blocked_at else None,
    }


async def _write_audit(db: AsyncSession, action: str, actor: str, target: str, details: str) -> None:
    db.add(
        AuditLog(
            action=action,
            actor=actor,
            target=target,
            details=details,
            timestamp=datetime.utcnow(),
        )
    )


@ip_control_router.get("/blocked")
async def list_blocked_ips(
    user: User = Depends(allow_admin),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    result = await db.execute(select(BlockedIP).order_by(desc(BlockedIP.blocked_at)))
    return [_serialize_blocked_ip(row) for row in result.scalars().all()]


@ip_control_router.post("/blocked", status_code=status.HTTP_201_CREATED)
async def block_ip(
    payload: BlockIPRequest,
    user: User = Depends(allow_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    existing = await db.execute(select(BlockedIP).where(BlockedIP.ip == payload.ip.strip()))
    row = existing.scalar_one_or_none()

    if row is None:
        row = BlockedIP(
            ip=payload.ip.strip(),
            reason=payload.reason.strip() or "Blocked by admin",
            blocked_at=datetime.utcnow(),
            blocked_by=f"admin:{user.username}",
        )
        db.add(row)
    else:
        row.reason = payload.reason.strip() or row.reason
        row.blocked_by = f"admin:{user.username}"
        row.blocked_at = datetime.utcnow()

    await _write_audit(
        db,
        action="ADMIN_BLOCK_IP",
        actor=user.username,
        target=row.ip,
        details=row.reason,
    )

    await db.flush()
    return {"blocked_ip": _serialize_blocked_ip(row)}


@ip_control_router.delete("/blocked/{ip}")
async def unblock_ip(
    ip: str,
    user: User = Depends(allow_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    result = await db.execute(select(BlockedIP).where(BlockedIP.ip == ip))
    row = result.scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Blocked IP not found")

    await _write_audit(
        db,
        action="ADMIN_UNBLOCK_IP",
        actor=user.username,
        target=row.ip,
        details=row.reason,
    )

    await db.delete(row)
    return {"unblocked": True, "ip": ip}
