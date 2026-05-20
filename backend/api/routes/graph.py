from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ...core.identity_graph import IdentityGraph
from ...db.database import get_db
from ...db.models import Investigation

router = APIRouter()


@router.get("/report/{investigation_id}/graph")
async def get_investigation_graph(
    investigation_id: str,
    session: AsyncSession = Depends(get_db),
) -> dict:
    """Return the identity graph in D3.js force-directed format."""
    result = await session.execute(
        select(Investigation)
        .where(Investigation.id == investigation_id)
        .options(
            selectinload(Investigation.findings),
        )
    )
    inv = result.scalar_one_or_none()
    if inv is None:
        raise HTTPException(status_code=404, detail="Investigation not found")

    if inv.graph_data and inv.graph_data.get("nodes"):
        return {
            "nodes": inv.graph_data.get("nodes", []),
            "links": inv.graph_data.get("links", []),
        }

    if inv.status.value != "complete":
        raise HTTPException(
            status_code=409,
            detail="Investigation not complete — graph not yet available",
        )

    graph_input = {
        "email": inv.email,
        "findings": [
            {"module_name": f.module_name, "data": f.data}
            for f in inv.findings
        ],
    }
    graph = IdentityGraph.build(graph_input)
    d3 = graph.to_d3()
    return d3
