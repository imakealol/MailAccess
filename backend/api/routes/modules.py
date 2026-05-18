from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from ...modules import get_all_modules

router = APIRouter()


class ModuleInfo(BaseModel):
    name: str
    description: str
    requires_key: bool


@router.get("/", response_model=list[ModuleInfo])
async def list_modules() -> list[ModuleInfo]:
    return [
        ModuleInfo(
            name=m.name,
            description=m.description,
            requires_key=m.requires_key,
        )
        for m in get_all_modules()
    ]
