from fastapi import APIRouter

from .routes.investigations import router as investigations_router
from .routes.modules import router as modules_router
from .websocket import router as ws_router

api_router = APIRouter()
api_router.include_router(investigations_router, tags=["investigations"])
api_router.include_router(modules_router, prefix="/modules", tags=["modules"])

__all__ = ["api_router", "ws_router"]
