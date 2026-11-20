from fastapi import APIRouter

from app.api.v1.routes import audit, auth, dashboard, health, notifications, organizations

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(organizations.router)
api_router.include_router(dashboard.router)
api_router.include_router(audit.router)
api_router.include_router(notifications.router)
