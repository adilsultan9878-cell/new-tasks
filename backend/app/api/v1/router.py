from fastapi import APIRouter

from app.api.v1.routes import (
    agent,
    audit,
    auth,
    dashboard,
    devices,
    events,
    health,
    intel,
    network,
    notifications,
    organizations,
    realtime,
)

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(organizations.router)
api_router.include_router(dashboard.router)
api_router.include_router(audit.router)
api_router.include_router(notifications.router)
api_router.include_router(devices.router)
api_router.include_router(events.router)
api_router.include_router(agent.router)
api_router.include_router(realtime.router)
api_router.include_router(intel.router)
api_router.include_router(network.router)
