"""Root-level /health for load balancers (Render health checks)."""

from fastapi import APIRouter

from app.api.v1.routes.health import liveness

router = APIRouter(include_in_schema=False)
router.add_api_route("/health", liveness, methods=["GET"])
