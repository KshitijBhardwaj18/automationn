"""FastAPI application for BYOC Platform."""

from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI

from api.routes.configs import router as configs_router
from api.routes.deployments import router as deployments_router
from api.routes.cluster import router as cluster_router

app = FastAPI(
    title="Cortex Prod automation",
    description="Multi-tenant infrastructure deployment API. "
    "Manage customer configurations and deploy EKS infrastructure.",
    version="1.0.0",
)

app.include_router(configs_router)
app.include_router(deployments_router)
app.include_router(cluster_router)


@app.get("/health", tags=["health"])
async def health_check() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
