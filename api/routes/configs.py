"""Customer configuration management endpoints."""

from fastapi import APIRouter, HTTPException, status

from api.config_storage import config_storage
from api.models import (
    CustomerConfig,
    CustomerConfigCreate,
    CustomerConfigListResponse,
    CustomerConfigResponse,
    CustomerConfigUpdate,
)

router = APIRouter(prefix="/api/v1/configs", tags=["configurations"])


@router.post(
    "",
    response_model=CustomerConfigResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create customer configuration",
    description="Create a new customer configuration. The configuration will be stored "
    "and can be used for deployments.",
)
async def create_config(request: CustomerConfigCreate) -> CustomerConfigResponse:
    """Create a new customer configuration. """
    if config_storage.exists(request.customer_id):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Configuration for customer '{request.customer_id}' already exists. "
            "Use PUT to update.",
        )

    config = CustomerConfig.from_create_request(request)
    config_storage.save(request.customer_id, config)

    return CustomerConfigResponse.from_config(config)


@router.get(
    "",
    response_model=CustomerConfigListResponse,
    summary="List all customer configurations",
    description="Retrieve all customer configurations.",
)
async def list_configs() -> CustomerConfigListResponse:
    """List all customer configurations."""
    configs = config_storage.list_all()
    return CustomerConfigListResponse(
        configs=[CustomerConfigResponse.from_config(c) for c in configs],
        total=len(configs),
    )


@router.get(
    "/{customer_id}",
    response_model=CustomerConfigResponse,
    summary="Get customer configuration",
    description="Retrieve a specific customer's configuration.",
)
async def get_config(customer_id: str) -> CustomerConfigResponse:
    """Get a customer configuration by ID"""
    config = config_storage.get(customer_id)
    if config is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Configuration for customer '{customer_id}' not found",
        )

    return CustomerConfigResponse.from_config(config)


@router.put(
    "/{customer_id}",
    response_model=CustomerConfigResponse,
    summary="Update customer configuration",
    description="Update an existing customer's configuration. Only provided fields "
    "will be updated.",
)
async def update_config(
    customer_id: str,
    request: CustomerConfigUpdate,
) -> CustomerConfigResponse:
    """Update a customer configuration."""
    existing_config = config_storage.get(customer_id)
    if existing_config is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Configuration for customer '{customer_id}' not found",
        )

    updated_config = existing_config.apply_update(request)
    config_storage.save(customer_id, updated_config)

    return CustomerConfigResponse.from_config(updated_config)


@router.delete(
    "/{customer_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete customer configuration",
    description="Delete a customer's configuration. This does not destroy any "
    "deployed infrastructure.",
)
async def delete_config(customer_id: str) -> None:
    """Delete a customer configuration."""
    if not config_storage.delete(customer_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Configuration for customer '{customer_id}' not found",
        )