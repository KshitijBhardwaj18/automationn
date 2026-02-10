"""Customer configuration management endpoints."""

from typing import Union

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import JSONResponse

from api.config_resolver import resolve_customer_config
from api.config_storage import config_storage
from api.models import (
    CustomerConfigInput,
    CustomerConfigListResponse,
    CustomerConfigResolved,
    CustomerConfigResponse,
    ValidationErrorResponse,
)
from api.validation import ConfigValidationError, validate_config

router = APIRouter(prefix="/api/v1/configs", tags=["configurations"])


@router.post(
    "",
    response_model=CustomerConfigResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create customer configuration",
    description="""Create a new customer configuration.""",
    responses={
        201: {"description": "Configuration created successfully"},
        400: {"model": ValidationErrorResponse, "description": "Validation error"},
        409: {"description": "Configuration already exists"},
    },
)
async def create_config(
    request: CustomerConfigInput,
) -> Union[CustomerConfigResponse, JSONResponse]:
    """Create a new customer configuration."""

    if config_storage.exists(request.customer_id):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Configuration for customer '{request.customer_id}' already exists. "
            "Use PUT to update.",
        )

    try:
        resolved = resolve_customer_config(request)

        validate_config(request, resolved)

        config_storage.save(request.customer_id, resolved)

        return CustomerConfigResponse.from_resolved(resolved)

    except ConfigValidationError as e:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=e.to_response().model_dump(),
        )


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
        configs=[CustomerConfigResponse.from_resolved(c) for c in configs],
        total=len(configs),
    )


@router.get(
    "/{customer_id}",
    response_model=CustomerConfigResolved,
    summary="Get customer configuration",
    description="Retrieve a specific customer's fully-resolved configuration.",
)
async def get_config(customer_id: str) -> CustomerConfigResolved:
    """Get a customer configuration by ID."""
    config = config_storage.get(customer_id)
    if config is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Configuration for customer '{customer_id}' not found",
        )

    return config


@router.put(
    "/{customer_id}",
    response_model=CustomerConfigResponse,
    summary="Update customer configuration",
    description="""Update an existing customer's configuration.""",
    responses={
        200: {"description": "Configuration updated successfully"},
        400: {"model": ValidationErrorResponse, "description": "Validation error"},
        404: {"description": "Configuration not found"},
    },
)
async def update_config(
    customer_id: str,
    request: CustomerConfigInput,
) -> Union[CustomerConfigResponse, JSONResponse]:
    """Update a customer configuration."""
   
    existing_config = config_storage.get(customer_id)
    if existing_config is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Configuration for customer '{customer_id}' not found",
        )


    if request.customer_id != customer_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Customer ID in request body '{request.customer_id}' does not match URL '{customer_id}'",
        )

    try:
       
        resolved = resolve_customer_config(request)

       
        resolved.created_at = existing_config.created_at

     
        validate_config(request, resolved)

      
        config_storage.save(customer_id, resolved)

        return CustomerConfigResponse.from_resolved(resolved)

    except ConfigValidationError as e:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=e.to_response().model_dump(),
        )


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


@router.post(
    "/validate",
    response_model=CustomerConfigResponse,
    summary="Validate configuration without saving",
    description="""Validate a configuration and return the resolved result without saving.""",
    responses={
        200: {"description": "Configuration is valid"},
        400: {"model": ValidationErrorResponse, "description": "Validation error"},
    },
)
async def validate_config_endpoint(
    request: CustomerConfigInput,
) -> Union[CustomerConfigResponse, JSONResponse]:
    """Validate a configuration without saving it."""
    try:
        
        resolved = resolve_customer_config(request)

        validate_config(request, resolved)

        return CustomerConfigResponse.from_resolved(resolved)

    except ConfigValidationError as e:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=e.to_response().model_dump(),
        )
