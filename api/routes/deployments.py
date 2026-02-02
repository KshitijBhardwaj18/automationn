"""Deployment management endpoints."""

import json

from fastapi import APIRouter, BackgroundTasks, HTTPException, status

from api.config_storage import config_storage
from api.database import Database, db
from api.models import (
    CustomerConfigResolved,
    CustomerDeployment,
    DeploymentResponse,
    DeploymentStatus,
    DeployRequest,
    DestroyRequest,
)
from api.pulumi_deployments import PulumiDeploymentsClient
from api.settings import settings

router = APIRouter(prefix="/api/v1/deployments", tags=["deployments"])


def get_pulumi_client() -> PulumiDeploymentsClient:
    """Get Pulumi Deployments client."""
    return PulumiDeploymentsClient(
        organization=settings.pulumi_org,
        access_token=settings.pulumi_access_token,
        aws_access_key_id=settings.aws_access_key_id,
        aws_secret_access_key=settings.aws_secret_access_key,
        github_token=settings.github_token or None,
    )


async def run_deployment(
    config: CustomerConfigResolved,
    environment: str,
    database: Database,
) -> None:
    """Background task to run customer deployment."""
    stack_name = f"{config.customer_id}-{environment}"

    try:
        client = get_pulumi_client()

        database.update_deployment_status(
            stack_name=stack_name,
            status=DeploymentStatus.IN_PROGRESS,
        )

        try:
            await client.create_stack(
                project_name=settings.pulumi_project,
                stack_name=stack_name,
            )
        except Exception:
            pass

        await client.configure_deployment_settings(
            project_name=settings.pulumi_project,
            stack_name=stack_name,
            config=config,
            repo_url=settings.git_repo_url,
            repo_branch=settings.git_repo_branch,
            repo_dir=settings.git_repo_dir,
        )

        result = await client.trigger_deployment(
            project_name=settings.pulumi_project,
            stack_name=stack_name,
            operation="update",
        )

        deployment_id = result.get("id", "")

        database.update_deployment_status(
            stack_name=stack_name,
            status=DeploymentStatus.IN_PROGRESS,
            pulumi_deployment_id=deployment_id,
        )

    except Exception as e:
        database.update_deployment_status(
            stack_name=stack_name,
            status=DeploymentStatus.FAILED,
            error_message=str(e),
        )


@router.post(
    "/{customer_id}",
    response_model=DeploymentResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Deploy customer infrastructure",
    description="Trigger infrastructure deployment for a customer using their stored "
    "configuration.",
)
async def deploy(
    customer_id: str,
    request: DeployRequest,
    background_tasks: BackgroundTasks,
) -> DeploymentResponse:
    """Deploy infrastructure for a customer."""
    config = config_storage.get(customer_id)
    if config is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Configuration for customer '{customer_id}' not found. "
            "Create a configuration first using POST /api/v1/configs",
        )

    stack_name = f"{customer_id}-{request.environment}"

    existing = db.get_deployment(customer_id, request.environment)
    if existing:
        if existing.status == DeploymentStatus.IN_PROGRESS:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Deployment {stack_name} is already in progress",
            )
        if existing.status == DeploymentStatus.DESTROYING:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Deployment {stack_name} is being destroyed. "
                "Wait for destruction to complete.",
            )

    if existing is None:
        try:
            db.create_deployment(
                customer_id=customer_id,
                environment=request.environment,
                aws_region=config.aws_config.region,
                role_arn=config.aws_config.role_arn,
            )
        except ValueError as e:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    else:
        db.update_deployment_status(
            stack_name=stack_name,
            status=DeploymentStatus.PENDING,
        )

    background_tasks.add_task(run_deployment, config, request.environment, db)

    return DeploymentResponse(
        customer_id=customer_id,
        environment=request.environment,
        stack_name=stack_name,
        status=DeploymentStatus.PENDING,
        message="Deployment initiated. Check status endpoint for progress.",
    )


@router.get(
    "/{customer_id}/{environment}/status",
    response_model=CustomerDeployment,
    summary="Get deployment status",
    description="Get the current status of a customer deployment.",
)
async def get_deployment_status(
    customer_id: str,
    environment: str = "prod",
) -> CustomerDeployment:
    """Get the current deployment status."""
    deployment = db.get_deployment(customer_id, environment)
    if not deployment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Deployment for {customer_id}-{environment} not found",
        )

    if (
        deployment.status
        in (
            DeploymentStatus.IN_PROGRESS,
            DeploymentStatus.DESTROYING,
        )
        and deployment.pulumi_deployment_id
    ):
        try:
            client = get_pulumi_client()
            pulumi_status = await client.get_deployment_status(
                project_name=settings.pulumi_project,
                stack_name=deployment.stack_name,
                deployment_id=deployment.pulumi_deployment_id,
            )

            status_value = pulumi_status.get("status", "")
            is_destroying = deployment.status == DeploymentStatus.DESTROYING

            if status_value == "succeeded":
                if is_destroying:
                    db.update_deployment_status(
                        stack_name=deployment.stack_name,
                        status=DeploymentStatus.DESTROYED,
                    )
                else:
                    outputs = await client.get_stack_outputs(
                        project_name=settings.pulumi_project,
                        stack_name=deployment.stack_name,
                    )
                    db.update_deployment_status(
                        stack_name=deployment.stack_name,
                        status=DeploymentStatus.SUCCEEDED,
                        outputs=json.dumps(outputs),
                    )
                updated = db.get_deployment(customer_id, environment)
                if updated:
                    deployment = updated
            elif status_value == "failed":
                error_msg = pulumi_status.get("message", "Operation failed")
                if is_destroying:
                    error_msg = f"Destroy failed: {error_msg}"
                db.update_deployment_status(
                    stack_name=deployment.stack_name,
                    status=DeploymentStatus.FAILED,
                    error_message=error_msg,
                )
                updated = db.get_deployment(customer_id, environment)
                if updated:
                    deployment = updated
        except Exception:
            pass

    return CustomerDeployment(
        id=deployment.id,
        customer_id=deployment.customer_id,
        environment=deployment.environment,
        stack_name=deployment.stack_name,
        aws_region=deployment.aws_region,
        role_arn=deployment.role_arn,
        status=deployment.status,
        pulumi_deployment_id=deployment.pulumi_deployment_id,
        outputs=json.loads(deployment.outputs) if deployment.outputs else None,
        error_message=deployment.error_message,
        created_at=deployment.created_at,
        updated_at=deployment.updated_at,
    )


@router.get(
    "/{customer_id}",
    response_model=list[CustomerDeployment],
    summary="List customer deployments",
    description="List all deployments for a customer across environments.",
)
async def list_customer_deployments(customer_id: str) -> list[CustomerDeployment]:
    """List all deployments for a customer."""
    deployments = db.get_deployments_by_customer(customer_id)
    return [
        CustomerDeployment(
            id=d.id,
            customer_id=d.customer_id,
            environment=d.environment,
            stack_name=d.stack_name,
            aws_region=d.aws_region,
            role_arn=d.role_arn,
            status=d.status,
            pulumi_deployment_id=d.pulumi_deployment_id,
            outputs=json.loads(d.outputs) if d.outputs else None,
            error_message=d.error_message,
            created_at=d.created_at,
            updated_at=d.updated_at,
        )
        for d in deployments
    ]


async def run_destroy(
    customer_id: str,
    environment: str,
    database: Database,
) -> None:
    """Background task to destroy customer infrastructure."""
    stack_name = f"{customer_id}-{environment}"

    try:
        client = get_pulumi_client()

        database.update_deployment_status(
            stack_name=stack_name,
            status=DeploymentStatus.DESTROYING,
        )

        result = await client.trigger_deployment(
            project_name=settings.pulumi_project,
            stack_name=stack_name,
            operation="destroy",
        )

        deployment_id = result.get("id", "")

        database.update_deployment_status(
            stack_name=stack_name,
            status=DeploymentStatus.DESTROYING,
            pulumi_deployment_id=deployment_id,
        )

    except Exception as e:
        database.update_deployment_status(
            stack_name=stack_name,
            status=DeploymentStatus.FAILED,
            error_message=f"Destroy failed: {e}",
        )


@router.post(
    "/{customer_id}/{environment}/destroy",
    response_model=DeploymentResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Destroy customer infrastructure",
    description="Trigger destruction of customer infrastructure. Requires explicit "
    "confirmation. This operation cannot be undone.",
)
async def destroy(
    customer_id: str,
    environment: str,
    request: DestroyRequest,
    background_tasks: BackgroundTasks,
) -> DeploymentResponse:
    """Destroy infrastructure for a customer."""
    stack_name = f"{customer_id}-{environment}"

    existing = db.get_deployment(customer_id, environment)
    if not existing:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Deployment {stack_name} not found",
        )

    if existing.status == DeploymentStatus.IN_PROGRESS:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Deployment {stack_name} is in progress. "
            "Wait for it to complete before destroying.",
        )
    if existing.status == DeploymentStatus.DESTROYING:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Deployment {stack_name} is already being destroyed",
        )
    if existing.status == DeploymentStatus.DESTROYED:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Deployment {stack_name} has already been destroyed",
        )

    background_tasks.add_task(run_destroy, customer_id, environment, db)

    return DeploymentResponse(
        customer_id=customer_id,
        environment=environment,
        stack_name=stack_name,
        status=DeploymentStatus.DESTROYING,
        message="Destruction initiated. Check status endpoint for progress. "
        "This operation cannot be undone.",
    )
