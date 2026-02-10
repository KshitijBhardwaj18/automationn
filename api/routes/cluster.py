from fastapi import APIRouter, HTTPException, Query, status

from api.config_storage import config_storage
from api.database import db
from api.models import (
    AddonInstallResult,
    DeploymentStatus,
    SsmSessionResponse,
    SsmStatusResponse,
)
from api.services.addon_installer import AddonInstallerService
from api.services.ssm_access import SsmAccessService

router = APIRouter(prefix="/api/v1/clusters", tags=["cluster access"])


@router.get(
    "/{customer_id}/{environment}/ssm/status",
    response_model=SsmStatusResponse,
    summary="Get SSM access status",
    description="Check if SSM access is configured and ready for a private cluster",
)
async def get_ssm_status(
    customer_id: str,
    environment: str = "prod",
) -> SsmStatusResponse:
    """Get SSM access node status and readiness."""
    
    deployment = db.get_deployment(customer_id, environment)
    if not deployment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Deployment {customer_id}-{environment} not found",
        )

    if deployment.status != DeploymentStatus.SUCCEEDED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Deployment is not ready. Status: {deployment.status.value}",
        )

    try:
        service = SsmAccessService(customer_id, environment)
        
        node_status = await service.get_access_node_status()
        
        vpc_endpoints = await service.check_vpc_endpoints()
        
        issues = []
        
        if not node_status.enabled:
            issues.append("SSM access node is not enabled in deployment config")
        elif node_status.instance_state != "running":
            issues.append(f"Access node is not running (state: {node_status.instance_state})")
        
        if not vpc_endpoints.get("ssm"):
            issues.append("VPC endpoint for SSM is not configured")
        if not vpc_endpoints.get("ssmmessages"):
            issues.append("VPC endpoint for SSM Messages is not configured")
        if not vpc_endpoints.get("ec2messages"):
            issues.append("VPC endpoint for EC2 Messages is not configured")
        
        ready = len(issues) == 0
        
        return SsmStatusResponse(
            customer_id=customer_id,
            environment=environment,
            cluster_name=service.outputs.get("eks_cluster_name", ""),
            access_node=node_status,
            vpc_endpoints=vpc_endpoints,
            ready=ready,
            issues=issues,
        )

    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get SSM status: {str(e)}",
        )


@router.post(
    "/{customer_id}/{environment}/ssm/session",
    response_model=SsmSessionResponse,
    summary="Get SSM session info",
    description="Get commands and instructions to start an SSM session",
)
async def get_ssm_session(
    customer_id: str,
    environment: str = "prod",
) -> SsmSessionResponse:
    """Get SSM session connection information."""
    
    deployment = db.get_deployment(customer_id, environment)
    if not deployment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Deployment {customer_id}-{environment} not found",
        )

    if deployment.status != DeploymentStatus.SUCCEEDED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Deployment is not ready. Status: {deployment.status.value}",
        )

    try:
        service = SsmAccessService(customer_id, environment)
        session_info = await service.get_session_info()
        
        return SsmSessionResponse(
            customer_id=customer_id,
            environment=environment,
            session=session_info,
        )

    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get session info: {str(e)}",
        )


@router.post(
    "/{customer_id}/{environment}/ssm/start",
    summary="Start access node",
    description="Start a stopped SSM access node",
)
async def start_access_node(
    customer_id: str,
    environment: str = "prod",
) -> dict:
    """Start the SSM access node (if stopped)."""
    deployment = db.get_deployment(customer_id, environment)
    if not deployment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Deployment {customer_id}-{environment} not found",
        )

    if deployment.status != DeploymentStatus.SUCCEEDED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Deployment is not ready. Status: {deployment.status.value}",
        )

    try:
        service = SsmAccessService(customer_id, environment)
        result = await service.start_access_node()
        return result
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to start access node: {str(e)}",
        )


@router.post(
    "/{customer_id}/{environment}/ssm/stop",
    summary="Stop access node",
    description="Stop the SSM access node to save costs",
)
async def stop_access_node(
    customer_id: str,
    environment: str = "prod",
) -> dict:
    """Stop the SSM access node (to save costs when not in use)."""
    deployment = db.get_deployment(customer_id, environment)
    if not deployment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Deployment {customer_id}-{environment} not found",
        )

    if deployment.status != DeploymentStatus.SUCCEEDED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Deployment is not ready. Status: {deployment.status.value}",
        )

    try:
        service = SsmAccessService(customer_id, environment)
        result = await service.stop_access_node()
        return result
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to stop access node: {str(e)}",
        )


# -- ArgoCD Addon Endpoints --


@router.post(
    "/{customer_id}/{environment}/addons/argocd/install",
    response_model=AddonInstallResult,
    summary="Install ArgoCD",
    description="Install ArgoCD on the EKS cluster via SSM Run Command on the access node. "
    "Returns immediately with a command ID that can be polled for status.",
)
async def install_argocd(
    customer_id: str,
    environment: str = "prod",
) -> AddonInstallResult:
    """Trigger ArgoCD installation via SSM Run Command."""
    deployment = db.get_deployment(customer_id, environment)
    if not deployment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Deployment {customer_id}-{environment} not found",
        )

    if deployment.status != DeploymentStatus.SUCCEEDED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Deployment must be in SUCCEEDED state. Current: {deployment.status.value}",
        )

    config = config_storage.get(customer_id)
    if not config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Configuration for customer '{customer_id}' not found",
        )

    if not config.addons or not config.addons.argocd or not config.addons.argocd.enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ArgoCD is not enabled in the customer configuration. "
            "Update the config with addons.argocd.enabled = true first.",
        )

    try:
        installer = AddonInstallerService(customer_id, environment)
        result = await installer.install_argocd(config.addons.argocd)
        return result
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to trigger ArgoCD installation: {str(e)}",
        )


@router.get(
    "/{customer_id}/{environment}/addons/argocd/status",
    response_model=AddonInstallResult,
    summary="Get ArgoCD install status",
    description="Check the status of an ArgoCD installation. "
    "If no command_id is provided, checks the most recent installation.",
)
async def get_argocd_install_status(
    customer_id: str,
    environment: str = "prod",
    command_id: str | None = Query(
        default=None,
        description="SSM command ID from the install response. "
        "If omitted, checks the most recent install.",
    ),
) -> AddonInstallResult:
    """Check ArgoCD installation status via SSM command invocation."""
    deployment = db.get_deployment(customer_id, environment)
    if not deployment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Deployment {customer_id}-{environment} not found",
        )

    try:
        installer = AddonInstallerService(customer_id, environment)
        result = await installer.get_install_status(command_id=command_id)
        return result
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get ArgoCD install status: {str(e)}",
        )