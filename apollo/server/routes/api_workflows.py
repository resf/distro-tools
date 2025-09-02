"""
API routes for workflow management
"""
from fastapi import APIRouter, Depends, HTTPException, status
from typing import List

from apollo.server.models.workflow import (
    ProductListResponse, ProductInfo, WorkflowTriggerRequest,
    WorkflowTriggerResponse, WorkflowStatusResponse, WorkflowListResponse
)
from apollo.server.services.workflow_service import WorkflowService
from apollo.server.utils import admin_user_scheme, user_scheme
from apollo.server.auth import workflow_api_key_auth, api_key_or_session_auth
from apollo.db import User
from common.logger import Logger

router = APIRouter(tags=["workflows"])


@router.get("/products", response_model=ProductListResponse)
async def list_products():
    """
    Get list of available products for workflow filtering.
    Public endpoint - no authentication required.
    """
    try:
        service = WorkflowService()
        products = await service.get_available_products()
        
        return ProductListResponse(
            products=[ProductInfo(**product) for product in products],
            total_count=len(products)
        )
    except Exception as e:
        logger = Logger()
        logger.error(f"Error listing products: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve products"
        )


@router.post("/rh-matcher/trigger", response_model=WorkflowTriggerResponse)
async def trigger_rh_matcher_workflow(
    request: WorkflowTriggerRequest,
    user: User = Depends(workflow_api_key_auth)
):
    """
    Trigger RhMatcherWorkflow with optional major version filtering.
    Requires API key with 'workflow:trigger' permission.
    """
    try:
        service = WorkflowService()
        workflow_id = await service.trigger_rh_matcher_workflow(request.major_versions)
        
        logger = Logger()
        logger.info(f"User {user.email} triggered RhMatcherWorkflow {workflow_id} with major_versions: {request.major_versions}")
        
        return WorkflowTriggerResponse(
            workflow_id=workflow_id,
            status="started",
            message="RhMatcherWorkflow triggered successfully",
            filtered_major_versions=request.major_versions
        )
        
    except ValueError as e:
        # Handle validation errors (invalid major versions)
        logger = Logger()
        logger.error(f"Validation error triggering workflow: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except RuntimeError as e:
        # Handle Temporal client errors
        logger = Logger()
        logger.error(f"Runtime error triggering workflow: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Workflow service unavailable"
        )
    except Exception as e:
        logger = Logger()
        logger.error(f"Error triggering workflow: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to trigger workflow"
        )


@router.post("/poll-rhcsaf/trigger", response_model=WorkflowTriggerResponse)
async def trigger_poll_rhcsaf_workflow(
    user: User = Depends(workflow_api_key_auth)
):
    """
    Trigger PollRHCSAFAdvisoriesWorkflow to poll Red Hat CSAF advisories.
    Requires API key with 'workflow:trigger' permission.
    """
    try:
        service = WorkflowService()
        workflow_id = await service.trigger_poll_rhcsaf_workflow()
        
        logger = Logger()
        logger.info(f"User {user.email} triggered PollRHCSAFAdvisoriesWorkflow {workflow_id}")
        
        return WorkflowTriggerResponse(
            workflow_id=workflow_id,
            status="started",
            message="PollRHCSAFAdvisoriesWorkflow triggered successfully"
        )
        
    except RuntimeError as e:
        # Handle Temporal client errors
        logger = Logger()
        logger.error(f"Runtime error triggering PollRHCSAF workflow: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Workflow service unavailable"
        )
    except Exception as e:
        logger = Logger()
        logger.error(f"Error triggering PollRHCSAF workflow: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to trigger workflow"
        )


@router.get("/{workflow_id}/status", response_model=WorkflowStatusResponse)
async def get_workflow_status(
    workflow_id: str,
    user: User = Depends(workflow_api_key_auth)
):
    """
    Get status of a specific workflow.
    Requires API key with 'workflow:trigger' permission.
    """
    try:
        service = WorkflowService()
        status_info = await service.get_workflow_status(workflow_id)
        
        return WorkflowStatusResponse(**status_info)
        
    except Exception as e:
        logger = Logger()
        logger.error(f"Error getting workflow status for {workflow_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve workflow status"
        )


@router.get("/list", response_model=WorkflowListResponse)
async def list_workflows(limit: int = 50):
    """
    List recent workflows (sanitized for public access).
    Public endpoint - no authentication required initially.
    """
    try:
        service = WorkflowService()
        workflows = await service.list_recent_workflows(limit)
        
        return WorkflowListResponse(
            workflows=workflows,
            total_count=len(workflows)
        )
        
    except Exception as e:
        logger = Logger()
        logger.error(f"Error listing workflows: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve workflows"
        )