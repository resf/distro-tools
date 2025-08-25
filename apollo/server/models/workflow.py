"""
Pydantic models for workflow management API
"""
from typing import Optional, List, Any
from datetime import datetime

from pydantic import BaseModel, Field


class ProductInfo(BaseModel):
    """Information about a supported product"""
    id: int
    name: str
    variant: str
    vendor: str
    code: Optional[str] = None

    class Config:
        orm_mode = True


class WorkflowTriggerRequest(BaseModel):
    """Request model for triggering RhMatcherWorkflow"""
    product_ids: Optional[List[int]] = Field(
        None,
        description="Optional list of supported product IDs to process. If omitted, processes all products."
    )


class WorkflowTriggerResponse(BaseModel):
    """Response model for workflow trigger"""
    workflow_id: str
    status: str = "started"
    message: str = "Workflow triggered successfully"
    filtered_products: Optional[List[int]] = None


class WorkflowStatusResponse(BaseModel):
    """Response model for workflow status"""
    workflow_id: str
    status: str  # running, completed, error
    result: Optional[Any] = None
    error: Optional[str] = None
    execution_info: Optional[dict] = None


class WorkflowListItem(BaseModel):
    """Sanitized workflow information for public listing"""
    workflow_id: str
    status: str
    workflow_type: str = "RhMatcherWorkflow"
    started_at: Optional[datetime] = None


class WorkflowListResponse(BaseModel):
    """Response model for workflow listing"""
    workflows: List[WorkflowListItem]
    total_count: int


class ProductListResponse(BaseModel):
    """Response model for product listing"""
    products: List[ProductInfo]
    total_count: int