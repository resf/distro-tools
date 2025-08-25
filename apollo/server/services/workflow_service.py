"""
Workflow service for managing Temporal workflows from Apollo server
"""
import uuid
from typing import Optional, List, Dict, Any
from datetime import datetime

from temporalio.client import WorkflowHandle

from apollo.db import SupportedProduct
from apollo.rpmworker.rh_matcher_workflows import RhMatcherWorkflow, RhMatcherWorkflowInput
from apollo.rpmworker.temporal import TASK_QUEUE
from common.temporal import Temporal
from common.logger import Logger


class WorkflowService:
    """Service class for managing workflow operations"""
    
    def __init__(self):
        self.logger = Logger()
        self._temporal_client = None
    
    async def _get_temporal_client(self):
        """Get or create Temporal client"""
        if self._temporal_client is None:
            temporal = Temporal(True)
            await temporal.connect()
            self._temporal_client = temporal
        return self._temporal_client
    
    async def get_available_products(self) -> List[Dict[str, Any]]:
        """Get list of available products for filtering"""
        products = await SupportedProduct.all().prefetch_related("code")
        
        return [
            {
                "id": product.id,
                "name": product.name,
                "variant": product.variant,
                "vendor": product.vendor,
                "code": product.code.code if product.code else None
            }
            for product in products
        ]
    
    async def trigger_rh_matcher_workflow(self, product_ids: Optional[List[int]] = None) -> str:
        """
        Trigger RhMatcherWorkflow with optional product filtering
        
        Args:
            product_ids: Optional list of supported product IDs to process
                        If None, processes all products (backward compatibility)
        
        Returns:
            Workflow ID for tracking
        """
        temporal_client = await self._get_temporal_client()
        
        if not temporal_client or not temporal_client.client:
            raise RuntimeError("Temporal client not initialized")
        
        # Validate product IDs if provided
        if product_ids:
            await self._validate_product_ids(product_ids)
        
        # Create workflow input
        workflow_input = RhMatcherWorkflowInput(supported_product_ids=product_ids) if product_ids else None
        
        # Generate unique workflow ID
        workflow_id = f"rh-matcher-{uuid.uuid4()}"
        
        self.logger.info(f"Starting RhMatcherWorkflow with ID: {workflow_id}, products: {product_ids}")
        
        # Start the workflow
        workflow_handle: WorkflowHandle = await temporal_client.client.start_workflow(
            RhMatcherWorkflow.run,
            workflow_input,
            id=workflow_id,
            task_queue=TASK_QUEUE,
        )
        
        return workflow_id
    
    async def get_workflow_status(self, workflow_id: str) -> Dict[str, Any]:
        """
        Get status of a specific workflow
        
        Args:
            workflow_id: The workflow ID to check
        
        Returns:
            Dictionary containing workflow status information
        """
        temporal_client = await self._get_temporal_client()
        
        if not temporal_client or not temporal_client.client:
            raise RuntimeError("Temporal client not initialized")
        
        try:
            workflow_handle = temporal_client.client.get_workflow_handle(workflow_id)
            
            # Check workflow status without blocking
            try:
                # Try to get result with timeout to avoid blocking
                import asyncio
                result = await asyncio.wait_for(workflow_handle.result(), timeout=1.0)
                status = "completed"
                result_data = result
            except asyncio.TimeoutError:
                # Workflow is still running
                status = "running"
                result_data = None
            except Exception as e:
                # Check if workflow failed
                if "workflow execution already completed" in str(e).lower():
                    # Try to get the result without timeout
                    try:
                        result = await workflow_handle.result()
                        status = "completed"
                        result_data = result
                    except Exception:
                        status = "failed"
                        result_data = str(e)
                else:
                    status = "error"
                    result_data = str(e)
            
            return {
                "workflow_id": workflow_id,
                "status": status,
                "result": result_data,
                "execution_info": {
                    "workflow_id": workflow_id,
                    "run_id": workflow_handle.run_id if hasattr(workflow_handle, 'run_id') else None
                }
            }
            
        except Exception as e:
            self.logger.error(f"Error getting workflow status for {workflow_id}: {str(e)}")
            return {
                "workflow_id": workflow_id,
                "status": "error",
                "error": str(e)
            }
    
    async def list_recent_workflows(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        List recent workflows (sanitized for public access)
        
        Args:
            limit: Maximum number of workflows to return
        
        Returns:
            List of workflow information dictionaries
        """
        # Note: This is a simplified implementation
        # In a full implementation, you might query Temporal's visibility API
        # or maintain a database table of workflow executions
        
        # For now, return empty list - this would need to be implemented
        # based on how you want to track workflow history
        self.logger.info("list_recent_workflows called - implementation needed for workflow history tracking")
        return []
    
    async def _validate_product_ids(self, product_ids: List[int]) -> None:
        """
        Validate that the provided product IDs exist and have RH mirrors
        
        Args:
            product_ids: List of product IDs to validate
            
        Raises:
            ValueError: If any product ID is invalid
        """
        if not product_ids:
            return
        
        # Check if all product IDs exist
        existing_products = await SupportedProduct.filter(id__in=product_ids).all()
        existing_ids = {p.id for p in existing_products}
        
        missing_ids = set(product_ids) - existing_ids
        if missing_ids:
            raise ValueError(f"Invalid product IDs: {sorted(missing_ids)}")
        
        self.logger.info(f"Validated product IDs: {product_ids}")