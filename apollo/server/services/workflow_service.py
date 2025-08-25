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
    
    async def trigger_rh_matcher_workflow(self, major_versions: Optional[List[int]] = None) -> str:
        """
        Trigger RhMatcherWorkflow with optional major version filtering
        
        Args:
            major_versions: Optional list of Rocky Linux major versions to process (e.g., [8, 9, 10])
                           If None, processes all versions (backward compatibility)
        
        Returns:
            Workflow ID for tracking
        """
        temporal_client = await self._get_temporal_client()
        
        if not temporal_client or not temporal_client.client:
            raise RuntimeError("Temporal client not initialized")
        
        # Validate major versions if provided
        if major_versions:
            await self._validate_major_versions(major_versions)
        
        # Create workflow input
        workflow_input = RhMatcherWorkflowInput(major_versions=major_versions) if major_versions else None
        
        # Generate unique workflow ID
        workflow_id = f"rh-matcher-{uuid.uuid4()}"
        
        self.logger.info(f"Starting RhMatcherWorkflow with ID: {workflow_id}, major_versions: {major_versions}")
        
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
    
    async def _validate_major_versions(self, major_versions: List[int]) -> None:
        """
        Validate that the provided major versions are available in RH mirrors
        
        Args:
            major_versions: List of major versions to validate
            
        Raises:
            ValueError: If any major version is invalid
        """
        if not major_versions:
            return
        
        # Import here to avoid circular imports
        from apollo.db import SupportedProductsRhMirror
        
        # Get available major versions from RH mirrors
        rh_mirrors = await SupportedProductsRhMirror.all()
        available_versions = {int(mirror.match_major_version) for mirror in rh_mirrors}
        
        # Check if all requested major versions are available
        invalid_versions = set(major_versions) - available_versions
        if invalid_versions:
            raise ValueError(f"Invalid major versions: {sorted(invalid_versions)}. Available: {sorted(available_versions)}")
        
        self.logger.info(f"Validated major versions: {major_versions}")