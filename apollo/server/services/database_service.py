"""
Database service for safe database operations including partial resets
"""
import os
from datetime import datetime, timezone
from typing import Dict, Any
from tortoise.transactions import in_transaction

from apollo.db import RedHatAdvisory, RedHatIndexState
from common.logger import Logger


class DatabaseService:
    """Service class for safe database operations"""
    
    def __init__(self):
        pass
    
    def is_production_environment(self) -> bool:
        """Check if running in production environment"""
        return os.environ.get("ENV", "development").lower() == "production"
    
    async def preview_partial_reset(self, cutoff_date: datetime) -> Dict[str, Any]:
        """
        Preview the impact of a partial reset without making changes
        
        Args:
            cutoff_date: Delete advisories created after this date
            
        Returns:
            Dictionary with counts of records that would be affected
            
        Raises:
            ValueError: If in production environment or invalid date
        """
        if self.is_production_environment():
            raise ValueError("Database reset operations are not allowed in production environment")
        
        # Validate cutoff date
        if cutoff_date >= datetime.now(timezone.utc):
            raise ValueError("Cutoff date must be in the past")
        
        # Count records that would be affected
        rh_advisories_count = await RedHatAdvisory.filter(created_at__gt=cutoff_date).count()
        
        Logger().info(f"Preview partial reset: {rh_advisories_count} Red Hat advisories would be deleted after {cutoff_date}")
        
        return {
            "cutoff_date": cutoff_date.isoformat(),
            "red_hat_advisories_count": rh_advisories_count,
            "note": "Related records (packages, CVEs, bugzilla bugs, etc.) will be deleted automatically via CASCADE constraints"
        }
    
    async def perform_partial_reset(self, cutoff_date: datetime, user_email: str) -> Dict[str, Any]:
        """
        Perform partial database reset by deleting Red Hat advisories after cutoff date
        
        Args:
            cutoff_date: Delete advisories created after this date
            user_email: Email of user performing the reset (for logging)
            
        Returns:
            Dictionary with operation results
            
        Raises:
            ValueError: If in production environment or invalid date
            RuntimeError: If database operation fails
        """
        if self.is_production_environment():
            raise ValueError("Database reset operations are not allowed in production environment")
        
        # Validate cutoff date
        if cutoff_date >= datetime.now(timezone.utc):
            raise ValueError("Cutoff date must be in the past")
        
        logger = Logger()
        
        try:
            async with in_transaction() as conn:
                # First, count what we're about to delete for logging
                count_before = await RedHatAdvisory.filter(created_at__gt=cutoff_date).count()
                
                if count_before == 0:
                    logger.info(f"No Red Hat advisories found after {cutoff_date}, no reset needed")
                    return {
                        "success": True,
                        "deleted_count": 0,
                        "cutoff_date": cutoff_date.isoformat(),
                        "message": "No advisories found after cutoff date"
                    }
                
                # Delete advisories (CASCADE will handle related records)
                deleted_count = await RedHatAdvisory.filter(created_at__gt=cutoff_date).delete()
                
                # Update the red_hat_index_state table
                # Get or create the index state record (there should only be one)
                index_state = await RedHatIndexState.first()
                if index_state:
                    index_state.last_indexed_at = cutoff_date
                    await index_state.save()
                else:
                    # Create new index state record if none exists
                    await RedHatIndexState.create(last_indexed_at=cutoff_date)
                
                logger.info(f"Partial database reset completed by {user_email}: deleted {deleted_count} Red Hat advisories after {cutoff_date}")
                
                return {
                    "success": True,
                    "deleted_count": deleted_count,
                    "cutoff_date": cutoff_date.isoformat(),
                    "updated_index_state": True,
                    "message": f"Successfully deleted {deleted_count} advisories and updated index state"
                }
                
        except Exception as e:
            logger.error(f"Partial database reset failed: {str(e)}")
            raise RuntimeError(f"Database reset operation failed: {str(e)}")
    
    async def get_environment_info(self) -> Dict[str, str]:
        """Get current environment information"""
        env_name = os.environ.get("ENV", "development")
        return {
            "environment": env_name,
            "is_production": self.is_production_environment(),
            "reset_allowed": not self.is_production_environment()
        }