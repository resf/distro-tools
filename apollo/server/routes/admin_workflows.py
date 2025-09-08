"""
Admin workflows route for manual workflow triggering via web interface
"""
import os
from datetime import datetime, timezone
from fastapi import APIRouter, Request, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from typing import List, Optional

from apollo.server.utils import templates, admin_user_scheme
from apollo.server.services.workflow_service import WorkflowService
from apollo.server.services.database_service import DatabaseService
from apollo.db import User
from common.logger import Logger

router = APIRouter(tags=["admin-workflows"])


@router.get("/workflows", response_class=HTMLResponse)
async def admin_workflows(request: Request, user: User = Depends(admin_user_scheme)):
    """Render admin workflows page for manual workflow triggering"""
    db_service = DatabaseService()
    env_info = await db_service.get_environment_info()
    
    return templates.TemplateResponse(
        "admin_workflows.jinja", {
            "request": request,
            "user": user,
            "env_name": env_info["environment"],
            "is_production": env_info["is_production"],
            "reset_allowed": env_info["reset_allowed"],
        }
    )


@router.post("/workflows/rh-matcher/trigger")
async def trigger_rh_matcher(
    request: Request,
    major_versions: Optional[List[str]] = Form(default=None),
    user: User = Depends(admin_user_scheme)
):
    """Trigger RHMatcherWorkflow from admin web interface"""
    try:
        # Convert string versions to integers if provided
        int_versions = None
        if major_versions:
            int_versions = [int(v) for v in major_versions if v.isdigit()]
        
        service = WorkflowService()
        workflow_id = await service.trigger_rh_matcher_workflow(int_versions)
        
        Logger().info(f"Admin user {user.email} triggered RhMatcherWorkflow {workflow_id} with major_versions: {int_versions}")
        
        # Store success message in session
        request.session["workflow_message"] = f"RhMatcherWorkflow triggered successfully: {workflow_id}"
        request.session["workflow_type"] = "success"
        
    except ValueError as e:
        Logger().error(f"Validation error triggering RhMatcher workflow: {str(e)}")
        request.session["workflow_message"] = f"Error: {str(e)}"
        request.session["workflow_type"] = "error"
        
    except Exception as e:
        Logger().error(f"Error triggering RhMatcher workflow: {str(e)}")
        request.session["workflow_message"] = f"Error triggering workflow: {str(e)}"
        request.session["workflow_type"] = "error"
    
    return RedirectResponse(url="/admin/workflows", status_code=303)


@router.post("/workflows/poll-rhcsaf/trigger")
async def trigger_poll_rhcsaf(
    request: Request,
    user: User = Depends(admin_user_scheme)
):
    """Trigger PollRHCSAFAdvisoriesWorkflow from admin web interface"""
    try:
        service = WorkflowService()
        workflow_id = await service.trigger_poll_rhcsaf_workflow()
        
        Logger().info(f"Admin user {user.email} triggered PollRHCSAFAdvisoriesWorkflow {workflow_id}")
        
        # Store success message in session
        request.session["workflow_message"] = f"PollRHCSAFAdvisoriesWorkflow triggered successfully: {workflow_id}"
        request.session["workflow_type"] = "success"
        
    except Exception as e:
        Logger().error(f"Error triggering PollRHCSAF workflow: {str(e)}")
        request.session["workflow_message"] = f"Error triggering workflow: {str(e)}"
        request.session["workflow_type"] = "error"
    
    return RedirectResponse(url="/admin/workflows", status_code=303)


@router.get("/workflows/database/preview-reset")
async def preview_database_reset(
    request: Request,
    cutoff_date: str,
    user: User = Depends(admin_user_scheme)
):
    """Preview the impact of a partial database reset"""
    try:
        db_service = DatabaseService()
        
        # Parse the date string
        try:
            cutoff_datetime = datetime.fromisoformat(cutoff_date).replace(tzinfo=timezone.utc)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid date format. Use YYYY-MM-DD.")
        
        preview_result = await db_service.preview_partial_reset(cutoff_datetime)
        return JSONResponse(preview_result)
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        Logger().error(f"Error previewing database reset: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to preview database reset")


@router.post("/workflows/database/partial-reset")
async def perform_database_reset(
    request: Request,
    cutoff_date: str = Form(...),
    confirm: bool = Form(False),
    user: User = Depends(admin_user_scheme)
):
    """Perform partial database reset"""
    try:
        if not confirm:
            request.session["workflow_message"] = "Reset not performed: confirmation required"
            request.session["workflow_type"] = "error"
            return RedirectResponse(url="/admin/workflows", status_code=303)
        
        db_service = DatabaseService()
        
        # Parse the date string
        try:
            cutoff_datetime = datetime.fromisoformat(cutoff_date).replace(tzinfo=timezone.utc)
        except ValueError:
            request.session["workflow_message"] = "Invalid date format. Use YYYY-MM-DD."
            request.session["workflow_type"] = "error"
            return RedirectResponse(url="/admin/workflows", status_code=303)
        
        result = await db_service.perform_partial_reset(cutoff_datetime, user.email)
        
        Logger().info(f"Admin user {user.email} performed partial database reset with cutoff {cutoff_date}")
        
        # Store success message in session
        request.session["workflow_message"] = f"Database reset completed: {result['message']}"
        request.session["workflow_type"] = "success"
        
    except ValueError as e:
        Logger().error(f"Validation error in database reset: {str(e)}")
        request.session["workflow_message"] = f"Reset failed: {str(e)}"
        request.session["workflow_type"] = "error"
        
    except Exception as e:
        Logger().error(f"Error performing database reset: {str(e)}")
        request.session["workflow_message"] = f"Reset failed: {str(e)}"
        request.session["workflow_type"] = "error"
    
    return RedirectResponse(url="/admin/workflows", status_code=303)