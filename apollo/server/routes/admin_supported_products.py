import json
import math
from decimal import Decimal
from math import ceil
from typing import Optional, Union, Type, Dict, Any, List, Tuple
from urllib.parse import quote

from fastapi import APIRouter, Request, Depends, Form, Query, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi_pagination import Params
from fastapi_pagination.ext.tortoise import paginate

from tortoise.models import Model
from apollo.db import (
    SupportedProduct,
    SupportedProductsRhMirror,
    SupportedProductsRpmRepomd,
    SupportedProductsRhBlock,
    SupportedProductsRpmRhOverride,
    RedHatAdvisory,
    AdvisoryPackage,
    AdvisoryAffectedProduct,
    Code
)
from apollo.server.utils import templates
from apollo.server.validation import (
    FieldValidator,
    FormValidator,
    ConfigValidator,
    ValidationError,
    get_supported_architectures
)


async def get_entity_or_error_response(
    request: Request,
    model_class: Type[Model],
    error_name: str,
    entity_id: Optional[int] = None,
    filters: Optional[Dict] = None,
    prefetch_related: Optional[List[str]] = None
) -> Union[Model, Response]:
    """Get an entity by ID or filters, or return error template response."""

    # Build the query
    if entity_id is not None:
        query = model_class.get_or_none(id=entity_id)
    elif filters:
        query = model_class.get_or_none(**filters)
    else:
        raise ValueError("Either entity_id or filters must be provided")

    # Add prefetch_related if specified
    if prefetch_related:
        query = query.prefetch_related(*prefetch_related)

    entity = await query

    if entity is None:
        return templates.TemplateResponse(
            "error.jinja", {
                "request": request,
                "message": f"{error_name} not found",
            }
        )
    return entity


async def check_mirror_dependencies(mirror) -> Tuple[int, int]:
    """
    Check dependencies for a single mirror.

    Args:
        mirror: The mirror object to check

    Returns:
        Tuple[int, int]: (blocks_count, overrides_count)
    """
    blocks_count = await SupportedProductsRhBlock.filter(
        supported_products_rh_mirror=mirror
    ).count()
    overrides_count = await SupportedProductsRpmRhOverride.filter(
        supported_products_rh_mirror=mirror
    ).count()

    return blocks_count, overrides_count


def format_dependency_error_parts(blocks_count: int, overrides_count: int) -> List[str]:
    """
    Format dependency counts into error message parts.

    Args:
        blocks_count: Number of blocks
        overrides_count: Number of overrides

    Returns:
        List[str]: List of formatted error parts
    """
    error_parts = []
    if blocks_count > 0:
        error_parts.append(f"{blocks_count} blocked product(s)")
    if overrides_count > 0:
        error_parts.append(f"{overrides_count} override(s)")

    return error_parts




def create_error_redirect(base_url: str, error_message: str) -> RedirectResponse:
    """
    Create a RedirectResponse with URL-encoded error message.

    Args:
        base_url: Base URL to redirect to
        error_message: Error message to include

    Returns:
        RedirectResponse: Configured redirect response
    """
    return RedirectResponse(
        f"{base_url}?error={quote(error_message)}",
        status_code=302
    )


def create_success_redirect(base_url: str, success_message: str) -> RedirectResponse:
    """
    Create a RedirectResponse with URL-encoded success message.

    Args:
        base_url: Base URL to redirect to
        success_message: Success message to include

    Returns:
        RedirectResponse: Configured redirect response
    """
    return RedirectResponse(
        f"{base_url}?success={quote(success_message)}",
        status_code=302
    )


router = APIRouter(tags=["non-api"])


@router.get("/", response_class=HTMLResponse)
async def admin_supported_products(
    request: Request,
    params: Params = Depends(),
    success: Optional[str] = None,
    error: Optional[str] = None
):
    params.size = 50
    products = await paginate(
        SupportedProduct.all().order_by("name").prefetch_related("rh_mirrors"),
        params=params,
    )

    # Get statistics for each product
    for product in products.items:
        mirrors_count = await SupportedProductsRhMirror.filter(supported_product=product).count()
        repomds_count = await SupportedProductsRpmRepomd.filter(
            supported_products_rh_mirror__supported_product=product
        ).count()
        blocks_count = await SupportedProductsRhBlock.filter(
            supported_products_rh_mirror__supported_product=product
        ).count()
        overrides_count = await SupportedProductsRpmRhOverride.filter(
            supported_products_rh_mirror__supported_product=product
        ).count()

        product.stats = {
            'mirrors': mirrors_count,
            'repomds': repomds_count,
            'blocks': blocks_count,
            'overrides': overrides_count,
        }

    return templates.TemplateResponse(
        "admin_supported_products.jinja", {
            "request": request,
            "products": products,
            "products_pages": ceil(products.total / products.size),
            "success": success,
            "error": error,
        }
    )

@router.get("/export")
async def export_all_configs(
    major_version: Optional[int] = Query(None),
    arch: Optional[str] = Query(None),
    production_only: Optional[bool] = Query(None)
):
    """Export configurations for all supported products as JSON with optional filtering"""
    # Build query with filters
    query = SupportedProductsRhMirror.all()
    if major_version is not None:
        query = query.filter(match_major_version=major_version)
    if arch is not None:
        query = query.filter(match_arch=arch)

    mirrors = await query.prefetch_related(
        "supported_product",
        "rpm_repomds"
    ).all()

    # Filter repositories by production status if specified
    config_data = []
    for mirror in mirrors:
        mirror_data = await _get_mirror_config_data(mirror)
        if production_only is not None:
            mirror_data["repositories"] = [
                repo for repo in mirror_data["repositories"]
                if repo["production"] == production_only
            ]
        config_data.append(mirror_data)

    formatted_data = _format_export_data(config_data)

    filename_parts = ["all_products_config"]
    if major_version is not None:
        filename_parts.append(f"v{major_version}")
    if arch is not None:
        filename_parts.append(arch)
    if production_only is not None:
        filename_parts.append("prod" if production_only else "staging")

    filename = "_".join(filename_parts) + ".json"

    return Response(
        content=formatted_data,
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

async def _validate_import_data(import_data: List[Dict[str, Any]]) -> List[str]:
    """Validate imported configuration data and return list of errors"""
    return ConfigValidator.validate_import_data_structure(import_data)

async def _import_configuration(import_data: List[Dict[str, Any]], replace_existing: bool = False) -> Dict[str, Any]:
    """Import configuration data into database"""
    created_count = 0
    updated_count = 0
    skipped_count = 0

    for config in import_data:
        product_data = config["product"]
        mirror_data = config["mirror"]
        repositories_data = config["repositories"]

        # Find or create product
        product = await SupportedProduct.get_or_none(name=product_data["name"])
        if not product:
            # For import, we should require products to exist already
            skipped_count += 1
            continue

        # Check if mirror already exists
        existing_mirror = await SupportedProductsRhMirror.get_or_none(
            supported_product=product,
            name=mirror_data["name"],
            match_variant=mirror_data["match_variant"],
            match_major_version=mirror_data["match_major_version"],
            match_minor_version=mirror_data.get("match_minor_version"),
            match_arch=mirror_data["match_arch"]
        )

        if existing_mirror and not replace_existing:
            skipped_count += 1
            continue

        if existing_mirror and replace_existing:
            # Delete existing repositories
            await SupportedProductsRpmRepomd.filter(supported_products_rh_mirror=existing_mirror).delete()
            mirror = existing_mirror
            # Update active field if provided
            mirror.active = mirror_data.get("active", True)
            await mirror.save()
            updated_count += 1
        else:
            # Create new mirror
            mirror = SupportedProductsRhMirror(
                supported_product=product,
                name=mirror_data["name"],
                match_variant=mirror_data["match_variant"],
                match_major_version=mirror_data["match_major_version"],
                match_minor_version=mirror_data.get("match_minor_version"),
                match_arch=mirror_data["match_arch"],
                active=mirror_data.get("active", True)
            )
            await mirror.save()
            created_count += 1

        # Create repositories
        for repo_data in repositories_data:
            repo = SupportedProductsRpmRepomd(
                supported_products_rh_mirror=mirror,
                repo_name=repo_data["repo_name"],
                arch=repo_data["arch"],
                production=repo_data["production"],
                url=repo_data["url"],
                debug_url=repo_data.get("debug_url", ""),
                source_url=repo_data.get("source_url", "")
            )
            await repo.save()

    return {
        "created": created_count,
        "updated": updated_count,
        "skipped": skipped_count
    }

@router.post("/import")
async def import_configurations(
    request: Request,
    file: UploadFile = File(...),
    replace_existing: bool = Form(False)
):
    """Import repository configurations from JSON file"""
    if not file.filename.endswith('.json'):
        return RedirectResponse(
            f"/admin/supported-products?error={quote('File must be a JSON file (.json extension required)')}",
            status_code=302
        )

    try:
        content = await file.read()
        import_data = json.loads(content.decode('utf-8'))
    except json.JSONDecodeError as e:
        return RedirectResponse(
            f"/admin/supported-products?error={quote(f'Invalid JSON file: {str(e)}')}",
            status_code=302
        )
    except Exception as e:
        return RedirectResponse(
            f"/admin/supported-products?error={quote(f'Error reading file: {str(e)}')}",
            status_code=302
        )

    # Validate import data
    validation_errors = await _validate_import_data(import_data)
    if validation_errors:
        # Limit the number of errors shown to avoid overwhelming the user
        max_errors = 20
        if len(validation_errors) > max_errors:
            shown_errors = validation_errors[:max_errors]
            error_message = f"Validation errors ({len(validation_errors)} total, showing first {max_errors}):\n" + "\n".join(shown_errors)
        else:
            error_message = "Validation errors:\n" + "\n".join(validation_errors)

        return RedirectResponse(
            f"/admin/supported-products?error={quote(error_message)}",
            status_code=302
        )

    # Import the data
    try:
        results = await _import_configuration(import_data, replace_existing)
        success_message = f"Import completed: {results['created']} created, {results['updated']} updated, {results['skipped']} skipped"

        return RedirectResponse(
            f"/admin/supported-products?success={quote(success_message)}",
            status_code=302
        )
    except Exception as e:
        return RedirectResponse(
            f"/admin/supported-products?error={quote(f'Import failed: {str(e)}')}",
            status_code=302
        )

@router.get("/{product_id}", response_class=HTMLResponse)
async def admin_supported_product(request: Request, product_id: int):
    product = await get_entity_or_error_response(
        request,
        SupportedProduct,
        f"Supported product with id {product_id}",
        entity_id=product_id,
        prefetch_related=["code"]
    )
    if isinstance(product, Response):
        return product

    # Fetch mirrors with explicit ordering: active first, then by version (desc), then by name
    mirrors = await SupportedProductsRhMirror.filter(
        supported_product=product
    ).order_by("-active", "-match_major_version", "name").prefetch_related("rpm_repomds").all()

    # Get detailed statistics for each mirror
    for mirror in mirrors:
        repomds_count = await SupportedProductsRpmRepomd.filter(
            supported_products_rh_mirror=mirror
        ).count()
        blocks_count = await SupportedProductsRhBlock.filter(
            supported_products_rh_mirror=mirror
        ).count()
        overrides_count = await SupportedProductsRpmRhOverride.filter(
            supported_products_rh_mirror=mirror
        ).count()

        mirror.stats = {
            'repomds': repomds_count,
            'blocks': blocks_count,
            'overrides': overrides_count,
        }

    return templates.TemplateResponse(
        "admin_supported_product.jinja", {
            "request": request,
            "product": product,
            "mirrors": mirrors,
        }
    )


@router.post("/{product_id}/delete", response_class=HTMLResponse)
async def admin_supported_product_delete(
    request: Request,
    product_id: int
):
    product = await SupportedProduct.get_or_none(id=product_id)
    if product is None:
        return templates.TemplateResponse(
            "error.jinja", {
                "request": request,
                "message": f"Supported product with id {product_id} not found",
            }
        )

    # Check for existing mirrors (which would contain blocks, overrides, and repomds)
    mirrors_count = await SupportedProductsRhMirror.filter(supported_product=product).count()

    # Check for existing advisory packages and affected products
    packages_count = await AdvisoryPackage.filter(supported_product=product).count()
    affected_products_count = await AdvisoryAffectedProduct.filter(supported_product=product).count()

    if mirrors_count > 0 or packages_count > 0 or affected_products_count > 0:
        error_parts = []
        if mirrors_count > 0:
            error_parts.append(f"{mirrors_count} mirror(s)")
        if packages_count > 0:
            error_parts.append(f"{packages_count} advisory package(s)")
        if affected_products_count > 0:
            error_parts.append(f"{affected_products_count} affected product(s)")

        error_message = (f"Cannot delete supported product '{product.name}' because it has associated "
                        f"{', '.join(error_parts)}. Please remove these dependencies first.")

        return templates.TemplateResponse(
            "error.jinja", {
                "request": request,
                "message": error_message,
            }
        )

    await product.delete()
    return RedirectResponse("/admin/supported-products?success=Supported product deleted successfully", status_code=302)

@router.get("/{product_id}/mirrors/new", response_class=HTMLResponse)
async def admin_supported_product_mirror_new(request: Request, product_id: int):
    product = await get_entity_or_error_response(
        request,
        SupportedProduct,
        f"Supported product with id {product_id}",
        entity_id=product_id
    )
    if isinstance(product, Response):
        return product

    return templates.TemplateResponse(
        "admin_supported_product_mirror_new.jinja", {
            "request": request,
            "product": product,
        }
    )

@router.post("/{product_id}/mirrors/new", response_class=HTMLResponse)
async def admin_supported_product_mirror_new_post(
    request: Request,
    product_id: int,
    name: str = Form(),
    match_variant: str = Form(),
    match_major_version: int = Form(),
    match_minor_version: Optional[int] = Form(default=None),
    match_arch: str = Form(),
):
    product = await get_entity_or_error_response(
        request,
        SupportedProduct,
        f"Supported product with id {product_id}",
        entity_id=product_id
    )
    if isinstance(product, Response):
        return product

    # Parse form data to get the active field
    form_data_raw = await request.form()
    # When checkbox is checked: active will be ["false", "true"], take the last value
    # When checkbox is unchecked: active will be ["false"], take that value
    active_values = form_data_raw.getlist("active")
    active_value = active_values[-1] if active_values else "false"

    # Validation using centralized validation utility
    form_data = {
        "name": name,
        "match_variant": match_variant,
        "match_major_version": match_major_version,
        "match_minor_version": match_minor_version,
        "match_arch": match_arch,
        "active": active_value,
    }

    try:
        validated_name = FieldValidator.validate_name(
            name,
            min_length=3,
            field_name="mirror name"
        )
        validated_arch = FieldValidator.validate_architecture(
            match_arch,
            field_name="architecture"
        )
    except ValidationError as e:
        return templates.TemplateResponse(
            "admin_supported_product_mirror_new.jinja", {
                "request": request,
                "product": product,
                "error": e.message,
                "form_data": form_data
            }
        )

    mirror = SupportedProductsRhMirror(
        supported_product=product,
        name=validated_name,
        match_variant=match_variant,
        match_major_version=match_major_version,
        match_minor_version=match_minor_version,
        match_arch=validated_arch,
        active=(active_value == "true"),
    )
    await mirror.save()

    return RedirectResponse(f"/admin/supported-products/{product_id}", status_code=302)

@router.get("/{product_id}/mirrors/{mirror_id}", response_class=HTMLResponse)
async def admin_supported_product_mirror(request: Request, product_id: int, mirror_id: int):
    mirror = await get_entity_or_error_response(
        request,
        SupportedProductsRhMirror,
        f"Mirror with id {mirror_id}",
        filters={"id": mirror_id, "supported_product_id": product_id},
        prefetch_related=[
            "supported_product",
            "rpm_repomds",
            "rh_blocks",
            "rh_blocks__red_hat_advisory",
            "rpm_rh_overrides",
            "rpm_rh_overrides__red_hat_advisory"
        ]
    )
    if isinstance(mirror, Response):
        return mirror

    return templates.TemplateResponse(
        "admin_supported_product_mirror.jinja", {
            "request": request,
            "mirror": mirror,
        }
    )


@router.post("/{product_id}/mirrors/{mirror_id}", response_class=HTMLResponse)
async def admin_supported_product_mirror_post(
    request: Request,
    product_id: int,
    mirror_id: int,
    name: str = Form(),
    match_variant: str = Form(),
    match_major_version: int = Form(),
    match_minor_version: Optional[int] = Form(default=None),
    match_arch: str = Form(),
):
    mirror = await get_entity_or_error_response(
        request,
        SupportedProductsRhMirror,
        f"Mirror with id {mirror_id}",
        filters={"id": mirror_id, "supported_product_id": product_id},
        prefetch_related=[
            "supported_product",
            "rpm_repomds",
            "rh_blocks",
            "rh_blocks__red_hat_advisory",
            "rpm_rh_overrides",
            "rpm_rh_overrides__red_hat_advisory"
        ]
    )
    if isinstance(mirror, Response):
        return mirror

    # Parse form data to get the active field
    form_data = await request.form()
    # When checkbox is checked: active will be ["false", "true"], take the last value
    # When checkbox is unchecked: active will be ["false"], take that value
    active_values = form_data.getlist("active")
    active_value = active_values[-1] if active_values else "false"

    # Validation using centralized validation utility
    try:
        validated_name = FieldValidator.validate_name(
            name,
            min_length=3,
            field_name="mirror name"
        )
        validated_arch = FieldValidator.validate_architecture(
            match_arch,
            field_name="architecture"
        )
    except ValidationError as e:
        return templates.TemplateResponse(
            "admin_supported_product_mirror.jinja", {
                "request": request,
                "mirror": mirror,
                "error": e.message,
            }
        )

    mirror.name = validated_name
    mirror.match_variant = match_variant
    mirror.match_major_version = match_major_version
    mirror.match_minor_version = match_minor_version
    mirror.match_arch = validated_arch
    mirror.active = (active_value == "true")
    await mirror.save()

    # Re-fetch the mirror with all required relations after saving
    mirror = await SupportedProductsRhMirror.get_or_none(
        id=mirror_id,
        supported_product_id=product_id
    ).prefetch_related(
        "supported_product",
        "rpm_repomds",
        "rh_blocks",
        "rh_blocks__red_hat_advisory",
        "rpm_rh_overrides",
        "rpm_rh_overrides__red_hat_advisory"
    )

    return templates.TemplateResponse(
        "admin_supported_product_mirror.jinja", {
            "request": request,
            "mirror": mirror,
            "success": "Mirror updated successfully",
        }
    )


@router.post("/{product_id}/mirrors/{mirror_id}/delete", response_class=HTMLResponse)
async def admin_supported_product_mirror_delete(
    request: Request,
    product_id: int,
    mirror_id: int
):
    mirror = await get_entity_or_error_response(
        request,
        SupportedProductsRhMirror,
        f"Mirror with id {mirror_id}",
        filters={"id": mirror_id, "supported_product_id": product_id},
        prefetch_related=["supported_product"]
    )
    if isinstance(mirror, Response):
        return mirror

    # Check for existing blocks and overrides using shared logic
    blocks_count, overrides_count = await check_mirror_dependencies(mirror)

    if blocks_count > 0 or overrides_count > 0:
        error_parts = format_dependency_error_parts(blocks_count, overrides_count)
        error_message = (f"Cannot delete mirror '{mirror.name}' because it has associated "
                        f"{' and '.join(error_parts)}. Please remove these dependencies first.")

        return templates.TemplateResponse(
            "error.jinja", {
                "request": request,
                "message": error_message,
            }
        )

    await mirror.delete()
    return RedirectResponse(f"/admin/supported-products/{product_id}", status_code=302)


@router.post("/{product_id}/bulk-delete-mirrors", response_class=HTMLResponse)
async def admin_supported_product_mirrors_bulk_delete(
    request: Request,
    product_id: int,
    mirror_ids: str = Form(),
):
    """Bulk delete multiple mirrors by calling individual delete logic for each mirror"""
    base_url = f"/admin/supported-products/{product_id}"

    # Parse and validate mirror IDs
    if not mirror_ids or not mirror_ids.strip():
        return create_error_redirect(base_url, "No mirror IDs provided")

    try:
        mirror_id_list = [int(id_str.strip()) for id_str in mirror_ids.split(",") if id_str.strip()]
        if not mirror_id_list:
            return create_error_redirect(base_url, "No valid mirror IDs provided")
        # Validate all IDs are positive
        for id_val in mirror_id_list:
            if id_val <= 0:
                return create_error_redirect(base_url, "All mirror IDs must be positive numbers")
    except ValueError:
        return create_error_redirect(base_url, "Invalid mirror IDs: must be comma-separated numbers")

    # Get all mirrors to delete
    mirrors = await SupportedProductsRhMirror.filter(
        id__in=mirror_id_list, supported_product_id=product_id
    ).prefetch_related("supported_product")

    if not mirrors:
        return create_error_redirect(base_url, "No mirrors found with provided IDs")

    # Process each mirror individually using existing single delete logic
    successful_deletes = []
    failed_deletes = []

    for mirror in mirrors:
        # Check for existing blocks and overrides using shared logic
        blocks_count, overrides_count = await check_mirror_dependencies(mirror)

        if blocks_count > 0 or overrides_count > 0:
            # Mirror has dependencies, cannot delete
            error_parts = format_dependency_error_parts(blocks_count, overrides_count)
            error_reason = f"{' and '.join(error_parts)}"
            failed_deletes.append({"name": mirror.name, "reason": error_reason})
        else:
            # Mirror can be deleted
            try:
                await mirror.delete()
                successful_deletes.append(mirror.name)
            except Exception as e:
                failed_deletes.append({"name": mirror.name, "reason": f"deletion failed: {str(e)}"})

    # Build result message with clear formatting
    message_parts = []

    if successful_deletes:
        message_parts.append(f"✓ DELETED {len(successful_deletes)} mirror(s): {', '.join(successful_deletes)}")

    if failed_deletes:
        failed_summary = []
        for item in failed_deletes:
            failed_summary.append(f"{item['name']} ({item['reason']})")
        message_parts.append(f"✗ FAILED TO DELETE {len(failed_deletes)} mirror(s): {'; '.join(failed_summary)}")

    message = ". ".join(message_parts)

    # If we had any successful deletes, treat as success even if some failed
    if successful_deletes:
        return create_success_redirect(base_url, message)
    else:
        # All deletes failed
        return create_error_redirect(base_url, message)


# Repository (repomd) management routes
@router.get("/{product_id}/mirrors/{mirror_id}/repomds/new", response_class=HTMLResponse)
async def admin_supported_product_mirror_repomd_new(
    request: Request,
    product_id: int,
    mirror_id: int
):
    mirror = await get_entity_or_error_response(
        request,
        SupportedProductsRhMirror,
        f"Mirror with id {mirror_id}",
        filters={"id": mirror_id, "supported_product_id": product_id},
        prefetch_related=["supported_product"]
    )
    if isinstance(mirror, Response):
        return mirror

    return templates.TemplateResponse(
        "admin_supported_product_repomd_new.jinja", {
            "request": request,
            "mirror": mirror,
        }
    )


@router.post("/{product_id}/mirrors/{mirror_id}/repomds/new", response_class=HTMLResponse)
async def admin_supported_product_mirror_repomd_new_post(
    request: Request,
    product_id: int,
    mirror_id: int,
    production: bool = Form(),
    arch: str = Form(),
    url: str = Form(),
    debug_url: str = Form(""),
    source_url: str = Form(""),
    repo_name: str = Form(),
):
    mirror = await get_entity_or_error_response(
        request,
        SupportedProductsRhMirror,
        f"Mirror with id {mirror_id}",
        filters={"id": mirror_id, "supported_product_id": product_id},
        prefetch_related=["supported_product"]
    )
    if isinstance(mirror, Response):
        return mirror

    # Validation using centralized validation utility
    form_data = {
        "production": production,
        "arch": arch,
        "url": url,
        "debug_url": debug_url,
        "source_url": source_url,
        "repo_name": repo_name,
    }

    validated_data, validation_errors = FormValidator.validate_repomd_form(form_data)

    if validation_errors:
        return templates.TemplateResponse(
            "admin_supported_product_repomd_new.jinja", {
                "request": request,
                "mirror": mirror,
                "error": validation_errors[0],  # Show first error
                "form_data": form_data
            }
        )

    repomd = SupportedProductsRpmRepomd(
        supported_products_rh_mirror=mirror,
        production=validated_data['production'],
        arch=validated_data['arch'],
        url=validated_data['url'],
        debug_url=validated_data['debug_url'],
        source_url=validated_data['source_url'],
        repo_name=validated_data['repo_name'],
    )
    await repomd.save()

    return RedirectResponse(f"/admin/supported-products/{product_id}/mirrors/{mirror_id}", status_code=302)


@router.get("/{product_id}/mirrors/{mirror_id}/repomds/{repomd_id}", response_class=HTMLResponse)
async def admin_supported_product_mirror_repomd(
    request: Request,
    product_id: int,
    mirror_id: int,
    repomd_id: int
):
    repomd = await get_entity_or_error_response(
        request,
        SupportedProductsRpmRepomd,
        f"Repository configuration with id {repomd_id}",
        filters={
            "id": repomd_id,
            "supported_products_rh_mirror_id": mirror_id,
            "supported_products_rh_mirror__supported_product_id": product_id
        },
        prefetch_related=["supported_products_rh_mirror", "supported_products_rh_mirror__supported_product"]
    )
    if isinstance(repomd, Response):
        return repomd

    return templates.TemplateResponse(
        "admin_supported_product_repomd.jinja", {
            "request": request,
            "repomd": repomd,
        }
    )


@router.post("/{product_id}/mirrors/{mirror_id}/repomds/{repomd_id}", response_class=HTMLResponse)
async def admin_supported_product_mirror_repomd_post(
    request: Request,
    product_id: int,
    mirror_id: int,
    repomd_id: int,
    production: bool = Form(),
    arch: str = Form(),
    url: str = Form(),
    debug_url: str = Form(""),
    source_url: str = Form(""),
    repo_name: str = Form(),
):
    repomd = await get_entity_or_error_response(
        request,
        SupportedProductsRpmRepomd,
        f"Repository configuration with id {repomd_id}",
        filters={
            "id": repomd_id,
            "supported_products_rh_mirror_id": mirror_id,
            "supported_products_rh_mirror__supported_product_id": product_id
        },
        prefetch_related=["supported_products_rh_mirror", "supported_products_rh_mirror__supported_product"]
    )
    if isinstance(repomd, Response):
        return repomd

    # Validation using centralized validation utility
    form_data = {
        "production": production,
        "arch": arch,
        "url": url,
        "debug_url": debug_url,
        "source_url": source_url,
        "repo_name": repo_name,
    }

    validated_data, validation_errors = FormValidator.validate_repomd_form(form_data)

    if validation_errors:
        return templates.TemplateResponse(
            "admin_supported_product_repomd.jinja", {
                "request": request,
                "repomd": repomd,
                "error": validation_errors[0],  # Show first error
            }
        )

    repomd.production = validated_data['production']
    repomd.arch = validated_data['arch']
    repomd.url = validated_data['url']
    repomd.debug_url = validated_data['debug_url']
    repomd.source_url = validated_data['source_url']
    repomd.repo_name = validated_data['repo_name']
    await repomd.save()

    return templates.TemplateResponse(
        "admin_supported_product_repomd.jinja", {
            "request": request,
            "repomd": repomd,
            "success": "Repository configuration updated successfully",
        }
    )


@router.post("/{product_id}/mirrors/{mirror_id}/repomds/{repomd_id}/delete", response_class=HTMLResponse)
async def admin_supported_product_mirror_repomd_delete(
    request: Request,
    product_id: int,
    mirror_id: int,
    repomd_id: int
):
    repomd = await get_entity_or_error_response(
        request,
        SupportedProductsRpmRepomd,
        f"Repository configuration with id {repomd_id}",
        filters={
            "id": repomd_id,
            "supported_products_rh_mirror_id": mirror_id,
            "supported_products_rh_mirror__supported_product_id": product_id
        },
        prefetch_related=["supported_products_rh_mirror", "supported_products_rh_mirror__supported_product"]
    )
    if isinstance(repomd, Response):
        return repomd

    # Check for existing advisory packages using this repository
    packages_count = await AdvisoryPackage.filter(
        supported_products_rh_mirror=repomd.supported_products_rh_mirror,
        repo_name=repomd.repo_name
    ).count()

    if packages_count > 0:
        return templates.TemplateResponse(
            "error.jinja", {
                "request": request,
                "message": f"Cannot delete repository '{repomd.repo_name}' because it has {packages_count} associated advisory package(s). Please remove these dependencies first.",
            }
        )

    await repomd.delete()
    return RedirectResponse(f"/admin/supported-products/{product_id}/mirrors/{mirror_id}", status_code=302)


# Blocks management routes
@router.get("/{product_id}/mirrors/{mirror_id}/blocks", response_class=HTMLResponse)
async def admin_supported_product_mirror_blocks(
    request: Request,
    product_id: int,
    mirror_id: int,
    params: Params = Depends(),
    search: Optional[str] = Query(None),
    success: Optional[str] = None,
    error: Optional[str] = None,
):
    """List all blocked advisories for a specific mirror with search and pagination"""
    mirror = await get_entity_or_error_response(
        request,
        SupportedProductsRhMirror,
        f"Mirror with id {mirror_id}",
        filters={"id": mirror_id, "supported_product_id": product_id},
        prefetch_related=["supported_product"],
    )
    if isinstance(mirror, Response):
        return mirror

    # Build query for blocked advisories
    query = SupportedProductsRhBlock.filter(
        supported_products_rh_mirror=mirror
    ).prefetch_related("red_hat_advisory")

    # Apply search if provided
    if search:
        query = query.filter(red_hat_advisory__name__icontains=search)

    # Set page size and get paginated results
    params.size = min(params.size or 50, 100)  # Default 50, max 100
    blocks = await paginate(
        query.order_by("-red_hat_advisory__red_hat_issued_at"), params=params
    )

    return templates.TemplateResponse(
        "admin_supported_product_mirror_blocks.jinja",
        {
            "request": request,
            "mirror": mirror,
            "blocks": blocks,
            "blocks_pages": ceil(blocks.total / blocks.size),
            "search": search,
            "success": success,
            "error": error,
        },
    )


@router.get("/{product_id}/mirrors/{mirror_id}/blocks/new", response_class=HTMLResponse)
async def admin_supported_product_mirror_block_new(
    request: Request,
    product_id: int,
    mirror_id: int,
    params: Params = Depends(),
    search: Optional[str] = Query(None),
):
    mirror = await get_entity_or_error_response(
        request,
        SupportedProductsRhMirror,
        f"Mirror with id {mirror_id}",
        filters={"id": mirror_id, "supported_product_id": product_id},
        prefetch_related=["supported_product"]
    )
    if isinstance(mirror, Response):
        return mirror

    # Get advisories that are not already blocked
    existing_blocks = await SupportedProductsRhBlock.filter(
        supported_products_rh_mirror=mirror
    ).values_list("red_hat_advisory_id", flat=True)

    query = RedHatAdvisory.exclude(id__in=existing_blocks)
    if search:
        query = query.filter(name__icontains=search)

    # Set page size and get paginated results
    params.size = min(params.size or 50, 100)  # Default 50, max 100
    advisories = await paginate(query.order_by("-red_hat_issued_at"), params=params)

    # Calculate total pages for pagination component
    advisories_pages = (
        math.ceil(advisories.total / advisories.size) if advisories.size > 0 else 1
    )

    return templates.TemplateResponse(
        "admin_supported_product_block_new.jinja", {
            "request": request,
            "mirror": mirror,
            "advisories": advisories,
            "advisories_pages": advisories_pages,
            "search": search or "",
        },
    )


@router.post("/{product_id}/mirrors/{mirror_id}/blocks/new", response_class=HTMLResponse)
async def admin_supported_product_mirror_block_new_post(
    request: Request,
    product_id: int,
    mirror_id: int,
    advisory_id: int = Form(),
):
    mirror = await get_entity_or_error_response(
        request,
        SupportedProductsRhMirror,
        f"Mirror with id {mirror_id}",
        filters={"id": mirror_id, "supported_product_id": product_id},
        prefetch_related=["supported_product"]
    )
    if isinstance(mirror, Response):
        return mirror

    advisory = await get_entity_or_error_response(
        request,
        RedHatAdvisory,
        f"Advisory with id {advisory_id}",
        entity_id=advisory_id
    )
    if isinstance(advisory, Response):
        return advisory

    # Check if block already exists
    existing_block = await SupportedProductsRhBlock.get_or_none(
        supported_products_rh_mirror=mirror, red_hat_advisory=advisory
    )

    if existing_block:
        return templates.TemplateResponse(
            "error.jinja", {
                "request": request,
                "message": f"Advisory {advisory.name} is already blocked for this mirror",
            }
        )

    block = SupportedProductsRhBlock(
        supported_products_rh_mirror=mirror,
        red_hat_advisory=advisory,
    )
    await block.save()

    return RedirectResponse(
        f"/admin/supported-products/{product_id}/mirrors/{mirror_id}/blocks?success=Advisory blocked successfully",
        status_code=302,
    )


@router.post("/{product_id}/mirrors/{mirror_id}/blocks/{block_id}/delete", response_class=HTMLResponse)
async def admin_supported_product_mirror_block_delete(
    request: Request, product_id: int, mirror_id: int, block_id: int
):
    block = await SupportedProductsRhBlock.get_or_none(
        id=block_id,
        supported_products_rh_mirror_id=mirror_id,
        supported_products_rh_mirror__supported_product_id=product_id
    )

    if block is None:
        return templates.TemplateResponse(
            "error.jinja", {
                "request": request,
                "message": f"Block with id {block_id} not found",
            }
        )

    await block.delete()
    return RedirectResponse(
        f"/admin/supported-products/{product_id}/mirrors/{mirror_id}/blocks?success=Block removed successfully",
        status_code=302,
    )


# Overrides management routes (similar structure to blocks)
@router.get("/{product_id}/mirrors/{mirror_id}/overrides/new", response_class=HTMLResponse)
async def admin_supported_product_mirror_override_new(
    request: Request,
    product_id: int,
    mirror_id: int,
    params: Params = Depends(),
    search: Optional[str] = Query(None),
):
    mirror = await get_entity_or_error_response(
        request,
        SupportedProductsRhMirror,
        f"Mirror with id {mirror_id}",
        filters={"id": mirror_id, "supported_product_id": product_id},
        prefetch_related=["supported_product"]
    )
    if isinstance(mirror, Response):
        return mirror

    # Get advisories that don't already have overrides
    existing_overrides = await SupportedProductsRpmRhOverride.filter(
        supported_products_rh_mirror=mirror
    ).values_list("red_hat_advisory_id", flat=True)

    query = RedHatAdvisory.exclude(id__in=existing_overrides)
    if search:
        query = query.filter(name__icontains=search)

    # Set page size and get paginated results
    params.size = min(params.size or 50, 100)  # Default 50, max 100
    advisories = await paginate(query.order_by("-red_hat_issued_at"), params=params)

    # Calculate total pages for pagination component
    advisories_pages = (
        math.ceil(advisories.total / advisories.size) if advisories.size > 0 else 1
    )

    return templates.TemplateResponse(
        "admin_supported_product_override_new.jinja", {
            "request": request,
            "mirror": mirror,
            "advisories": advisories,
            "advisories_pages": advisories_pages,
            "search": search or "",
        },
    )


@router.post("/{product_id}/mirrors/{mirror_id}/overrides/new", response_class=HTMLResponse)
async def admin_supported_product_mirror_override_new_post(
    request: Request,
    product_id: int,
    mirror_id: int,
    advisory_id: int = Form(),
):
    mirror = await get_entity_or_error_response(
        request,
        SupportedProductsRhMirror,
        f"Mirror with id {mirror_id}",
        filters={"id": mirror_id, "supported_product_id": product_id},
        prefetch_related=["supported_product"]
    )
    if isinstance(mirror, Response):
        return mirror

    advisory = await get_entity_or_error_response(
        request,
        RedHatAdvisory,
        f"Advisory with id {advisory_id}",
        entity_id=advisory_id
    )
    if isinstance(advisory, Response):
        return advisory

    # Check if override already exists
    existing_override = await SupportedProductsRpmRhOverride.get_or_none(
        supported_products_rh_mirror=mirror,
        red_hat_advisory=advisory
    )

    if existing_override:
        return templates.TemplateResponse(
            "error.jinja", {
                "request": request,
                "message": f"Advisory {advisory.name} already has an override for this mirror",
            }
        )

    override = SupportedProductsRpmRhOverride(
        supported_products_rh_mirror=mirror,
        red_hat_advisory=advisory,
    )
    await override.save()

    return RedirectResponse(
        f"/admin/supported-products/{product_id}/mirrors/{mirror_id}/overrides?success=Override created successfully",
        status_code=302,
    )


@router.post("/{product_id}/mirrors/{mirror_id}/overrides/{override_id}/delete", response_class=HTMLResponse)
async def admin_supported_product_mirror_override_delete(
    request: Request,
    product_id: int,
    mirror_id: int,
    override_id: int
):
    override = await SupportedProductsRpmRhOverride.get_or_none(
        id=override_id,
        supported_products_rh_mirror_id=mirror_id,
        supported_products_rh_mirror__supported_product_id=product_id
    )

    if override is None:
        return templates.TemplateResponse(
            "error.jinja", {
                "request": request,
                "message": f"Override with id {override_id} not found",
            }
        )

    await override.delete()
    return RedirectResponse(
        f"/admin/supported-products/{product_id}/mirrors/{mirror_id}/overrides?success=Override removed successfully",
        status_code=302,
    )


async def _get_mirror_config_data(mirror: SupportedProductsRhMirror) -> Dict[str, Any]:
    """Extract mirror configuration data including all related repositories"""
    return {
        "product": {
            "id": mirror.supported_product.id,
            "name": mirror.supported_product.name,
            "variant": mirror.supported_product.variant,
            "vendor": mirror.supported_product.vendor,
        },
        "mirror": {
            "id": mirror.id,
            "name": mirror.name,
            "match_variant": mirror.match_variant,
            "match_major_version": mirror.match_major_version,
            "match_minor_version": mirror.match_minor_version,
            "match_arch": mirror.match_arch,
            "active": mirror.active,
            "created_at": mirror.created_at.isoformat(),
            "updated_at": mirror.updated_at.isoformat() if mirror.updated_at else None,
        },
        "repositories": [
            {
                "id": repo.id,
                "repo_name": repo.repo_name,
                "arch": repo.arch,
                "production": repo.production,
                "url": repo.url,
                "debug_url": repo.debug_url,
                "source_url": repo.source_url,
                "created_at": repo.created_at.isoformat(),
                "updated_at": repo.updated_at.isoformat() if repo.updated_at else None,
            }
            for repo in mirror.rpm_repomds
        ]
    }

def _json_serializer(obj):
    """Custom JSON serializer for non-standard types"""
    if isinstance(obj, Decimal):
        if obj % 1 == 0:
            return int(obj)
        return float(obj)
    raise TypeError(f"Object of type {obj.__class__.__name__} is not JSON serializable")

def _format_export_data(data: List[Dict[str, Any]]) -> str:
    """Format configuration data for JSON export"""
    return json.dumps(data, indent=2, default=_json_serializer)

@router.get("/{product_id}/mirrors/{mirror_id}/export")
async def export_mirror_config(product_id: int, mirror_id: int):
    """Export configuration for a single mirror as JSON"""
    mirror = await SupportedProductsRhMirror.get_or_none(
        id=mirror_id,
        supported_product_id=product_id
    ).prefetch_related(
        "supported_product",
        "rpm_repomds"
    )

    if mirror is None:
        return Response(
            content=f"Mirror with id {mirror_id} not found",
            status_code=404,
            media_type="text/plain"
        )

    config_data = await _get_mirror_config_data(mirror)
    formatted_data = _format_export_data([config_data])

    filename = f"{mirror.name.replace(' ', '_').lower()}_config.json"

    return Response(
        content=formatted_data,
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@router.get("/{product_id}/export")
async def export_product_config(
    product_id: int,
    major_version: Optional[int] = Query(None),
    arch: Optional[str] = Query(None),
    production_only: Optional[bool] = Query(None)
):
    """Export configurations for all mirrors of a product as JSON with optional filtering"""
    product = await SupportedProduct.get_or_none(id=product_id)
    if product is None:
        return Response(
            content=f"Product with id {product_id} not found",
            status_code=404,
            media_type="text/plain"
        )

    # Build query with filters
    query = SupportedProductsRhMirror.filter(supported_product_id=product_id)
    if major_version is not None:
        query = query.filter(match_major_version=major_version)
    if arch is not None:
        query = query.filter(match_arch=arch)

    mirrors = await query.prefetch_related(
        "supported_product",
        "rpm_repomds"
    ).all()

    # Filter repositories by production status if specified
    config_data = []
    for mirror in mirrors:
        mirror_data = await _get_mirror_config_data(mirror)
        if production_only is not None:
            mirror_data["repositories"] = [
                repo for repo in mirror_data["repositories"]
                if repo["production"] == production_only
            ]
        config_data.append(mirror_data)

    formatted_data = _format_export_data(config_data)

    filename_parts = [product.name.replace(' ', '_').lower(), "config"]
    if major_version is not None:
        filename_parts.append(f"v{major_version}")
    if arch is not None:
        filename_parts.append(arch)
    if production_only is not None:
        filename_parts.append("prod" if production_only else "staging")

    filename = "_".join(filename_parts) + ".json"

    return Response(
        content=formatted_data,
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/{product_id}/mirrors/{mirror_id}/overrides", response_class=HTMLResponse)
async def admin_supported_product_mirror_overrides(
    request: Request,
    product_id: int,
    mirror_id: int,
    params: Params = Depends(),
    search: Optional[str] = Query(None),
    success: Optional[str] = None,
    error: Optional[str] = None,
):
    """Display paginated overrides for a mirror with search functionality"""
    mirror = await get_entity_or_error_response(
        request,
        SupportedProductsRhMirror,
        f"Mirror with id {mirror_id}",
        filters={"id": mirror_id, "supported_product_id": product_id},
        prefetch_related=["supported_product"],
    )
    if isinstance(mirror, Response):
        return mirror

    # Build query for overrides with search
    query = SupportedProductsRpmRhOverride.filter(
        supported_products_rh_mirror_id=mirror_id
    ).prefetch_related("red_hat_advisory")

    if search:
        query = query.filter(red_hat_advisory__name__icontains=search)

    # Apply ordering and pagination
    query = query.order_by("-created_at")
    overrides = await paginate(query, params)

    # Calculate total pages for pagination component
    overrides_pages = (
        math.ceil(overrides.total / overrides.size) if overrides.size > 0 else 1
    )

    return templates.TemplateResponse(
        "admin_supported_product_mirror_overrides.jinja",
        {
            "request": request,
            "mirror": mirror,
            "overrides": overrides,
            "overrides_pages": overrides_pages,
            "search": search or "",
            "success": success,
            "error": error,
        },
    )
