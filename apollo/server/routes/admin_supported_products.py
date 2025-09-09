import json
from decimal import Decimal
from math import ceil
from typing import Optional, Dict, Any, List

from fastapi import APIRouter, Request, Depends, Form, Query, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi_pagination import Params
from fastapi_pagination.ext.tortoise import paginate

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
    errors = []

    if not isinstance(import_data, list):
        return ["Import data must be a list of configuration objects"]

    for i, config in enumerate(import_data):
        # Validate structure
        required_keys = ["product", "mirror", "repositories"]
        for key in required_keys:
            if key not in config:
                errors.append(f"Config {i+1}: Missing required key '{key}'")
                continue

        # Validate product data
        product = config.get("product", {})
        product_required = ["name", "variant", "vendor"]
        for key in product_required:
            if key not in product or not product[key]:
                errors.append(f"Config {i+1}: Product missing required field '{key}'")

        # Validate mirror data
        mirror = config.get("mirror", {})
        mirror_required = ["name", "match_variant", "match_major_version", "match_arch"]
        for key in mirror_required:
            if key not in mirror or mirror[key] is None:
                errors.append(f"Config {i+1}: Mirror missing required field '{key}'")

        # Validate repositories
        repositories = config.get("repositories", [])
        if not isinstance(repositories, list):
            errors.append(f"Config {i+1}: Repositories must be a list")
        else:
            for j, repo in enumerate(repositories):
                repo_required = ["repo_name", "arch", "production", "url"]
                for key in repo_required:
                    if key not in repo or repo[key] is None:
                        errors.append(f"Config {i+1}, Repo {j+1}: Missing required field '{key}'")

    return errors

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
            updated_count += 1
        else:
            # Create new mirror
            mirror = SupportedProductsRhMirror(
                supported_product=product,
                name=mirror_data["name"],
                match_variant=mirror_data["match_variant"],
                match_major_version=mirror_data["match_major_version"],
                match_minor_version=mirror_data.get("match_minor_version"),
                match_arch=mirror_data["match_arch"]
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
        return templates.TemplateResponse(
            "admin_supported_products.jinja", {
                "request": request,
                "error": "File must be a JSON file (.json extension required)",
            }
        )

    try:
        content = await file.read()
        import_data = json.loads(content.decode('utf-8'))
    except json.JSONDecodeError as e:
        return templates.TemplateResponse(
            "admin_supported_products.jinja", {
                "request": request,
                "error": f"Invalid JSON file: {str(e)}",
            }
        )
    except Exception as e:
        return templates.TemplateResponse(
            "admin_supported_products.jinja", {
                "request": request,
                "error": f"Error reading file: {str(e)}",
            }
        )

    # Validate import data
    validation_errors = await _validate_import_data(import_data)
    if validation_errors:
        return templates.TemplateResponse(
            "admin_supported_products.jinja", {
                "request": request,
                "error": "Validation errors:\n" + "\n".join(validation_errors),
            }
        )

    # Import the data
    try:
        results = await _import_configuration(import_data, replace_existing)
        success_message = f"Import completed: {results['created']} created, {results['updated']} updated, {results['skipped']} skipped"

        return RedirectResponse(
            f"/admin/supported-products?success={success_message}",
            status_code=302
        )
    except Exception as e:
        return templates.TemplateResponse(
            "admin_supported_products.jinja", {
                "request": request,
                "error": f"Import failed: {str(e)}",
            }
        )

@router.get("/{product_id}", response_class=HTMLResponse)
async def admin_supported_product(request: Request, product_id: int):
    product = await SupportedProduct.get_or_none(id=product_id).prefetch_related(
        "rh_mirrors",
        "rh_mirrors__rpm_repomds",
        "code"
    )
    if product is None:
        return templates.TemplateResponse(
            "error.jinja", {
                "request": request,
                "message": f"Supported product with id {product_id} not found",
            }
        )

    # Get detailed statistics for each mirror
    for mirror in product.rh_mirrors:
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
    product = await SupportedProduct.get_or_none(id=product_id)
    if product is None:
        return templates.TemplateResponse(
            "error.jinja", {
                "request": request,
                "message": f"Supported product with id {product_id} not found",
            }
        )

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
    product = await SupportedProduct.get_or_none(id=product_id)
    if product is None:
        return templates.TemplateResponse(
            "error.jinja", {
                "request": request,
                "message": f"Supported product with id {product_id} not found",
            }
        )

    # Validation
    if not name or len(name.strip()) < 3:
        return templates.TemplateResponse(
            "admin_supported_product_mirror_new.jinja", {
                "request": request,
                "product": product,
                "error": "Mirror name must be at least 3 characters long",
                "form_data": {
                    "name": name,
                    "match_variant": match_variant,
                    "match_major_version": match_major_version,
                    "match_minor_version": match_minor_version,
                    "match_arch": match_arch,
                }
            }
        )

    mirror = SupportedProductsRhMirror(
        supported_product=product,
        name=name.strip(),
        match_variant=match_variant,
        match_major_version=match_major_version,
        match_minor_version=match_minor_version,
        match_arch=match_arch,
    )
    await mirror.save()

    return RedirectResponse(f"/admin/supported-products/{product_id}", status_code=302)

@router.get("/{product_id}/mirrors/{mirror_id}", response_class=HTMLResponse)
async def admin_supported_product_mirror(request: Request, product_id: int, mirror_id: int):
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

    if mirror is None:
        return templates.TemplateResponse(
            "error.jinja", {
                "request": request,
                "message": f"Mirror with id {mirror_id} not found",
            }
        )

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

    if mirror is None:
        return templates.TemplateResponse(
            "error.jinja", {
                "request": request,
                "message": f"Mirror with id {mirror_id} not found",
            }
        )

    # Validation
    if not name or len(name.strip()) < 3:
        return templates.TemplateResponse(
            "admin_supported_product_mirror.jinja", {
                "request": request,
                "mirror": mirror,
                "error": "Mirror name must be at least 3 characters long",
            }
        )

    mirror.name = name.strip()
    mirror.match_variant = match_variant
    mirror.match_major_version = match_major_version
    mirror.match_minor_version = match_minor_version
    mirror.match_arch = match_arch
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
    mirror = await SupportedProductsRhMirror.get_or_none(
        id=mirror_id,
        supported_product_id=product_id
    ).prefetch_related("supported_product")

    if mirror is None:
        return templates.TemplateResponse(
            "error.jinja", {
                "request": request,
                "message": f"Mirror with id {mirror_id} not found",
            }
        )

    # Check for existing blocks and overrides
    blocks_count = await SupportedProductsRhBlock.filter(
        supported_products_rh_mirror=mirror
    ).count()
    overrides_count = await SupportedProductsRpmRhOverride.filter(
        supported_products_rh_mirror=mirror
    ).count()
    
    if blocks_count > 0 or overrides_count > 0:
        error_parts = []
        if blocks_count > 0:
            error_parts.append(f"{blocks_count} blocked product(s)")
        if overrides_count > 0:
            error_parts.append(f"{overrides_count} override(s)")
        
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


# Repository (repomd) management routes
@router.get("/{product_id}/mirrors/{mirror_id}/repomds/new", response_class=HTMLResponse)
async def admin_supported_product_mirror_repomd_new(
    request: Request,
    product_id: int,
    mirror_id: int
):
    mirror = await SupportedProductsRhMirror.get_or_none(
        id=mirror_id, supported_product_id=product_id
    ).prefetch_related("supported_product")

    if mirror is None:
        return templates.TemplateResponse(
            "error.jinja", {
                "request": request,
                "message": f"Mirror with id {mirror_id} not found",
            }
        )

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
    mirror = await SupportedProductsRhMirror.get_or_none(
        id=mirror_id, supported_product_id=product_id
    ).prefetch_related("supported_product")

    if mirror is None:
        return templates.TemplateResponse(
            "error.jinja", {
                "request": request,
                "message": f"Mirror with id {mirror_id} not found",
            }
        )

    # Validation
    if not repo_name or len(repo_name.strip()) < 2:
        return templates.TemplateResponse(
            "admin_supported_product_repomd_new.jinja", {
                "request": request,
                "mirror": mirror,
                "error": "Repository name must be at least 2 characters long",
                "form_data": {
                    "production": production,
                    "arch": arch,
                    "url": url,
                    "debug_url": debug_url,
                    "source_url": source_url,
                    "repo_name": repo_name,
                }
            }
        )

    if not url.startswith(('http://', 'https://')):
        return templates.TemplateResponse(
            "admin_supported_product_repomd_new.jinja", {
                "request": request,
                "mirror": mirror,
                "error": "Repository URL must start with http:// or https://",
                "form_data": {
                    "production": production,
                    "arch": arch,
                    "url": url,
                    "debug_url": debug_url,
                    "source_url": source_url,
                    "repo_name": repo_name,
                }
            }
        )

    repomd = SupportedProductsRpmRepomd(
        supported_products_rh_mirror=mirror,
        production=production,
        arch=arch,
        url=url.strip(),
        debug_url=debug_url.strip(),
        source_url=source_url.strip(),
        repo_name=repo_name.strip(),
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
    repomd = await SupportedProductsRpmRepomd.get_or_none(
        id=repomd_id,
        supported_products_rh_mirror_id=mirror_id,
        supported_products_rh_mirror__supported_product_id=product_id
    ).prefetch_related("supported_products_rh_mirror", "supported_products_rh_mirror__supported_product")

    if repomd is None:
        return templates.TemplateResponse(
            "error.jinja", {
                "request": request,
                "message": f"Repository configuration with id {repomd_id} not found",
            }
        )

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
    repomd = await SupportedProductsRpmRepomd.get_or_none(
        id=repomd_id,
        supported_products_rh_mirror_id=mirror_id,
        supported_products_rh_mirror__supported_product_id=product_id
    ).prefetch_related("supported_products_rh_mirror", "supported_products_rh_mirror__supported_product")

    if repomd is None:
        return templates.TemplateResponse(
            "error.jinja", {
                "request": request,
                "message": f"Repository configuration with id {repomd_id} not found",
            }
        )

    # Validation
    if not repo_name or len(repo_name.strip()) < 2:
        return templates.TemplateResponse(
            "admin_supported_product_repomd.jinja", {
                "request": request,
                "repomd": repomd,
                "error": "Repository name must be at least 2 characters long",
            }
        )

    if not url.startswith(('http://', 'https://')):
        return templates.TemplateResponse(
            "admin_supported_product_repomd.jinja", {
                "request": request,
                "repomd": repomd,
                "error": "Repository URL must start with http:// or https://",
            }
        )

    repomd.production = production
    repomd.arch = arch
    repomd.url = url.strip()
    repomd.debug_url = debug_url.strip()
    repomd.source_url = source_url.strip()
    repomd.repo_name = repo_name.strip()
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
    repomd = await SupportedProductsRpmRepomd.get_or_none(
        id=repomd_id,
        supported_products_rh_mirror_id=mirror_id,
        supported_products_rh_mirror__supported_product_id=product_id
    ).prefetch_related("supported_products_rh_mirror")

    if repomd is None:
        return templates.TemplateResponse(
            "error.jinja", {
                "request": request,
                "message": f"Repository configuration with id {repomd_id} not found",
            }
        )

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
@router.get("/{product_id}/mirrors/{mirror_id}/blocks/new", response_class=HTMLResponse)
async def admin_supported_product_mirror_block_new(
    request: Request,
    product_id: int,
    mirror_id: int,
    search: str = None
):
    mirror = await SupportedProductsRhMirror.get_or_none(
        id=mirror_id, supported_product_id=product_id
    ).prefetch_related("supported_product")

    if mirror is None:
        return templates.TemplateResponse(
            "error.jinja", {
                "request": request,
                "message": f"Mirror with id {mirror_id} not found",
            }
        )

    # Get advisories that are not already blocked
    existing_blocks = await SupportedProductsRhBlock.filter(
        supported_products_rh_mirror=mirror
    ).values_list("red_hat_advisory_id", flat=True)

    query = RedHatAdvisory.exclude(id__in=existing_blocks)
    if search:
        query = query.filter(name__icontains=search)

    advisories = await query.order_by("-red_hat_issued_at").limit(50)

    return templates.TemplateResponse(
        "admin_supported_product_block_new.jinja", {
            "request": request,
            "mirror": mirror,
            "advisories": advisories,
            "search": search,
        }
    )


@router.post("/{product_id}/mirrors/{mirror_id}/blocks/new", response_class=HTMLResponse)
async def admin_supported_product_mirror_block_new_post(
    request: Request,
    product_id: int,
    mirror_id: int,
    advisory_id: int = Form(),
):
    mirror = await SupportedProductsRhMirror.get_or_none(
        id=mirror_id, supported_product_id=product_id
    ).prefetch_related("supported_product")

    if mirror is None:
        return templates.TemplateResponse(
            "error.jinja", {
                "request": request,
                "message": f"Mirror with id {mirror_id} not found",
            }
        )

    advisory = await RedHatAdvisory.get_or_none(id=advisory_id)
    if advisory is None:
        return templates.TemplateResponse(
            "error.jinja", {
                "request": request,
                "message": f"Advisory with id {advisory_id} not found",
            }
        )

    # Check if block already exists
    existing_block = await SupportedProductsRhBlock.get_or_none(
        supported_products_rh_mirror=mirror,
        red_hat_advisory=advisory
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

    return RedirectResponse(f"/admin/supported-products/{product_id}/mirrors/{mirror_id}", status_code=302)


@router.post("/{product_id}/mirrors/{mirror_id}/blocks/{block_id}/delete", response_class=HTMLResponse)
async def admin_supported_product_mirror_block_delete(
    request: Request,
    product_id: int,
    mirror_id: int,
    block_id: int
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
    return RedirectResponse(f"/admin/supported-products/{product_id}/mirrors/{mirror_id}", status_code=302)


# Overrides management routes (similar structure to blocks)
@router.get("/{product_id}/mirrors/{mirror_id}/overrides/new", response_class=HTMLResponse)
async def admin_supported_product_mirror_override_new(
    request: Request,
    product_id: int,
    mirror_id: int,
    search: str = None
):
    mirror = await SupportedProductsRhMirror.get_or_none(
        id=mirror_id, supported_product_id=product_id
    ).prefetch_related("supported_product")

    if mirror is None:
        return templates.TemplateResponse(
            "error.jinja", {
                "request": request,
                "message": f"Mirror with id {mirror_id} not found",
            }
        )

    # Get advisories that don't already have overrides
    existing_overrides = await SupportedProductsRpmRhOverride.filter(
        supported_products_rh_mirror=mirror
    ).values_list("red_hat_advisory_id", flat=True)

    query = RedHatAdvisory.exclude(id__in=existing_overrides)
    if search:
        query = query.filter(name__icontains=search)

    advisories = await query.order_by("-red_hat_issued_at").limit(50)

    return templates.TemplateResponse(
        "admin_supported_product_override_new.jinja", {
            "request": request,
            "mirror": mirror,
            "advisories": advisories,
            "search": search,
        }
    )


@router.post("/{product_id}/mirrors/{mirror_id}/overrides/new", response_class=HTMLResponse)
async def admin_supported_product_mirror_override_new_post(
    request: Request,
    product_id: int,
    mirror_id: int,
    advisory_id: int = Form(),
):
    mirror = await SupportedProductsRhMirror.get_or_none(
        id=mirror_id, supported_product_id=product_id
    ).prefetch_related("supported_product")

    if mirror is None:
        return templates.TemplateResponse(
            "error.jinja", {
                "request": request,
                "message": f"Mirror with id {mirror_id} not found",
            }
        )

    advisory = await RedHatAdvisory.get_or_none(id=advisory_id)
    if advisory is None:
        return templates.TemplateResponse(
            "error.jinja", {
                "request": request,
                "message": f"Advisory with id {advisory_id} not found",
            }
        )

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

    return RedirectResponse(f"/admin/supported-products/{product_id}/mirrors/{mirror_id}", status_code=302)


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
    return RedirectResponse(f"/admin/supported-products/{product_id}/mirrors/{mirror_id}", status_code=302)

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
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

