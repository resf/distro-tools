from math import ceil
from typing import Optional, Union, Type, Dict, List

from fastapi import APIRouter, Request, Depends, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.responses import Response
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
    Code
)
from apollo.server.utils import templates


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

router = APIRouter(tags=["non-api"])


@router.get("/", response_class=HTMLResponse)
async def admin_supported_products(request: Request, params: Params = Depends()):
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
        }
    )


@router.get("/{product_id}", response_class=HTMLResponse)
async def admin_supported_product(request: Request, product_id: int):
    product = await get_entity_or_error_response(
        request,
        SupportedProduct,
        f"Supported product with id {product_id}",
        entity_id=product_id,
        prefetch_related=["rh_mirrors", "rh_mirrors__rpm_repomds", "code"]
    )
    if isinstance(product, Response):
        return product

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
        prefetch_related=["supported_product"]
    )
    if isinstance(mirror, Response):
        return mirror

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

    await mirror.delete()
    return RedirectResponse(f"/admin/supported-products/{product_id}", status_code=302)


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
