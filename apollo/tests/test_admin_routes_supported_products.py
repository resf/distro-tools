"""
Tests for admin supported products route utility functions
Tests utility functions that don't require database dependencies
"""

import unittest
import asyncio
import json
from decimal import Decimal
from unittest.mock import Mock, MagicMock
from datetime import datetime
from typing import Dict, List, Any

# Add the project root to the Python path
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from apollo.server.routes.admin_supported_products import (
    format_dependency_error_parts,
    create_error_redirect,
    create_success_redirect,
    _json_serializer,
    _format_export_data,
    _get_mirror_config_data,
    _validate_import_data,
)


class TestDependencyErrorFormatting(unittest.TestCase):
    """Test dependency error message formatting."""

    def test_no_dependencies(self):
        """Test formatting when there are no dependencies."""
        result = format_dependency_error_parts(0, 0)
        self.assertEqual(result, [])

    def test_blocks_only(self):
        """Test formatting with only blocked products."""
        result = format_dependency_error_parts(3, 0)
        self.assertEqual(result, ["3 blocked product(s)"])

    def test_overrides_only(self):
        """Test formatting with only overrides."""
        result = format_dependency_error_parts(0, 2)
        self.assertEqual(result, ["2 override(s)"])

    def test_both_dependencies(self):
        """Test formatting with both blocks and overrides."""
        result = format_dependency_error_parts(3, 2)
        expected = ["3 blocked product(s)", "2 override(s)"]
        self.assertEqual(result, expected)

    def test_single_block(self):
        """Test formatting with single blocked product."""
        result = format_dependency_error_parts(1, 0)
        self.assertEqual(result, ["1 blocked product(s)"])

    def test_single_override(self):
        """Test formatting with single override."""
        result = format_dependency_error_parts(0, 1)
        self.assertEqual(result, ["1 override(s)"])

    def test_large_numbers(self):
        """Test formatting with large dependency counts."""
        result = format_dependency_error_parts(100, 50)
        expected = ["100 blocked product(s)", "50 override(s)"]
        self.assertEqual(result, expected)


class TestRedirectHelpers(unittest.TestCase):
    """Test redirect response helper functions."""

    def test_create_error_redirect_basic(self):
        """Test creating error redirect with basic message."""
        base_url = "/admin/supported-products"
        error_message = "Product not found"

        response = create_error_redirect(base_url, error_message)

        self.assertEqual(response.status_code, 302)
        self.assertIn("error=Product%20not%20found", response.headers["location"])
        self.assertTrue(response.headers["location"].startswith(base_url))

    def test_create_error_redirect_special_chars(self):
        """Test creating error redirect with special characters."""
        base_url = "/admin/supported-products/123"
        error_message = "Error: Product 'Test & Debug' not found!"

        response = create_error_redirect(base_url, error_message)

        self.assertEqual(response.status_code, 302)
        # URL encoding should handle special characters
        location = response.headers["location"]
        self.assertTrue(location.startswith(base_url))
        self.assertIn("error=", location)
        # Ensure special characters are encoded
        self.assertNotIn("'", location)
        self.assertNotIn(
            "&", location.split("error=")[1]
        )  # & in error part should be encoded

    def test_create_success_redirect_basic(self):
        """Test creating success redirect with basic message."""
        base_url = "/admin/supported-products"
        success_message = "Product created successfully"

        response = create_success_redirect(base_url, success_message)

        self.assertEqual(response.status_code, 302)
        self.assertIn(
            "success=Product%20created%20successfully", response.headers["location"]
        )
        self.assertTrue(response.headers["location"].startswith(base_url))

    def test_create_success_redirect_with_numbers(self):
        """Test creating success redirect with numbers and special formatting."""
        base_url = "/admin/products/456"
        success_message = "Deleted 5 mirrors: Mirror-1, Mirror-2, Mirror-3"

        response = create_success_redirect(base_url, success_message)

        self.assertEqual(response.status_code, 302)
        location = response.headers["location"]
        self.assertTrue(location.startswith(base_url))
        self.assertIn("success=", location)
        # Commas and colons should be encoded
        self.assertNotIn(":", location.split("success=")[1])
        self.assertNotIn(",", location.split("success=")[1])

    def test_redirect_with_existing_query_params(self):
        """Test redirect when base URL already has query parameters."""
        base_url = "/admin/supported-products?page=2&size=50"
        error_message = "Validation failed"

        response = create_error_redirect(base_url, error_message)

        self.assertEqual(response.status_code, 302)
        location = response.headers["location"]
        self.assertIn("page=2", location)
        self.assertIn("size=50", location)
        self.assertIn("error=Validation%20failed", location)

    def test_empty_base_url(self):
        """Test redirect with empty base URL."""
        base_url = ""
        error_message = "Error occurred"

        response = create_error_redirect(base_url, error_message)

        self.assertEqual(response.status_code, 302)
        location = response.headers["location"]
        self.assertEqual(location, "?error=Error%20occurred")


class TestJSONSerialization(unittest.TestCase):
    """Test JSON serialization functions."""

    def test_json_serializer_decimal(self):
        """Test JSON serializer with Decimal objects."""
        decimal_val = Decimal("123.456")
        result = _json_serializer(decimal_val)
        self.assertEqual(result, 123.456)
        self.assertIsInstance(result, float)

    def test_json_serializer_decimal_integer(self):
        """Test JSON serializer with integer Decimal."""
        decimal_val = Decimal("42")
        result = _json_serializer(decimal_val)
        self.assertEqual(result, 42)
        self.assertIsInstance(result, int)

    def test_json_serializer_unsupported_type(self):
        """Test JSON serializer with unsupported type."""
        unsupported_obj = object()

        with self.assertRaises(TypeError) as cm:
            _json_serializer(unsupported_obj)

        self.assertIn("is not JSON serializable", str(cm.exception))
        self.assertIn("object", str(cm.exception))

    def test_json_serializer_datetime_unsupported(self):
        """Test that datetime objects raise TypeError (not handled by this serializer)."""
        dt = datetime.now()

        with self.assertRaises(TypeError):
            _json_serializer(dt)

    def test_format_export_data_basic(self):
        """Test formatting basic export data."""
        data = [{"name": "test", "value": 123}, {"name": "test2", "value": 456}]

        result = _format_export_data(data)

        # Should be valid JSON
        parsed = json.loads(result)
        self.assertEqual(parsed, data)

        # Should be properly indented
        self.assertIn("\n", result)
        self.assertIn("  ", result)  # 2-space indentation

    def test_format_export_data_with_decimal(self):
        """Test formatting export data containing Decimal objects."""
        data = [
            {"name": "test", "price": Decimal("19.99")},
            {"name": "test2", "price": Decimal("99")},
        ]

        result = _format_export_data(data)

        parsed = json.loads(result)
        self.assertEqual(parsed[0]["price"], 19.99)
        self.assertEqual(parsed[1]["price"], 99)

    def test_format_export_data_empty(self):
        """Test formatting empty export data."""
        data = []

        result = _format_export_data(data)

        parsed = json.loads(result)
        self.assertEqual(parsed, [])

    def test_format_export_data_nested_structure(self):
        """Test formatting complex nested data structure."""
        data = [
            {
                "product": {"name": "Rocky Linux", "version": 9},
                "repositories": [
                    {"name": "BaseOS", "arch": "x86_64"},
                    {"name": "AppStream", "arch": "x86_64"},
                ],
            }
        ]

        result = _format_export_data(data)

        parsed = json.loads(result)
        self.assertEqual(parsed, data)
        self.assertEqual(len(parsed[0]["repositories"]), 2)


class TestMirrorConfigDataExtraction(unittest.TestCase):
    """Test mirror configuration data extraction with mock objects."""

    def create_mock_supported_product(self):
        """Create a mock supported product."""
        product = Mock()
        product.id = 1
        product.name = "Rocky Linux"
        product.variant = "Rocky Linux"
        product.vendor = "Rocky Enterprise Software Foundation"
        return product

    def create_mock_repository(self, repo_id=1, repo_name="BaseOS", arch="x86_64"):
        """Create a mock repository."""
        repo = Mock()
        repo.id = repo_id
        repo.repo_name = repo_name
        repo.arch = arch
        repo.production = True
        repo.url = f"https://example.com/{repo_name}/{arch}/os"
        repo.debug_url = ""
        repo.source_url = ""
        repo.created_at = datetime(2024, 1, 1, 12, 0, 0)
        repo.updated_at = datetime(2024, 1, 2, 12, 0, 0)
        return repo

    def create_mock_mirror(self):
        """Create a mock mirror with related objects."""
        mirror = Mock()
        mirror.id = 10
        mirror.name = "Rocky Linux 9.6 x86_64"
        mirror.match_variant = "Red Hat Enterprise Linux"
        mirror.match_major_version = 9
        mirror.match_minor_version = 6
        mirror.match_arch = "x86_64"
        mirror.created_at = datetime(2024, 1, 1, 10, 0, 0)
        mirror.updated_at = datetime(2024, 1, 2, 10, 0, 0)

        # Mock supported product
        mirror.supported_product = self.create_mock_supported_product()

        # Mock repositories
        mirror.rpm_repomds = [
            self.create_mock_repository(1, "BaseOS", "x86_64"),
            self.create_mock_repository(2, "AppStream", "x86_64"),
        ]

        return mirror

    def test_get_mirror_config_data_complete(self):
        """Test extracting complete mirror configuration data."""
        mirror = self.create_mock_mirror()

        result = asyncio.run(_get_mirror_config_data(mirror))

        # Verify product data
        self.assertEqual(result["product"]["id"], 1)
        self.assertEqual(result["product"]["name"], "Rocky Linux")
        self.assertEqual(result["product"]["variant"], "Rocky Linux")
        self.assertEqual(
            result["product"]["vendor"], "Rocky Enterprise Software Foundation"
        )

        # Verify mirror data
        self.assertEqual(result["mirror"]["id"], 10)
        self.assertEqual(result["mirror"]["name"], "Rocky Linux 9.6 x86_64")
        self.assertEqual(result["mirror"]["match_variant"], "Red Hat Enterprise Linux")
        self.assertEqual(result["mirror"]["match_major_version"], 9)
        self.assertEqual(result["mirror"]["match_minor_version"], 6)
        self.assertEqual(result["mirror"]["match_arch"], "x86_64")

        # Verify datetime serialization
        self.assertEqual(result["mirror"]["created_at"], "2024-01-01T10:00:00")
        self.assertEqual(result["mirror"]["updated_at"], "2024-01-02T10:00:00")

        # Verify repositories
        self.assertEqual(len(result["repositories"]), 2)

        repo1 = result["repositories"][0]
        self.assertEqual(repo1["id"], 1)
        self.assertEqual(repo1["repo_name"], "BaseOS")
        self.assertEqual(repo1["arch"], "x86_64")
        self.assertEqual(repo1["production"], True)
        self.assertEqual(repo1["url"], "https://example.com/BaseOS/x86_64/os")

        repo2 = result["repositories"][1]
        self.assertEqual(repo2["repo_name"], "AppStream")

    def test_get_mirror_config_data_no_minor_version(self):
        """Test extracting mirror config when minor_version is None."""
        mirror = self.create_mock_mirror()
        mirror.match_minor_version = None

        result = asyncio.run(_get_mirror_config_data(mirror))

        self.assertIsNone(result["mirror"]["match_minor_version"])

    def test_get_mirror_config_data_no_updated_at(self):
        """Test extracting mirror config when updated_at is None."""
        mirror = self.create_mock_mirror()
        mirror.updated_at = None

        # Also set repository updated_at to None
        for repo in mirror.rpm_repomds:
            repo.updated_at = None

        result = asyncio.run(_get_mirror_config_data(mirror))

        self.assertIsNone(result["mirror"]["updated_at"])
        for repo in result["repositories"]:
            self.assertIsNone(repo["updated_at"])

    def test_get_mirror_config_data_empty_repositories(self):
        """Test extracting mirror config with no repositories."""
        mirror = self.create_mock_mirror()
        mirror.rpm_repomds = []

        result = asyncio.run(_get_mirror_config_data(mirror))

        self.assertEqual(len(result["repositories"]), 0)

    def test_get_mirror_config_data_riscv64_architecture(self):
        """Test extracting mirror config for riscv64 architecture."""
        mirror = self.create_mock_mirror()
        mirror.match_arch = "riscv64"
        mirror.name = "Rocky Linux 10.0 riscv64"
        mirror.match_major_version = 10
        mirror.match_minor_version = 0

        # Update repository architecture
        mirror.rpm_repomds[0].arch = "riscv64"
        mirror.rpm_repomds[0].url = "https://example.com/BaseOS/riscv64/os"

        result = asyncio.run(_get_mirror_config_data(mirror))

        self.assertEqual(result["mirror"]["match_arch"], "riscv64")
        self.assertEqual(result["repositories"][0]["arch"], "riscv64")


class TestImportValidation(unittest.TestCase):
    """Test import validation wrapper function."""

    def test_validate_import_data_valid(self):
        """Test validation of valid import data."""
        valid_data = [
            {
                "product": {
                    "name": "Rocky Linux",
                    "variant": "Rocky Linux",
                    "vendor": "RESF",
                },
                "mirror": {
                    "name": "Rocky Linux 9.6 x86_64",
                    "match_variant": "Red Hat Enterprise Linux",
                    "match_major_version": 9,
                    "match_minor_version": 6,
                    "match_arch": "x86_64",
                },
                "repositories": [
                    {
                        "repo_name": "BaseOS",
                        "arch": "x86_64",
                        "production": True,
                        "url": "https://example.com/repo",
                    }
                ],
            }
        ]

        errors = asyncio.run(_validate_import_data(valid_data))
        self.assertEqual(errors, [])

    def test_validate_import_data_invalid_structure(self):
        """Test validation of invalid import data structure."""
        invalid_data = [
            {
                "product": {
                    "name": "Rocky Linux"
                    # Missing variant and vendor
                },
                "mirror": {
                    # Missing required fields
                },
                "repositories": [],
            }
        ]

        errors = asyncio.run(_validate_import_data(invalid_data))
        self.assertGreater(len(errors), 0)

    def test_validate_import_data_not_list(self):
        """Test validation when import data is not a list."""
        invalid_data = {"not": "a list"}

        errors = asyncio.run(_validate_import_data(invalid_data))
        self.assertIn("must be a list", errors[0])


if __name__ == "__main__":
    # Run with verbose output
    unittest.main(verbosity=2)
