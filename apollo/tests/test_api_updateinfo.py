"""
Unit tests for updateinfo API v2
Tests product slug resolution, database queries, XML generation,
and data integrity validation
"""

import unittest
import sys
import os

# Add the project root to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from apollo.server.routes.api_updateinfo import (
    resolve_product_slug,
    PRODUCT_SLUG_MAP,
)


class TestProductSlugResolution(unittest.TestCase):
    """Test product slug to product name resolution."""

    def test_resolve_valid_slugs(self):
        """Test that valid slugs resolve correctly."""
        test_cases = [
            ("rocky-linux", "Rocky Linux"),
            ("rocky-linux-sig-cloud", "Rocky Linux SIG Cloud"),
        ]

        for slug, expected_name in test_cases:
            with self.subTest(slug=slug):
                result = resolve_product_slug(slug)
                self.assertEqual(result, expected_name)

    def test_resolve_case_insensitive(self):
        """Test that slug resolution is case insensitive."""
        test_cases = [
            ("Rocky-Linux", "Rocky Linux"),
            ("ROCKY-LINUX", "Rocky Linux"),
            ("rocky-LINUX", "Rocky Linux"),
            ("Rocky-Linux-SIG-Cloud", "Rocky Linux SIG Cloud"),
        ]

        for slug, expected_name in test_cases:
            with self.subTest(slug=slug):
                result = resolve_product_slug(slug)
                self.assertEqual(result, expected_name)

    def test_resolve_invalid_slug(self):
        """Test that invalid slugs return None."""
        test_cases = [
            "invalid-slug",
            "rocky",
            "linux",
            "centos-linux",
            "",
            "rocky_linux",  # underscore instead of hyphen
        ]

        for slug in test_cases:
            with self.subTest(slug=slug):
                result = resolve_product_slug(slug)
                self.assertIsNone(result)

    def test_all_mapped_slugs_unique(self):
        """Test that all product slugs map to unique names."""
        product_names = list(PRODUCT_SLUG_MAP.values())
        self.assertEqual(len(product_names), len(set(product_names)),
                        "Product names should be unique")

    def test_slug_map_not_empty(self):
        """Test that the slug map is not empty."""
        self.assertGreater(len(PRODUCT_SLUG_MAP), 0,
                          "PRODUCT_SLUG_MAP should not be empty")


class TestProductSlugFormat(unittest.TestCase):
    """Test product slug formatting requirements."""

    def test_slugs_are_lowercase(self):
        """Test that all defined slugs are lowercase."""
        for slug in PRODUCT_SLUG_MAP.keys():
            with self.subTest(slug=slug):
                self.assertEqual(slug, slug.lower(),
                               f"Slug '{slug}' should be lowercase")

    def test_slugs_use_hyphens(self):
        """Test that slugs use hyphens not underscores."""
        for slug in PRODUCT_SLUG_MAP.keys():
            with self.subTest(slug=slug):
                self.assertNotIn("_", slug,
                               f"Slug '{slug}' should not contain underscores")
                if len(slug) > 5:  # Only check multi-word slugs
                    self.assertIn("-", slug,
                                f"Multi-word slug '{slug}' should contain hyphens")

    def test_product_names_are_capitalized(self):
        """Test that product names are properly capitalized."""
        for product_name in PRODUCT_SLUG_MAP.values():
            with self.subTest(product_name=product_name):
                # Should start with capital letter
                self.assertTrue(product_name[0].isupper(),
                              f"Product name '{product_name}' should start with capital letter")


if __name__ == "__main__":
    unittest.main()
