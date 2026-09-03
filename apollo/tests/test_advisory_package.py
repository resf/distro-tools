"""Tests for AdvisoryPackage.package_name JSON serialization."""

import unittest

from tortoise.contrib.pydantic import pydantic_model_creator

from apollo.db import AdvisoryPackage


class TestAdvisoryPackageName(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = pydantic_model_creator(
            AdvisoryPackage, name="AdvisoryPackageNameTest"
        ).schema()

    def test_pydantic_schema_exposes_package_name(self):
        properties = self.schema["properties"]
        self.assertIn("package_name", properties)
        self.assertNotIn("_package_name", properties)

    def test_clean_strips_module_prefix_once(self):
        self.assertEqual(
            AdvisoryPackage._clean_package_name("module.nodejs"),
            "nodejs",
        )
        self.assertEqual(
            AdvisoryPackage._clean_package_name("nodejs"),
            "nodejs",
        )
        self.assertIsNone(AdvisoryPackage._clean_package_name(None))

    def test_instance_attribute_returns_cleaned_name(self):
        pkg = AdvisoryPackage.__new__(AdvisoryPackage)
        pkg._package_name = "module.httpd"
        self.assertEqual(pkg.package_name, "httpd")

    def test_computed_class_access_is_annotated_method(self):
        func = AdvisoryPackage.package_name
        self.assertTrue(callable(func))
        self.assertIn("return", func.__annotations__)


if __name__ == "__main__":
    unittest.main()
