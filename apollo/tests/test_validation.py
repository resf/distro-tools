"""
Comprehensive tests for apollo.server.validation module.

Tests all validator classes, enums, patterns, and utility functions without
external dependencies (no database, no FastAPI).
"""

import unittest
import sys
import os
from typing import Dict, Any, List

# Add the project root to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from apollo.server.validation import (
    Architecture,
    URLProtocol,
    ValidationErrorType,
    ValidationError,
    ValidationPatterns,
    FieldValidator,
    ConfigValidator,
    FormValidator,
    get_supported_architectures,
    is_valid_url,
    is_valid_architecture,
)


class TestEnumsAndPatterns(unittest.TestCase):
    """Test enums, patterns, and basic validation components."""

    def test_architecture_enum_values(self):
        """Test all Architecture enum values."""
        expected_architectures = [
            "x86_64",
            "aarch64",
            "i386",
            "i686",
            "ppc64",
            "ppc64le",
            "s390x",
            "riscv64",
            "noarch",
        ]

        for arch in expected_architectures:
            with self.subTest(arch=arch):
                self.assertEqual(Architecture(arch), arch)

    def test_url_protocol_enum_values(self):
        """Test URLProtocol enum values."""
        self.assertEqual(URLProtocol.HTTP, "http://")
        self.assertEqual(URLProtocol.HTTPS, "https://")

    def test_validation_error_type_enum(self):
        """Test ValidationErrorType enum values."""
        expected_types = [
            "required",
            "min_length",
            "max_length",
            "invalid_format",
            "invalid_url",
            "invalid_architecture",
        ]

        for error_type in expected_types:
            with self.subTest(error_type=error_type):
                self.assertEqual(ValidationErrorType(error_type), error_type)

    def test_validation_error_exception(self):
        """Test ValidationError exception behavior."""
        message = "Test error"
        error_type = ValidationErrorType.REQUIRED
        field = "test_field"

        error = ValidationError(message, error_type, field)

        self.assertEqual(str(error), message)
        self.assertEqual(error.message, message)
        self.assertEqual(error.error_type, error_type)
        self.assertEqual(error.field, field)

    def test_validation_patterns(self):
        """Test regex patterns work correctly."""
        # URL pattern
        self.assertTrue(ValidationPatterns.URL_PATTERN.match("http://example.com"))
        self.assertTrue(ValidationPatterns.URL_PATTERN.match("https://example.com"))
        self.assertFalse(ValidationPatterns.URL_PATTERN.match("ftp://example.com"))
        self.assertFalse(ValidationPatterns.URL_PATTERN.match("example.com"))

        # Name pattern
        self.assertTrue(ValidationPatterns.NAME_PATTERN.match("Rocky Linux"))
        self.assertTrue(ValidationPatterns.NAME_PATTERN.match("Test_Name-123.v1"))
        self.assertFalse(ValidationPatterns.NAME_PATTERN.match("name@invalid"))

        # Architecture pattern
        self.assertTrue(ValidationPatterns.ARCH_PATTERN.match("x86_64"))
        self.assertTrue(ValidationPatterns.ARCH_PATTERN.match("riscv64"))
        self.assertFalse(ValidationPatterns.ARCH_PATTERN.match("invalid_arch"))

        # Repository name pattern
        self.assertTrue(ValidationPatterns.REPO_NAME_PATTERN.match("BaseOS"))
        self.assertTrue(ValidationPatterns.REPO_NAME_PATTERN.match("test-repo_123"))
        self.assertFalse(ValidationPatterns.REPO_NAME_PATTERN.match("repo with spaces"))


class TestFieldValidator(unittest.TestCase):
    """Test FieldValidator class methods."""

    def test_validate_name_success(self):
        """Test successful name validation."""
        test_cases = [
            ("Rocky Linux", "Rocky Linux"),
            ("  Test Name  ", "Test Name"),  # Trimmed
            ("Test_Name-123.v1", "Test_Name-123.v1"),
            ("A" * 100, "A" * 100),  # Long name
        ]

        for input_name, expected in test_cases:
            with self.subTest(input_name=input_name):
                result = FieldValidator.validate_name(input_name)
                self.assertEqual(result, expected)

    def test_validate_name_failure(self):
        """Test name validation failures."""
        test_cases = [
            ("", ValidationErrorType.REQUIRED),
            ("  ", ValidationErrorType.REQUIRED),
            ("AB", ValidationErrorType.MIN_LENGTH),  # Too short (default min_length=3)
            ("invalid@name", ValidationErrorType.INVALID_FORMAT),
            ("name#with$special", ValidationErrorType.INVALID_FORMAT),
        ]

        for invalid_name, expected_error_type in test_cases:
            with self.subTest(invalid_name=invalid_name):
                with self.assertRaises(ValidationError) as context:
                    FieldValidator.validate_name(invalid_name)
                self.assertEqual(context.exception.error_type, expected_error_type)

    def test_validate_name_custom_min_length(self):
        """Test name validation with custom minimum length."""
        # Should pass with min_length=1
        result = FieldValidator.validate_name("A", min_length=1)
        self.assertEqual(result, "A")

        # Should fail with min_length=5
        with self.assertRaises(ValidationError) as context:
            FieldValidator.validate_name("ABC", min_length=5)
        self.assertEqual(context.exception.error_type, ValidationErrorType.MIN_LENGTH)

    def test_validate_url_success(self):
        """Test successful URL validation."""
        test_cases = [
            ("http://example.com", "http://example.com"),
            (
                "https://mirror.rockylinux.org/pub/rocky/",
                "https://mirror.rockylinux.org/pub/rocky/",
            ),
            ("  https://example.com  ", "https://example.com"),  # Trimmed
        ]

        for input_url, expected in test_cases:
            with self.subTest(input_url=input_url):
                result = FieldValidator.validate_url(input_url)
                self.assertEqual(result, expected)

    def test_validate_url_optional_success(self):
        """Test optional URL validation."""
        # Empty URL should return None when not required
        result = FieldValidator.validate_url("", required=False)
        self.assertIsNone(result)

        result = FieldValidator.validate_url("  ", required=False)
        self.assertIsNone(result)

    def test_validate_url_failure(self):
        """Test URL validation failures."""
        test_cases = [
            ("", ValidationErrorType.REQUIRED),  # Required but empty
            ("example.com", ValidationErrorType.INVALID_URL),  # Missing protocol
            ("ftp://example.com", ValidationErrorType.INVALID_URL),  # Wrong protocol
            ("http://", ValidationErrorType.INVALID_URL),  # Incomplete URL
        ]

        for invalid_url, expected_error_type in test_cases:
            with self.subTest(invalid_url=invalid_url):
                with self.assertRaises(ValidationError) as context:
                    FieldValidator.validate_url(invalid_url, required=True)
                self.assertEqual(context.exception.error_type, expected_error_type)

    def test_validate_architecture_success(self):
        """Test successful architecture validation."""
        valid_architectures = [
            "x86_64",
            "aarch64",
            "i386",
            "i686",
            "ppc64",
            "ppc64le",
            "s390x",
            "riscv64",
            "noarch",
        ]

        for arch in valid_architectures:
            with self.subTest(arch=arch):
                result = FieldValidator.validate_architecture(arch)
                self.assertEqual(result, arch)

    def test_validate_architecture_with_whitespace(self):
        """Test architecture validation handles whitespace."""
        result = FieldValidator.validate_architecture("  x86_64  ")
        self.assertEqual(result, "x86_64")

    def test_validate_architecture_failure(self):
        """Test architecture validation failures."""
        test_cases = [
            ("", ValidationErrorType.REQUIRED),
            ("  ", ValidationErrorType.REQUIRED),
            ("invalid_arch", ValidationErrorType.INVALID_ARCHITECTURE),
            ("x86", ValidationErrorType.INVALID_ARCHITECTURE),
            ("arm64", ValidationErrorType.INVALID_ARCHITECTURE),  # Should be aarch64
        ]

        for invalid_arch, expected_error_type in test_cases:
            with self.subTest(invalid_arch=invalid_arch):
                with self.assertRaises(ValidationError) as context:
                    FieldValidator.validate_architecture(invalid_arch)
                self.assertEqual(context.exception.error_type, expected_error_type)

    def test_validate_repo_name_success(self):
        """Test successful repository name validation."""
        test_cases = [
            ("BaseOS", "BaseOS"),
            ("AppStream", "AppStream"),
            ("extras", "extras"),
            ("test-repo_123", "test-repo_123"),
            ("  devel  ", "devel"),  # Trimmed
        ]

        for input_name, expected in test_cases:
            with self.subTest(input_name=input_name):
                result = FieldValidator.validate_repo_name(input_name)
                self.assertEqual(result, expected)

    def test_validate_repo_name_failure(self):
        """Test repository name validation failures."""
        test_cases = [
            ("", ValidationErrorType.REQUIRED),
            ("  ", ValidationErrorType.REQUIRED),
            ("A", ValidationErrorType.MIN_LENGTH),  # Too short (default min_length=2)
            ("repo with spaces", ValidationErrorType.INVALID_FORMAT),
            ("repo@invalid", ValidationErrorType.INVALID_FORMAT),
        ]

        for invalid_name, expected_error_type in test_cases:
            with self.subTest(invalid_name=invalid_name):
                with self.assertRaises(ValidationError) as context:
                    FieldValidator.validate_repo_name(invalid_name)
                self.assertEqual(context.exception.error_type, expected_error_type)


class TestConfigValidator(unittest.TestCase):
    """Test ConfigValidator class methods."""

    def test_validate_import_data_structure_success(self):
        """Test successful import data structure validation."""
        valid_data = [
            {
                "product": {
                    "name": "Rocky Linux",
                    "variant": "Rocky Linux",
                    "vendor": "Rocky Enterprise Software Foundation",
                },
                "mirror": {
                    "name": "Rocky Linux 9.6 x86_64",
                    "match_variant": "Red Hat Enterprise Linux",
                    "match_major_version": 9,
                    "match_minor_version": None,
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

        errors = ConfigValidator.validate_import_data_structure(valid_data)
        self.assertEqual(errors, [])

    def test_validate_import_data_structure_not_list(self):
        """Test import data validation when input is not a list."""
        invalid_data = {"not": "a list"}

        errors = ConfigValidator.validate_import_data_structure(invalid_data)
        self.assertEqual(len(errors), 1)
        self.assertIn("must be a list", errors[0])

    def test_validate_config_structure_success(self):
        """Test successful config structure validation."""
        valid_config = {
            "product": {
                "name": "Rocky Linux",
                "variant": "Rocky Linux",
                "vendor": "RESF",
            },
            "mirror": {
                "name": "Test Mirror",
                "match_variant": "Red Hat Enterprise Linux",
                "match_major_version": 9,
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

        errors = ConfigValidator.validate_config_structure(valid_config, 1)
        self.assertEqual(errors, [])

    def test_validate_config_structure_missing_keys(self):
        """Test config structure validation with missing required keys."""
        invalid_config = {
            "product": {"name": "Rocky Linux", "variant": "test", "vendor": "test"}
            # Missing 'mirror' and 'repositories'
        }

        errors = ConfigValidator.validate_config_structure(invalid_config, 1)

        self.assertGreater(len(errors), 0)
        missing_keys = [error for error in errors if "Missing required key" in error]
        self.assertGreater(len(missing_keys), 0)

    def test_validate_config_structure_not_dict(self):
        """Test config structure validation when config is not a dictionary."""
        invalid_config = "not a dictionary"

        errors = ConfigValidator.validate_config_structure(invalid_config, 1)

        self.assertEqual(len(errors), 1)
        self.assertIn("Must be a dictionary", errors[0])

    def test_validate_product_config_success(self):
        """Test successful product config validation."""
        valid_product = {
            "name": "Rocky Linux",
            "variant": "Rocky Linux",
            "vendor": "Rocky Enterprise Software Foundation",
        }

        errors = ConfigValidator.validate_product_config(valid_product, 1)
        self.assertEqual(errors, [])

    def test_validate_product_config_missing_fields(self):
        """Test product config validation with missing required fields."""
        invalid_product = {
            "name": "Rocky Linux"
            # Missing 'variant' and 'vendor'
        }

        errors = ConfigValidator.validate_product_config(invalid_product, 1)

        self.assertGreater(len(errors), 0)
        missing_fields = [
            error for error in errors if "missing required field" in error
        ]
        self.assertEqual(len(missing_fields), 2)  # Should have 2 missing fields

    def test_validate_product_config_not_dict(self):
        """Test product config validation when product is not a dictionary."""
        invalid_product = "not a dictionary"

        errors = ConfigValidator.validate_product_config(invalid_product, 1)

        self.assertEqual(len(errors), 1)
        self.assertIn("Product must be a dictionary", errors[0])

    def test_validate_mirror_config_success(self):
        """Test successful mirror config validation."""
        valid_mirror = {
            "name": "Rocky Linux 9.6 x86_64",
            "match_variant": "Red Hat Enterprise Linux",
            "match_major_version": 9,
            "match_minor_version": 6,
            "match_arch": "x86_64",
        }

        errors = ConfigValidator.validate_mirror_config(valid_mirror, 1)
        self.assertEqual(errors, [])

    def test_validate_mirror_config_riscv64(self):
        """Test mirror config validation with riscv64 architecture."""
        riscv64_mirror = {
            "name": "Rocky Linux 10.0 riscv64",
            "match_variant": "Red Hat Enterprise Linux",
            "match_major_version": 10,
            "match_minor_version": None,
            "match_arch": "riscv64",
        }

        errors = ConfigValidator.validate_mirror_config(riscv64_mirror, 1)
        self.assertEqual(errors, [])

    def test_validate_mirror_config_i686(self):
        """Test mirror config validation with i686 architecture."""
        i686_mirror = {
            "name": "Rocky Linux 8.10 i686",
            "match_variant": "Red Hat Enterprise Linux",
            "match_major_version": 8,
            "match_minor_version": 10,
            "match_arch": "i686",
        }

        errors = ConfigValidator.validate_mirror_config(i686_mirror, 1)
        self.assertEqual(errors, [])

    def test_validate_mirror_config_invalid_arch(self):
        """Test mirror config validation with invalid architecture."""
        invalid_mirror = {
            "name": "Test Mirror",
            "match_variant": "Red Hat Enterprise Linux",
            "match_major_version": 9,
            "match_arch": "invalid_arch",
        }

        errors = ConfigValidator.validate_mirror_config(invalid_mirror, 1)

        self.assertGreater(len(errors), 0)
        arch_errors = [error for error in errors if "Invalid architecture" in error]
        self.assertGreater(len(arch_errors), 0)

    def test_validate_mirror_config_invalid_versions(self):
        """Test mirror config validation with invalid version numbers."""
        invalid_mirror = {
            "name": "Test Mirror",
            "match_variant": "Red Hat Enterprise Linux",
            "match_major_version": -1,  # Invalid: negative
            "match_minor_version": "not_a_number",  # Invalid: not an int
            "match_arch": "x86_64",
        }

        errors = ConfigValidator.validate_mirror_config(invalid_mirror, 1)

        version_errors = [error for error in errors if "version must be" in error]
        self.assertGreater(len(version_errors), 0)

    def test_validate_mirror_config_not_dict(self):
        """Test mirror config validation when mirror is not a dictionary."""
        invalid_mirror = "not a dictionary"

        errors = ConfigValidator.validate_mirror_config(invalid_mirror, 1)

        self.assertEqual(len(errors), 1)
        self.assertIn("Mirror must be a dictionary", errors[0])

    def test_validate_repositories_config_success(self):
        """Test successful repositories config validation."""
        valid_repositories = [
            {
                "repo_name": "BaseOS",
                "arch": "x86_64",
                "production": True,
                "url": "https://example.com/BaseOS",
            },
            {
                "repo_name": "AppStream",
                "arch": "x86_64",
                "production": True,
                "url": "https://example.com/AppStream",
            },
        ]

        errors = ConfigValidator.validate_repositories_config(valid_repositories, 1)
        self.assertEqual(errors, [])

    def test_validate_repositories_config_not_list(self):
        """Test repositories config validation when input is not a list."""
        invalid_repositories = {"not": "a list"}

        errors = ConfigValidator.validate_repositories_config(invalid_repositories, 1)

        self.assertGreater(len(errors), 0)
        list_errors = [error for error in errors if "must be a list" in error]
        self.assertEqual(len(list_errors), 1)

    def test_validate_repository_config_success(self):
        """Test successful individual repository config validation."""
        valid_repo = {
            "repo_name": "BaseOS",
            "arch": "riscv64",
            "production": True,
            "url": "https://example.com/BaseOS/riscv64/os/repodata/repomd.xml",
            "debug_url": "https://example.com/debug",
            "source_url": "https://example.com/source",
        }

        errors = ConfigValidator.validate_repository_config(valid_repo, 1, 1)
        self.assertEqual(errors, [])

    def test_validate_repository_config_missing_fields(self):
        """Test repository config validation with missing required fields."""
        invalid_repo = {
            "repo_name": "BaseOS",
            # Missing 'arch', 'production', 'url'
        }

        errors = ConfigValidator.validate_repository_config(invalid_repo, 1, 1)

        missing_fields = [
            error for error in errors if "Missing required field" in error
        ]
        self.assertEqual(len(missing_fields), 3)  # arch, production, url

    def test_validate_repository_config_invalid_production(self):
        """Test repository config validation with invalid production value."""
        invalid_repo = {
            "repo_name": "BaseOS",
            "arch": "x86_64",
            "production": "not_a_boolean",  # Invalid
            "url": "https://example.com/repo",
        }

        errors = ConfigValidator.validate_repository_config(invalid_repo, 1, 1)

        production_errors = [
            error for error in errors if "must be true or false" in error
        ]
        self.assertEqual(len(production_errors), 1)

    def test_validate_repository_config_not_dict(self):
        """Test repository config validation when repo is not a dictionary."""
        invalid_repo = "not a dictionary"

        errors = ConfigValidator.validate_repository_config(invalid_repo, 1, 1)

        self.assertEqual(len(errors), 1)
        self.assertIn("Must be a dictionary", errors[0])


class TestFormValidator(unittest.TestCase):
    """Test FormValidator class methods."""

    def test_validate_mirror_form_success(self):
        """Test successful mirror form validation."""
        valid_form_data = {
            "name": "Rocky Linux 9.6 x86_64",
            "match_variant": "Red Hat Enterprise Linux",
            "match_major_version": 9,
            "match_minor_version": 6,
            "match_arch": "x86_64",
        }

        validated_data, errors = FormValidator.validate_mirror_form(valid_form_data)

        self.assertEqual(errors, [])
        self.assertEqual(validated_data["name"], "Rocky Linux 9.6 x86_64")
        self.assertEqual(validated_data["match_arch"], "x86_64")

    def test_validate_mirror_form_validation_errors(self):
        """Test mirror form validation with validation errors."""
        invalid_form_data = {
            "name": "",  # Invalid: empty
            "match_arch": "invalid_arch",  # Invalid: unsupported architecture
            "match_variant": "Red Hat Enterprise Linux",
            "match_major_version": 9,
        }

        validated_data, errors = FormValidator.validate_mirror_form(invalid_form_data)

        self.assertGreater(len(errors), 0)
        # Should have errors for both name and architecture
        self.assertGreaterEqual(len(errors), 2)

    def test_validate_repomd_form_success(self):
        """Test successful repository form validation."""
        valid_form_data = {
            "repo_name": "BaseOS",
            "arch": "riscv64",
            "production": True,
            "url": "https://example.com/BaseOS",
            "debug_url": "https://example.com/debug",
            "source_url": "https://example.com/source",
        }

        validated_data, errors = FormValidator.validate_repomd_form(valid_form_data)

        self.assertEqual(errors, [])
        self.assertEqual(validated_data["repo_name"], "BaseOS")
        self.assertEqual(validated_data["arch"], "riscv64")
        self.assertEqual(validated_data["url"], "https://example.com/BaseOS")
        self.assertTrue(validated_data["production"])

    def test_validate_repomd_form_optional_urls(self):
        """Test repository form validation with optional URLs."""
        form_data = {
            "repo_name": "BaseOS",
            "arch": "i686",
            "production": False,
            "url": "https://example.com/BaseOS",
            "debug_url": "",  # Empty optional URL
            "source_url": "",  # Empty optional URL
        }

        validated_data, errors = FormValidator.validate_repomd_form(form_data)

        self.assertEqual(errors, [])
        self.assertEqual(validated_data["debug_url"], "")
        self.assertEqual(validated_data["source_url"], "")

    def test_validate_repomd_form_validation_errors(self):
        """Test repository form validation with validation errors."""
        invalid_form_data = {
            "repo_name": "",  # Invalid: empty
            "arch": "invalid_arch",  # Invalid: unsupported architecture
            "production": False,
            "url": "invalid_url",  # Invalid: no protocol
            "debug_url": "also_invalid",  # Invalid: no protocol
        }

        validated_data, errors = FormValidator.validate_repomd_form(invalid_form_data)

        self.assertGreater(len(errors), 0)
        # Should have errors for repo_name, arch, url, and debug_url
        self.assertGreaterEqual(len(errors), 4)


class TestUtilityFunctions(unittest.TestCase):
    """Test utility functions."""

    def test_get_supported_architectures(self):
        """Test get_supported_architectures returns all architecture values."""
        architectures = get_supported_architectures()

        expected = [
            "x86_64",
            "aarch64",
            "i386",
            "i686",
            "ppc64",
            "ppc64le",
            "s390x",
            "riscv64",
            "noarch",
        ]

        self.assertEqual(sorted(architectures), sorted(expected))

    def test_is_valid_url(self):
        """Test is_valid_url function."""
        # Valid URLs
        valid_urls = [
            "http://example.com",
            "https://mirror.rockylinux.org/pub/rocky/",
            "https://example.com/path/to/resource?param=value",
        ]

        for url in valid_urls:
            with self.subTest(url=url):
                self.assertTrue(is_valid_url(url))

        # Invalid URLs
        invalid_urls = ["", "example.com", "ftp://example.com", "http://", None]

        for url in invalid_urls:
            with self.subTest(url=url):
                self.assertFalse(is_valid_url(url))

    def test_is_valid_url_with_whitespace(self):
        """Test is_valid_url handles whitespace."""
        self.assertTrue(is_valid_url("  https://example.com  "))

    def test_is_valid_architecture(self):
        """Test is_valid_architecture function."""
        # Valid architectures
        valid_archs = [
            "x86_64",
            "aarch64",
            "i386",
            "i686",
            "ppc64",
            "ppc64le",
            "s390x",
            "riscv64",
            "noarch",
        ]

        for arch in valid_archs:
            with self.subTest(arch=arch):
                self.assertTrue(is_valid_architecture(arch))

        # Invalid architectures
        invalid_archs = ["", "invalid_arch", "x86", "arm64", None]  # Should be aarch64

        for arch in invalid_archs:
            with self.subTest(arch=arch):
                self.assertFalse(is_valid_architecture(arch))

    def test_is_valid_architecture_with_whitespace(self):
        """Test is_valid_architecture handles whitespace."""
        self.assertTrue(is_valid_architecture("  x86_64  "))


if __name__ == "__main__":
    # Run with verbose output
    unittest.main(verbosity=2)
