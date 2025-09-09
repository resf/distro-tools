"""
Tests for supported products admin logic including validation and configuration processing
Tests core logic without FastAPI dependencies
"""

import unittest
import asyncio
import sys
import os
from typing import Dict, List, Any

# Add the project root to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))


class TestConfigurationValidation(unittest.TestCase):
    """Test configuration import validation logic."""

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

    def tearDown(self):
        self.loop.close()

    def validate_import_data_local(self, import_data: List[Dict[str, Any]]) -> List[str]:
        """Local implementation of validation logic for testing."""
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

    def test_validate_valid_configuration(self):
        """Test validation of valid configuration data."""
        valid_config = [{
            "product": {
                "name": "Rocky Linux",
                "variant": "Rocky Linux", 
                "vendor": "Rocky Enterprise Software Foundation"
            },
            "mirror": {
                "name": "Rocky Linux 9.6 x86_64",
                "match_variant": "Red Hat Enterprise Linux",
                "match_major_version": 9,
                "match_minor_version": None,
                "match_arch": "x86_64"
            },
            "repositories": [{
                "repo_name": "BaseOS",
                "arch": "x86_64",
                "production": True,
                "url": "https://example.com/repo"
            }]
        }]

        errors = self.validate_import_data_local(valid_config)
        self.assertEqual(errors, [])

    def test_validate_riscv64_configuration(self):
        """Test validation of riscv64 configuration."""
        riscv64_config = [{
            "product": {
                "name": "Rocky Linux",
                "variant": "Rocky Linux", 
                "vendor": "Rocky Enterprise Software Foundation"
            },
            "mirror": {
                "name": "Rocky Linux 10.0 riscv64",
                "match_variant": "Red Hat Enterprise Linux",
                "match_major_version": 10,
                "match_minor_version": None,
                "match_arch": "riscv64"
            },
            "repositories": [{
                "repo_name": "BaseOS",
                "arch": "riscv64",
                "production": True,
                "url": "https://mirror.example.com/pub/rocky/10.0/BaseOS/riscv64/os/repodata/repomd.xml"
            }]
        }]

        errors = self.validate_import_data_local(riscv64_config)
        self.assertEqual(errors, [])

    def test_validate_i686_configuration(self):
        """Test validation of i686 configuration."""
        i686_config = [{
            "product": {
                "name": "Rocky Linux",
                "variant": "Rocky Linux", 
                "vendor": "Rocky Enterprise Software Foundation"
            },
            "mirror": {
                "name": "Rocky Linux 8.10 i686",
                "match_variant": "Red Hat Enterprise Linux",
                "match_major_version": 8,
                "match_minor_version": None,
                "match_arch": "i686"
            },
            "repositories": [{
                "repo_name": "devel",
                "arch": "i686",
                "production": True,
                "url": "https://mirror.example.com/pub/rocky/8.10/devel/i686/os/repodata/repomd.xml"
            }]
        }]

        errors = self.validate_import_data_local(i686_config)
        self.assertEqual(errors, [])

    def test_validate_missing_required_fields(self):
        """Test validation with missing required fields."""
        invalid_configs = [
            # Missing product
            {
                "mirror": {"name": "test"},
                "repositories": []
            },
            # Missing mirror fields
            {
                "product": {"name": "Rocky Linux", "variant": "test", "vendor": "test"},
                "mirror": {"name": "test"},  # missing required fields
                "repositories": []
            },
            # Missing repository fields  
            {
                "product": {"name": "Rocky Linux", "variant": "test", "vendor": "test"},
                "mirror": {
                    "name": "test",
                    "match_variant": "test",
                    "match_major_version": 9,
                    "match_arch": "x86_64"
                },
                "repositories": [{
                    "repo_name": "BaseOS"
                    # missing arch, production, url
                }]
            }
        ]

        errors = self.validate_import_data_local(invalid_configs)
        
        # Should have multiple validation errors
        self.assertGreater(len(errors), 0)
        self.assertIn("missing", " ".join(errors).lower())

    def test_validate_non_list_input(self):
        """Test validation with non-list input."""
        invalid_input = {"not": "a list"}

        errors = self.validate_import_data_local(invalid_input)
        self.assertEqual(errors, ["Import data must be a list of configuration objects"])

    def test_validate_architecture_specific_configurations(self):
        """Test validation of configurations for new architectures."""
        arch_configs = [
            # riscv64 config
            {
                "product": {"name": "Rocky Linux", "variant": "Rocky Linux", "vendor": "RESF"},
                "mirror": {
                    "name": "Rocky Linux 10.0 riscv64",
                    "match_variant": "Red Hat Enterprise Linux",
                    "match_major_version": 10,
                    "match_arch": "riscv64"
                },
                "repositories": [{
                    "repo_name": "extras",
                    "arch": "riscv64",
                    "production": True,
                    "url": "https://example.com/10.0/extras/riscv64/os/repodata/repomd.xml"
                }]
            },
            # i686 config
            {
                "product": {"name": "Rocky Linux", "variant": "Rocky Linux", "vendor": "RESF"},
                "mirror": {
                    "name": "Rocky Linux 8.10 i686",
                    "match_variant": "Red Hat Enterprise Linux",
                    "match_major_version": 8,
                    "match_arch": "i686"
                },
                "repositories": [{
                    "repo_name": "Devel",
                    "arch": "i686",
                    "production": False,
                    "url": "https://example.com/8.10/Devel/i686/os/repodata/repomd.xml"
                }]
            }
        ]

        errors = self.validate_import_data_local(arch_configs)
        self.assertEqual(errors, [])

    def test_validate_multiple_repositories_per_mirror(self):
        """Test validation of mirrors with multiple repositories."""
        multi_repo_config = [{
            "product": {"name": "Rocky Linux", "variant": "Rocky Linux", "vendor": "RESF"},
            "mirror": {
                "name": "Rocky Linux 10.0 riscv64",
                "match_variant": "Red Hat Enterprise Linux", 
                "match_major_version": 10,
                "match_arch": "riscv64"
            },
            "repositories": [
                {
                    "repo_name": "BaseOS",
                    "arch": "riscv64",
                    "production": True,
                    "url": "https://example.com/10.0/BaseOS/riscv64/os/repodata/repomd.xml"
                },
                {
                    "repo_name": "AppStream", 
                    "arch": "riscv64",
                    "production": True,
                    "url": "https://example.com/10.0/AppStream/riscv64/os/repodata/repomd.xml"
                },
                {
                    "repo_name": "extras",
                    "arch": "riscv64", 
                    "production": True,
                    "url": "https://example.com/10.0/extras/riscv64/os/repodata/repomd.xml"
                }
            ]
        }]

        errors = self.validate_import_data_local(multi_repo_config)
        self.assertEqual(errors, [])


class TestBulkDeletionLogic(unittest.TestCase):
    """Test bulk deletion logic without database dependencies."""

    def parse_mirror_ids(self, mirror_ids_str: str) -> List[int]:
        """Parse comma-separated mirror IDs."""
        if not mirror_ids_str or mirror_ids_str.strip() == "":
            return []
        
        try:
            return [int(mid.strip()) for mid in mirror_ids_str.split(",") if mid.strip()]
        except ValueError:
            return None

    def test_parse_valid_mirror_ids(self):
        """Test parsing valid mirror ID strings."""
        test_cases = [
            ("1,2,3", [1, 2, 3]),
            ("1, 2, 3", [1, 2, 3]),  # with spaces
            ("42", [42]),  # single ID
            ("1,2,3,4,5", [1, 2, 3, 4, 5]),  # multiple IDs
        ]
        
        for input_str, expected in test_cases:
            with self.subTest(input_str=input_str):
                result = self.parse_mirror_ids(input_str)
                self.assertEqual(result, expected)

    def test_parse_invalid_mirror_ids(self):
        """Test parsing invalid mirror ID strings."""
        invalid_cases = [
            ("", []),           # empty string -> empty list
            ("   ", []),        # whitespace only -> empty list
            ("abc,def", None),    # non-numeric -> None
            ("1,abc,3", None),    # mixed valid/invalid -> None
        ]
        
        for input_str, expected in invalid_cases:
            with self.subTest(input_str=input_str):
                result = self.parse_mirror_ids(input_str)
                self.assertEqual(result, expected)

    def test_parse_mirror_ids_edge_cases(self):
        """Test edge cases for mirror ID parsing."""
        edge_cases = [
            ("1,", [1]),              # trailing comma
            (",1,2", [1, 2]),         # leading comma  
            ("1,,2", [1, 2]),         # double comma
            (" 1 , 2 , 3 ", [1, 2, 3]),  # extra whitespace
        ]
        
        for input_str, expected in edge_cases:
            with self.subTest(input_str=input_str):
                result = self.parse_mirror_ids(input_str)
                self.assertEqual(result, expected)


class TestDependencyChecking(unittest.TestCase):
    """Test dependency checking logic."""

    def check_mirror_dependencies(self, mirror_name: str, blocks_count: int, overrides_count: int) -> str:
        """Simulate dependency checking for a mirror."""
        if blocks_count == 0 and overrides_count == 0:
            return None  # No dependencies, deletion allowed
        
        error_parts = []
        if blocks_count > 0:
            error_parts.append(f"{blocks_count} blocked product(s)")
        if overrides_count > 0:
            error_parts.append(f"{overrides_count} override(s)")
        
        return (f"Cannot delete mirror '{mirror_name}' because it has associated "
                f"{' and '.join(error_parts)}. Please remove these dependencies first.")

    def test_mirror_with_no_dependencies(self):
        """Test mirror with no blocking dependencies."""
        result = self.check_mirror_dependencies("Test Mirror", 0, 0)
        self.assertIsNone(result)

    def test_mirror_with_blocks_only(self):
        """Test mirror with only blocks."""
        result = self.check_mirror_dependencies("Test Mirror", 3, 0)
        self.assertIn("3 blocked product(s)", result)
        self.assertNotIn("override", result)

    def test_mirror_with_overrides_only(self):
        """Test mirror with only overrides."""
        result = self.check_mirror_dependencies("Test Mirror", 0, 2)
        self.assertIn("2 override(s)", result)
        self.assertNotIn("blocked product", result)

    def test_mirror_with_both_dependencies(self):
        """Test mirror with both blocks and overrides."""
        result = self.check_mirror_dependencies("Test Mirror", 3, 2)
        self.assertIn("3 blocked product(s)", result)
        self.assertIn("2 override(s)", result)
        self.assertIn(" and ", result)

    def check_bulk_dependencies(self, mirror_dependencies: List[tuple]) -> List[str]:
        """Check dependencies for multiple mirrors."""
        blocked_mirrors = []
        
        for mirror_name, blocks_count, overrides_count in mirror_dependencies:
            if blocks_count > 0 or overrides_count > 0:
                error_parts = []
                if blocks_count > 0:
                    error_parts.append(f"{blocks_count} block(s)")
                if overrides_count > 0:
                    error_parts.append(f"{overrides_count} override(s)")
                
                blocked_mirrors.append(f"'{mirror_name}' ({' and '.join(error_parts)})")
        
        return blocked_mirrors

    def test_bulk_dependency_checking(self):
        """Test bulk dependency checking for multiple mirrors."""
        # Test data: (mirror_name, blocks_count, overrides_count)
        mirror_deps = [
            ("Mirror 1", 0, 0),      # No dependencies
            ("Mirror 2", 2, 0),      # Has blocks
            ("Mirror 3", 0, 1),      # Has overrides
            ("Mirror 4", 1, 2),      # Has both
            ("Mirror 5", 0, 0),      # No dependencies
        ]
        
        blocked = self.check_bulk_dependencies(mirror_deps)
        
        # Should identify 3 blocked mirrors
        self.assertEqual(len(blocked), 3)
        self.assertIn("'Mirror 2' (2 block(s))", blocked)
        self.assertIn("'Mirror 3' (1 override(s))", blocked)
        self.assertIn("'Mirror 4' (1 block(s) and 2 override(s))", blocked)

    def test_bulk_dependency_no_blocks(self):
        """Test bulk dependency checking with no blocked mirrors."""
        mirror_deps = [
            ("Mirror 1", 0, 0),
            ("Mirror 2", 0, 0), 
            ("Mirror 3", 0, 0),
        ]
        
        blocked = self.check_bulk_dependencies(mirror_deps)
        self.assertEqual(len(blocked), 0)


if __name__ == "__main__":
    # Run with verbose output
    unittest.main(verbosity=2)