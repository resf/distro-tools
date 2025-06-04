import unittest
from pathlib import Path
import json
from unittest.mock import patch, MagicMock

# Mock logger before importing module
mock_logger = MagicMock()
with patch('common.logger.Logger') as mock_logger_class:
    mock_logger_class.return_value = mock_logger
    from apollo.rhcsaf import red_hat_advisory_scraper

from apollo.rhcsaf import extract_rhel_affected_products_for_db

class TestRedHatAdvisoryScraper(unittest.TestCase):
    def setUp(self):
        # Create sample CSAF data
        self.sample_csaf = {
            "document": {
                "tracking": {
                    "initial_release_date": "2025-02-24T03:42:46+00:00",
                    "current_release_date": "2025-04-17T12:08:56+00:00",
                    "id": "RHSA-2025:1234"
                },
                "title": "Red Hat Security Advisory: Important: package security update",
                "aggregate_severity": {
                    "text": "Important"
                },
                "notes": [
                    {
                        "category": "general",
                        "text": "Test description"
                    },
                    {
                        "category": "summary",
                        "text": "Test topic"
                    }
                ]
            },
            "product_tree": {
                "branches": [
                    {
                        "branches": [
                            {
                                "category": "product_family",
                                "name": "Red Hat Enterprise Linux",
                                "branches": [
                                    {
                                        "category": "product_name",
                                        "name": "Red Hat Enterprise Linux 9",
                                        "product": {
                                            "name": "Red Hat Enterprise Linux 9",
                                            "product_identification_helper": {
                                                "cpe": "cpe:/o:redhat:enterprise_linux:9.4"
                                            }
                                        }
                                    }
                                ]
                            },
                            {
                                "category": "architecture",
                                "name": "x86_64"
                            }
                        ]
                    }
                ]
            },
            "vulnerabilities": [
                {
                    "cve": "CVE-2025-1234",
                    "ids": [
                        {
                        "system_name": "Red Hat Bugzilla ID",
                        "text": "123456"
                        }
                    ],
                    "product_status": {
                        "fixed": [
                            "AppStream-9.4.0.Z.EUS:rsync-0:3.2.3-19.el9_4.1.x86_64",
                            "AppStream-9.4.0.Z.EUS:rsync-0:3.2.3-19.el9_4.1.src"
                        ]
                    },
                    "scores": [{
                        "cvss_v3": {
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "baseScore": 9.8
                        }
                    }],
                    "cwe": {
                        "id": "CWE-79"
                    },
                    "references": [
                        {
                            "category": "external",
                            "url": "https://bugzilla.redhat.com/show_bug.cgi?id=123456"
                        }
                    ]
                }
            ]
        }
        
        # Write test CSAF file
        self.test_file = Path("test_csaf.json")
        with open(self.test_file, "w") as f:
            json.dump(self.sample_csaf, f)

    def tearDown(self):
        # Clean up test file
        self.test_file.unlink(missing_ok=True)

    def test_parse_security_advisory(self):
        """Test parsing a security advisory"""
        result = red_hat_advisory_scraper(self.sample_csaf)
        
        self.assertEqual(result["name"], "RHSA-2025:1234")
        self.assertEqual(result["kind"], "Security")
        self.assertEqual(result["severity"], "Important")
        self.assertEqual(result["red_hat_description"], "Test description")
        self.assertEqual(result["topic"], "Test topic")
        
        # Check fixed packages
        self.assertIn("rsync-0:3.2.3-19.el9_4.1.x86_64", result["red_hat_fixed_packages"])
        self.assertIn("rsync-0:3.2.3-19.el9_4.1.src", result["red_hat_fixed_packages"])
        
        # Check CVE information
        self.assertIn(
            ("CVE-2025-1234", 
             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
             9.8,
             "CWE-79"),
            result["red_hat_cve_list"]
        )
        
        # Check Bugzilla information
        self.assertIn("123456", result["red_hat_bugzilla_list"])
        
        # Check affected products
        self.assertIn(
            ("Red Hat Enterprise Linux", "Red Hat Enterprise Linux for x86_64", 9, 4, "x86_64"),
            result["red_hat_affected_products"]
        )

    def test_bugfix_advisory(self):
        """Test parsing a bug fix advisory"""
        self.sample_csaf["document"]["tracking"]["id"] = "RHBA-2025:1234"
        self.sample_csaf["document"]["title"] = "Red Hat Bug Fix Advisory: package update"
        
        with open(self.test_file, "w") as f:
            json.dump(self.sample_csaf, f)
            
        result = red_hat_advisory_scraper(self.sample_csaf)
        self.assertEqual(result["kind"], "Bug Fix")

    def test_enhancement_advisory(self):
        """Test parsing an enhancement advisory"""
        self.sample_csaf["document"]["tracking"]["id"] = "RHEA-2025:1234"
        self.sample_csaf["document"]["title"] = "Red Hat Enhancement Advisory: package update"
        
        with open(self.test_file, "w") as f:
            json.dump(self.sample_csaf, f)
            
        result = red_hat_advisory_scraper(self.sample_csaf)
        self.assertEqual(result["kind"], "Enhancement")

    def test_no_vulnerabilities(self):
        """Test handling of CSAF file with no vulnerabilities"""
        self.sample_csaf.pop("vulnerabilities")
        
        with open(self.test_file, "w") as f:
            json.dump(self.sample_csaf, f)
            
        result = red_hat_advisory_scraper(self.sample_csaf)
        self.assertIsNone(result)


class TestExtractRhelAffectedProducts(unittest.TestCase):
    def setUp(self):
        self.base_csaf = {
            "product_tree": {
                "branches": [
                    {
                        "branches": [
                            {
                                "category": "product_family",
                                "name": "Red Hat Enterprise Linux",
                                "branches": [
                                    {
                                        "category": "product_name",
                                        "product": {
                                            "name": "Red Hat Enterprise Linux 9",
                                            "product_identification_helper": {
                                                "cpe": "cpe:/o:redhat:enterprise_linux:9.4"
                                            }
                                        }
                                    }
                                ]
                            },
                            {
                                "category": "architecture",
                                "name": "x86_64"
                            }
                        ]
                    }
                ]
            }
        }

    def test_extract_basic(self):
        result = extract_rhel_affected_products_for_db(self.base_csaf)
        self.assertIn(
            ("Red Hat Enterprise Linux", "Red Hat Enterprise Linux for x86_64", 9, 4, "x86_64"),
            result
        )

    def test_no_product_tree(self):
        csaf = {}
        result = extract_rhel_affected_products_for_db(csaf)
        self.assertEqual(result, set())

    def test_unknown_architecture(self):
        csaf = self.base_csaf.copy()
        csaf["product_tree"]["branches"][0]["branches"].append({
            "category": "architecture",
            "name": "unknownarch"
        })
        result = extract_rhel_affected_products_for_db(csaf)
        # Should still only include x86_64, unknownarch is skipped
        self.assertTrue(all(t[4] != "unknownarch" for t in result))

    def test_noarch_expansion(self):
        csaf = self.base_csaf.copy()
        csaf["product_tree"]["branches"][0]["branches"] = [
            csaf["product_tree"]["branches"][0]["branches"][0],  # product_family
            {"category": "architecture", "name": "noarch"}
        ]
        result = extract_rhel_affected_products_for_db(csaf)
        arches = [t[4] for t in result]
        self.assertIn("x86_64", arches)
        self.assertIn("aarch64", arches)
        self.assertIn("ppc64le", arches)
        self.assertIn("s390x", arches)

    def test_missing_cpe(self):
        csaf = self.base_csaf.copy()
        csaf["product_tree"]["branches"][0]["branches"][0]["branches"][0]["product"].pop("product_identification_helper")
        result = extract_rhel_affected_products_for_db(csaf)
        self.assertEqual(result, set())

    def test_major_only_version(self):
        csaf = self.base_csaf.copy()
        csaf["product_tree"]["branches"][0]["branches"][0]["branches"][0]["product"]["product_identification_helper"]["cpe"] = "cpe:/o:redhat:enterprise_linux:9"
        result = extract_rhel_affected_products_for_db(csaf)
        self.assertIn(
            ("Red Hat Enterprise Linux", "Red Hat Enterprise Linux for x86_64", 9, None, "x86_64"),
            result
        )