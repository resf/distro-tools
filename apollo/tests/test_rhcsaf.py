import unittest
from pathlib import Path
import json
from unittest.mock import patch, MagicMock

# Mock logger before importing module
mock_logger = MagicMock()
with patch('common.logger.Logger') as mock_logger_class:
    mock_logger_class.return_value = mock_logger
    from apollo.rhcsaf import red_hat_advisory_scraper

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
            "vulnerabilities": [
                {
                    "cve": "CVE-2025-1234",
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
        result = red_hat_advisory_scraper(self.test_file)
        
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
            ("Red Hat Enterprise Linux", 
             "Red Hat Enterprise Linux 9",
             9,
             4,
             "x86_64"),
            result["red_hat_affected_products"]
        )

    def test_bugfix_advisory(self):
        """Test parsing a bug fix advisory"""
        self.sample_csaf["document"]["tracking"]["id"] = "RHBA-2025:1234"
        self.sample_csaf["document"]["title"] = "Red Hat Bug Fix Advisory: package update"
        
        with open(self.test_file, "w") as f:
            json.dump(self.sample_csaf, f)
            
        result = red_hat_advisory_scraper(self.test_file)
        self.assertEqual(result["kind"], "Bug Fix")

    def test_enhancement_advisory(self):
        """Test parsing an enhancement advisory"""
        self.sample_csaf["document"]["tracking"]["id"] = "RHEA-2025:1234"
        self.sample_csaf["document"]["title"] = "Red Hat Enhancement Advisory: package update"
        
        with open(self.test_file, "w") as f:
            json.dump(self.sample_csaf, f)
            
        result = red_hat_advisory_scraper(self.test_file)
        self.assertEqual(result["kind"], "Enhancement")

    def test_no_vulnerabilities(self):
        """Test handling of CSAF file with no vulnerabilities"""
        self.sample_csaf.pop("vulnerabilities")
        
        with open(self.test_file, "w") as f:
            json.dump(self.sample_csaf, f)
            
        result = red_hat_advisory_scraper(self.test_file)
        self.assertIsNone(result)