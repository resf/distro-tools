import unittest
import json
import pathlib
from unittest.mock import patch, MagicMock
from datetime import datetime

# Import the test database configuration
from test_db_config import initialize_test_db, close_test_db

# Mock the logger before importing the target module
mock_logger = MagicMock()
with patch('common.logger.Logger') as mock_logger_class:
    mock_logger_class.return_value = mock_logger
    from apollo.rhworker.poll_rh_activities import process_csaf_file
    # Import DB models directly to use with the test database
    from apollo.db import (
        RedHatAdvisory, 
        RedHatAdvisoryPackage, 
        RedHatAdvisoryCVE, 
        RedHatAdvisoryBugzillaBug, 
        RedHatAdvisoryAffectedProduct
    )

class TestCsafProcessing(unittest.IsolatedAsyncioTestCase):
    @classmethod
    async def asyncSetUp(cls):
        # Initialize test database for all tests in this class
        await initialize_test_db()
    
    @classmethod
    async def asyncTearDown(cls):
        # Close database connections when tests are done
        await close_test_db()

    def setUp(self):
        # Create sample CSAF data matching schema requirements
        self.sample_csaf = {
            "document": {
                "tracking": {
                    "initial_release_date": "2025-02-24T03:42:46+00:00",
                    "current_release_date": "2025-04-17T12:08:56+00:00",
                    "id": "RHSA-2025:1234"
                },
                "title": "Red Hat Security Advisory: package security update",
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
        
        # Create a temporary file with the sample data
        self.test_file = pathlib.Path("test_csaf.json")
        with open(self.test_file, "w") as f:
            json.dump(self.sample_csaf, f)

    async def tearDown(self):
        # Clean up database and temporary files after each test
        await RedHatAdvisory.all().delete()
        await RedHatAdvisoryPackage.all().delete()
        await RedHatAdvisoryCVE.all().delete()
        await RedHatAdvisoryBugzillaBug.all().delete() 
        await RedHatAdvisoryAffectedProduct.all().delete()
        
        # Clean up temporary file
        self.test_file.unlink(missing_ok=True)
        
        if pathlib.Path("invalid_csaf.json").exists():
            pathlib.Path("invalid_csaf.json").unlink()

    async def test_new_advisory_creation(self):
        # Test creating a new advisory with a real test database
        result = await process_csaf_file(self.sample_csaf, "test.json")
        
        # Verify advisory was created correctly
        advisory = await RedHatAdvisory.get_or_none(name="RHSA-2025:1234")
        self.assertIsNotNone(advisory)
        self.assertEqual(advisory.name, "RHSA-2025:1234")
        self.assertEqual(advisory.synopsis, "Important: package security update")
        self.assertEqual(advisory.description, "Test description")
        self.assertEqual(advisory.kind, "Security")
        self.assertEqual(advisory.severity, "Important")
        self.assertEqual(advisory.topic, "Test topic")
        
        # Verify packages were created
        packages = await RedHatAdvisoryPackage.filter(red_hat_advisory=advisory)
        self.assertEqual(len(packages), 2)
        package_nevras = [pkg.nevra for pkg in packages]
        self.assertIn("rsync-0:3.2.3-19.el9_4.1.x86_64", package_nevras)
        self.assertIn("rsync-0:3.2.3-19.el9_4.1.src", package_nevras)
        
        # Verify CVEs were created
        cves = await RedHatAdvisoryCVE.filter(red_hat_advisory=advisory)
        self.assertEqual(len(cves), 1)
        cve = cves[0]
        self.assertEqual(cve.cve, "CVE-2025-1234")
        self.assertEqual(cve.cvss3_scoring_vector, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertEqual(cve.cvss3_base_score, "9.8")
        self.assertEqual(cve.cwe, "CWE-79")
        
        # Verify Bugzilla bugs were created
        bugs = await RedHatAdvisoryBugzillaBug.filter(red_hat_advisory=advisory)
        self.assertEqual(len(bugs), 1)
        self.assertEqual(bugs[0].bugzilla_bug_id, "123456")
        
        # Verify affected products were created
        products = await RedHatAdvisoryAffectedProduct.filter(red_hat_advisory=advisory)
        self.assertGreater(len(products), 0)
        self.assertEqual(products[0].variant, "Red Hat Enterprise Linux")
        self.assertEqual(products[0].arch, "x86_64")
        self.assertEqual(products[0].major_version, 9)
        self.assertEqual(products[0].minor_version, 4)

    async def test_advisory_update(self):
        # First create an advisory with different values
        existing = await RedHatAdvisory.create(
            name="RHSA-2025:1234",
            red_hat_issued_at=datetime(2024, 1, 1),
            red_hat_updated_at=datetime(2024, 1, 1),
            synopsis="Moderate: Old Synopsis",
            description="Old Description",
            kind="SecurityFix",
            severity="Moderate",
            topic="Old Topic"
        )
        
        # Process the CSAF file which should update the existing advisory
        result = await process_csaf_file(self.sample_csaf, "test.json")
        
        # Verify the advisory was updated
        updated = await RedHatAdvisory.get(id=existing.id)
        self.assertEqual(updated.severity, "Important")
        self.assertEqual(updated.synopsis, "Important: package security update")
        self.assertEqual(updated.description, "Test description")
        self.assertEqual(updated.topic, "Test topic")
        
        # Verify the issue date was updated
        self.assertNotEqual(updated.red_hat_issued_at, datetime(2024, 1, 1))

    async def test_invalid_csaf_file(self):
        # Test handling of invalid CSAF file
        with open("invalid_csaf.json", "w") as f:
            f.write("invalid json")
            
        with self.assertRaises(Exception):
            await process_csaf_file("invalid_csaf.json")

    async def test_no_vulnerabilities(self):
        # Test CSAF with no vulnerabilities
        csaf = self.sample_csaf.copy()
        csaf.pop("vulnerabilities")
        result = await process_csaf_file(csaf, "test.json")
        self.assertIsNone(result)
        
        # Verify nothing was created
        count = await RedHatAdvisory.all().count()
        self.assertEqual(count, 0)

    async def test_no_fixed_packages(self):
        # Test CSAF with vulnerabilities but no fixed packages
        csaf = self.sample_csaf.copy()
        csaf["vulnerabilities"][0]["product_status"]["fixed"] = []
        result = await process_csaf_file(csaf, "test.json")
        self.assertIsNone(result)
        
        # Verify nothing was created
        count = await RedHatAdvisory.all().count()
        self.assertEqual(count, 0)

    @patch('apollo.db.RedHatAdvisory.get_or_none')
    async def test_db_exception(self, mock_get_or_none):
        # Simulate a database error
        mock_get_or_none.side_effect = Exception("DB error")
        with self.assertRaises(Exception):
            await process_csaf_file(self.sample_csaf, "test.json")