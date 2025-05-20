import unittest
from unittest.mock import patch, MagicMock, AsyncMock
from datetime import datetime
import json
import pathlib

# Mock the logger before importing the target module
mock_logger = MagicMock()
with patch('common.logger.Logger') as mock_logger_class:
    mock_logger_class.return_value = mock_logger
    from apollo.rhworker.poll_rh_activities import process_csaf_file

class TestCsafProcessing(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        # Mock Info class
        with patch('common.info.Info') as mock_info:
            mock_info_instance = MagicMock()
            mock_info_instance.name = "test_csaf_processing"
            mock_info.return_value = mock_info_instance

    def setUp(self):
        # Create sample CSAF data matching schema requirements
        self.sample_csaf = {
            "document": {
                "tracking": {
                    "initial_release_date": "2025-01-01T00:00:00+00:00",
                    "current_release_date": "2025-01-02T00:00:00+00:00",
                    "id": "RHSA-2025:0001"
                },
                "title": "Important: Test Advisory",
                "notes": [
                    {
                        "category": "general",
                        "text": "Test Description"
                    },
                    {
                        "category": "summary",
                        "text": "Test Topic"
                    }
                ],
                "aggregate_severity": {
                    "text": "Important"
                }
            },
            "vulnerabilities": [{
                "product_status": {
                    "fixed": [
                        "package-1.0-1.el8.x86_64",
                        "package-1.0-1.el8.i686"
                    ]
                },
                "cve": "CVE-2025-0001",
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
                        "url": "https://bugzilla.redhat.com/show_bug.cgi?id=12345"
                    },
                    {
                        "category": "external",
                        "url": "https://bugzilla.redhat.com/show_bug.cgi?id=67890"
                    }
                ]
            }]
        }
        
        # Create a temporary file with the sample data
        self.test_file = pathlib.Path("test_csaf.json")
        with open(self.test_file, "w") as f:
            json.dump(self.sample_csaf, f)

    def tearDown(self):
        # Clean up temporary file
        self.test_file.unlink(missing_ok=True)

    @patch('apollo.db.RedHatAdvisory')
    @patch('apollo.db.RedHatAdvisoryPackage')
    @patch('apollo.db.RedHatAdvisoryCVE')
    @patch('apollo.db.RedHatAdvisoryBugzillaBug')
    @patch('apollo.db.RedHatAdvisoryAffectedProduct')
    async def test_new_advisory_creation(self, mock_affected, mock_bz, mock_cve, 
                                       mock_pkg, mock_advisory):
        # Set up mocks with schema-compliant data
        mock_advisory.get_or_none.return_value = None
        mock_advisory.create.return_value = MagicMock(
            id=1,
            created_at=datetime.now(),
            updated_at=None,
            red_hat_issued_at=datetime(2025, 1, 1),
            red_hat_updated_at=datetime(2025, 1, 2),
            name="RHSA-2025:0001",
            synopsis="Important: Test Advisory",
            description="Test Description",
            kind="SecurityFix",
            severity="Important",
            topic="Test Topic"
        )
        
        result = await process_csaf_file(str(self.test_file))
        
        # Verify advisory creation with schema fields
        mock_advisory.create.assert_called_once()
        create_args = mock_advisory.create.call_args[1]
        self.assertEqual(create_args["name"], "RHSA-2025:0001")
        self.assertEqual(create_args["synopsis"], "Important: Test Advisory")
        self.assertEqual(create_args["description"], "Test Description")
        self.assertEqual(create_args["kind"], "SecurityFix")
        self.assertEqual(create_args["severity"], "Important")
        self.assertEqual(create_args["topic"], "Test Topic")
        
        # Verify package creation with schema fields
        mock_pkg.bulk_create.assert_called_once()
        pkg_args = mock_pkg.bulk_create.call_args[0][0]
        for pkg in pkg_args:
            self.assertIn("red_hat_advisory_id", pkg)
            self.assertIn("nevra", pkg)
        
        # Verify CVE creation with schema fields
        mock_cve.bulk_create.assert_called_once()
        cve_args = mock_cve.bulk_create.call_args[0][0]
        for cve in cve_args:
            self.assertIn("red_hat_advisory_id", cve)
            self.assertIn("cve", cve)
            self.assertIn("cvss3_scoring_vector", cve)
            self.assertIn("cvss3_base_score", cve)
            self.assertIn("cwe", cve)
        
        # Verify Bugzilla creation with schema fields
        mock_bz.bulk_create.assert_called_once()
        bz_args = mock_bz.bulk_create.call_args[0][0]
        for bz in bz_args:
            self.assertIn("red_hat_advisory_id", bz)
            self.assertIn("bugzilla", bz)
        
        # Verify affected products creation with schema fields
        mock_affected.bulk_create.assert_called_once()
        affected_args = mock_affected.bulk_create.call_args[0][0]
        for affected in affected_args:
            self.assertIn("red_hat_advisory_id", affected)
            self.assertIn("variant", affected)
            self.assertIn("arch", affected)
            self.assertIn("major_version", affected)
            self.assertIn("minor_version", affected)

    @patch('apollo.db.RedHatAdvisory')
    async def test_advisory_update(self, mock_advisory):
        # Test updating an existing advisory with schema-compliant data
        existing = MagicMock(
            id=1,
            created_at=datetime(2024, 1, 1),
            updated_at=None,
            red_hat_issued_at=datetime(2024, 1, 1),
            red_hat_updated_at=datetime(2024, 1, 1),
            name="RHSA-2025:0001",
            synopsis="Moderate: Old Synopsis",
            description="Old Description",
            kind="SecurityFix",
            severity="Moderate",
            topic="Old Topic"
        )
        mock_advisory.get_or_none.return_value = existing
        
        result = await process_csaf_file(str(self.test_file))
        
        self.assertEqual(existing.severity, "Important")
        self.assertEqual(existing.synopsis, "Important: Test Advisory")
        self.assertEqual(existing.description, "Test Description")
        self.assertEqual(existing.topic, "Test Topic")

    async def test_invalid_csaf_file(self):
        # Test handling of invalid CSAF file
        with open("invalid_csaf.json", "w") as f:
            f.write("invalid json")
            
        with self.assertRaises(Exception):
            await process_csaf_file("invalid_csaf.json")

    @patch('apollo.db.RedHatAdvisory')
    @patch('apollo.db.RedHatAdvisoryPackage')
    @patch('apollo.db.RedHatAdvisoryCVE')
    @patch('apollo.db.RedHatAdvisoryBugzillaBug')
    @patch('apollo.db.RedHatAdvisoryAffectedProduct')
    async def test_no_vulnerabilities(self, mock_affected, mock_bz, mock_cve, mock_pkg, mock_advisory):
        # CSAF with no vulnerabilities
        csaf = self.sample_csaf.copy()
        csaf.pop("vulnerabilities")
        result = await process_csaf_file(csaf, "test.json")
        self.assertIsNone(result)

    @patch('apollo.db.RedHatAdvisory')
    @patch('apollo.db.RedHatAdvisoryPackage')
    @patch('apollo.db.RedHatAdvisoryCVE')
    @patch('apollo.db.RedHatAdvisoryBugzillaBug')
    @patch('apollo.db.RedHatAdvisoryAffectedProduct')
    async def test_no_fixed_packages(self, mock_affected, mock_bz, mock_cve, mock_pkg, mock_advisory):
        # CSAF with vulnerabilities but no fixed packages
        csaf = self.sample_csaf.copy()
        csaf["vulnerabilities"][0]["product_status"]["fixed"] = []
        result = await process_csaf_file(csaf, "test.json")
        self.assertIsNone(result)

    @patch('apollo.db.RedHatAdvisory')
    @patch('apollo.db.RedHatAdvisoryPackage')
    @patch('apollo.db.RedHatAdvisoryCVE')
    @patch('apollo.db.RedHatAdvisoryBugzillaBug')
    @patch('apollo.db.RedHatAdvisoryAffectedProduct')
    async def test_db_exception(self, mock_affected, mock_bz, mock_cve, mock_pkg, mock_advisory):
        # Simulate DB error
        mock_advisory.get_or_none.side_effect = Exception("DB error")
        with self.assertRaises(Exception):
            await process_csaf_file(self.sample_csaf, "test.json")

    @patch("aiohttp.ClientSession")
    @patch("apollo.rhworker.poll_rh_activities.process_csaf_file", new_callable=AsyncMock)
    async def test_process_csaf_files_success(self, mock_process_csaf_file, mock_client_session):
        # Simulate aiohttp session and CSV responses
        mock_session = AsyncMock()
        mock_client_session.return_value.__aenter__.return_value = mock_session

        # Simulate CSV data
        csv_content = '"RHSA-2025:0001.json","2025-01-01T00:00:00Z"\n'
        async def fake_fetch_csv_with_dates(session, url):
            return {"RHSA-2025:0001.json": "2025-01-01T00:00:00Z"}

        # Patch fetch_csv_with_dates inside the function
        with patch("apollo.rhworker.poll_rh_activities.fetch_csv_with_dates", new=fake_fetch_csv_with_dates):
            # Simulate advisory JSON fetch
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json.return_value = self.sample_csaf
            mock_session.get.return_value.__aenter__.return_value = mock_response

            mock_process_csaf_file.return_value = MagicMock()  # Simulate successful processing

            from apollo.rhworker.poll_rh_activities import process_csaf_files
            result = await process_csaf_files()
            self.assertEqual(result["processed"], 1)
            self.assertEqual(result["errors"], 0)

    @patch("aiohttp.ClientSession")
    @patch("apollo.rhworker.poll_rh_activities.process_csaf_file", new_callable=AsyncMock)
    async def test_process_csaf_files_error(self, mock_process_csaf_file, mock_client_session):
        # Simulate aiohttp session and CSV responses
        mock_session = AsyncMock()
        mock_client_session.return_value.__aenter__.return_value = mock_session

        # Simulate CSV data
        async def fake_fetch_csv_with_dates(session, url):
            return {"RHSA-2025:0002.json": "2025-01-01T00:00:00Z"}

        with patch("apollo.rhworker.poll_rh_activities.fetch_csv_with_dates", new=fake_fetch_csv_with_dates):
            # Simulate advisory JSON fetch with error
            mock_response = AsyncMock()
            mock_response.status = 404
            mock_session.get.return_value.__aenter__.return_value = mock_response

            from apollo.rhworker.poll_rh_activities import process_csaf_files
            result = await process_csaf_files()
            self.assertEqual(result["processed"], 0)
            self.assertEqual(result["errors"], 1)