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
                                        },
                                        "branches": [
                                            {
                                                "category": "product_version",
                                                "name": "rsync-0:3.2.3-19.el9_4.1.x86_64",
                                                "product": {
                                                    "product_id": "rsync-0:3.2.3-19.el9_4.1.x86_64",
                                                    "product_identification_helper": {
                                                        "purl": "pkg:rpm/redhat/rsync@3.2.3-19.el9_4.1?arch=x86_64"
                                                    }
                                                }
                                            },
                                            {
                                                "category": "product_version",
                                                "name": "rsync-0:3.2.3-19.el9_4.1.src",
                                                "product": {
                                                    "product_id": "rsync-0:3.2.3-19.el9_4.1.src",
                                                    "product_identification_helper": {
                                                        "purl": "pkg:rpm/redhat/rsync@3.2.3-19.el9_4.1?arch=src"
                                                    }
                                                }
                                            }
                                        ]
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


class TestEUSDetection(unittest.TestCase):
    """Test EUS product detection and filtering"""

    def setUp(self):
        with patch('common.logger.Logger') as mock_logger_class:
            mock_logger_class.return_value = MagicMock()
            from apollo.rhcsaf import _is_eus_product
            self._is_eus_product = _is_eus_product

    def test_detect_eus_via_cpe(self):
        """Test EUS detection via CPE product field"""
        # EUS CPE products
        self.assertTrue(self._is_eus_product("Some Product", "cpe:/a:redhat:rhel_eus:9.4::appstream"))
        self.assertTrue(self._is_eus_product("Some Product", "cpe:/a:redhat:rhel_e4s:9.0::appstream"))
        self.assertTrue(self._is_eus_product("Some Product", "cpe:/a:redhat:rhel_aus:8.2::appstream"))
        self.assertTrue(self._is_eus_product("Some Product", "cpe:/a:redhat:rhel_tus:8.8::appstream"))

        # Non-EUS CPE product
        self.assertFalse(self._is_eus_product("Some Product", "cpe:/a:redhat:enterprise_linux:9::appstream"))

    def test_detect_eus_via_name(self):
        """Test EUS detection via product name keywords"""
        self.assertTrue(self._is_eus_product("Red Hat Enterprise Linux AppStream EUS (v.9.4)", ""))
        self.assertTrue(self._is_eus_product("Red Hat Enterprise Linux AppStream E4S (v.9.0)", ""))
        self.assertTrue(self._is_eus_product("Red Hat Enterprise Linux AppStream AUS (v.8.2)", ""))
        self.assertTrue(self._is_eus_product("Red Hat Enterprise Linux AppStream TUS (v.8.8)", ""))

        # Non-EUS product name
        self.assertFalse(self._is_eus_product("Red Hat Enterprise Linux AppStream", ""))

    def test_eus_filtering_in_affected_products(self):
        """Test that EUS products are filtered from affected products"""
        csaf = {
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
                                            "name": "Red Hat Enterprise Linux AppStream EUS (v.9.4)",
                                            "product_identification_helper": {
                                                "cpe": "cpe:/a:redhat:rhel_eus:9.4::appstream"
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

        result = extract_rhel_affected_products_for_db(csaf)
        # Should be empty because the only product is EUS
        self.assertEqual(len(result), 0)


class TestModularPackages(unittest.TestCase):
    """Test modular package extraction"""

    def test_extract_modular_packages(self):
        """Test extraction of modular packages with ::module:stream suffix"""
        csaf = {
            "document": {
                "tracking": {
                    "initial_release_date": "2025-07-28T00:00:00+00:00",
                    "current_release_date": "2025-07-28T00:00:00+00:00",
                    "id": "RHSA-2025:12008"
                },
                "title": "Red Hat Security Advisory: Important: redis:7 security update",
                "aggregate_severity": {"text": "Important"},
                "notes": [
                    {"category": "general", "text": "Test description"},
                    {"category": "summary", "text": "Test topic"}
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
                                                "cpe": "cpe:/o:redhat:enterprise_linux:9::appstream"
                                            }
                                        },
                                        "branches": [
                                            {
                                                "category": "product_version",
                                                "name": "redis-0:7.2.10-1.module+el9.6.0+23332+115a3b01.x86_64::redis:7",
                                                "product": {
                                                    "product_id": "redis-0:7.2.10-1.module+el9.6.0+23332+115a3b01.x86_64::redis:7",
                                                    "product_identification_helper": {
                                                        "purl": "pkg:rpm/redhat/redis@7.2.10-1.module+el9.6.0+23332+115a3b01?arch=x86_64&rpmmod=redis:7:9060020250716081121:9"
                                                    }
                                                }
                                            },
                                            {
                                                "category": "product_version",
                                                "name": "redis-0:7.2.10-1.module+el9.6.0+23332+115a3b01.src::redis:7",
                                                "product": {
                                                    "product_id": "redis-0:7.2.10-1.module+el9.6.0+23332+115a3b01.src::redis:7",
                                                    "product_identification_helper": {
                                                        "purl": "pkg:rpm/redhat/redis@7.2.10-1.module+el9.6.0+23332+115a3b01?arch=src&rpmmod=redis:7:9060020250716081121:9"
                                                    }
                                                }
                                            }
                                        ]
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
                    "cve": "CVE-2025-12345",
                    "ids": [{"system_name": "Red Hat Bugzilla ID", "text": "123456"}],
                    "product_status": {"fixed": []},
                    "scores": [{"cvss_v3": {"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "baseScore": 9.8}}],
                    "cwe": {"id": "CWE-79"}
                }
            ]
        }

        result = red_hat_advisory_scraper(csaf)

        # Check that modular packages were extracted with ::module:stream stripped
        self.assertIn("redis-0:7.2.10-1.module+el9.6.0+23332+115a3b01.x86_64", result["red_hat_fixed_packages"])
        self.assertIn("redis-0:7.2.10-1.module+el9.6.0+23332+115a3b01.src", result["red_hat_fixed_packages"])

        # Verify epoch is preserved
        for pkg in result["red_hat_fixed_packages"]:
            if "redis" in pkg:
                self.assertIn("0:", pkg, "Epoch should be preserved in NEVRA")


class TestEUSAdvisoryFiltering(unittest.TestCase):
    """Test that EUS-only advisories are filtered out"""

    def test_eus_only_advisory_returns_none(self):
        """Test that advisory with only EUS products returns None"""
        csaf = {
            "document": {
                "tracking": {
                    "initial_release_date": "2025-01-01T00:00:00+00:00",
                    "current_release_date": "2025-01-01T00:00:00+00:00",
                    "id": "RHSA-2025:9756"
                },
                "title": "Red Hat Security Advisory: Important: package security update",
                "aggregate_severity": {"text": "Important"},
                "notes": [
                    {"category": "general", "text": "EUS advisory"},
                    {"category": "summary", "text": "EUS topic"}
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
                                        "name": "Red Hat Enterprise Linux AppStream EUS (v.9.4)",
                                        "product": {
                                            "name": "Red Hat Enterprise Linux AppStream EUS (v.9.4)",
                                            "product_identification_helper": {
                                                "cpe": "cpe:/a:redhat:rhel_eus:9.4::appstream"
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
                    "cve": "CVE-2025-99999",
                    "ids": [{"system_name": "Red Hat Bugzilla ID", "text": "999999"}],
                    "product_status": {"fixed": []},
                    "scores": [{"cvss_v3": {"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "baseScore": 9.8}}],
                    "cwe": {"id": "CWE-79"}
                }
            ]
        }

        result = red_hat_advisory_scraper(csaf)

        # Advisory should be filtered out (return None) because all products are EUS
        self.assertIsNone(result)