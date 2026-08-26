import unittest
from apollo.rpm_helpers import (
    parse_nevra,
    parse_dist_version,
    rpmvercmp,
    label_compare,
    evr_gte,
)

class TestRpmHelpers(unittest.TestCase):
    def test_parse_dist_version(self):
        test_cases = [
            # Regular packages
            ("1.el8", {"major": 8, "minor": None}),
            ("427.55.1.el9_4", {"major": 9, "minor": 4}),
            ("2.el8_7", {"major": 8, "minor": 7}),
            
            # Module packages
            ("4.module+el8.10.0+22411+85254afd", {"major": 8, "minor": 10}),
            ("6.module+el9.2.0+18751+b6bd9bab", {"major": 9, "minor": 2}),
            
            # Invalid cases
            ("1.fc38", {"major": None, "minor": None}),
            ("noversion", {"major": None, "minor": None}),
        ]
        
        for release, expected in test_cases:
            with self.subTest(release=release):
                result = parse_dist_version(release)
                self.assertEqual(result, expected)

    def test_parse_nevra(self):
        test_cases = [
            # Regular package
            (
                "openssh-9.0p1-15.el9.x86_64",
                {
                    "raw": "openssh-9.0p1-15.el9.x86_64",
                    "name": "openssh",
                    "epoch": 0,
                    "version": "9.0p1",
                    "release": "15.el9",
                    "arch": "x86_64",
                    "dist_major": 9,
                    "dist_minor": None,
                }
            ),
            # Package with epoch
            (
                "python-requests-2:2.14.2-2.el8.noarch",
                {
                    "raw": "python-requests-2:2.14.2-2.el8.noarch",
                    "name": "python-requests",
                    "epoch": "2",
                    "version": "2.14.2",
                    "release": "2.el8",
                    "arch": "noarch",
                    "dist_major": 8,
                    "dist_minor": None,
                }
            ),
            # Module package
            (
                "perl-App-cpanminus-1.7044-6.module+el8.10.0+22411+409a293e.noarch",
                {
                    "raw": "perl-App-cpanminus-1.7044-6.module+el8.10.0+22411+409a293e.noarch",
                    "name": "perl-App-cpanminus",
                    "epoch": 0,
                    "version": "1.7044",
                    "release": "6.module+el8.10.0+22411+409a293e",
                    "arch": "noarch",
                    "dist_major": 8,
                    "dist_minor": 10,
                }
            ),
        ]
        
        for nevra, expected in test_cases:
            with self.subTest(nevra=nevra):
                result = parse_nevra(nevra)
                self.assertEqual(result, expected)

    def test_parse_nevra_errors(self):
        invalid_nevras = [
            "package-1.0", # Missing arch
            "package.x86_64", # Missing version and release
            "package-1.0.x86_64", # Missing release
            "package-1.fc38.x86_64", # Invalid distribution
        ]
        
        for nevra in invalid_nevras:
            with self.subTest(nevra=nevra):
                with self.assertRaises(ValueError):
                    parse_nevra(nevra)

    def test_rpmvercmp(self):
        cases = [
            ("1.0", "1.0", 0),
            ("1.0", "1.1", -1),
            ("1.1", "1.0", 1),
            ("8", "7.1", 1),
            ("7.1", "8", -1),
            ("49", "48", 1),
            ("48.rocky.0.1", "49", -1),
            ("50.rocky.0.1", "49", 1),
        ]
        for a, b, expected in cases:
            with self.subTest(a=a, b=b):
                self.assertEqual(rpmvercmp(a, b), expected)

    def test_label_compare_and_evr_gte(self):
        self.assertEqual(
            label_compare(0, "1.12.20", "8.el9", 0, "1.12.20", "7.el9_2.1"),
            1,
        )
        self.assertTrue(evr_gte(1, "1.12.20", "8.el9", 1, "1.12.20", "7.el9_2.1"))
        self.assertFalse(
            evr_gte(0, "8.7p1", "48.el9_7.rocky.0.1", 0, "8.7p1", "49.el9_7")
        )


if __name__ == '__main__':
    unittest.main()