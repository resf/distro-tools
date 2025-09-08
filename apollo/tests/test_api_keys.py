"""
Consolidated API key management tests
Focuses on core functionality without performance-intensive tests
"""

import unittest
import sys
import os

# Add the project root to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from apollo.server.auth import generate_api_key, get_api_key_prefix, api_key_context


class TestAPIKeyGeneration(unittest.TestCase):
    """Test API key generation functions."""

    def test_generate_api_key_format(self):
        """Test that generated API keys have correct format."""
        raw_key, key_hash = generate_api_key()

        # Check raw key format
        self.assertTrue(raw_key.startswith("apollo_sk_"))
        self.assertGreater(len(raw_key), 10)

        # Check hash is different from raw key
        self.assertNotEqual(key_hash, raw_key)
        self.assertGreater(len(key_hash), 50)


    def test_generate_api_key_randomness(self):
        """Test that generated keys are unique."""
        keys = []
        hashes = []

        for _ in range(10):
            raw_key, key_hash = generate_api_key()
            keys.append(raw_key)
            hashes.append(key_hash)

        # All keys should be unique
        self.assertEqual(len(set(keys)), 10)
        self.assertEqual(len(set(hashes)), 10)


    def test_get_api_key_prefix_valid(self):
        """Test prefix extraction from valid API keys."""
        raw_key, _ = generate_api_key()
        prefix = get_api_key_prefix(raw_key)

        self.assertTrue(prefix.startswith("apollo_sk_"))
        self.assertEqual(len(prefix), 22)
        self.assertTrue(raw_key.startswith(prefix))


    def test_get_api_key_prefix_invalid(self):
        """Test prefix extraction from invalid keys."""
        test_cases = [
            ("invalid_key_format", "invalid_key_form"),
            ("apollo_wrong_format", "apollo_wrong_for"),
            ("short", "short"),
            ("", ""),
        ]

        for invalid_key, expected_prefix in test_cases:
            with self.subTest(invalid_key=invalid_key):
                prefix = get_api_key_prefix(invalid_key)
                self.assertEqual(prefix, expected_prefix)

    def test_key_hash_verification(self):
        """Test that generated hashes can verify original keys."""
        raw_key, key_hash = generate_api_key()

        # Should verify correctly
        self.assertTrue(api_key_context.verify(raw_key, key_hash))

        # Should not verify with different key
        other_key, _ = generate_api_key()
        self.assertFalse(api_key_context.verify(other_key, key_hash))



class TestAPIKeySecurityScenarios(unittest.TestCase):
    """Test security-focused scenarios."""

    def test_hash_security(self):
        """Test that hashes are properly generated and secure."""
        raw_key, key_hash = generate_api_key()

        # Hash should not contain the raw key
        self.assertNotIn(raw_key, key_hash)

        # Hash should be bcrypt format
        self.assertTrue(key_hash.startswith("$2b$"))

        # Different keys should have different hashes
        raw_key2, key_hash2 = generate_api_key()
        self.assertNotEqual(key_hash, key_hash2)


    def test_key_format_validation(self):
        """Test key format validation logic."""
        # Test that our keys have the expected format
        for _ in range(5):
            raw_key, _ = generate_api_key()

            # Should start with apollo_sk_
            self.assertTrue(raw_key.startswith("apollo_sk_"))

            # Should be reasonable length
            self.assertGreaterEqual(len(raw_key), 43)

            # Should contain only valid characters
            valid_chars = set(
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
            )
            key_chars = set(raw_key)
            self.assertTrue(key_chars.issubset(valid_chars))



class TestAPIKeyEdgeCases(unittest.TestCase):
    """Test edge cases and boundary conditions."""

    def test_prefix_edge_cases(self):
        """Test prefix extraction edge cases."""
        edge_cases = [
            ("", ""),
            ("a", "a"),
            ("apollo_sk_", "apollo_sk_"),
            ("apollo_sk_a", "apollo_sk_a"),
            ("apollo_sk_1234567890ab", "apollo_sk_1234567890ab"),  # exactly 22 chars
            ("apollo_sk_1234567890abc", "apollo_sk_1234567890ab"),  # more than 22 chars
            (
                "not_apollo_key_but_very_long",
                "not_apollo_key_b",
            ),  # Fixed expected value
        ]

        for input_key, expected_prefix in edge_cases:
            with self.subTest(input_key=input_key):
                actual_prefix = get_api_key_prefix(input_key)
                self.assertEqual(actual_prefix, expected_prefix)

    def test_moderate_scale_generation(self):
        """Test generating a moderate number of keys."""
        keys = set()
        hashes = set()

        # Generate 20 keys
        for _ in range(20):
            raw_key, key_hash = generate_api_key()
            keys.add(raw_key)
            hashes.add(key_hash)

        # All should be unique
        self.assertEqual(len(keys), 20)
        self.assertEqual(len(hashes), 20)



class TestAPIKeyValidation(unittest.TestCase):
    """Test API key validation logic."""

    def test_prefix_extraction_consistency(self):
        """Test that prefix extraction is consistent."""
        raw_key, _ = generate_api_key()

        # Extract prefix multiple times - should be the same
        prefix1 = get_api_key_prefix(raw_key)
        prefix2 = get_api_key_prefix(raw_key)

        self.assertEqual(prefix1, prefix2)

        # Prefix should be exactly 22 characters for valid keys
        self.assertEqual(len(prefix1), 22)

        # Original key should start with the prefix
        self.assertTrue(raw_key.startswith(prefix1))



class TestAPIKeyEntropy(unittest.TestCase):
    """Test entropy and randomness of generated keys."""

    def test_key_entropy(self):
        """Test that generated keys have sufficient entropy."""
        keys = []
        for _ in range(15):  # Moderate number for entropy testing
            raw_key, _ = generate_api_key()
            keys.append(raw_key)

        # All keys should be unique (very high probability with good entropy)
        unique_keys = len(set(keys))
        self.assertEqual(unique_keys, 15)

        # Test character distribution in suffixes (after apollo_sk_)
        suffixes = [key[10:] for key in keys]  # Remove apollo_sk_ prefix
        all_chars = "".join(suffixes)

        # Should have reasonable character distribution
        char_counts = {}
        for char in all_chars:
            char_counts[char] = char_counts.get(char, 0) + 1

        # Should have a decent variety of characters
        unique_chars = len(char_counts)
        self.assertGreater(unique_chars, 10)  # Should use variety of base64 charset


    def test_hash_uniqueness(self):
        """Test that hashes are unique for different keys."""
        raw_key1, hash1 = generate_api_key()
        raw_key2, hash2 = generate_api_key()

        self.assertNotEqual(hash1, hash2)

        # Each hash should verify only its own key
        self.assertTrue(api_key_context.verify(raw_key1, hash1))
        self.assertFalse(api_key_context.verify(raw_key1, hash2))

        self.assertTrue(api_key_context.verify(raw_key2, hash2))
        self.assertFalse(api_key_context.verify(raw_key2, hash1))



if __name__ == "__main__":
    # Run with verbose output
    unittest.main(verbosity=2)
