"""
Consolidated authentication tests with embedded mock helpers
Complete coverage of authentication functionality including database scenarios
"""

import unittest
import asyncio
import datetime
import sys
import os
from unittest.mock import Mock, patch, AsyncMock

# Add the project root to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from apollo.server.auth import (
    api_key_auth,
    workflow_api_key_auth,
    api_key_or_session_auth,
    verify_api_key,
    generate_api_key,
    get_api_key_prefix,
    api_key_context,
)


# Embedded mock helpers (simplified)
class MockAPIKey:
    """Mock APIKey model that behaves like the real Tortoise ORM model."""

    def __init__(
        self,
        raw_key=None,
        permissions=None,
        expires_at=None,
        revoked_at=None,
        user_email="test@example.com",
    ):
        if raw_key is None:
            raw_key, key_hash = generate_api_key()
        else:
            key_hash = api_key_context.hash(raw_key)
        self.id = 1
        self.name = "Test API Key"
        self.key_hash = key_hash
        self.key_prefix = get_api_key_prefix(raw_key)
        self.user_id = 1
        self.permissions = permissions or ["workflow:trigger", "workflow:status"]
        self.expires_at = expires_at
        self.last_used_at = None
        self.revoked_at = revoked_at
        self.created_at = datetime.datetime.now(datetime.timezone.utc)

        # Mock user
        self.user = Mock()
        self.user.id = 1
        self.user.email = user_email

        # Mock save method
        self.save = AsyncMock()


def create_mock_api_key_query(return_keys=None):
    """Create a mock for APIKey.filter().prefetch_related().all() chain"""
    mock_queryset = Mock()
    mock_prefetch = Mock()
    mock_filter = Mock()

    mock_queryset.all = AsyncMock(return_value=return_keys or [])
    mock_prefetch.return_value = mock_queryset
    mock_filter.prefetch_related = mock_prefetch

    return mock_filter


class TestAPIKeyAuth(unittest.TestCase):
    """Test the main API key authentication function."""

    def setUp(self):
        """Set up test data for each test."""
        self.raw_key, self.key_hash = generate_api_key()

        # Create mock request with valid Authorization header
        self.mock_request = Mock()
        self.mock_request.headers = {"Authorization": f"Bearer {self.raw_key}"}

        # Create mock API key
        self.mock_api_key = MockAPIKey(self.raw_key)

    @patch("apollo.server.auth.verify_api_key")
    def test_successful_authentication_no_permission_required(self, mock_verify):
        """Test successful authentication when no specific permission is required."""
        mock_verify.return_value = self.mock_api_key

        result = asyncio.run(api_key_auth(self.mock_request))

        self.assertEqual(result, self.mock_api_key.user)
        mock_verify.assert_called_once_with(self.raw_key)

    @patch("apollo.server.auth.verify_api_key")
    def test_successful_authentication_with_valid_permission(self, mock_verify):
        """Test successful authentication with valid permission."""
        mock_verify.return_value = self.mock_api_key

        result = asyncio.run(api_key_auth(self.mock_request, "workflow:trigger"))

        self.assertEqual(result, self.mock_api_key.user)
        mock_verify.assert_called_once_with(self.raw_key)

    @patch("apollo.server.auth.verify_api_key")
    def test_authentication_with_wildcard_permission(self, mock_verify):
        """Test authentication with wildcard permission."""
        wildcard_api_key = MockAPIKey(self.raw_key, permissions=["*"])
        mock_verify.return_value = wildcard_api_key

        result = asyncio.run(api_key_auth(self.mock_request, "any:permission"))

        self.assertEqual(result, wildcard_api_key.user)

    def test_missing_authorization_header(self):
        """Test authentication failure when Authorization header is missing."""
        from fastapi import HTTPException

        mock_request = Mock()
        mock_request.headers = {}  # No Authorization header

        with self.assertRaises(HTTPException) as context:
            asyncio.run(api_key_auth(mock_request))

        self.assertEqual(context.exception.status_code, 401)
        self.assertIn(
            "Missing or invalid Authorization header", context.exception.detail
        )

    def test_invalid_authorization_header_format(self):
        """Test authentication failure with invalid Authorization header format."""
        from fastapi import HTTPException

        invalid_headers = [
            {"Authorization": "Basic dXNlcjpwYXNz"},  # Basic auth
            {"Authorization": "Bearer"},  # No token
            {"Authorization": "apollo_sk_12345"},  # Missing Bearer
            {"Authorization": "Bearer invalid_format"},  # Wrong token format
        ]

        for headers in invalid_headers:
            with self.subTest(headers=headers):
                mock_request = Mock()
                mock_request.headers = headers

                with self.assertRaises(HTTPException) as context:
                    asyncio.run(api_key_auth(mock_request))

                self.assertEqual(context.exception.status_code, 401)

    @patch("apollo.server.auth.verify_api_key")
    def test_invalid_api_key(self, mock_verify):
        """Test authentication failure with invalid API key."""
        from fastapi import HTTPException

        mock_verify.return_value = None  # Invalid key

        with self.assertRaises(HTTPException) as context:
            asyncio.run(api_key_auth(self.mock_request))

        self.assertEqual(context.exception.status_code, 401)
        self.assertEqual(context.exception.detail, "Invalid API key")

    @patch("apollo.server.auth.verify_api_key")
    def test_insufficient_permissions(self, mock_verify):
        """Test authentication failure when API key lacks required permission."""
        from fastapi import HTTPException

        # Create API key with limited permissions
        limited_api_key = MockAPIKey(self.raw_key, permissions=["workflow:status"])
        mock_verify.return_value = limited_api_key

        with self.assertRaises(HTTPException) as context:
            asyncio.run(api_key_auth(self.mock_request, "workflow:trigger"))

        self.assertEqual(context.exception.status_code, 403)
        self.assertIn("does not have required permission", context.exception.detail)


class TestWorkflowAPIKeyAuth(unittest.TestCase):
    """Test the workflow-specific authentication function."""

    def setUp(self):
        """Set up test data."""
        self.raw_key, _ = generate_api_key()
        self.mock_request = Mock()
        self.mock_request.headers = {"Authorization": f"Bearer {self.raw_key}"}

        self.mock_user = Mock()
        self.mock_user.email = "test@example.com"

    @patch("apollo.server.auth.api_key_auth")
    def test_workflow_auth_success(self, mock_api_key_auth):
        """Test successful workflow authentication."""
        mock_api_key_auth.return_value = self.mock_user

        result = asyncio.run(workflow_api_key_auth(self.mock_request))

        self.assertEqual(result, self.mock_user)
        mock_api_key_auth.assert_called_once_with(self.mock_request, "workflow:trigger")

    @patch("apollo.server.auth.api_key_auth")
    def test_workflow_auth_failure(self, mock_api_key_auth):
        """Test workflow authentication failure."""
        from fastapi import HTTPException

        mock_api_key_auth.side_effect = HTTPException(
            status_code=403,
            detail="API key does not have required permission: workflow:trigger",
        )

        with self.assertRaises(HTTPException) as context:
            asyncio.run(workflow_api_key_auth(self.mock_request))

        self.assertEqual(context.exception.status_code, 403)


class TestAPIKeyOrSessionAuth(unittest.TestCase):
    """Test the dual authentication function."""

    def setUp(self):
        """Set up test data."""
        self.mock_user = Mock()
        self.mock_user.email = "test@example.com"

    @patch("apollo.server.auth.api_key_auth")
    def test_api_key_authentication_priority(self, mock_api_key_auth):
        """Test that API key authentication is tried first."""
        mock_request = Mock()
        mock_request.headers = {"Authorization": "Bearer apollo_sk_12345"}
        mock_api_key_auth.return_value = self.mock_user

        result = asyncio.run(api_key_or_session_auth(mock_request))

        self.assertEqual(result, self.mock_user)
        mock_api_key_auth.assert_called_once_with(mock_request)

    @patch("apollo.server.utils.admin_user_scheme")
    def test_session_authentication_fallback(self, mock_session_auth):
        """Test fallback to session authentication."""
        mock_request = Mock()
        mock_request.headers = {"Authorization": "Bearer other_token"}  # Not apollo_sk_
        mock_session_auth.return_value = self.mock_user

        result = asyncio.run(api_key_or_session_auth(mock_request))

        self.assertEqual(result, self.mock_user)
        mock_session_auth.assert_called_once_with(mock_request)

    @patch("apollo.server.utils.admin_user_scheme")
    def test_session_authentication_no_header(self, mock_session_auth):
        """Test fallback to session auth when no Authorization header."""
        mock_request = Mock()
        mock_request.headers = {}  # No Authorization header
        mock_session_auth.return_value = self.mock_user

        result = asyncio.run(api_key_or_session_auth(mock_request))

        self.assertEqual(result, self.mock_user)
        mock_session_auth.assert_called_once_with(mock_request)


class TestAuthenticationSecurity(unittest.TestCase):
    """Test security improvements in authentication."""

    def test_strict_bearer_format_validation(self):
        """Test that Bearer format is strictly validated."""
        from fastapi import HTTPException

        raw_key, _ = generate_api_key()

        invalid_formats = [
            f"Bearer  {raw_key}",  # Extra spaces
            f"Bearer {raw_key} ",  # Trailing space
            f"Bearer\t{raw_key}",  # Tab instead of space
            f" Bearer {raw_key}",  # Leading space
        ]

        for auth_header in invalid_formats:
            with self.subTest(auth_header=repr(auth_header)):
                mock_request = Mock()
                mock_request.headers = {"Authorization": auth_header}

                with self.assertRaises(HTTPException) as context:
                    asyncio.run(api_key_auth(mock_request))

                self.assertEqual(context.exception.status_code, 401)

    def test_api_key_format_validation(self):
        """Test that API key format is strictly validated."""
        from fastapi import HTTPException

        invalid_key_formats = [
            "Bearer not_apollo_key_format",
            "Bearer apollo_wrong_prefix_12345",
            "Bearer wrong_sk_12345",
            "Bearer apollo_sk_",  # Empty suffix - caught by format validation
        ]

        for auth_header in invalid_key_formats:
            with self.subTest(auth_header=auth_header):
                mock_request = Mock()
                mock_request.headers = {"Authorization": auth_header}

                with self.assertRaises(HTTPException) as context:
                    asyncio.run(api_key_auth(mock_request))

                self.assertEqual(context.exception.status_code, 401)
                # The error message will be "Invalid API key format" for format issues
                # that are caught before database lookup
                expected_messages = [
                    "Invalid API key format",
                    "Missing or invalid Authorization header",
                ]
                self.assertTrue(
                    any(msg in context.exception.detail for msg in expected_messages)
                )

    def test_case_sensitivity_enforcement(self):
        """Test that case sensitivity is properly enforced."""
        from fastapi import HTTPException

        raw_key, _ = generate_api_key()

        case_variants = [
            f"bearer {raw_key}",  # Lowercase bearer
            f"BEARER {raw_key}",  # Uppercase bearer
        ]

        for auth_header in case_variants:
            with self.subTest(auth_header=auth_header):
                mock_request = Mock()
                mock_request.headers = {"Authorization": auth_header}

                with self.assertRaises(HTTPException) as context:
                    asyncio.run(api_key_auth(mock_request))

                self.assertEqual(context.exception.status_code, 401)


class TestAPIKeyVerificationWithDatabase(unittest.TestCase):
    """Test verify_api_key function with comprehensive database mocking."""

    def test_verify_invalid_format_keys(self):
        """Test verification of invalid key formats."""
        invalid_keys = [None, "", "invalid_format", "apollo_wrong_prefix"]

        for invalid_key in invalid_keys:
            with self.subTest(invalid_key=invalid_key):
                result = asyncio.run(verify_api_key(invalid_key))
                self.assertIsNone(result)

    @patch("apollo.server.auth.APIKey")
    def test_verify_valid_api_key_with_database_mock(self, mock_api_key_model):
        """Test verification of a valid API key with full database mock."""
        raw_key, _ = generate_api_key()
        mock_api_key = MockAPIKey(raw_key)

        # Mock the database query chain
        mock_api_key_model.filter.return_value = create_mock_api_key_query(
            [mock_api_key]
        )

        result = asyncio.run(verify_api_key(raw_key))

        # Verify the result
        self.assertIsNotNone(result)
        self.assertEqual(result.id, mock_api_key.id)
        self.assertEqual(result.name, mock_api_key.name)

        # Verify that save was called to update last_used_at
        mock_api_key.save.assert_called_once()
        self.assertIsNotNone(mock_api_key.last_used_at)

        # Verify correct database query was made
        mock_api_key_model.filter.assert_called_once_with(
            key_prefix=mock_api_key.key_prefix, revoked_at__isnull=True
        )

    @patch("apollo.server.auth.APIKey")
    def test_verify_expired_key_with_database_mock(self, mock_api_key_model):
        """Test verification of an expired API key."""
        raw_key, _ = generate_api_key()
        expired_time = datetime.datetime.now(
            datetime.timezone.utc
        ) - datetime.timedelta(days=1)
        expired_key = MockAPIKey(raw_key, expires_at=expired_time)

        mock_api_key_model.filter.return_value = create_mock_api_key_query(
            [expired_key]
        )

        result = asyncio.run(verify_api_key(raw_key))
        self.assertIsNone(result)

        # Save should not be called for expired key
        expired_key.save.assert_not_called()

    @patch("apollo.server.auth.APIKey")
    def test_verify_nonexistent_key_with_database_mock(self, mock_api_key_model):
        """Test verification of a non-existent key."""
        raw_key, _ = generate_api_key()

        # Mock empty database result
        mock_api_key_model.filter.return_value = create_mock_api_key_query([])

        result = asyncio.run(verify_api_key(raw_key))
        self.assertIsNone(result)


class TestAuthenticationEdgeCases(unittest.TestCase):
    """Test edge cases and security scenarios."""

    @patch("apollo.server.auth.verify_api_key")
    def test_permission_validation_comprehensive(self, mock_verify):
        """Test comprehensive permission validation scenarios."""
        from fastapi import HTTPException

        raw_key, _ = generate_api_key()
        mock_request = Mock()
        mock_request.headers = {"Authorization": f"Bearer {raw_key}"}

        # Test various permission scenarios
        permission_tests = [
            # (user_permissions, required_permission, should_succeed)
            (["workflow:trigger"], "workflow:trigger", True),
            (["workflow:trigger"], "workflow:status", False),
            (["*"], "any:permission", True),
            (["workflow:trigger", "workflow:status"], "workflow:trigger", True),
            ([], "any:permission", False),
            (["workflow:trigger"], "WORKFLOW:TRIGGER", False),  # Case sensitive
            (["workflow:trigger"], "workflow", False),  # Exact match required
        ]

        for user_permissions, required_permission, should_succeed in permission_tests:
            with self.subTest(
                user_permissions=user_permissions, required=required_permission
            ):
                mock_api_key = MockAPIKey(raw_key, permissions=user_permissions)
                mock_verify.return_value = mock_api_key

                if should_succeed:
                    result = asyncio.run(
                        api_key_auth(mock_request, required_permission)
                    )
                    self.assertEqual(result, mock_api_key.user)
                else:
                    with self.assertRaises(HTTPException) as context:
                        asyncio.run(api_key_auth(mock_request, required_permission))
                    self.assertEqual(context.exception.status_code, 403)

    @patch("apollo.server.auth.verify_api_key")
    def test_permission_injection_resistance(self, mock_verify):
        """Test that permission checking is resistant to injection attacks."""
        from fastapi import HTTPException

        raw_key, _ = generate_api_key()
        mock_request = Mock()
        mock_request.headers = {"Authorization": f"Bearer {raw_key}"}
        limited_key = MockAPIKey(raw_key, permissions=["workflow:status"])
        mock_verify.return_value = limited_key

        malicious_permissions = [
            "workflow:status OR workflow:trigger",
            "workflow:*",
            "*",
            "'; DROP TABLE api_keys; --",
            "workflow:status,workflow:trigger",
        ]

        for malicious_permission in malicious_permissions:
            with self.subTest(permission=malicious_permission):
                with self.assertRaises(HTTPException) as context:
                    asyncio.run(api_key_auth(mock_request, malicious_permission))

                self.assertEqual(context.exception.status_code, 403)


class TestDatabaseIntegrationScenarios(unittest.TestCase):
    """Test database integration scenarios with mocking."""

    @patch("apollo.server.auth.APIKey")
    def test_database_query_optimization(self, mock_api_key_model):
        """Test that database queries are optimized correctly."""
        raw_key, _ = generate_api_key()
        key_prefix = get_api_key_prefix(raw_key)
        mock_api_key = MockAPIKey(raw_key)

        mock_api_key_model.filter.return_value = create_mock_api_key_query(
            [mock_api_key]
        )

        result = asyncio.run(verify_api_key(raw_key))

        # Verify optimized query structure
        mock_api_key_model.filter.assert_called_once_with(
            key_prefix=key_prefix, revoked_at__isnull=True
        )

        # Verify prefetch_related was called for user
        filter_result = mock_api_key_model.filter.return_value
        filter_result.prefetch_related.assert_called_once_with("user")


    @patch("apollo.server.auth.APIKey")
    def test_last_used_timestamp_update(self, mock_api_key_model):
        """Test that last_used_at timestamp is properly updated."""
        raw_key, _ = generate_api_key()
        mock_api_key = MockAPIKey(raw_key)

        # Initially no last_used_at
        self.assertIsNone(mock_api_key.last_used_at)

        mock_api_key_model.filter.return_value = create_mock_api_key_query(
            [mock_api_key]
        )

        result = asyncio.run(verify_api_key(raw_key))

        # Should have set last_used_at and called save
        self.assertIsNotNone(mock_api_key.last_used_at)
        mock_api_key.save.assert_called_once()



if __name__ == "__main__":
    # Run with verbose output
    unittest.main(verbosity=2)
