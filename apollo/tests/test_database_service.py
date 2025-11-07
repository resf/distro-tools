"""
Tests for DatabaseService functionality
Tests utility functions for database operations including timestamp management
"""

import unittest
import asyncio
from datetime import datetime, timezone
from unittest.mock import Mock, AsyncMock, patch
import os

# Add the project root to the Python path
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from apollo.server.services.database_service import DatabaseService


class TestEnvironmentDetection(unittest.TestCase):
    """Test environment detection functionality."""

    def test_is_production_when_env_is_production(self):
        """Test production detection when ENV=production."""
        with patch.dict(os.environ, {"ENV": "production"}):
            service = DatabaseService()
            self.assertTrue(service.is_production_environment())

    def test_is_not_production_when_env_is_development(self):
        """Test production detection when ENV=development."""
        with patch.dict(os.environ, {"ENV": "development"}):
            service = DatabaseService()
            self.assertFalse(service.is_production_environment())

    def test_is_not_production_when_env_not_set(self):
        """Test production detection when ENV is not set."""
        with patch.dict(os.environ, {}, clear=True):
            service = DatabaseService()
            self.assertFalse(service.is_production_environment())

    def test_is_not_production_with_staging_env(self):
        """Test production detection with staging environment."""
        with patch.dict(os.environ, {"ENV": "staging"}):
            service = DatabaseService()
            self.assertFalse(service.is_production_environment())

    def test_get_environment_info_production(self):
        """Test getting environment info for production."""
        with patch.dict(os.environ, {"ENV": "production"}):
            service = DatabaseService()
            result = asyncio.run(service.get_environment_info())

            self.assertEqual(result["environment"], "production")
            self.assertTrue(result["is_production"])
            self.assertFalse(result["reset_allowed"])

    def test_get_environment_info_development(self):
        """Test getting environment info for development."""
        with patch.dict(os.environ, {"ENV": "development"}):
            service = DatabaseService()
            result = asyncio.run(service.get_environment_info())

            self.assertEqual(result["environment"], "development")
            self.assertFalse(result["is_production"])
            self.assertTrue(result["reset_allowed"])


class TestLastIndexedAtOperations(unittest.TestCase):
    """Test last_indexed_at timestamp operations."""

    def test_get_last_indexed_at_when_exists(self):
        """Test getting last_indexed_at when record exists."""
        mock_index_state = Mock()
        test_time = datetime(2025, 7, 1, 0, 0, 0, tzinfo=timezone.utc)
        mock_index_state.last_indexed_at = test_time

        with patch("apollo.server.services.database_service.RedHatIndexState") as mock_state:
            mock_state.first = AsyncMock(return_value=mock_index_state)

            service = DatabaseService()
            result = asyncio.run(service.get_last_indexed_at())

            self.assertEqual(result["last_indexed_at"], test_time)
            self.assertEqual(result["last_indexed_at_iso"], "2025-07-01T00:00:00+00:00")
            self.assertTrue(result["exists"])

    def test_get_last_indexed_at_when_not_exists(self):
        """Test getting last_indexed_at when no record exists."""
        with patch("apollo.server.services.database_service.RedHatIndexState") as mock_state:
            mock_state.first = AsyncMock(return_value=None)

            service = DatabaseService()
            result = asyncio.run(service.get_last_indexed_at())

            self.assertIsNone(result["last_indexed_at"])
            self.assertIsNone(result["last_indexed_at_iso"])
            self.assertFalse(result["exists"])

    def test_get_last_indexed_at_when_timestamp_is_none(self):
        """Test getting last_indexed_at when timestamp field is None."""
        mock_index_state = Mock()
        mock_index_state.last_indexed_at = None

        with patch("apollo.server.services.database_service.RedHatIndexState") as mock_state:
            mock_state.first = AsyncMock(return_value=mock_index_state)

            service = DatabaseService()
            result = asyncio.run(service.get_last_indexed_at())

            self.assertIsNone(result["last_indexed_at"])
            self.assertIsNone(result["last_indexed_at_iso"])
            self.assertFalse(result["exists"])

    def test_update_last_indexed_at_existing_record(self):
        """Test updating last_indexed_at for existing record."""
        old_time = datetime(2025, 6, 1, 0, 0, 0, tzinfo=timezone.utc)
        new_time = datetime(2025, 7, 1, 0, 0, 0, tzinfo=timezone.utc)

        mock_index_state = Mock()
        mock_index_state.last_indexed_at = old_time
        mock_index_state.save = AsyncMock()

        with patch("apollo.server.services.database_service.RedHatIndexState") as mock_state, \
             patch("apollo.server.services.database_service.Logger"):
            mock_state.first = AsyncMock(return_value=mock_index_state)

            service = DatabaseService()
            result = asyncio.run(service.update_last_indexed_at(new_time, "admin@example.com"))

            self.assertTrue(result["success"])
            self.assertEqual(result["old_timestamp"], "2025-06-01T00:00:00+00:00")
            self.assertEqual(result["new_timestamp"], "2025-07-01T00:00:00+00:00")
            self.assertIn("Successfully updated", result["message"])

            # Verify save was called
            mock_index_state.save.assert_called_once()
            # Verify timestamp was updated
            self.assertEqual(mock_index_state.last_indexed_at, new_time)

    def test_update_last_indexed_at_create_new_record(self):
        """Test updating last_indexed_at when no record exists (creates new)."""
        new_time = datetime(2025, 7, 1, 0, 0, 0, tzinfo=timezone.utc)

        with patch("apollo.server.services.database_service.RedHatIndexState") as mock_state, \
             patch("apollo.server.services.database_service.Logger"):
            mock_state.first = AsyncMock(return_value=None)
            mock_state.create = AsyncMock()

            service = DatabaseService()
            result = asyncio.run(service.update_last_indexed_at(new_time, "admin@example.com"))

            self.assertTrue(result["success"])
            self.assertIsNone(result["old_timestamp"])
            self.assertEqual(result["new_timestamp"], "2025-07-01T00:00:00+00:00")
            self.assertIn("Successfully updated", result["message"])

            # Verify create was called with correct timestamp
            mock_state.create.assert_called_once_with(last_indexed_at=new_time)

    def test_update_last_indexed_at_handles_exception(self):
        """Test that update_last_indexed_at handles database exceptions."""
        new_time = datetime(2025, 7, 1, 0, 0, 0, tzinfo=timezone.utc)

        with patch("apollo.server.services.database_service.RedHatIndexState") as mock_state, \
             patch("apollo.server.services.database_service.Logger"):
            mock_state.first = AsyncMock(side_effect=Exception("Database error"))

            service = DatabaseService()

            with self.assertRaises(RuntimeError) as cm:
                asyncio.run(service.update_last_indexed_at(new_time, "admin@example.com"))

            self.assertIn("Failed to update timestamp", str(cm.exception))


class TestPartialResetValidation(unittest.TestCase):
    """Test partial reset validation logic."""

    def test_preview_partial_reset_blocks_in_production(self):
        """Test that preview_partial_reset raises error in production."""
        with patch.dict(os.environ, {"ENV": "production"}):
            service = DatabaseService()
            cutoff_date = datetime(2025, 6, 1, 0, 0, 0, tzinfo=timezone.utc)

            with self.assertRaises(ValueError) as cm:
                asyncio.run(service.preview_partial_reset(cutoff_date))

            self.assertIn("production environment", str(cm.exception))

    def test_preview_partial_reset_rejects_future_date(self):
        """Test that preview_partial_reset rejects future dates."""
        with patch.dict(os.environ, {"ENV": "development"}):
            service = DatabaseService()
            future_date = datetime(2099, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

            with self.assertRaises(ValueError) as cm:
                asyncio.run(service.preview_partial_reset(future_date))

            self.assertIn("must be in the past", str(cm.exception))

    def test_perform_partial_reset_blocks_in_production(self):
        """Test that perform_partial_reset raises error in production."""
        with patch.dict(os.environ, {"ENV": "production"}):
            service = DatabaseService()
            cutoff_date = datetime(2025, 6, 1, 0, 0, 0, tzinfo=timezone.utc)

            with self.assertRaises(ValueError) as cm:
                asyncio.run(service.perform_partial_reset(cutoff_date, "admin@example.com"))

            self.assertIn("production environment", str(cm.exception))

    def test_perform_partial_reset_rejects_future_date(self):
        """Test that perform_partial_reset rejects future dates."""
        with patch.dict(os.environ, {"ENV": "development"}):
            service = DatabaseService()
            future_date = datetime(2099, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

            with self.assertRaises(ValueError) as cm:
                asyncio.run(service.perform_partial_reset(future_date, "admin@example.com"))

            self.assertIn("must be in the past", str(cm.exception))


if __name__ == "__main__":
    # Run with verbose output
    unittest.main(verbosity=2)
