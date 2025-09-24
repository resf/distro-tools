"""
Validation utilities for the Apollo server.

This module provides centralized validation logic with regex patterns and enums
to ensure consistent validation standards across the application.
"""

import re
from enum import Enum
from typing import Optional, Dict, Any, List, Tuple


class Architecture(str, Enum):
    """Supported system architectures."""

    X86_64 = "x86_64"
    AARCH64 = "aarch64"
    I386 = "i386"
    PPC64 = "ppc64"
    PPC64LE = "ppc64le"
    S390X = "s390x"
    NOARCH = "noarch"


class URLProtocol(str, Enum):
    """Supported URL protocols."""

    HTTP = "http://"
    HTTPS = "https://"


class ValidationErrorType(str, Enum):
    """Types of validation errors."""

    REQUIRED = "required"
    MIN_LENGTH = "min_length"
    MAX_LENGTH = "max_length"
    INVALID_FORMAT = "invalid_format"
    INVALID_URL = "invalid_url"
    INVALID_ARCHITECTURE = "invalid_architecture"


class ValidationError(Exception):
    """Custom exception for validation errors."""

    def __init__(
        self, message: str, error_type: ValidationErrorType, field: str = None
    ):
        super().__init__(message)
        self.message = message
        self.error_type = error_type
        self.field = field


class ValidationPatterns:
    """Regex patterns for common validations."""

    # URL validation - must start with http:// or https://
    URL_PATTERN = re.compile(r"^https?://.+")

    # Name patterns - alphanumeric with common special characters
    NAME_PATTERN = re.compile(r"^[a-zA-Z0-9._-]+$")

    # Architecture validation
    ARCH_PATTERN = re.compile(r"^(x86_64|aarch64|i386|ppc64|ppc64le|s390x|noarch)$")

    # Repository name - more permissive for repo naming conventions
    REPO_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9._-]+$")


class FieldValidator:
    """Individual field validation utilities."""

    @staticmethod
    def validate_name(name: str, min_length: int = 3, field_name: str = "name") -> str:
        """
        Validate a name field.

        Args:
            name: The name to validate
            min_length: Minimum required length
            field_name: Name of the field for error messages

        Returns:
            str: The trimmed and validated name

        Raises:
            ValidationError: If validation fails
        """
        if not name or not name.strip():
            raise ValidationError(
                f"{field_name.title()} is required",
                ValidationErrorType.REQUIRED,
                field_name,
            )

        trimmed_name = name.strip()

        if len(trimmed_name) < min_length:
            raise ValidationError(
                f"{field_name.title()} must be at least {min_length} characters long",
                ValidationErrorType.MIN_LENGTH,
                field_name,
            )

        if not ValidationPatterns.NAME_PATTERN.match(trimmed_name):
            raise ValidationError(
                f"{field_name.title()} can only contain letters, numbers, dots, hyphens, and underscores",
                ValidationErrorType.INVALID_FORMAT,
                field_name,
            )

        return trimmed_name

    @staticmethod
    def validate_url(
        url: str, field_name: str = "URL", required: bool = True
    ) -> Optional[str]:
        """
        Validate a URL field.

        Args:
            url: The URL to validate
            field_name: Name of the field for error messages
            required: Whether the field is required

        Returns:
            Optional[str]: The trimmed and validated URL, or None if not required and empty

        Raises:
            ValidationError: If validation fails
        """
        if not url or not url.strip():
            if required:
                raise ValidationError(
                    f"{field_name} is required",
                    ValidationErrorType.REQUIRED,
                    field_name.lower().replace(" ", "_"),
                )
            return None

        trimmed_url = url.strip()

        if not ValidationPatterns.URL_PATTERN.match(trimmed_url):
            raise ValidationError(
                f"{field_name} must start with http:// or https://",
                ValidationErrorType.INVALID_URL,
                field_name.lower().replace(" ", "_"),
            )

        return trimmed_url

    @staticmethod
    def validate_architecture(arch: str, field_name: str = "architecture") -> str:
        """
        Validate an architecture field.

        Args:
            arch: The architecture to validate
            field_name: Name of the field for error messages

        Returns:
            str: The validated architecture

        Raises:
            ValidationError: If validation fails
        """
        if not arch or not arch.strip():
            raise ValidationError(
                f"{field_name.title()} is required",
                ValidationErrorType.REQUIRED,
                field_name,
            )

        trimmed_arch = arch.strip()

        # Check if it's a valid architecture enum value
        try:
            Architecture(trimmed_arch)
        except ValueError:
            valid_archs = [arch.value for arch in Architecture]
            raise ValidationError(
                f"Invalid architecture. Must be one of: {', '.join(valid_archs)}",
                ValidationErrorType.INVALID_ARCHITECTURE,
                field_name,
            )

        return trimmed_arch

    @staticmethod
    def validate_repo_name(
        repo_name: str, min_length: int = 2, field_name: str = "repository name"
    ) -> str:
        """
        Validate a repository name field.

        Args:
            repo_name: The repository name to validate
            min_length: Minimum required length
            field_name: Name of the field for error messages

        Returns:
            str: The trimmed and validated repository name

        Raises:
            ValidationError: If validation fails
        """
        if not repo_name or not repo_name.strip():
            raise ValidationError(
                f"{field_name.title()} is required",
                ValidationErrorType.REQUIRED,
                field_name.replace(" ", "_"),
            )

        trimmed_name = repo_name.strip()

        if len(trimmed_name) < min_length:
            raise ValidationError(
                f"{field_name.title()} must be at least {min_length} characters long",
                ValidationErrorType.MIN_LENGTH,
                field_name.replace(" ", "_"),
            )

        if not ValidationPatterns.REPO_NAME_PATTERN.match(trimmed_name):
            raise ValidationError(
                f"{field_name.title()} can only contain letters, numbers, dots, hyphens, and underscores",
                ValidationErrorType.INVALID_FORMAT,
                field_name.replace(" ", "_"),
            )

        return trimmed_name


class FormValidator:
    """Form-level validation utilities."""

    @staticmethod
    def validate_mirror_form(
        form_data: Dict[str, Any]
    ) -> Tuple[Dict[str, str], List[str]]:
        """
        Validate mirror form data.

        Args:
            form_data: Dictionary containing form field values

        Returns:
            Tuple[Dict[str, str], List[str]]: (validated_data, errors)
        """
        validated_data = {}
        errors = []

        # Validate name
        try:
            validated_data["name"] = FieldValidator.validate_name(
                form_data.get("name", ""), min_length=3, field_name="mirror name"
            )
        except ValidationError as e:
            errors.append(e.message)

        # Validate architecture
        try:
            validated_data["match_arch"] = FieldValidator.validate_architecture(
                form_data.get("match_arch", ""), field_name="architecture"
            )
        except ValidationError as e:
            errors.append(e.message)

        # Copy other fields as-is for now (they have different validation requirements)
        for field in ["match_variant", "match_major_version", "match_minor_version"]:
            if field in form_data:
                validated_data[field] = form_data[field]

        return validated_data, errors

    @staticmethod
    def validate_repomd_form(
        form_data: Dict[str, Any]
    ) -> Tuple[Dict[str, str], List[str]]:
        """
        Validate repository configuration form data.

        Args:
            form_data: Dictionary containing form field values

        Returns:
            Tuple[Dict[str, str], List[str]]: (validated_data, errors)
        """
        validated_data = {}
        errors = []

        # Validate repository name
        try:
            validated_data["repo_name"] = FieldValidator.validate_repo_name(
                form_data.get("repo_name", ""),
                min_length=2,
                field_name="repository name",
            )
        except ValidationError as e:
            errors.append(e.message)

        # Validate main URL (required)
        try:
            validated_data["url"] = FieldValidator.validate_url(
                form_data.get("url", ""), field_name="repository URL", required=True
            )
        except ValidationError as e:
            errors.append(e.message)

        # Validate debug URL (optional)
        try:
            debug_url = FieldValidator.validate_url(
                form_data.get("debug_url", ""), field_name="debug URL", required=False
            )
            validated_data["debug_url"] = debug_url or ""
        except ValidationError as e:
            errors.append(e.message)

        # Validate source URL (optional)
        try:
            source_url = FieldValidator.validate_url(
                form_data.get("source_url", ""), field_name="source URL", required=False
            )
            validated_data["source_url"] = source_url or ""
        except ValidationError as e:
            errors.append(e.message)

        # Validate architecture
        try:
            validated_data["arch"] = FieldValidator.validate_architecture(
                form_data.get("arch", ""), field_name="architecture"
            )
        except ValidationError as e:
            errors.append(e.message)

        # Copy production flag
        validated_data["production"] = form_data.get("production", False)

        return validated_data, errors


def get_supported_architectures() -> List[str]:
    """
    Get list of supported architecture values.

    Returns:
        List[str]: List of supported architecture strings
    """
    return [arch.value for arch in Architecture]


def is_valid_url(url: str) -> bool:
    """
    Check if a URL has a valid format.

    Args:
        url: The URL to check

    Returns:
        bool: True if the URL format is valid
    """
    if not url:
        return False
    return ValidationPatterns.URL_PATTERN.match(url.strip()) is not None


def is_valid_architecture(arch: str) -> bool:
    """
    Check if an architecture is supported.

    Args:
        arch: The architecture string to check

    Returns:
        bool: True if the architecture is supported
    """
    if not arch:
        return False
    try:
        Architecture(arch.strip())
        return True
    except ValueError:
        return False
