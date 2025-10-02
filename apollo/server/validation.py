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
    I686 = "i686"
    PPC64 = "ppc64"
    PPC64LE = "ppc64le"
    S390X = "s390x"
    RISCV64 = "riscv64"
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

    # Name patterns - alphanumeric with common special characters and spaces
    NAME_PATTERN = re.compile(r"^[a-zA-Z0-9._\s-]+$")

    # Architecture validation
    ARCH_PATTERN = re.compile(r"^(x86_64|aarch64|i386|i686|ppc64|ppc64le|s390x|riscv64|noarch)$")

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
                f"{field_name.title()} can only contain letters, numbers, spaces, dots, hyphens, and underscores",
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


class ConfigValidator:
    """Configuration data validation utilities."""

    @staticmethod
    def validate_import_data_structure(import_data: Any) -> List[str]:
        """
        Validate the basic structure of import data.

        Args:
            import_data: The data to validate (should be a list)

        Returns:
            List[str]: List of validation error messages
        """
        errors = []

        if not isinstance(import_data, list):
            errors.append("Import data must be a list of configuration objects")
            return errors

        for i, config in enumerate(import_data):
            config_errors = ConfigValidator.validate_config_structure(config, i + 1)
            errors.extend(config_errors)

        return errors

    @staticmethod
    def validate_config_structure(config: Any, config_index: int) -> List[str]:
        """
        Validate the structure of a single configuration object.

        Args:
            config: The configuration object to validate
            config_index: The 1-based index of the config for error messages

        Returns:
            List[str]: List of validation error messages
        """
        errors = []

        if not isinstance(config, dict):
            errors.append(f"Config {config_index}: Must be a dictionary")
            return errors

        # Validate required top-level keys
        required_keys = ["product", "mirror", "repositories"]
        for key in required_keys:
            if key not in config:
                errors.append(f"Config {config_index}: Missing required key '{key}'")

        # Validate product data structure
        if "product" in config:
            product_errors = ConfigValidator.validate_product_config(
                config["product"], config_index
            )
            errors.extend(product_errors)

        # Validate mirror data structure
        if "mirror" in config:
            mirror_errors = ConfigValidator.validate_mirror_config(
                config["mirror"], config_index
            )
            errors.extend(mirror_errors)

        # Validate repositories data structure
        if "repositories" in config:
            repo_errors = ConfigValidator.validate_repositories_config(
                config["repositories"], config_index
            )
            errors.extend(repo_errors)

        return errors

    @staticmethod
    def validate_product_config(product: Any, config_index: int) -> List[str]:
        """
        Validate product configuration data.

        Args:
            product: The product configuration to validate
            config_index: The 1-based index of the config for error messages

        Returns:
            List[str]: List of validation error messages
        """
        errors = []

        if not isinstance(product, dict):
            errors.append(f"Config {config_index}: Product must be a dictionary")
            return errors

        # Validate required product fields
        required_fields = ["name", "variant", "vendor"]
        for field in required_fields:
            if field not in product or not product[field]:
                errors.append(
                    f"Config {config_index}: Product missing required field '{field}'"
                )

        # Validate product name format if present
        if product.get("name"):
            try:
                FieldValidator.validate_name(
                    product["name"], min_length=1, field_name="product name"
                )
            except ValidationError as e:
                errors.append(f"Config {config_index}: Product name '{product['name']}' - {e.message}")

        return errors

    @staticmethod
    def validate_mirror_config(mirror: Any, config_index: int) -> List[str]:
        """
        Validate mirror configuration data.

        Args:
            mirror: The mirror configuration to validate
            config_index: The 1-based index of the config for error messages

        Returns:
            List[str]: List of validation error messages
        """
        errors = []

        if not isinstance(mirror, dict):
            errors.append(f"Config {config_index}: Mirror must be a dictionary")
            return errors

        # Validate required mirror fields
        required_fields = ["name", "match_variant", "match_major_version", "match_arch"]
        for field in required_fields:
            if field not in mirror or mirror[field] is None:
                errors.append(
                    f"Config {config_index}: Mirror missing required field '{field}'"
                )

        # Validate mirror name format if present
        if mirror.get("name"):
            try:
                FieldValidator.validate_name(
                    mirror["name"], min_length=3, field_name="mirror name"
                )
            except ValidationError as e:
                errors.append(f"Config {config_index}: Mirror name '{mirror['name']}' - {e.message}")

        # Validate architecture if present
        if mirror.get("match_arch"):
            try:
                FieldValidator.validate_architecture(
                    mirror["match_arch"], field_name="architecture"
                )
            except ValidationError as e:
                errors.append(f"Config {config_index}: Mirror architecture '{mirror['match_arch']}' - {e.message}")

        # Validate major version is numeric if present
        if mirror.get("match_major_version") is not None:
            if (
                not isinstance(mirror["match_major_version"], int)
                or mirror["match_major_version"] < 0
            ):
                errors.append(
                    f"Config {config_index}: Mirror match_major_version must be a non-negative integer"
                )

        # Validate minor version is numeric if present
        if mirror.get("match_minor_version") is not None:
            if (
                not isinstance(mirror["match_minor_version"], int)
                or mirror["match_minor_version"] < 0
            ):
                errors.append(
                    f"Config {config_index}: Mirror match_minor_version must be a non-negative integer"
                )

        return errors

    @staticmethod
    def validate_repositories_config(repositories: Any, config_index: int) -> List[str]:
        """
        Validate repositories configuration data.

        Args:
            repositories: The repositories configuration to validate
            config_index: The 1-based index of the config for error messages

        Returns:
            List[str]: List of validation error messages
        """
        errors = []

        if not isinstance(repositories, list):
            errors.append(f"Config {config_index}: Repositories must be a list")
            return errors

        for j, repo in enumerate(repositories):
            repo_errors = ConfigValidator.validate_repository_config(
                repo, config_index, j + 1
            )
            errors.extend(repo_errors)

        return errors

    @staticmethod
    def validate_repository_config(
        repo: Any, config_index: int, repo_index: int
    ) -> List[str]:
        """
        Validate a single repository configuration.

        Args:
            repo: The repository configuration to validate
            config_index: The 1-based index of the config for error messages
            repo_index: The 1-based index of the repository for error messages

        Returns:
            List[str]: List of validation error messages
        """
        errors = []

        if not isinstance(repo, dict):
            errors.append(
                f"Config {config_index}, Repo {repo_index}: Must be a dictionary"
            )
            return errors

        # Validate required repository fields
        required_fields = ["repo_name", "arch", "production", "url"]
        for field in required_fields:
            if field not in repo or repo[field] is None:
                errors.append(
                    f"Config {config_index}, Repo {repo_index}: Missing required field '{field}'"
                )

        # Validate repository name format if present
        if repo.get("repo_name"):
            try:
                FieldValidator.validate_repo_name(
                    repo["repo_name"], min_length=2, field_name="repository name"
                )
            except ValidationError as e:
                errors.append(f"Config {config_index}, Repo {repo_index}: Repository name '{repo['repo_name']}' - {e.message}")

        # Validate architecture if present
        if repo.get("arch"):
            try:
                FieldValidator.validate_architecture(
                    repo["arch"], field_name="architecture"
                )
            except ValidationError as e:
                errors.append(f"Config {config_index}, Repo {repo_index}: Architecture '{repo['arch']}' - {e.message}")

        # Validate URLs if present
        for url_field in ["url", "debug_url", "source_url"]:
            url_value = repo.get(url_field)
            if url_value:  # Only validate if not empty
                try:
                    FieldValidator.validate_url(
                        url_value,
                        field_name=url_field.replace("_", " "),
                        required=url_field == "url",
                    )
                except ValidationError as e:
                    errors.append(
                        f"Config {config_index}, Repo {repo_index}: {url_field.replace('_', ' ').title()} '{url_value}' - {e.message}"
                    )

        # Validate production is boolean if present
        if "production" in repo and repo["production"] is not None:
            if not isinstance(repo["production"], bool):
                errors.append(
                    f"Config {config_index}, Repo {repo_index}: Production value '{repo['production']}' must be true or false"
                )

        return errors


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
