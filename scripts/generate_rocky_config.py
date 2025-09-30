#!/usr/bin/env python3
"""
Rocky Linux Repository Configuration Generator

This script generates a complete configuration file for Rocky Linux
by crawling the repository structure and discovering repomd.xml files.
Supports both structured and flat repository layouts.

Usage:
    python3 generate_rocky_config.py <base_url> [options]

Example:
    python3 generate_rocky_config.py https://mirror.example.com/pub/rocky/
    python3 generate_rocky_config.py http://user:pass@private-repo.com/rocky/ --version 9.6
"""

import argparse
import json
import sys
import re
from enum import Enum
from typing import Dict, List, Any, Tuple, Optional, Set
from urllib.parse import urljoin, urlparse, urlunparse
import requests
from bs4 import BeautifulSoup


# Constants
UNKNOWN_VALUE = "unknown"


class Architecture(str, Enum):
    """Supported system architectures for Rocky Linux repositories."""

    X86_64 = "x86_64"
    AARCH64 = "aarch64"
    PPC64LE = "ppc64le"
    S390X = "s390x"
    RISCV64 = "riscv64"
    I686 = "i686"
    NOARCH = "noarch"
    SOURCE = "source"
    SRPMS = "SRPMS"


class RepositoryName(str, Enum):
    """Supported Rocky Linux repository names."""

    BASE_OS = "BaseOS"
    APP_STREAM = "AppStream"
    CRB = "CRB"
    POWER_TOOLS = "PowerTools"
    EXTRAS = "extras"
    RT = "RT"
    NFV = "NFV"
    RESILIENT_STORAGE = "ResilientStorage"
    PLUS = "plus"
    DEVEL = "Devel"


class RepositoryType(str, Enum):
    """Repository type classifications."""

    MAIN = "main"
    DEBUG = "debug"
    SOURCE = "source"


class ValidationErrorType(str, Enum):
    """Types of validation errors."""

    REQUIRED = "required"
    INVALID_FORMAT = "invalid_format"
    INVALID_URL = "invalid_url"
    INVALID_ARCHITECTURE = "invalid_architecture"
    INVALID_REPOSITORY = "invalid_repository"
    INVALID_VERSION = "invalid_version"


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

    # Version validation - matches X.Y or X format
    VERSION_PATTERN = re.compile(r"^\d+(\.\d+)?$")



class ConfigValidator:
    """Configuration validation utilities following Apollo patterns."""

    @staticmethod
    def validate_url(
        url: str, field_name: str = "URL", required: bool = True
    ) -> Optional[str]:
        """
        Validate a URL field using urllib.parse for robust validation.

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

        try:
            parsed = urlparse(trimmed_url)

            # Check for required scheme
            if not parsed.scheme:
                raise ValidationError(
                    f"{field_name} must include a scheme (http:// or https://)",
                    ValidationErrorType.INVALID_URL,
                    field_name.lower().replace(" ", "_"),
                )

            # Only allow http and https schemes
            if parsed.scheme.lower() not in ["http", "https"]:
                raise ValidationError(
                    f"{field_name} must use http:// or https://",
                    ValidationErrorType.INVALID_URL,
                    field_name.lower().replace(" ", "_"),
                )

            # Check for required netloc (domain/host)
            if not parsed.netloc:
                raise ValidationError(
                    f"{field_name} must include a valid domain",
                    ValidationErrorType.INVALID_URL,
                    field_name.lower().replace(" ", "_"),
                )

            # Check for invalid characters in netloc (basic validation)
            if " " in parsed.netloc:
                raise ValidationError(
                    f"{field_name} domain cannot contain spaces",
                    ValidationErrorType.INVALID_URL,
                    field_name.lower().replace(" ", "_"),
                )

        except ValidationError:
            # Re-raise our custom validation errors
            raise
        except Exception as e:
            # Catch any other URL parsing errors
            raise ValidationError(
                f"{field_name} format is invalid: {str(e)}",
                ValidationErrorType.INVALID_URL,
                field_name.lower().replace(" ", "_"),
            )

        return trimmed_url

    @staticmethod
    def validate_architecture(arch: str, field_name: str = "architecture") -> str:
        """
        Validate an architecture field against the Architecture enum.

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
    def validate_repository_name(
        repo_name: str, field_name: str = "repository name"
    ) -> str:
        """
        Validate a repository name against the RepositoryName enum.

        Args:
            repo_name: The repository name to validate
            field_name: Name of the field for error messages

        Returns:
            str: The validated repository name

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

        # Check if it's a valid repository name enum value
        try:
            RepositoryName(trimmed_name)
        except ValueError:
            valid_repos = [repo.value for repo in RepositoryName]
            raise ValidationError(
                f"Invalid repository name. Must be one of: {', '.join(valid_repos)}",
                ValidationErrorType.INVALID_REPOSITORY,
                field_name.replace(" ", "_"),
            )

        return trimmed_name

    @staticmethod
    def validate_version(version: str, field_name: str = "version") -> str:
        """
        Validate a version string format.

        Args:
            version: The version to validate
            field_name: Name of the field for error messages

        Returns:
            str: The validated version

        Raises:
            ValidationError: If validation fails
        """
        if not version or not version.strip():
            raise ValidationError(
                f"{field_name.title()} is required",
                ValidationErrorType.REQUIRED,
                field_name,
            )

        trimmed_version = version.strip()

        if not ValidationPatterns.VERSION_PATTERN.match(trimmed_version):
            raise ValidationError(
                f"Invalid version format '{trimmed_version}'. Expected format: X.Y or X",
                ValidationErrorType.INVALID_VERSION,
                field_name,
            )

        return trimmed_version

    @staticmethod
    def is_valid_architecture(arch: str) -> bool:
        """
        Check if an architecture is valid without raising an exception.

        Args:
            arch: The architecture string to check

        Returns:
            bool: True if the architecture is valid
        """
        if not arch:
            return False
        try:
            Architecture(arch.strip())
            return True
        except (ValueError, TypeError):
            # ValueError: Invalid enum value
            # TypeError: Invalid type passed to enum constructor
            return False

    @staticmethod
    def is_valid_repository_name(repo_name: str) -> bool:
        """
        Check if a repository name is valid without raising an exception.

        Args:
            repo_name: The repository name to check

        Returns:
            bool: True if the repository name is valid
        """
        if not repo_name:
            return False
        try:
            RepositoryName(repo_name.strip())
            return True
        except (ValueError, TypeError):
            # ValueError: Invalid enum value
            # TypeError: Invalid type passed to enum constructor
            return False

    @staticmethod
    def get_supported_architectures() -> List[str]:
        """
        Get list of supported architecture values.

        Returns:
            List[str]: List of supported architecture strings
        """
        return [arch.value for arch in Architecture]

    @staticmethod
    def get_supported_repository_names() -> List[str]:
        """
        Get list of supported repository names.

        Returns:
            List[str]: List of supported repository name strings
        """
        return [repo.value for repo in RepositoryName]


def normalize_url(url: str) -> str:
    """
    Normalize URL to prevent duplicate crawling due to variations.

    Args:
        url: URL to normalize

    Returns:
        Normalized URL string
    """
    parsed = urlparse(url)
    # Remove fragment and normalize path
    normalized_path = parsed.path.rstrip("/") + "/"
    normalized = urlunparse(
        (
            parsed.scheme,
            parsed.netloc.lower(),
            normalized_path,
            parsed.params,
            parsed.query,
            "",  # Remove fragment
        )
    )
    return normalized


def discover_repomd_files(
    base_url: str, max_depth: int = 4, max_visited: int = 10000
) -> List[Tuple[str, Dict[str, str]]]:
    """
    Crawl repository structure to discover repomd.xml files.

    Args:
        base_url: Base URL to start crawling from
        max_depth: Maximum depth to crawl (default: 4)
        max_visited: Maximum number of URLs to visit (default: 10000)

    Returns:
        List of tuples: (repomd_url, metadata_dict)
        metadata includes: arch, repo_name, repo_type (main/debug/source), version

    Raises:
        ValueError: If base_url is invalid
        requests.RequestException: If network requests fail persistently
    """
    # Input validation
    if not base_url or not isinstance(base_url, str):
        raise ValueError("base_url must be a non-empty string")

    parsed_base = urlparse(base_url)
    if not parsed_base.scheme or not parsed_base.netloc:
        raise ValueError("base_url must be a valid URL with scheme and netloc")

    if max_depth < 0:
        raise ValueError("max_depth must be non-negative")

    if max_visited <= 0:
        raise ValueError("max_visited must be positive")

    session = requests.Session()
    session.headers.update({"User-Agent": "Rocky-Config-Generator/1.0"})

    found_repomds = []
    visited_urls: Set[str] = set()
    base_url_normalized = normalize_url(base_url)

    def crawl_directory(url: str, depth: int = 0) -> None:
        if depth > max_depth:
            return

        # Memory management: prevent unbounded growth
        if len(visited_urls) >= max_visited:
            print(
                f"Warning: Reached maximum visited URLs limit ({max_visited})",
                file=sys.stderr,
            )
            return

        url_normalized = normalize_url(url)
        if url_normalized in visited_urls:
            return

        # Security check: ensure URL is within base domain
        if not url_normalized.startswith(base_url_normalized):
            return

        visited_urls.add(url_normalized)
        print(f"Crawling: {url}", file=sys.stderr)

        try:
            response = session.get(url, timeout=30)
            response.raise_for_status()

            # Parse directory listing to look for repodata subdirectories
            if "text/html" in response.headers.get("content-type", "").lower():
                soup = BeautifulSoup(response.text, "html.parser")

                # Look for repodata directory and other subdirectories
                has_repodata = False
                subdirs_to_crawl = []

                for link in soup.find_all("a", href=True):
                    href = link["href"]
                    link_text = link.get_text(strip=True).lower()

                    # Skip parent directory, current directory, and files
                    if (
                        href in [".", "..", "../", "./"]
                        or not href.endswith("/")
                        or "parent" in link_text
                        or ".." in href
                    ):
                        continue

                    # Skip obvious files
                    if "." in href and href.count(".") > href.count("/"):
                        continue

                    # Check if this is a repodata directory
                    if href.rstrip("/").lower() == "repodata":
                        has_repodata = True
                        # Check for repomd.xml in this repodata directory
                        repomd_url = urljoin(url, "repodata/repomd.xml")
                        try:
                            repomd_response = session.head(repomd_url, timeout=10)
                            if repomd_response.status_code == 200:
                                try:
                                    metadata = parse_repomd_path(repomd_url, base_url)
                                    found_repomds.append((repomd_url, metadata))
                                    print(
                                        f"Found repomd.xml: {repomd_url}",
                                        file=sys.stderr,
                                    )
                                except ValueError as e:
                                    print(
                                        f"Warning: Could not parse repomd path {repomd_url}: {e}",
                                        file=sys.stderr,
                                    )
                        except requests.RequestException:
                            pass
                    else:
                        # Add to subdirectories to crawl if we don't find repodata here
                        subdir_url = urljoin(url, href)
                        subdir_url_normalized = normalize_url(subdir_url)
                        if (
                            subdir_url_normalized != url_normalized
                            and subdir_url_normalized not in visited_urls
                            and subdir_url_normalized.startswith(base_url_normalized)
                        ):
                            subdirs_to_crawl.append(subdir_url)

                # Only crawl subdirectories if we didn't find repodata in current directory
                # This prevents going deeper once we find a repository
                if not has_repodata:
                    for subdir_url in subdirs_to_crawl:
                        crawl_directory(subdir_url, depth + 1)

        except requests.Timeout as e:
            print(f"Timeout crawling {url}: {e}", file=sys.stderr)
        except requests.ConnectionError as e:
            print(f"Connection error crawling {url}: {e}", file=sys.stderr)
        except requests.HTTPError as e:
            print(
                f"HTTP error crawling {url}: {e.response.status_code} {e.response.reason}",
                file=sys.stderr,
            )
        except requests.RequestException as e:
            print(f"Request error crawling {url}: {e}", file=sys.stderr)

    crawl_directory(base_url)
    return found_repomds


def parse_repomd_path(repomd_url: str, base_url: str) -> Dict[str, str]:
    """
    Parse repomd.xml URL to extract repository metadata using proper URL parsing.

    Args:
        repomd_url: Full URL to repomd.xml file
        base_url: Base repository URL

    Returns:
        Dictionary with arch, repo_name, repo_type, version

    Raises:
        ValueError: If URLs are invalid or malformed
    """
    # Input validation
    if not repomd_url or not base_url:
        raise ValueError("Both repomd_url and base_url must be provided")

    try:
        parsed_repomd = urlparse(repomd_url)
        parsed_base = urlparse(base_url)
    except Exception as e:
        raise ValueError(f"Invalid URL format: {e}")

    # Ensure repomd_url is a descendant of base_url
    if not repomd_url.startswith(base_url.rstrip("/")):
        raise ValueError("repomd_url must be under base_url")

    # Extract relative path by removing base URL path from repomd URL path
    base_path = parsed_base.path.rstrip("/")
    repomd_path = parsed_repomd.path

    if not repomd_path.startswith(base_path):
        raise ValueError("URL path structure inconsistent")

    # Remove base path and trailing /repodata/repomd.xml
    relative_path = repomd_path[len(base_path) :].lstrip("/")
    if relative_path.endswith("/repodata/repomd.xml"):
        relative_path = relative_path[: -len("/repodata/repomd.xml")]

    path_parts = [p for p in relative_path.split("/") if p]

    # Also parse the base_url path to extract version if present
    base_path_parts = [p for p in base_path.split("/") if p]
    full_path_parts = base_path_parts + path_parts

    metadata = {
        "arch": UNKNOWN_VALUE,
        "repo_name": UNKNOWN_VALUE,
        "repo_type": RepositoryType.MAIN.value,
        "version": UNKNOWN_VALUE,
    }

    # Try to identify components from both base URL and relative path
    for part in full_path_parts:
        # Check for architecture using enum validation
        if ConfigValidator.is_valid_architecture(part):
            metadata["arch"] = part

        # Check for repository name using enum validation
        if ConfigValidator.is_valid_repository_name(part):
            metadata["repo_name"] = part

        # Check for version pattern using validation pattern
        if ValidationPatterns.VERSION_PATTERN.match(part):
            metadata["version"] = part

        # Check for debug repositories
        if "debug" in part.lower():
            metadata["repo_type"] = RepositoryType.DEBUG.value

        # Check for source repositories
        if part.lower() in ["source", "srpms"] or "src" in part.lower():
            metadata["repo_type"] = RepositoryType.SOURCE.value
            metadata["arch"] = Architecture.SOURCE.value

    return metadata


def build_mirror_config(
    version: str, arch: str, name_suffix: Optional[str] = None
) -> Dict[str, Any]:
    """
    Build a mirror configuration dictionary.

    Args:
        version: Rocky Linux version
        arch: Architecture
        name_suffix: Optional suffix for mirror name

    Returns:
        Mirror configuration dictionary
    """
    # Build mirror name with optional suffix
    if name_suffix is not None and name_suffix != "":
        mirror_name = f"Rocky Linux {version} {name_suffix} {arch}"
    else:
        mirror_name = f"Rocky Linux {version} {arch}"

    # Parse version to extract major and minor components
    if version != UNKNOWN_VALUE and "." in version:
        version_parts = version.split(".")
        major_version = int(version_parts[0])
        minor_version = int(version_parts[1]) if len(version_parts) > 1 else None
    elif version != UNKNOWN_VALUE:
        major_version = int(version)
        minor_version = None
    else:
        major_version = 10
        minor_version = None

    return {
        "product": {
            "name": "Rocky Linux",
            "variant": "Rocky Linux",
            "vendor": "Rocky Enterprise Software Foundation",
        },
        "mirror": {
            "name": mirror_name,
            "match_variant": "Red Hat Enterprise Linux",
            "match_major_version": major_version,
            "match_minor_version": minor_version,
            "match_arch": arch,
        },
        "repositories": [],
    }


def build_repository_config(
    repo_name: str,
    arch: str,
    production: bool,
    main_url: str,
    debug_url: str = "",
    source_url: str = "",
) -> Dict[str, Any]:
    """
    Build a repository configuration dictionary.

    Args:
        repo_name: Repository name
        arch: Architecture
        production: Whether repository is production
        main_url: Main repository URL
        debug_url: Debug repository URL (optional)
        source_url: Source repository URL (optional)

    Returns:
        Repository configuration dictionary
    """
    return {
        "repo_name": repo_name,
        "arch": arch,
        "production": production,
        "url": main_url,
        "debug_url": debug_url,
        "source_url": source_url,
    }


def generate_rocky_config(
    base_url: str,
    version: Optional[str] = None,
    production: bool = True,
    include_debug: bool = True,
    include_source: bool = True,
    architectures: List[str] = None,
    name_suffix: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Generate Rocky Linux configuration by discovering repository structure.

    Args:
        base_url: Base URL for the Rocky Linux repository
        version: Rocky Linux version filter (default: auto-detect)
        production: Whether repositories are production (default: True)
        include_debug: Whether to include debug repository URLs (default: True)
        include_source: Whether to include source repository URLs (default: True)
        architectures: List of architectures to include (default: auto-detect)
        name_suffix: Optional suffix to add to mirror names (e.g., "test", "staging")

    Returns:
        List of configuration dictionaries ready for JSON export
    """
    # Discover repositories by crawling
    print("Discovering repository structure...", file=sys.stderr)
    repomds = discover_repomd_files(base_url)

    if not repomds:
        print(
            "No repomd.xml files found. Repository may be empty or inaccessible.",
            file=sys.stderr,
        )
        return []

    print(f"Found {len(repomds)} repositories", file=sys.stderr)

    # Group by architecture and filter
    arch_repos = {}

    for repomd_url, metadata in repomds:
        arch = metadata["arch"]

        # Skip if architecture filter specified and doesn't match
        if architectures and arch not in architectures and arch != "source":
            continue

        # Skip if version filter specified and doesn't match
        if (
            version
            and metadata["version"] != version
            and metadata["version"] != UNKNOWN_VALUE
        ):
            continue

        # Skip debug repos if not wanted
        if not include_debug and metadata["repo_type"] == "debug":
            continue

        # Skip source repos if not wanted
        if not include_source and metadata["repo_type"] == "source":
            continue

        # Skip repositories with unknown names (not in repo_names list)
        if metadata["repo_name"] == UNKNOWN_VALUE:
            continue

        # Group repositories by architecture
        if arch not in arch_repos:
            arch_repos[arch] = {}

        repo_key = f"{metadata['repo_name']}_{metadata['repo_type']}"
        arch_repos[arch][repo_key] = {"url": repomd_url, "metadata": metadata}

    # Convert to configuration format
    config_data = []

    for arch, repos in arch_repos.items():
        if arch == "source":  # Handle source repos separately
            continue

        # Determine version from repos
        detected_version = version
        if not detected_version:
            for repo_info in repos.values():
                if repo_info["metadata"]["version"] != UNKNOWN_VALUE:
                    detected_version = repo_info["metadata"]["version"]
                    break
            if not detected_version:
                detected_version = UNKNOWN_VALUE

        mirror_config = build_mirror_config(detected_version, arch, name_suffix)

        # Group repos by name and type
        repo_groups = {}
        for repo_key, repo_info in repos.items():
            repo_name = repo_info["metadata"]["repo_name"]
            repo_type = repo_info["metadata"]["repo_type"]

            if repo_name not in repo_groups:
                repo_groups[repo_name] = {}

            repo_groups[repo_name][repo_type] = repo_info["url"]

        # Create repository configurations
        for repo_name, repo_urls in repo_groups.items():
            main_url = repo_urls.get("main", "")
            debug_url = repo_urls.get("debug", "")

            # Look for source URL in source arch repos
            source_url = ""
            if include_source and "source" in arch_repos:
                for source_repo_key, source_repo_info in arch_repos[
                    "source"
                ].items():
                    if source_repo_info["metadata"]["repo_name"] == repo_name:
                        source_url = source_repo_info["url"]
                        break

            if main_url:  # Only add if we have a main repository
                repo_config = build_repository_config(
                    repo_name, arch, production, main_url, debug_url, source_url
                )
                mirror_config["repositories"].append(repo_config)

        if mirror_config["repositories"]:  # Only add if we have repositories
            config_data.append(mirror_config)

    return config_data




def main():
    parser = argparse.ArgumentParser(
        description="Generate Rocky Linux repository configuration by crawling repository structure",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s https://mirror.example.com/pub/rocky/
  %(prog)s http://user:pass@private-repo.com/Rocky9.6/ --version 9.6
  %(prog)s https://mirror.example.com/pub/rocky/ --no-debug --no-source
  %(prog)s https://mirror.example.com/pub/rocky/ --arch x86_64 aarch64
  %(prog)s https://mirror.example.com/pub/rocky/ --output rocky_config.json
  %(prog)s https://mirror.example.com/pub/rocky/ --name-suffix test --version 9.6
  %(prog)s https://staging.example.com/pub/rocky/ --name-suffix staging --arch riscv64
        """,
    )

    parser.add_argument(
        "base_url",
        help="Base URL for Rocky Linux repositories (supports authentication: http://user:pass@example.com/)",
    )

    parser.add_argument(
        "--version",
        "-v",
        help="Rocky Linux version filter (default: auto-detect)",
    )

    parser.add_argument(
        "--production",
        action="store_true",
        default=True,
        help="Mark repositories as production (default: true)",
    )

    parser.add_argument(
        "--staging",
        action="store_true",
        help="Mark repositories as staging (opposite of --production)",
    )

    parser.add_argument(
        "--no-debug", action="store_true", help="Exclude debug repository URLs"
    )

    parser.add_argument(
        "--no-source", action="store_true", help="Exclude source repository URLs"
    )

    parser.add_argument(
        "--arch",
        nargs="+",
        choices=ConfigValidator.get_supported_architectures(),
        help="Architectures to include (default: auto-detect)",
    )


    parser.add_argument(
        "--max-depth", type=int, default=4, help="Maximum crawling depth (default: 4)"
    )

    parser.add_argument(
        "--name-suffix",
        help="Optional suffix to add to mirror names (e.g., 'test', 'staging')",
    )

    parser.add_argument("--output", "-o", help="Output file path (default: stdout)")

    parser.add_argument(
        "--pretty",
        action="store_true",
        default=True,
        help="Pretty-print JSON output (default: true)",
    )

    args = parser.parse_args()

    # Handle production/staging flags
    production = args.production and not args.staging

    # Input validation

    # Validate base URL using ConfigValidator
    try:
        ConfigValidator.validate_url(args.base_url, "base_url", required=True)
    except ValidationError as e:
        print(f"Error: {e.message}", file=sys.stderr)
        sys.exit(1)

    # Validate version format if provided using ConfigValidator
    if args.version:
        try:
            ConfigValidator.validate_version(args.version, "version")
        except ValidationError as e:
            print(f"Error: {e.message}", file=sys.stderr)
            sys.exit(1)

    # Validate max_depth
    if args.max_depth < 0:
        print("Error: max_depth must be non-negative", file=sys.stderr)
        sys.exit(1)

    try:
        # Generate configuration
        config = generate_rocky_config(
            base_url=args.base_url,
            version=args.version,
            production=production,
            include_debug=not args.no_debug,
            include_source=not args.no_source,
            architectures=args.arch,
            name_suffix=args.name_suffix,
        )

        if not config:
            print("No repositories found or generated", file=sys.stderr)
            sys.exit(1)

        # Format JSON output
        if args.pretty:
            json_output = json.dumps(config, indent=2)
        else:
            json_output = json.dumps(config)

        # Write output
        if args.output:
            try:
                with open(args.output, "w") as f:
                    f.write(json_output)
                print(f"Configuration written to {args.output}", file=sys.stderr)
            except OSError as e:
                print(f"Error writing to file '{args.output}': {e}", file=sys.stderr)
                sys.exit(1)
        else:
            print(json_output)

    except KeyboardInterrupt:
        print("\nInterrupted by user", file=sys.stderr)
        sys.exit(1)
    except (ValueError, ValidationError) as e:
        print(f"Validation error: {e}", file=sys.stderr)
        sys.exit(1)
    except requests.RequestException as e:
        print(f"Network error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
