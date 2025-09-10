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
from typing import Dict, List, Any, Tuple, Optional
from urllib.parse import urljoin, urlparse
import requests
from bs4 import BeautifulSoup


def discover_repomd_files(base_url: str, max_depth: int = 4) -> List[Tuple[str, Dict[str, str]]]:
    """
    Crawl repository structure to discover repomd.xml files.
    
    Args:
        base_url: Base URL to start crawling from
        max_depth: Maximum depth to crawl (default: 4)
    
    Returns:
        List of tuples: (repomd_url, metadata_dict)
        metadata includes: arch, repo_name, repo_type (main/debug/source), version
    """
    session = requests.Session()
    session.headers.update({'User-Agent': 'Rocky-Config-Generator/1.0'})
    
    found_repomds = []
    visited_urls = set()
    
    def crawl_directory(url: str, depth: int = 0) -> None:
        if depth > max_depth or url in visited_urls:
            return
        
        visited_urls.add(url)
        print(f"Crawling: {url}", file=sys.stderr)
        
        try:
            response = session.get(url, timeout=30)
            response.raise_for_status()
            
            # Parse directory listing to look for repodata subdirectories
            if 'text/html' in response.headers.get('content-type', '').lower():
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Look for repodata directory and other subdirectories
                has_repodata = False
                subdirs_to_crawl = []
                
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    link_text = link.get_text(strip=True).lower()
                    
                    # Skip parent directory, current directory, and files
                    if (href in ['.', '..', '../', './'] or 
                        not href.endswith('/') or
                        'parent' in link_text or
                        '..' in href):
                        continue
                    
                    # Skip obvious files
                    if '.' in href and href.count('.') > href.count('/'):
                        continue
                    
                    # Check if this is a repodata directory
                    if href.rstrip('/').lower() == 'repodata':
                        has_repodata = True
                        # Check for repomd.xml in this repodata directory
                        repomd_url = urljoin(url, "repodata/repomd.xml")
                        try:
                            repomd_response = session.head(repomd_url, timeout=10)
                            if repomd_response.status_code == 200:
                                metadata = parse_repomd_path(repomd_url, base_url)
                                found_repomds.append((repomd_url, metadata))
                                print(f"Found repomd.xml: {repomd_url}", file=sys.stderr)
                        except requests.RequestException:
                            pass
                    else:
                        # Add to subdirectories to crawl if we don't find repodata here
                        subdir_url = urljoin(url, href)
                        if (subdir_url != url and 
                            subdir_url not in visited_urls and 
                            subdir_url.startswith(base_url)):
                            subdirs_to_crawl.append(subdir_url)
                
                # Only crawl subdirectories if we didn't find repodata in current directory
                # This prevents going deeper once we find a repository
                if not has_repodata:
                    for subdir_url in subdirs_to_crawl:
                        crawl_directory(subdir_url, depth + 1)
        
        except requests.RequestException as e:
            print(f"Error crawling {url}: {e}", file=sys.stderr)
    
    # Ensure base_url ends with slash
    if not base_url.endswith('/'):
        base_url += '/'
    
    crawl_directory(base_url)
    return found_repomds


def parse_repomd_path(repomd_url: str, base_url: str) -> Dict[str, str]:
    """
    Parse repomd.xml URL to extract repository metadata.
    
    Args:
        repomd_url: Full URL to repomd.xml file
        base_url: Base repository URL
    
    Returns:
        Dictionary with arch, repo_name, repo_type, version
    """
    # Remove base_url and repodata/repomd.xml to get the path structure
    relative_path = repomd_url.replace(base_url, '').replace('/repodata/repomd.xml', '')
    path_parts = [p for p in relative_path.split('/') if p]
    
    metadata = {
        'arch': 'unknown',
        'repo_name': 'unknown',
        'repo_type': 'main',
        'version': 'unknown'
    }
    
    # Common patterns for Rocky Linux repositories
    architectures = ['x86_64', 'aarch64', 'ppc64le', 's390x', 'noarch', 'source', 'SRPMS']
    repo_names = ['BaseOS', 'AppStream', 'CRB', 'PowerTools', 'extras', 'devel', 'RT', 'NFV', 'ResilientStorage']
    
    # Try to identify components from path
    for part in path_parts:
        # Check for architecture
        if part in architectures:
            metadata['arch'] = part
        
        # Check for repository name
        if part in repo_names:
            metadata['repo_name'] = part
        
        # Check for version pattern (e.g., 9.6, 10.0, 10)
        if re.match(r'^\d+(\.\d+)?$', part):
            metadata['version'] = part
        
        # Check for debug repositories
        if 'debug' in part.lower():
            metadata['repo_type'] = 'debug'
        
        # Check for source repositories
        if part.lower() in ['source', 'srpms'] or 'src' in part.lower():
            metadata['repo_type'] = 'source'
            metadata['arch'] = 'source'
    
    return metadata


def generate_rocky_config(
    base_url: str, 
    version: Optional[str] = None,
    production: bool = True,
    include_debug: bool = True,
    include_source: bool = True,
    architectures: List[str] = None,
    crawl: bool = True
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
        crawl: Whether to crawl for repositories (default: True)
    
    Returns:
        List of configuration dictionaries ready for JSON export
    """
    if crawl:
        # Discover repositories by crawling
        print("Discovering repository structure...", file=sys.stderr)
        repomds = discover_repomd_files(base_url)
        
        if not repomds:
            print("No repomd.xml files found. Repository may be empty or inaccessible.", file=sys.stderr)
            return []
        
        print(f"Found {len(repomds)} repositories", file=sys.stderr)
        
        # Group by architecture and filter
        arch_repos = {}
        
        for repomd_url, metadata in repomds:
            arch = metadata['arch']
            
            # Skip if architecture filter specified and doesn't match
            if architectures and arch not in architectures and arch != 'source':
                continue
            
            # Skip if version filter specified and doesn't match
            if version and metadata['version'] != version and metadata['version'] != 'unknown':
                continue
            
            # Skip debug repos if not wanted
            if not include_debug and metadata['repo_type'] == 'debug':
                continue
            
            # Skip source repos if not wanted
            if not include_source and metadata['repo_type'] == 'source':
                continue
            
            # Group repositories by architecture
            if arch not in arch_repos:
                arch_repos[arch] = {}
            
            repo_key = f"{metadata['repo_name']}_{metadata['repo_type']}"
            arch_repos[arch][repo_key] = {
                'url': repomd_url,
                'metadata': metadata
            }
        
        # Convert to configuration format
        config_data = []
        
        for arch, repos in arch_repos.items():
            if arch == 'source':  # Handle source repos separately
                continue
                
            # Determine version from repos
            detected_version = version
            if not detected_version:
                for repo_info in repos.values():
                    if repo_info['metadata']['version'] != 'unknown':
                        detected_version = repo_info['metadata']['version']
                        break
                if not detected_version:
                    detected_version = "unknown"
            
            mirror_config = {
                "product": {
                    "name": "Rocky Linux",
                    "variant": "Rocky Linux",
                    "vendor": "Rocky Enterprise Software Foundation"
                },
                "mirror": {
                    "name": f"Rocky Linux {detected_version} {arch}",
                    "match_variant": "Red Hat Enterprise Linux",
                    "match_major_version": int(detected_version.split('.')[0]) if detected_version != "unknown" else 10,
                    "match_minor_version": None,
                    "match_arch": arch
                },
                "repositories": []
            }
            
            # Group repos by name and type
            repo_groups = {}
            for repo_key, repo_info in repos.items():
                repo_name = repo_info['metadata']['repo_name']
                repo_type = repo_info['metadata']['repo_type']
                
                if repo_name not in repo_groups:
                    repo_groups[repo_name] = {}
                
                repo_groups[repo_name][repo_type] = repo_info['url']
            
            # Create repository configurations
            for repo_name, repo_urls in repo_groups.items():
                main_url = repo_urls.get('main', '')
                debug_url = repo_urls.get('debug', '')
                
                # Look for source URL in source arch repos
                source_url = ''
                if include_source and 'source' in arch_repos:
                    for source_repo_key, source_repo_info in arch_repos['source'].items():
                        if source_repo_info['metadata']['repo_name'] == repo_name:
                            source_url = source_repo_info['url']
                            break
                
                if main_url:  # Only add if we have a main repository
                    repo_config = {
                        "repo_name": repo_name,
                        "arch": arch,
                        "production": production,
                        "url": main_url,
                        "debug_url": debug_url,
                        "source_url": source_url
                    }
                    mirror_config["repositories"].append(repo_config)
            
            if mirror_config["repositories"]:  # Only add if we have repositories
                config_data.append(mirror_config)
        
        return config_data
    
    else:
        # Fallback to old static method
        return generate_static_config(base_url, version or "10.0", production, include_debug, include_source, architectures)


def generate_static_config(
    base_url: str, 
    version: str = "10.0",
    production: bool = True,
    include_debug: bool = True,
    include_source: bool = True,
    architectures: List[str] = None
) -> List[Dict[str, Any]]:
    """
    Generate Rocky Linux configuration using static repository structure.
    This is the original implementation as a fallback.
    """
    if architectures is None:
        architectures = ["x86_64", "aarch64", "ppc64le", "s390x"]
    
    repositories = ["BaseOS", "AppStream", "CRB"]
    
    if not base_url.endswith('/'):
        base_url += '/'
    
    config_data = []
    
    for arch in architectures:
        mirror_config = {
            "product": {
                "name": "Rocky Linux",
                "variant": "Rocky Linux",
                "vendor": "Rocky Enterprise Software Foundation"
            },
            "mirror": {
                "name": f"Rocky Linux {version} {arch}",
                "match_variant": "Red Hat Enterprise Linux",
                "match_major_version": int(version.split('.')[0]),
                "match_minor_version": None,
                "match_arch": arch
            },
            "repositories": []
        }
        
        for repo_name in repositories:
            main_url = urljoin(base_url, f"{version}/{repo_name}/{arch}/os/repodata/repomd.xml")
            
            debug_url = ""
            if include_debug:
                debug_url = urljoin(base_url, f"{version}/{repo_name}/{arch}/debug/tree/repodata/repomd.xml")
            
            source_url = ""
            if include_source:
                source_url = urljoin(base_url, f"{version}/{repo_name}/source/tree/repodata/repomd.xml")
            
            repo_config = {
                "repo_name": repo_name,
                "arch": arch,
                "production": production,
                "url": main_url,
                "debug_url": debug_url,
                "source_url": source_url
            }
            
            mirror_config["repositories"].append(repo_config)
        
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
  %(prog)s https://mirror.example.com/pub/rocky/ --no-crawl --version 10.0
        """
    )
    
    parser.add_argument(
        "base_url",
        help="Base URL for Rocky Linux repositories (supports authentication: http://user:pass@example.com/)"
    )
    
    parser.add_argument(
        "--version", "-v",
        help="Rocky Linux version filter (default: auto-detect when crawling, 10.0 when static)"
    )
    
    parser.add_argument(
        "--production",
        action="store_true",
        default=True,
        help="Mark repositories as production (default: true)"
    )
    
    parser.add_argument(
        "--staging",
        action="store_true",
        help="Mark repositories as staging (opposite of --production)"
    )
    
    parser.add_argument(
        "--no-debug",
        action="store_true",
        help="Exclude debug repository URLs"
    )
    
    parser.add_argument(
        "--no-source",
        action="store_true",
        help="Exclude source repository URLs"
    )
    
    parser.add_argument(
        "--arch",
        nargs="+",
        choices=["x86_64", "aarch64", "ppc64le", "s390x"],
        help="Architectures to include (default: auto-detect when crawling, all when static)"
    )
    
    parser.add_argument(
        "--no-crawl",
        action="store_true",
        help="Don't crawl repository structure, use static paths (requires --version)"
    )
    
    parser.add_argument(
        "--max-depth",
        type=int,
        default=4,
        help="Maximum crawling depth (default: 4)"
    )
    
    parser.add_argument(
        "--output", "-o",
        help="Output file path (default: stdout)"
    )
    
    parser.add_argument(
        "--pretty",
        action="store_true",
        default=True,
        help="Pretty-print JSON output (default: true)"
    )
    
    args = parser.parse_args()
    
    # Handle production/staging flags
    production = args.production and not args.staging
    
    # Validation
    if args.no_crawl and not args.version:
        print("Error: --version is required when using --no-crawl", file=sys.stderr)
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
            crawl=not args.no_crawl
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
            with open(args.output, 'w') as f:
                f.write(json_output)
            print(f"Configuration written to {args.output}", file=sys.stderr)
        else:
            print(json_output)
    
    except KeyboardInterrupt:
        print("\nInterrupted by user", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()