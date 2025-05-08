import re
import json

def parse_dist_version(release: str) -> dict:
    """
    Extract Red Hat major and minor versions from release string.
    
    Examples:
    - "4.module+el8.10.0+22411+85254afd" -> {"major": 8, "minor": 10}
    - "427.55.1.el9_4" -> {"major": 9, "minor": 4}
    - "1.el8" -> {"major": 8, "minor": None}
    """
    # Pattern matches:
    # 1. module+el{major}.{minor} - for module packages
    # 2. el{major}_{minor} - for regular packages with minor version
    # 3. el{major} - for regular packages without minor version
    pattern = r"""
        (?:module\+)?     # Optional module prefix
        (?:el|rhel)       # Distribution identifier
        (\d+)             # Major version (capture group 1)
        (?:[\._]          # Separator (dot or underscore)
        (\d+))?          # Optional minor version (capture group 2)
    """
    
    match = re.search(pattern, release, re.VERBOSE)
    if not match:
        return {"major": None, "minor": None}
    
    major = int(match.group(1))
    minor = int(match.group(2)) if match.group(2) else None
    
    return {
        "major": major,
        "minor": minor
    }

def parse_nevra(filename):
    # Strip off optional .rpm extension
    if filename.endswith('.rpm'):
        filename = filename[:-4]

    # Split off arch
    try:
        rest, arch = filename.rsplit('.', 1)
    except ValueError:
        raise ValueError("Missing architecture in NEVRA string")

    # Split off release
    try:
        nvr, release = rest.rsplit('-', 1)
    except ValueError:
        raise ValueError("Missing release in NEVRA string")

    # Split off version
    try:
        name_version, version = nvr.rsplit('-', 1)
    except ValueError:
        raise ValueError("Missing version in NEVRA string")

    # Split epoch if present (it will be in the version part)
    if ':' in version:
        epoch, version = version.split(':', 1)
    else:
        epoch = 0

    name = name_version
    dist_version = parse_dist_version(release)
    if dist_version["major"] is None:
        raise ValueError("Invalid distribution version in NEVRA string")
    major = dist_version["major"]
    minor = dist_version["minor"]
    return {
        "raw": filename,
        "name": name,
        "epoch": epoch,
        "version": version,
        "release": release,
        "arch": arch,
        "dist_major": major,
        "dist_minor": minor,
    }