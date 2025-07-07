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
        (?:el|rhel|sles)  # Distribution identifier
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

def parse_nevra(nevra_str: str) -> dict:
    """
    Parse a NEVRA (Name-Epoch-Version-Release-Architecture) string from an RPM nevra_str.

    The function extracts the following components from the given nevra_str:
        - name: Package name
        - epoch: Epoch (defaults to 0 if not present)
        - version: Version string
        - release: Release string
        - arch: Architecture
        - dist_major: Major distribution version (parsed from release)
        - dist_minor: Minor distribution version (parsed from release)
        - raw: The original nevra_str with optional '.rpm' extension removed

    Args:
        nevra_str (str): The RPM nevra_str or NEVRA string to parse.

    Returns:
        dict: A dictionary containing the parsed NEVRA components.

    Raises:
        ValueError: If the nevra_str is missing required NEVRA components or has an invalid distribution version.

    Example:
        parse_nevra("bash-0:5.1.8-6.el9.x86_64.rpm")
        {
            'raw': 'bash-0:5.1.8-6.el9.x86_64',
            'name': 'bash',
            'epoch': '0',
            'version': '5.1.8',
            'release': '6.el9',
            'arch': 'x86_64',
            'dist_major': 9,
            'dist_minor': None
        }
    """
    # Strip off optional .rpm extension
    if nevra_str.endswith('.rpm'):
        nevra_str = nevra_str[:-4]

    # Split off arch
    try:
        rest, arch = nevra_str.rsplit('.', 1)
    except ValueError:
        raise ValueError(f"Missing architecture in NEVRA string {nevra_str}")

    # Split off release
    try:
        nvr, release = rest.rsplit('-', 1)
    except ValueError:
        raise ValueError(f"Missing release in NEVRA string {nevra_str}")

    # Split off version
    try:
        name_version, version = nvr.rsplit('-', 1)
    except ValueError:
        raise ValueError(f"Missing version in NEVRA string {nevra_str}")

    # Split epoch if present (it will be in the version part)
    if ':' in version:
        epoch, version = version.split(':', 1)
    else:
        epoch = 0

    name = name_version
    dist_version = parse_dist_version(release)
    if dist_version["major"] is None:
        raise ValueError(f"Invalid distribution version in NEVRA string {nevra_str}")
    major = dist_version["major"]
    minor = dist_version["minor"]
    return {
        "raw": nevra_str,
        "name": name,
        "epoch": epoch,
        "version": version,
        "release": release,
        "arch": arch,
        "dist_major": major,
        "dist_minor": minor,
    }