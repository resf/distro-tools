from __future__ import annotations

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


def rpmvercmp(a: str, b: str) -> int:
    """
    Compare two RPM version or release strings (rpmvercmp semantics).

    Handles numeric/alpha segments, and the special ``~`` / ``^`` markers
    used by RPM (``1.0~rc1`` < ``1.0``; ``^`` sorts after the base when the
    other side ends, else like a normal separator).

    Returns -1 if a < b, 0 if equal, 1 if a > b.
    """
    if a == b:
        return 0

    i = j = 0
    la, lb = len(a), len(b)

    while i < la or j < lb:
        # Skip non-alnum separators except ~ and ^.
        while i < la and not a[i].isalnum() and a[i] not in "~^":
            i += 1
        while j < lb and not b[j].isalnum() and b[j] not in "~^":
            j += 1

        # '~' always sorts before anything (including end-of-string).
        if (i < la and a[i] == "~") or (j < lb and b[j] == "~"):
            if i >= la or a[i] != "~":
                return 1
            if j >= lb or b[j] != "~":
                return -1
            i += 1
            j += 1
            continue

        # '^' sorts after end-of-string, otherwise like a normal separator.
        if (i < la and a[i] == "^") or (j < lb and b[j] == "^"):
            if i >= la:
                return -1
            if j >= lb:
                return 1
            if a[i] != "^":
                return 1
            if b[j] != "^":
                return -1
            i += 1
            j += 1
            continue

        if i >= la and j >= lb:
            return 0
        if i >= la:
            return -1
        if j >= lb:
            return 1

        # Numeric segment vs alpha segment: numbers win (RPM rule).
        a_is_num = a[i].isdigit()
        b_is_num = b[j].isdigit()
        if a_is_num and not b_is_num:
            return 1
        if not a_is_num and b_is_num:
            return -1

        start_i, start_j = i, j
        if a_is_num:
            while i < la and a[i].isdigit():
                i += 1
            while j < lb and b[j].isdigit():
                j += 1
            seg_a = a[start_i:i].lstrip("0") or "0"
            seg_b = b[start_j:j].lstrip("0") or "0"
            if len(seg_a) != len(seg_b):
                return 1 if len(seg_a) > len(seg_b) else -1
            if seg_a != seg_b:
                return 1 if seg_a > seg_b else -1
        else:
            while i < la and a[i].isalpha():
                i += 1
            while j < lb and b[j].isalpha():
                j += 1
            seg_a = a[start_i:i]
            seg_b = b[start_j:j]
            if seg_a != seg_b:
                return 1 if seg_a > seg_b else -1

    return 0


def label_compare(
    e1: str | int,
    v1: str,
    r1: str,
    e2: str | int,
    v2: str,
    r2: str,
) -> int:
    """
    Compare two EVR labels (epoch, version, release).

    Returns -1 if first < second, 0 if equal, 1 if first > second.
    """
    epoch1 = int(e1 or 0)
    epoch2 = int(e2 or 0)
    if epoch1 != epoch2:
        return 1 if epoch1 > epoch2 else -1

    ver_cmp = rpmvercmp(str(v1), str(v2))
    if ver_cmp != 0:
        return ver_cmp

    return rpmvercmp(str(r1), str(r2))


def evr_gte(
    e1: str | int,
    v1: str,
    r1: str,
    e2: str | int,
    v2: str,
    r2: str,
) -> bool:
    """True if (e1,v1,r1) >= (e2,v2,r2) under RPM labelCompare rules."""
    return label_compare(e1, v1, r1, e2, v2, r2) >= 0
