#!/usr/bin/env python3
import subprocess
import sys
import os
import re
from pathlib import Path


# Keep ksud's numeric version aligned with manager/build.gradle.kts and
# kernel/Kbuild. The offset leaves room for the historical version range.
VERSION_CODE_BASE = 10000 - 3135


def normalize_version_name(describe):
    describe = describe.strip()
    match = re.match(r"^v?(\d+\.\d+\.\d+)(?:-\d+-g([0-9a-fA-F]+).*)?$", describe)
    if match:
        semver, commit = match.groups()
        return f"{semver}-{commit[:8]}" if commit else semver
    return describe.lstrip('v')


DIRTY_VERSION_PATTERN = re.compile(
    rb"(?:v?\d+\.\d+\.\d+|[0-9a-fA-F]{8})"
    rb"(?:-[0-9a-fA-F]{8})?-nc(?:@YukiSU)?(?:[^0-9A-Za-z]|$)"
)


def git_has_changes(repo_root, paths):
    try:
        result = subprocess.run(
            [
                "git",
                "-C",
                str(repo_root),
                "-c",
                "core.autocrlf=true",
                "status",
                "--porcelain",
                "--untracked-files=normal",
                "--",
                *paths,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
        return result.returncode == 0 and bool(result.stdout.strip())
    except OSError:
        return False


def has_dirty_version(path):
    try:
        return DIRTY_VERSION_PATTERN.search(path.read_bytes()) is not None
    except OSError:
        return False


def has_kernel_nc(repo_root):
    kernel_assets = (
        repo_root / "userspace" / "ksud" / "assets",
        repo_root / "out",
    )
    built_kernel_nc = any(
        has_dirty_version(path)
        for directory in kernel_assets
        for path in directory.glob("*_kernelsu.ko")
        if path.is_file()
    )
    return built_kernel_nc or git_has_changes(repo_root, ("kernel", "uapi"))


def has_ksud_nc(repo_root):
    return has_kernel_nc(repo_root) or git_has_changes(repo_root, ("userspace/ksud",))

def get_git_version():
    repo_root = Path(__file__).resolve().parents[3]
    dirty = has_ksud_nc(repo_root)
    try:
        count_output = subprocess.check_output(
            ["git", "rev-list", "--count", "HEAD"],
            stderr=subprocess.DEVNULL,
            text=True
        ).strip()
        version_code = int(count_output) + VERSION_CODE_BASE
        
        try:
            tag_output = subprocess.check_output(
                ["git", "describe", "--tags", "--always", "--abbrev=8"],
                stderr=subprocess.DEVNULL,
                text=True
            ).strip()
            version_name = normalize_version_name(tag_output)
        except:
            version_name = subprocess.check_output(
                ["git", "rev-parse", "--short=8", "HEAD"],
                stderr=subprocess.DEVNULL,
                text=True
            ).strip()
        
        if dirty and not version_name.endswith("-nc"):
            version_name += "-nc"
        return version_code, version_name
    except:
        print("Warning: Failed to get git version, using defaults", file=sys.stderr)
        return 12000, "1.2.0-nc" if dirty else "1.2.0"

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: generate_version.py <output_file>")
        sys.exit(1)
    
    output_file = sys.argv[1]
    code, name = get_git_version()
    
    # Generate C++ source file
    content = f'''#include "defs.hpp"

namespace ksud {{

// Auto-generated at build time
const char* const VERSION_CODE = "{code}";
const char* const VERSION_NAME = "{name}";

}}  // namespace ksud
'''
    
    # Only write if changed to avoid unnecessary rebuilds
    if os.path.exists(output_file):
        with open(output_file, 'r') as f:
            if f.read() == content:
                sys.exit(0)
    
    with open(output_file, 'w') as f:
        f.write(content)
    
    print(f"Generated version: {name} ({code})")
