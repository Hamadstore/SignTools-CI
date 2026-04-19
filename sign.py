#!/usr/bin/env python3
"""
iOS/macOS app resigning tool with tweak injection.
Supports developer accounts (fastlane) or pre‑existing provisioning profiles.
"""

import copy
import json
import logging
import os
import plistlib
import random
import re
import shutil
import string
import subprocess
import sys
import tempfile
import time
import traceback
from dataclasses import dataclass, field
from multiprocessing.pool import ThreadPool
from pathlib import Path
from subprocess import PIPE, Popen
from typing import Any, Dict, Iterable, List, NamedTuple, Optional, Set, Tuple, Union

# ----------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------
DEFAULT_KEYCHAIN_PASSWORD = "1234"
SUPPORTED_ENTITLEMENTS = {
    # Common
    "com.apple.developer.team-identifier",
    "get-task-allow",
    "keychain-access-groups",
    # iOS specific
    "aps-environment",
    "com.apple.developer.aps-environment",
    "com.apple.developer.healthkit",
    "com.apple.developer.healthkit.access",
    "com.apple.developer.homekit",
    "com.apple.external-accessory.wireless-configuration",
    "com.apple.security.application-groups",
    "inter-app-audio",
    "com.apple.developer.icloud-container-development-container-identifiers",
    "com.apple.developer.icloud-container-environment",
    "com.apple.developer.icloud-container-identifiers",
    "com.apple.developer.icloud-services",
    "com.apple.developer.kernel.extended-virtual-addressing",
    "com.apple.developer.networking.multipath",
    "com.apple.developer.networking.networkextension",
    "com.apple.developer.networking.vpn.api",
    "com.apple.developer.networking.wifi-info",
    "com.apple.developer.nfc.readersession.formats",
    "com.apple.developer.siri",
    "com.apple.developer.ubiquity-container-identifiers",
    "com.apple.developer.ubiquity-kvstore-identifier",
    "com.apple.developer.associated-domains",
    "com.apple.developer.usernotifications.communication",
    "com.apple.developer.usernotifications.filtering",
    # macOS specific
    "com.apple.security.app-sandbox",
    "com.apple.security.assets.pictures.read-write",
    "com.apple.security.cs.allow-jit",
    "com.apple.security.cs.allow-unsigned-executable-memory",
    "com.apple.security.cs.disable-library-validation",
    "com.apple.security.device.audio-input",
    "com.apple.security.device.bluetooth",
    "com.apple.security.device.usb",
    "com.apple.security.files.user-selected.read-only",
    "com.apple.security.files.user-selected.read-write",
    "com.apple.security.network.client",
    "com.apple.security.network.server",
}

# Files expected in the job archive
JOB_FILES = {
    "cert_pass.txt": "certificate_password",
    "args.txt": "signing_arguments",
    "id.txt": "job_id",
    "user_bundle_id.txt": "custom_bundle_id",
    "team_id.txt": "team_id",
    "account_name.txt": "apple_id_username",
    "account_pass.txt": "apple_id_password",
    "prov.mobileprovision": "provisioning_profile",
    "bundle_name.txt": "display_name",
}

# ----------------------------------------------------------------------
# Exceptions
# ----------------------------------------------------------------------
class SigningError(Exception):
    """Base exception for signing failures."""

class SubprocessError(SigningError):
    """Raised when a subprocess returns a non‑zero exit code or times out."""

class ConfigurationError(SigningError):
    """Missing or invalid configuration."""

# ----------------------------------------------------------------------
# Logging setup
# ----------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("ios_signer")

# ----------------------------------------------------------------------
# Helper functions
# ----------------------------------------------------------------------
def decode_clean(b: bytes) -> str:
    """Decode bytes to UTF‑8 string, stripping whitespace. Empty on error."""
    return b.decode("utf-8").strip() if b else ""

def safe_glob(root: Path, pattern: str) -> Iterable[Path]:
    """Glob ignoring macOS metadata files."""
    for p in sorted(root.glob(pattern)):
        if not p.name.startswith("._") and p.name not in {".DS_Store", ".AppleDouble", "__MACOSX"}:
            yield p

def rand_str(length: int, seed: Any = None) -> str:
    """Generate a random alphanumeric string."""
    if seed is not None:
        state = random.getstate()
        random.seed(seed)
    result = "".join(random.choices(string.ascii_lowercase + string.digits, k=length))
    if seed is not None:
        random.setstate(state)
    return result

def read_text(file_path: Path) -> str:
    """Read a text file, strip newline."""
    return file_path.read_text().strip()

def write_text(file_path: Path, content: str) -> None:
    """Write a string to a text file."""
    file_path.write_text(content)

def run_cmd(
    *cmd: str,
    capture: bool = True,
    check: bool = True,
    env: Optional[Dict[str, str]] = None,
    cwd: Optional[Path] = None,
    timeout: Optional[float] = None,
) -> subprocess.CompletedProcess:
    """Run a command, raising SubprocessError on failure."""
    try:
        return subprocess.run(
            cmd,
            capture_output=capture,
            check=check,
            env=env,
            cwd=str(cwd) if cwd else None,
            timeout=timeout,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        stdout = decode_clean(getattr(e, "stdout", b""))
        stderr = decode_clean(getattr(e, "stderr", b""))
        raise SubprocessError(f"{cmd[0]} failed: {stdout} {stderr}") from e

def run_cmd_async(*cmd: str, env: Optional[Dict[str, str]] = None, cwd: Optional[Path] = None) -> Popen:
    """Start a command asynchronously."""
    return subprocess.Popen(cmd, env=env, cwd=str(cwd) if cwd else None, stdout=PIPE, stderr=PIPE)

def plist_load(plist_path: Path) -> Any:
    """Load a plist file, converting binary to XML if needed."""
    # Use plutil to convert binary to XML, then parse
    result = run_cmd("plutil", "-convert", "xml1", "-o", "-", str(plist_path), capture=True)
    return plistlib.loads(result.stdout)

def plist_dump(data: Any, file_path: Path) -> None:
    """Write data as binary plist."""
    with file_path.open("wb") as f:
        plistlib.dump(data, f)

def plist_loads_from_string(content: str) -> Any:
    """Parse a plist from a string (XML format)."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".plist", delete=False) as tf:
        tf.write(content)
        tf.flush()
        return plist_load(Path(tf.name))

def move_merge_replace(src: Path, dest_dir: Path) -> None:
    """Move src into dest_dir, merging directories if needed."""
    dest = dest_dir / src.name
    if src == dest:
        return
    dest_dir.mkdir(exist_ok=True, parents=True)
    if src.is_dir():
        shutil.copytree(src, dest, dirs_exist_ok=True)
        shutil.rmtree(src)
    else:
        shutil.copy2(src, dest)
        src.unlink()

# ----------------------------------------------------------------------
# Subprocess wrappers for common tools
# ----------------------------------------------------------------------
def extract_zip(archive: Path, dest: Path) -> None:
    run_cmd("unzip", "-o", str(archive), "-d", str(dest))

def archive_zip(content_dir: Path, output: Path) -> None:
    run_cmd("zip", "-r", str(output.resolve()), ".", cwd=content_dir)

def extract_tar(archive: Path, dest: Path) -> None:
    run_cmd("tar", "-x", "-f", str(archive), "-C", str(dest))

def security_import(cert_path: Path, cert_password: str, keychain_name: str) -> List[str]:
    """Import a PKCS#12 certificate into a newly created keychain. Returns common names."""
    password = DEFAULT_KEYCHAIN_PASSWORD
    # Create and unlock keychain
    run_cmd("security", "create-keychain", "-p", password, keychain_name)
    run_cmd("security", "unlock-keychain", "-p", password, keychain_name)
    run_cmd("security", "set-keychain-settings", keychain_name)
    # Add to search list
    current = decode_clean(run_cmd("security", "list-keychains", "-d", "user").stdout).split()
    current = [c.strip('"') for c in current if keychain_name not in c]
    run_cmd("security", "list-keychains", "-d", "user", "-s", *current, keychain_name)
    # Import
    run_cmd("security", "import", str(cert_path), "-P", cert_password, "-A", "-k", keychain_name)
    run_cmd(
        "security",
        "set-key-partition-list",
        "-S",
        "apple-tool:,apple:,codesign:",
        "-s",
        "-k",
        password,
        keychain_name,
    )
    # Extract common names
    out = decode_clean(run_cmd("security", "find-identity", "-p", "appleID", "-v", keychain_name).stdout)
    return re.findall(r'"(.*?)"', out)

def security_remove_keychain(keychain_name: str) -> None:
    """Delete a keychain and remove it from the search list."""
    current = decode_clean(run_cmd("security", "list-keychains", "-d", "user").stdout).split()
    current = [c.strip('"') for c in current if keychain_name not in c]
    run_cmd("security", "list-keychains", "-d", "user", "-s", *current)
    run_cmd("security", "delete-keychain", keychain_name)

def get_otool_imports(binary: Path) -> List[str]:
    """List dynamic library dependencies of a Mach‑O binary."""
    out = decode_clean(run_cmd("otool", "-L", str(binary)).stdout).splitlines()[1:]
    results = []
    for line in out:
        m = re.search(r"(.+)\s\(.+\)", line.strip())
        if not m:
            raise SigningError(f"Failed to parse otool output: {line}")
        results.append(m.group(1))
    return results

def install_name_change(binary: Path, old: Path, new: Path) -> None:
    run_cmd("install_name_tool", "-change", str(old), str(new), str(binary))

def insert_dylib(binary: Path, dylib_path: Path) -> None:
    run_cmd("./insert_dylib", "--inplace", "--no-strip-codesig", "--all-yes", str(dylib_path), str(binary))

def codesign_async(identity: str, target: Path, entitlements: Optional[Path] = None) -> Popen:
    """Start codesign asynchronously."""
    cmd = ["codesign", "--continue", "-f", "--no-strict", "-s", identity]
    if entitlements:
        cmd.extend(["--entitlements", str(entitlements)])
    return run_cmd_async(*cmd, str(target))

def popen_check(proc: Popen) -> None:
    """Wait for a process and raise SubprocessError if it failed."""
    proc.wait()
    if proc.returncode != 0:
        stdout = decode_clean(proc.stdout.read() if proc.stdout else b"")
        stderr = decode_clean(proc.stderr.read() if proc.stderr else b"")
        raise SubprocessError(f"{proc.args} failed: {stdout} {stderr}")

def binary_replace(binary: Path, replacements: Dict[str, str]) -> None:
    """Replace all occurrences of old strings with new strings (same length) in a binary file."""
    if not replacements:
        return
    # Use a single perl invocation for all replacements
    expr = ";".join(f"s/{re.escape(old)}/{re.escape(new)}/g" for old, new in replacements.items())
    run_cmd("perl", "-p", "-i", "-e", expr, str(binary))

def security_dump_provisioning_profile(prov_path: Path) -> str:
    """Extract the embedded plist from a .mobileprovision file."""
    return decode_clean(run_cmd("security", "cms", "-D", "-i", str(prov_path)).stdout)

def dump_provisioning_profile(prov_path: Path) -> Dict[str, Any]:
    """Load the plist inside a provisioning profile."""
    return plistlib.loads(security_dump_provisioning_profile(prov_path).encode())

def codesign_dump_entitlements(binary: Path) -> Dict[str, Any]:
    """Extract entitlements from a signed binary."""
    out = decode_clean(
        run_cmd("codesign", "--no-strict", "-d", "--entitlements", "-", "--xml", str(binary)).stdout
    )
    return plist_loads_from_string(out)

# ----------------------------------------------------------------------
# Tweak injection
# ----------------------------------------------------------------------
def inject_tweaks(app_dir: Path, tweaks_dir: Path) -> None:
    """Inject tweaks (deb, zip, tar) into the app bundle."""
    main_app = get_main_app_path(app_dir)
    info_plist = get_info_plist_path(main_app)
    info = plist_load(info_plist)
    app_bundle_id = info["CFBundleIdentifier"]
    app_binary_name = info["CFBundleExecutable"]
    is_mac = info_plist.parent.name == "Contents"

    if is_mac:
        base_dir = info_plist.parent
        app_binary = base_dir / "MacOS" / app_binary_name
        base_load_path = Path("@executable_path") / ".."
    else:
        base_dir = main_app
        app_binary = base_dir / app_binary_name
        base_load_path = Path("@executable_path")

    with tempfile.TemporaryDirectory() as tmp:
        staging = Path(tmp)

        # Extract all tweaks into staging
        for tweak in safe_glob(tweaks_dir, "*"):
            logger.info("Processing tweak: %s", tweak.name)
            if tweak.suffix == ".zip":
                extract_zip(tweak, staging)
            elif tweak.suffix == ".tar":
                extract_tar(tweak, staging)
            elif tweak.suffix == ".deb":
                extract_deb(app_binary.name, app_bundle_id, tweak, staging)
            else:
                move_merge_replace(tweak, staging)

        # Move known bundle types to correct subdirectories
        move_map = {"Frameworks": ["*.framework", "*.dylib"], "PlugIns": ["*.appex"]}
        for dest_sub, patterns in move_map.items():
            dest = staging / dest_sub
            for pat in patterns:
                for f in safe_glob(staging, pat):
                    move_merge_replace(f, dest)

        # Support libraries (libsubstrate, etc.) – copy if needed
        support_libs = {Path("./libsubstrate"): ["libsubstrate.dylib", "CydiaSubstrate"]}
        aliases = {"libsubstitute.0.dylib": "libsubstitute.dylib", "CydiaSubstrate": "libsubstrate.dylib"}

        # First pass: detect required support libs
        binary_map = {p.name: p for p in safe_glob(staging, "**/*") if file_is_macho(p)}
        for binary in binary_map.values():
            for link in get_otool_imports(binary):
                link_name = Path(link).name
                if link_name in aliases:
                    link_name = aliases[link_name]
                for lib_dir, lib_names in support_libs.items():
                    if link_name not in lib_names:
                        continue
                    logger.info("Detected dependency on %s", lib_dir.name)
                    for lib_src in safe_glob(lib_dir, "*"):
                        lib_dest = staging / "Frameworks" / lib_src.name
                        if not lib_dest.exists():
                            logger.info("Installing %s", lib_src.name)
                            lib_dest.parent.mkdir(exist_ok=True, parents=True)
                            shutil.copy2(lib_src, lib_dest)

        # Refresh binary map after adding libraries
        binary_map = {p.name: p for p in safe_glob(staging, "**/*") if file_is_macho(p)}

        # Relink dependencies
        for binary in binary_map.values():
            for link in get_otool_imports(binary):
                link_path = Path(link)
                link_name = aliases.get(link_path.name, link_path.name)
                if link_name in binary_map:
                    fixed = base_load_path / binary_map[link_name].relative_to(staging)
                    logger.info("Re‑linking %s -> %s", binary, fixed)
                    install_name_change(binary, link_path, fixed)

        # Inject libraries into main binary
        for binary_path in binary_map.values():
            rel = binary_path.relative_to(staging)
            if (len(rel.parts) == 2 and rel.parent.name == "Frameworks") or (
                len(rel.parts) == 3 and rel.parent.suffix == ".framework" and rel.parent.parent.name == "Frameworks"
            ):
                fixed = base_load_path / rel
                logger.info("Injecting %s into %s", binary_path, fixed)
                insert_dylib(app_binary, fixed)

        # Move everything into the app bundle
        for item in safe_glob(staging, "*"):
            move_merge_replace(item, base_dir)

def extract_deb(binary_name: str, bundle_id: str, deb_path: Path, dest: Path) -> None:
    """Extract a .deb file, handling rootless and filtering by bundle/executable filters."""
    with tempfile.TemporaryDirectory() as td1, tempfile.TemporaryDirectory() as td2:
        ar_dir = Path(td1)
        data_dir = Path(td2)

        run_cmd("ar", "x", str(deb_path.resolve()), cwd=ar_dir)
        data_tar = next(safe_glob(ar_dir, "data.tar*"), None)
        if not data_tar:
            raise SigningError(f"No data.tar* found in {deb_path}")
        extract_tar(data_tar, data_dir)

        # Handle rootless jailbreak layout (var/jb)
        rootless = data_dir / "var" / "jb"
        if rootless.is_dir():
            data_dir = rootless

        # Copy relevant files, respecting .plist filters
        for glob_pat in [
            "Library/Application Support/*/*.bundle",
            "Library/Application Support/*",
            "Library/Frameworks/*.framework",
            "usr/lib/*.framework",
            "Library/MobileSubstrate/DynamicLibraries/*.dylib",
            "usr/lib/*.dylib",
        ]:
            for f in safe_glob(data_dir, glob_pat):
                if f.is_dir() and not any(safe_glob(f, "*")):
                    continue  # empty directory
                if f.suffix == ".dylib":
                    plist_path = f.parent / (f.stem + ".plist")
                    if plist_path.exists():
                        filter_info = plist_load(plist_path)
                        ok = False
                        if "Filter" in filter_info:
                            if "Bundles" in filter_info["Filter"] and bundle_id in filter_info["Filter"]["Bundles"]:
                                ok = True
                            if "Executables" in filter_info["Filter"] and binary_name in filter_info["Filter"]["Executables"]:
                                ok = True
                        if not ok:
                            continue
                move_merge_replace(f, dest)

def file_is_macho(path: Path) -> bool:
    """Return True if `file` reports Mach‑O."""
    out = decode_clean(run_cmd("file", str(path)).stdout)
    return "Mach-O" in out

def get_info_plist_path(app_dir: Path) -> Path:
    """Return the nearest Info.plist (usually the one inside the .app)."""
    candidates = list(safe_glob(app_dir, "**/Info.plist"))
    if not candidates:
        raise SigningError(f"No Info.plist found in {app_dir}")
    return min(candidates, key=lambda p: len(str(p)))

def get_main_app_path(container: Path) -> Path:
    """Return the main .app bundle inside the container."""
    candidates = list(safe_glob(container, "**/*.app"))
    if not candidates:
        raise SigningError(f"No .app bundle found in {container}")
    return min(candidates, key=lambda p: len(str(p)))

# ----------------------------------------------------------------------
# Fastlane integration
# ----------------------------------------------------------------------
def fastlane_auth(username: str, password: str, team_id: str, job_id: str, secret_url: str) -> None:
    """Authenticate with Apple using fastlane spaceauth, handling 2FA via web service."""
    env = os.environ.copy()
    env.update({"FASTLANE_USER": username, "FASTLANE_PASSWORD": password, "FASTLANE_TEAM_ID": team_id})

    proc = subprocess.Popen(
        ["fastlane", "spaceauth", "--copy_to_clipboard"],
        stdin=PIPE,
        stdout=PIPE,
        stderr=PIPE,
        env=env,
    )

    start = time.time()
    while True:
        if time.time() - start > 60:
            proc.kill()
            raise SigningError("Authentication timed out after 60 seconds")
        ret = proc.poll()
        if ret == 0:
            logger.info("Fastlane authentication successful")
            return
        if ret is not None:
            stdout, stderr = proc.communicate()
            raise SigningError(f"Fastlane auth failed: {decode_clean(stdout)} {decode_clean(stderr)}")

        # Check for 2FA code via web service
        twofa_file = Path("account_2fa.txt")
        result = curl_with_auth(f"{secret_url}/jobs/{job_id}/2fa", output=twofa_file, check=False)
        if result.returncode == 0 and twofa_file.exists():
            code = read_text(twofa_file).strip()
            if code:
                proc.stdin.write((code + "\n").encode())
                proc.stdin.flush()
        time.sleep(1)

def fastlane_register_app(
    username: str, password: str, team_id: str, bundle_id: str, entitlements: Dict[str, Any]
) -> None:
    """Create/update app ID and enable required services on Apple Developer portal."""
    env = os.environ.copy()
    env.update({"FASTLANE_USER": username, "FASTLANE_PASSWORD": password, "FASTLANE_TEAM_ID": team_id})

    # Create app ID (no‑op if exists)
    run_cmd(
        "fastlane", "produce", "create", "--skip_itc",
        "--app_identifier", bundle_id,
        "--app-name", clean_name(f"ST {bundle_id}"),
        env=env,
    )

    # Disable all services first
    all_services = [
        "--push-notification", "--health-kit", "--home-kit", "--wireless-accessory",
        "--inter-app-audio", "--extended-virtual-address-space", "--multipath",
        "--network-extension", "--personal-vpn", "--access-wifi", "--nfc-tag-reading",
        "--siri-kit", "--associated-domains", "--icloud", "--app-group",
    ]
    run_cmd("fastlane", "produce", "disable_services", "--skip_itc", "--app_identifier", bundle_id, *all_services, env=env)

    # Map entitlements to service flags
    service_map = {
        "aps-environment": ("--push-notification",),
        "com.apple.developer.aps-environment": ("--push-notification",),
        "com.apple.developer.healthkit": ("--health-kit",),
        "com.apple.developer.homekit": ("--home-kit",),
        "com.apple.external-accessory.wireless-configuration": ("--wireless-accessory",),
        "inter-app-audio": ("--inter-app-audio",),
        "com.apple.developer.kernel.extended-virtual-addressing": ("--extended-virtual-address-space",),
        "com.apple.developer.networking.multipath": ("--multipath",),
        "com.apple.developer.networking.networkextension": ("--network-extension",),
        "com.apple.developer.networking.vpn.api": ("--personal-vpn",),
        "com.apple.developer.networking.wifi-info": ("--access-wifi",),
        "com.apple.developer.nfc.readersession.formats": ("--nfc-tag-reading",),
        "com.apple.developer.siri": ("--siri-kit",),
        "com.apple.developer.associated-domains": ("--associated-domains",),
    }
    icloud_keys = {
        "com.apple.developer.icloud-container-development-container-identifiers",
        "com.apple.developer.icloud-container-identifiers",
        "com.apple.developer.ubiquity-container-identifiers",
        "com.apple.developer.ubiquity-kvstore-identifier",
    }
    group_keys = {"com.apple.security.application-groups"}

    flags = set()
    for key in entitlements:
        if key in service_map:
            flags.update(service_map[key])
        elif key in icloud_keys:
            flags.update(("--icloud", "xcode6_compatible"))
        elif key in group_keys:
            flags.add("--app-group")

    if flags:
        logger.info("Enabling services: %s", flags)
        run_cmd("fastlane", "produce", "enable_services", "--skip_itc", "--app_identifier", bundle_id, *flags, env=env)

    # Register app groups and cloud containers
    def register_extras(extra_type: str, prefix: str, match_keys: List[str]) -> None:
        ids: Set[str] = set()
        for key in match_keys:
            val = entitlements.get(key)
            if isinstance(val, list):
                ids.update(val)
            elif isinstance(val, str):
                ids.add(val)
        if not ids:
            return
        # Ensure prefix is correct
        ids = {id if id.startswith(prefix) else prefix + id[id.index(".")+1:] for id in ids}
        with ThreadPool(len(ids)) as pool:
            pool.map(lambda i: run_cmd(
                "fastlane", "produce", extra_type, "--skip_itc", "-g", i,
                "--app-name", clean_name(f"ST {i}"), env=env
            ), ids)
        run_cmd("fastlane", "produce", f"associate_{extra_type}", "--skip_itc",
                "--app_identifier", bundle_id, *ids, env=env)

    register_extras("group", "group.", list(group_keys))
    register_extras("cloud_container", "iCloud.", list(icloud_keys))

def fastlane_get_provisioning_profile(
    username: str, password: str, team_id: str, bundle_id: str, prov_type: str, platform: str, output: Path
) -> None:
    """Download a provisioning profile using fastlane sigh."""
    env = os.environ.copy()
    env.update({"FASTLANE_USER": username, "FASTLANE_PASSWORD": password, "FASTLANE_TEAM_ID": team_id})

    with tempfile.TemporaryDirectory() as td:
        tmpdir = Path(td)
        run_cmd(
            "fastlane", "sigh", "renew",
            "--app_identifier", bundle_id,
            "--provisioning_name", clean_name(f"ST {bundle_id} {prov_type}"),
            "--force", "--skip_install", "--include_mac_in_profiles",
            "--platform", platform,
            f"--{prov_type}",
            "--output_path", str(tmpdir),
            "--filename", "prov.mobileprovision",
            env=env,
        )
        shutil.copy2(tmpdir / "prov.mobileprovision", output)

def clean_name(name: str) -> str:
    """Replace non‑alphanumeric characters with spaces."""
    return re.sub(r"[^0-9a-zA-Z]+", " ", name).strip()

# ----------------------------------------------------------------------
# HTTP helpers
# ----------------------------------------------------------------------
def curl_with_auth(
    url: str, form_data: Optional[List[Tuple[str, str]]] = None, output: Optional[Path] = None, check: bool = True
) -> subprocess.CompletedProcess:
    """Perform a curl request with bearer token authentication."""
    args = ["curl", "-S", "-f", "-L", "-H", f"Authorization: Bearer {secret_key}"]
    if form_data:
        for k, v in form_data:
            args.extend(["-F", f"{k}={v}"])
    if output:
        args.extend(["-o", str(output)])
    args.append(url)
    return run_cmd(*args, check=check)

def node_upload(file_path: Path, endpoint: str) -> None:
    """Upload a file using the Node.js upload script."""
    run_cmd("node", "node-utils/upload.js", str(file_path), endpoint, secret_key)

def node_download(url: str, output: Path) -> None:
    """Download a file using the Node.js download script."""
    run_cmd("node", "node-utils/download.js", url, secret_key, str(output))

# ----------------------------------------------------------------------
# Signing orchestrator
# ----------------------------------------------------------------------
@dataclass
class SigningOptions:
    app_dir: Path
    common_name: str
    team_id: str
    account_name: str
    account_pass: str
    prov_file: Optional[Path]
    bundle_id: Optional[str]          # None = keep original, "" = use prov app id
    bundle_name: Optional[str]
    patch_debug: bool
    patch_all_devices: bool
    patch_mac: bool
    patch_file_sharing: bool
    encode_ids: bool
    patch_ids: bool
    force_original_id: bool

@dataclass
class ComponentData:
    old_bundle_id: str
    new_bundle_id: str
    entitlements: Dict[str, Any]
    info_plist: Path

class AppSigner:
    def __init__(self, opts: SigningOptions, job_id: str, secret_url: str):
        self.opts = opts
        self.job_id = job_id
        self.secret_url = secret_url
        self.main_app = get_main_app_path(opts.app_dir)
        self.main_info_plist = get_info_plist_path(self.main_app)
        self.main_info = plist_load(self.main_info_plist)
        self.old_main_bundle_id = self.main_info["CFBundleIdentifier"]
        self.is_mac = self.main_info_plist.parent.name == "Contents"
        self.is_distribution = "Distribution" in opts.common_name

        if self.is_distribution and self.is_mac:
            raise ConfigurationError("Distribution certificate cannot be used for macOS ad‑hoc signing.")

        # Determine final bundle ID
        if opts.prov_file:
            if opts.bundle_id is None:
                self.main_bundle_id = self.old_main_bundle_id
            elif opts.bundle_id == "":
                prov_app_id = dump_provisioning_profile(opts.prov_file)["Entitlements"][self._app_id_key()]
                self.main_bundle_id = prov_app_id.split(".", 1)[1]
                if self.main_bundle_id == "*":
                    self.main_bundle_id = self.old_main_bundle_id
            else:
                self.main_bundle_id = opts.bundle_id
        else:
            if opts.bundle_id:
                self.main_bundle_id = opts.bundle_id
            elif opts.encode_ids:
                self.main_bundle_id = self._gen_id(self.old_main_bundle_id)
                if self.old_main_bundle_id != self.main_bundle_id:
                    self.mappings[self.old_main_bundle_id] = self.main_bundle_id
            else:
                self.main_bundle_id = self.old_main_bundle_id

        if opts.bundle_name:
            self.main_info["CFBundleDisplayName"] = opts.bundle_name
            plist_dump(self.main_info, self.main_info_plist)

        if opts.patch_all_devices:
            if self.is_mac:
                self.main_info["LSMinimumSystemVersion"] = "10.0"
            else:
                self.main_info["MinimumOSVersion"] = "3.0"
            plist_dump(self.main_info, self.main_info_plist)

        # Remove Watch placeholder
        for watch in ["com.apple.WatchPlaceholder", "Watch"]:
            watch_dir = self.main_app / watch
            if watch_dir.exists():
                shutil.rmtree(watch_dir)

        # Order components: deepest first (so that nested components are signed before their container)
        patterns = ["*.app", "*.appex", "*.framework", "*.dylib", "PlugIns/*.bundle"]
        self.components = []
        for pat in patterns:
            self.components.extend(safe_glob(self.main_app, "**/" + pat))
        self.components = sorted(set(self.components), key=lambda p: len(p.parts), reverse=True)
        self.components.append(self.main_app)   # main app last

        self.mappings: Dict[str, str] = {}
        self.removed_entitlements: Set[str] = set()

    def _gen_id(self, input_id: str) -> str:
        if not self.opts.encode_ids or not input_id.strip():
            return input_id
        parts = [rand_str(len(p), p + self.opts.team_id) for p in input_id.split(".")]
        return ".".join(parts)

    def _app_id_key(self) -> str:
        return "com.apple.application-identifier" if self.is_mac else "application-identifier"

    def _aps_env_key(self) -> str:
        return "com.apple.developer.aps-environment" if self.is_mac else "aps-environment"

    def _prepare_primary(self, component: Path) -> ComponentData:
        """Extract bundle ID, entitlements, and prepare mapping for a primary component (.app or .appex)."""
        info_plist = get_info_plist_path(component)
        info = plist_load(info_plist)
        old_id = info["CFBundleIdentifier"]
        # Build new ID by replacing the main bundle prefix
        new_id = f"{self.main_bundle_id}{old_id[len(self.old_main_bundle_id):]}"
        if not self.opts.force_original_id and old_id != new_id:
            if len(old_id) != len(new_id):
                logger.warning("Component %s: bundle ID length mismatch – may cause crashes", component.name)
            else:
                self.mappings[old_id] = new_id

        # Read existing entitlements
        try:
            old_ent = codesign_dump_entitlements(component)
        except Exception:
            logger.warning("Failed to dump entitlements for %s, using empty", component.name)
            old_ent = {}

        # Remap team ID if needed
        old_team = old_ent.get("com.apple.developer.team-identifier")
        if old_team and old_team != self.opts.team_id:
            if len(old_team) == len(self.opts.team_id):
                self.mappings[old_team] = self.opts.team_id
        # Remap app ID prefix (old bundle seed ID)
        app_id_val = old_ent.get(self._app_id_key(), "")
        if "." in app_id_val:
            old_prefix = app_id_val.split(".", 1)[0]
            if old_prefix != self.opts.team_id and len(old_prefix) == len(self.opts.team_id):
                self.mappings[old_prefix] = self.opts.team_id

        if self.opts.prov_file:
            # Use entitlements from provisioning profile
            prov_ent = dump_provisioning_profile(self.opts.prov_file)["Entitlements"]
            prov_app_id = prov_ent.get(self._app_id_key(), "")
            wildcard = f"{self.opts.team_id}.*"
            if prov_app_id == wildcard:
                prov_ent[self._app_id_key()] = f"{self.opts.team_id}.{new_id}"
            elif prov_app_id != f"{self.opts.team_id}.{new_id}":
                logger.warning("Provisioning profile app ID %s does not match component %s – some features may break",
                               prov_app_id, new_id)
            # Keychain access groups wildcard expansion
            keychain_groups = prov_ent.get("keychain-access-groups")
            if keychain_groups and any(g == wildcard for g in keychain_groups):
                new_groups = []
                old_groups = old_ent.get("keychain-access-groups", [])
                for old_group in old_groups:
                    suffix = old_group.split(".", 1)[1] if "." in old_group else old_group
                    new_groups.append(f"{self.opts.team_id}.{suffix}")
                prov_ent["keychain-access-groups"] = new_groups
            entitlements = prov_ent
        else:
            # Start from existing entitlements, filter and adjust
            entitlements = {k: v for k, v in old_ent.items() if k in SUPPORTED_ENTITLEMENTS}
            removed = set(old_ent.keys()) - set(entitlements.keys())
            if removed:
                self.removed_entitlements.update(removed)
                logger.info("Removed unsupported entitlements: %s", removed)

            # Set environment‑sensitive values
            if self._aps_env_key() in entitlements:
                entitlements[self._aps_env_key()] = "production" if self.is_distribution else "development"
            if "get-task-allow" in entitlements:
                entitlements["get-task-allow"] = False if self.is_distribution else True
            if "com.apple.developer.icloud-container-environment" in entitlements:
                entitlements["com.apple.developer.icloud-container-environment"] = "Production" if self.is_distribution else "Development"

            # Set team ID and application identifier
            entitlements["com.apple.developer.team-identifier"] = self.opts.team_id
            entitlements[self._app_id_key()] = f"{self.opts.team_id}.{new_id}"

            # Remap IDs inside entitlements if encoding is enabled
            if self.opts.encode_ids:
                # Define remapping rules
                remap_rules = [
                    (["com.apple.security.application-groups"], "group.", False, True),
                    (["com.apple.developer.icloud-container-identifiers",
                      "com.apple.developer.ubiquity-container-identifiers",
                      "com.apple.developer.icloud-container-development-container-identifiers"], "iCloud.", False, True),
                    (["keychain-access-groups"], self.opts.team_id + ".", True, True),
                    (["com.apple.developer.ubiquity-kvstore-identifier"], self.opts.team_id + ".", False, False),
                ]
                for keys, prefix, prefix_only, is_list in remap_rules:
                    for key in keys:
                        val = entitlements.get(key)
                        if val is None:
                            continue
                        if isinstance(val, str):
                            val = [val]
                        new_vals = []
                        for item in val:
                            # Remove original prefix if present
                            rest = item[len(prefix):] if item.startswith(prefix) else item
                            if prefix_only:
                                new_id = prefix + rest
                            else:
                                new_id = prefix + self._gen_id(rest)
                                self.mappings[prefix + rest] = new_id
                            new_vals.append(new_id)
                        entitlements[key] = new_vals if is_list else new_vals[0]

        return ComponentData(old_bundle_id=old_id, new_bundle_id=new_id,
                             entitlements=entitlements, info_plist=info_plist)

    def _sign_secondary(self, component: Path) -> Popen:
        """Sign a framework/dylib (entitlements are ignored)."""
        logger.info("Signing secondary component: %s", component)
        return codesign_async(self.opts.common_name, component)

    def _sign_primary(self, component: Path, data: ComponentData, tmpdir: Path) -> Popen:
        """Sign an app or appex with proper entitlements and provisioning profile."""
        info = plist_load(data.info_plist)
        if self.opts.force_original_id:
            info["CFBundleIdentifier"] = data.old_bundle_id
        else:
            info["CFBundleIdentifier"] = data.new_bundle_id

        # Apply patches
        if self.opts.patch_debug:
            data.entitlements["get-task-allow"] = True
        else:
            data.entitlements.pop("get-task-allow", None)

        if not self.is_mac:
            if self.opts.patch_all_devices:
                info.pop("UISupportedDevices", None)
                info["UIDeviceFamily"] = [1, 2, 3, 4]   # iPhone, iPad, tvOS, watchOS
            if self.opts.patch_mac:
                info.pop("UIRequiresFullScreen", None)
                for dev in ["ipad", "iphone", "ipod"]:
                    info.pop(f"UISupportedInterfaceOrientations~{dev}", None)
                info["UISupportedInterfaceOrientations"] = [
                    "UIInterfaceOrientationPortrait",
                    "UIInterfaceOrientationPortraitUpsideDown",
                    "UIInterfaceOrientationLandscapeLeft",
                    "UIInterfaceOrientationLandscapeRight",
                ]
            if self.opts.patch_file_sharing:
                info["UIFileSharingEnabled"] = True
                info["UISupportsDocumentBrowser"] = True

        plist_dump(info, data.info_plist)

        # Install provisioning profile
        embedded_name = "embedded.provisionprofile" if self.is_mac else "embedded.mobileprovision"
        embedded_path = data.info_plist.parent / embedded_name
        if self.opts.prov_file:
            shutil.copy2(self.opts.prov_file, embedded_path)
        else:
            logger.info("Registering %s with Apple Developer Portal", data.new_bundle_id)
            fastlane_register_app(
                self.opts.account_name, self.opts.account_pass, self.opts.team_id,
                data.new_bundle_id, data.entitlements
            )
            prov_type = "adhoc" if self.is_distribution else "development"
            platform = "macos" if self.is_mac else "ios"
            fastlane_get_provisioning_profile(
                self.opts.account_name, self.opts.account_pass, self.opts.team_id,
                data.new_bundle_id, prov_type, platform, embedded_path
            )

        # Write entitlements to temporary file
        ent_file = tmpdir / f"{component.stem}_ent.plist"
        with ent_file.open("wb") as f:
            plistlib.dump(data.entitlements, f)

        logger.info("Signing primary component: %s", component)
        return codesign_async(self.opts.common_name, component, ent_file)

    def sign(self) -> None:
        """Perform the complete signing process."""
        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp)

            # Prepare all components
            jobs: List[Tuple[Path, Optional[ComponentData]]] = []
            for comp in self.components:
                if comp.suffix in {".app", ".appex"}:
                    data = self._prepare_primary(comp)
                    jobs.append((comp, data))
                else:
                    jobs.append((comp, None))

            # Output mapping info
            logger.info("ID mappings: %s", self.mappings)
            logger.info("Removed entitlements: %s", self.removed_entitlements)

            # Authenticate with Apple if needed
            if not self.opts.prov_file:
                logger.info("Authenticating with Apple Developer Portal...")
                fastlane_auth(self.opts.account_name, self.opts.account_pass,
                              self.opts.team_id, self.job_id, self.secret_url)

            # Sign components in order, waiting for dependencies
            active: Dict[Path, Popen] = {}
            for comp, data in jobs:
                # Wait for any sub‑component that is still signing
                for path in list(active.keys()):
                    try:
                        path.relative_to(comp)
                    except ValueError:
                        continue
                    if active[path].poll() is None:
                        logger.debug("Waiting for %s to finish signing", path)
                        active[path].wait()
                    popen_check(active[path])
                    del active[path]

                # Remove SC_Info (App Store metadata)
                sc_info = comp / "SC_Info"
                if sc_info.exists():
                    logger.warning("Removing SC_Info from %s – app may be encrypted and fail to launch", comp)
                    shutil.rmtree(sc_info)

                # Patch binary strings if requested
                if self.opts.patch_ids and self.mappings:
                    # Only use same‑length replacements
                    same_len = {k: v for k, v in self.mappings.items() if len(k) == len(v)}
                    if same_len:
                        targets = []
                        if comp.is_file():
                            targets.append(comp)
                        elif (comp / comp.stem).is_file():
                            targets.append(comp / comp.stem)
                        if data:
                            targets.append(data.info_plist)
                        for tgt in targets:
                            logger.info("Patching %d patterns in %s", len(same_len), tgt)
                            binary_replace(tgt, same_len)

                # Sign
                if data is not None:
                    active[comp] = self._sign_primary(comp, data, workdir)
                else:
                    active[comp] = self._sign_secondary(comp)

            # Wait for remaining jobs
            for proc in active.values():
                proc.wait()
                popen_check(proc)

# ----------------------------------------------------------------------
# Main workflow
# ----------------------------------------------------------------------
def run_main(secret_url: str, secret_key: str) -> None:
    """Main entry point, orchestrates download, tweak injection, signing, and upload."""
    # 1. Install Node dependencies
    logger.info("Installing Node dependencies")
    run_cmd("npm", "install", cwd="node-utils")

    # 2. Download job archive
    logger.info("Downloading job archive")
    job_tar = Path("job.tar")
    node_download(f"{secret_url}/jobs", job_tar)
    extract_tar(job_tar, Path("."))
    job_tar.unlink()

    # 3. Read job parameters
    cert_pass = read_text(Path("cert_pass.txt"))
    sign_args = read_text(Path("args.txt"))
    job_id = read_text(Path("id.txt"))
    user_bundle_id = read_text(Path("user_bundle_id.txt")).strip() or None
    team_id = read_text(Path("team_id.txt"))
    account_name = read_text(Path("account_name.txt")) if Path("account_name.txt").exists() else ""
    account_pass = read_text(Path("account_pass.txt")) if Path("account_pass.txt").exists() else ""
    prov_profile = Path("prov.mobileprovision") if Path("prov.mobileprovision").exists() else None
    bundle_name = read_text(Path("bundle_name.txt")) if Path("bundle_name.txt").exists() else None

    # 4. Download unsigned IPA
    logger.info("Downloading unsigned IPA")
    unsigned_ipa = Path("unsigned.ipa")
    node_download(f"{secret_url}/jobs/{job_id}/unsigned", unsigned_ipa)

    # 5. Create temporary keychain and import certificate
    keychain_name = f"ios-signer-{rand_str(8)}"
    logger.info("Creating keychain: %s", keychain_name)
    common_names = security_import(Path("cert.p12"), cert_pass, keychain_name)
    if not common_names:
        raise ConfigurationError("No valid code signing certificate found")

    # Choose certificate (Distribution > Development)
    common_name = None
    if "Distribution" in " ".join(common_names):
        common_name = next((n for n in common_names if "Distribution" in n), None)
        if "-d" in sign_args:
            raise ConfigurationError("Debugging cannot be enabled with a distribution certificate")
        logger.info("Using distribution certificate: %s", common_name)
    else:
        common_name = next((n for n in common_names if "Development" in n), None)
        if not common_name:
            raise ConfigurationError("No Development or Distribution certificate found")
        logger.info("Using development certificate: %s", common_name)

    # 6. Extract and optionally inject tweaks
    with tempfile.TemporaryDirectory() as tmp:
        app_dir = Path(tmp)
        logger.info("Extracting IPA")
        extract_zip(unsigned_ipa, app_dir)

        tweaks_dir = Path("tweaks")
        if tweaks_dir.exists():
            logger.info("Injecting tweaks")
            inject_tweaks(app_dir, tweaks_dir)

        # 7. Sign
        logger.info("Signing application")
        signer = AppSigner(
            SigningOptions(
                app_dir=app_dir,
                common_name=common_name,
                team_id=team_id,
                account_name=account_name,
                account_pass=account_pass,
                prov_file=prov_profile,
                bundle_id=user_bundle_id,
                bundle_name=bundle_name,
                patch_debug="-d" in sign_args,
                patch_all_devices="-a" in sign_args,
                patch_mac="-m" in sign_args,
                patch_file_sharing="-s" in sign_args,
                encode_ids="-e" in sign_args,
                patch_ids="-p" in sign_args,
                force_original_id="-o" in sign_args,
            ),
            job_id=job_id,
            secret_url=secret_url,
        )
        signer.sign()

        # 8. Package signed IPA
        signed_ipa = Path("signed.ipa")
        archive_zip(app_dir, signed_ipa)

    # 9. Upload result
    logger.info("Uploading signed IPA")
    node_upload(signed_ipa, f"{secret_url}/jobs/{job_id}/tus/")
    file_id = read_text(Path("file_id.txt"))
    bundle_id = read_text(Path("bundle_id.txt"))
    curl_with_auth(f"{secret_url}/jobs/{job_id}/signed", [("file_id", file_id), ("bundle_id", bundle_id)])

    logger.info("Signing completed successfully")

# ----------------------------------------------------------------------
# Entry point
# ----------------------------------------------------------------------
if __name__ == "__main__":
    secret_url = os.environ.get("SECRET_URL", "").strip().rstrip("/")
    secret_key = os.environ.get("SECRET_KEY", "").strip()
    if not secret_url or not secret_key:
        logger.error("SECRET_URL and SECRET_KEY must be set")
        sys.exit(1)

    try:
        run_main(secret_url, secret_key)
    except Exception as e:
        logger.exception("Signing failed")
        # Notify failure via web service
        try:
            curl_with_auth(f"{secret_url}/jobs/{job_id}/fail", check=False)
        except NameError:
            pass   # job_id not defined yet
        sys.exit(1)
    finally:
        # Clean up temporary keychain
        try:
            security_remove_keychain(keychain_name)
        except NameError:
            pass
