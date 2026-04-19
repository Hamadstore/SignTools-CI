#!/usr/bin/env python3
import os, sys, re, time, json, shutil, random, string, tempfile, traceback
import subprocess, plistlib, copy
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
from multiprocessing.pool import ThreadPool

# Configuration from Environment
URL = os.getenv("SECRET_URL", "").strip().rstrip("/")
KEY = os.getenv("SECRET_KEY", "")

def run_cmd(*cmd, capture=True, check=True, cwd=None, env=None):
    try:
        res = subprocess.run(cmd, capture_output=capture, check=check, cwd=cwd, env=env or os.environ)
        return res.stdout.decode("utf-8").strip() if capture else res
    except subprocess.CalledProcessError as e:
        print(f"Error: {e.stderr.decode() if e.stderr else e}")
        raise

def get_plist(path: Path): return plistlib.loads(run_cmd("plutil", "-convert", "xml1", "-o", "-", str(path), capture=True).encode())
def save_plist(data: Any, path: Path): 
    with path.open("wb") as f: plistlib.dump(data, f)

def safe_glob(path: Path, pattern: str):
    return [f for f in sorted(path.glob(pattern)) if not f.name.startswith("._") and f.name != ".DS_Store"]

def rand_id(n=8): return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))

def inject_tweaks(app_path: Path, tweaks_path: Path):
    print("-> Injecting Tweaks")
    info = get_plist(next(path for path in safe_glob(app_path, "**/Info.plist")))
    exec_name = info["CFBundleExecutable"]
    is_mac = "Contents" in str(app_path)
    binary = app_path / ("Contents/MacOS" if is_mac else "") / exec_name
    
    for tweak in safe_glob(tweaks_path, "*"):
        if tweak.suffix == ".deb":
            with tempfile.TemporaryDirectory() as td:
                run_cmd("ar", "x", str(tweak.resolve()), cwd=td)
                data_tar = next(Path(td).glob("data.tar*"))
                run_cmd("tar", "-xf", str(data_tar), "-C", td)
                # Move dylibs and frameworks
                for item in safe_glob(Path(td), "**/*.{dylib,framework}"):
                    dest = app_path / ("Contents/Frameworks" if is_mac else "Frameworks")
                    dest.mkdir(exist_ok=True)
                    shutil.move(str(item), str(dest / item.name))
                    if item.suffix == ".dylib":
                        load_path = f"@executable_path/../Frameworks/{item.name}" if is_mac else f"@executable_path/Frameworks/{item.name}"
                        run_cmd("./insert_dylib", "--inplace", "--all-yes", load_path, str(binary))

class Signer:
    def __init__(self, app_dir: Path, cert_name: str, team_id: str, bundle_id: Optional[str]):
        self.app_dir = app_dir
        self.cert = cert_name
        self.team_id = team_id
        self.main_app = min(safe_glob(app_dir, "**/*.app"), key=lambda p: len(str(p)))
        self.info_path = self.main_app / ("Contents/Info.plist" if (self.main_app/"Contents").exists() else "Info.plist")
        self.info = get_plist(self.info_path)
        self.old_id = self.info["CFBundleIdentifier"]
        self.new_id = bundle_id or self.old_id

    def sign_component(self, path: Path, entitlements: Path = None):
        cmd = ["codesign", "-f", "-s", self.cert]
        if entitlements: cmd += ["--entitlements", str(entitlements)]
        run_cmd(*cmd, str(path))

    def process(self):
        # Update IDs
        self.info["CFBundleIdentifier"] = self.new_id
        save_plist(self.info, self.info_path)
        
        # Collect sub-components (depth-first)
        components = [self.main_app]
        for ext in ["**/*.appex", "**/*.framework", "**/*.dylib"]:
            components.extend(safe_glob(self.main_app, ext))
        components.reverse()

        for comp in components:
            print(f"-> Signing: {comp.name}")
            if comp.suffix in [".app", ".appex"]:
                # Basic entitlement dump and swap
                ent_path = comp / "entitlements.plist"
                try:
                    ents = run_cmd("codesign", "-d", "--entitlements", "-", "--xml", str(comp))
                    e_data = plistlib.loads(ents.encode())
                    e_data["application-identifier"] = f"{self.team_id}.{self.new_id}"
                    e_data["com.apple.developer.team-identifier"] = self.team_id
                    save_plist(e_data, ent_path)
                    self.sign_component(comp, ent_path)
                except:
                    self.sign_component(comp)
            else:
                self.sign_component(comp)

def run_main():
    # Setup Paths
    tmp = Path(tempfile.mkdtemp())
    run_cmd("unzip", "-q", "unsigned.ipa", "-d", str(tmp))
    
    # 1. Setup Keychain
    keychain = f"sign-{rand_id()}"
    pw = "123"
    run_cmd("security", "create-keychain", "-p", pw, keychain)
    run_cmd("security", "unlock-keychain", "-p", pw, keychain)
    run_cmd("security", "import", "cert.p12", "-P", Path("cert_pass.txt").read_text().strip(), "-k", keychain, "-A")
    
    cert_common_name = run_cmd("security", "find-identity", "-v", "-p", "codesigning", keychain).split('"')[1]
    team_id = Path("team_id.txt").read_text().strip()
    
    # 2. Tweak Injection
    if Path("tweaks").exists():
        inject_tweaks(tmp, Path("tweaks"))

    # 3. Signing
    user_id = Path("user_bundle_id.txt").read_text().strip() or None
    signer = Signer(tmp, cert_common_name, team_id, user_id)
    signer.process()

    # 4. Repackage
    run_cmd("zip", "-r", "signed.ipa", ".", cwd=str(tmp))
    print("Done! Signed IPA created.")
    
    # Cleanup
    run_cmd("security", "delete-keychain", keychain)
    shutil.rmtree(tmp)

if __name__ == "__main__":
    try:
        run_main()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
