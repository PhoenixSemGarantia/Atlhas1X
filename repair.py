import sys
import argparse
import hashlib
import json
import os
import shutil
import urllib.request
import zipfile
import stat
import subprocess
from pathlib import Path

MANIFEST_FILE = "app_manifest.json"
OFFICIAL_REPO = "PhoenixSemGarantia/Atlhas1X"
TEMP_DIR = "temp/atlhas1x_repair"
BACKUP_DIR = "repair_backup"

def get_version():
    try:
        with open("version.json", "r") as f:
            return json.load(f).get("version", "1.4.0")
    except:
        return "1.4.0"

def get_file_hash(filepath):
    try:
        if not os.path.isfile(filepath):
            return None
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception:
        return "UNREADABLE"

def verify_integrity(manifest_path=MANIFEST_FILE, base_dir="."):
    if not os.path.exists(manifest_path):
        return {"error": "Missing manifest", "problems": {}}
    
    try:
        with open(manifest_path, "r") as f:
            manifest = json.load(f)
    except Exception:
        return {"error": "Invalid manifest", "problems": {}}
        
    problems = {}
    files_checked = 0
    for file, expected_hash in manifest.get("files", {}).items():
        files_checked += 1
        full_path = os.path.join(base_dir, file)
        if not os.path.exists(full_path):
            problems[file] = "MISSING"
        else:
            actual_hash = get_file_hash(full_path)
            if actual_hash == "UNREADABLE":
                problems[file] = "UNREADABLE"
            elif actual_hash != expected_hash:
                problems[file] = "HASH_MISMATCH"
                
    return {"error": None, "problems": problems, "checked": files_checked, "manifest": manifest}

def create_fix_bat():
    if not os.path.exists("FixAtlhas1x.bat"):
        with open("FixAtlhas1x.bat", "w") as f:
            f.write("@echo off\npython repair.py --interactive\npause\n")

def check_and_prompt():
    res = verify_integrity()
    if res["error"] or res["problems"]:
        create_fix_bat()
        print("\nAtlhas1x detected a problem with its installation.")
        num_problems = len(res["problems"]) if not res["error"] else "several"
        print(f"\n{num_problems} application files require repair.\n")
        print("Would you like to repair Atlhas1x?\n")
        print("[Y] Repair")
        print("[N] Continue if possible")
        try:
            choice = input("\nChoice: ").strip().lower()
        except:
            choice = "n"
            
        if choice == "y":
            print("\nPlease run FixAtlhas1x.bat to repair the installation.")
            sys.exit(1)
        else:
            print("\nAtlhas1x cannot start correctly until these files are repaired.")
            # We let it return False so Atlhas1x.bat can continue, but it might crash.
            return False
    else:
        print("Integrity check: OK")
    return True

def safe_extract(zip_ref, dest_dir, prefix):
    # Protect against path traversal and only extract files within prefix
    for member in zip_ref.namelist():
        if not member.startswith(prefix) or member.endswith("/"):
            continue
        
        # Remove prefix
        rel_path = member[len(prefix):]
        # Path traversal checks
        if ".." in rel_path or rel_path.startswith("/") or rel_path.startswith("\\"):
            continue
            
        target_path = os.path.join(dest_dir, rel_path)
        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        with zip_ref.open(member) as source, open(target_path, "wb") as target:
            shutil.copyfileobj(source, target)

def download_and_validate_release(version):
    url = f"https://github.com/{OFFICIAL_REPO}/archive/refs/tags/v{version}.zip"
    os.makedirs(TEMP_DIR, exist_ok=True)
    zip_path = os.path.join(TEMP_DIR, "release.zip")
    
    print(f"Downloading Official Atlhas1x v{version} release...")
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Atlhas1x-Repair'})
        with urllib.request.urlopen(req, timeout=15) as response, open(zip_path, "wb") as out_file:
            shutil.copyfileobj(response, out_file)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            print("\nThe matching Atlhas1x release could not be found.")
            print("Repair cannot continue safely.")
        else:
            print(f"\nRepair source unavailable. Error: {e.code}")
        return None
    except Exception as e:
        print("\nRepair source unavailable.")
        print("Internet connection is required to download clean Atlhas1x files.")
        return None
        
    print("Download complete. Validating package...")
    extract_dir = os.path.join(TEMP_DIR, "extracted")
    os.makedirs(extract_dir, exist_ok=True)
    
    try:
        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            # Find the root folder in the zip (e.g. Atlhas1X-1.4.0/)
            root_folders = set(m.split('/')[0] for m in zip_ref.namelist())
            if len(root_folders) != 1:
                print("Repair validation failed. Invalid package structure.")
                return None
            prefix = list(root_folders)[0] + "/"
            safe_extract(zip_ref, extract_dir, prefix)
    except Exception as e:
        print(f"Repair validation failed. Could not extract package: {e}")
        return None
        
    # Validate the manifest in the downloaded package
    pkg_manifest_path = os.path.join(extract_dir, MANIFEST_FILE)
    if not os.path.exists(pkg_manifest_path):
        print("Repair validation failed. Missing manifest in package.")
        return None
        
    with open(pkg_manifest_path, "r") as f:
        pkg_manifest = json.load(f)
        
    if pkg_manifest.get("version") != version:
        print("Repair validation failed. Version mismatch in package.")
        return None
        
    # Validate hashes of extracted files
    for file, expected_hash in pkg_manifest.get("files", {}).items():
        full_path = os.path.join(extract_dir, file)
        if not os.path.exists(full_path):
            print(f"Repair validation failed. Missing file in package: {file}")
            return None
        actual_hash = get_file_hash(full_path)
        if actual_hash != expected_hash:
            print(f"Repair validation failed. Hash mismatch in package for {file}.")
            return None
            
    print("Package validation passed.")
    return extract_dir, pkg_manifest

def do_repair(full=False):
    version = get_version()
    print(f"\nAtlhas1x Repair Tool\n\nChecking installation...\n\nVersion:\nv{version}\n")
    
    res = verify_integrity()
    if res["error"]:
        print(f"Integrity check failed: {res['error']}")
        files_to_repair = [] # Needs full repair probably, handled below
    else:
        files_checked = res["checked"]
        problems = res["problems"]
        damaged = len(problems)
        healthy = files_checked - damaged
        
        print(f"Files checked:\n{files_checked}\n\nHealthy:\n{healthy}\n\nRepair required:\n{damaged}\n")
        files_to_repair = list(problems.keys())
        
    if not full and not files_to_repair and not res["error"]:
        print("No repair needed.")
        return True
        
    package_data = download_and_validate_release(version)
    if not package_data:
        print("\nNo application files were replaced.")
        return False
        
    extract_dir, pkg_manifest = package_data
    
    if full or res["error"]:
        files_to_repair = list(pkg_manifest.get("files", {}).keys())
        
    print(f"\nRepairing:\n{len(files_to_repair)} files")
    
    os.makedirs(BACKUP_DIR, exist_ok=True)
    
    success = True
    repaired_count = 0
    
    # Backup and Replace
    for file in files_to_repair:
        src = os.path.join(extract_dir, file)
        dst = file
        backup = os.path.join(BACKUP_DIR, file)
        
        # Path traversal protection for destination
        if ".." in dst or dst.startswith("/") or dst.startswith("\\"):
            print(f"Skipping dangerous path: {dst}")
            success = False
            break
            
        try:
            if os.path.exists(dst):
                b_dir = os.path.dirname(backup)
                if b_dir: os.makedirs(b_dir, exist_ok=True)
                shutil.copy2(dst, backup)
            
            d_dir = os.path.dirname(dst)
            if d_dir: os.makedirs(d_dir, exist_ok=True)
            # Remove read-only attribute if exists to allow overwrite
            if os.path.exists(dst):
                os.chmod(dst, stat.S_IWRITE)
            shutil.copy2(src, dst)
            repaired_count += 1
        except Exception as e:
            print(f"Error repairing {file}: {e}")
            success = False
            break
            
    if not success:
        print("\nRepair failed.\nRestoring previous files...")
        for file in files_to_repair:
            dst = file
            backup = os.path.join(BACKUP_DIR, file)
            if os.path.exists(backup):
                try:
                    if os.path.exists(dst):
                        os.chmod(dst, stat.S_IWRITE)
                    shutil.copy2(backup, dst)
                except:
                    pass
        print("Rollback complete.")
    else:
        # Final validation
        final_res = verify_integrity()
        if final_res["error"] or final_res["problems"]:
            print(f"\nFinal integrity check failed. Missing/Corrupted: {len(final_res['problems'])}")
            success = False
        else:
            print(f"\nAtlhas1x Repair Summary\n\nFiles checked:\n{final_res['checked']}\n\nProblems detected:\n{len(files_to_repair)}\n\nFiles restored:\n{repaired_count}\n\nFailed:\n0\n\nFinal integrity:\nPASS\n")
            # Cleanup temp and backup
            try:
                shutil.rmtree(TEMP_DIR)
                shutil.rmtree(BACKUP_DIR)
            except:
                pass
                
    return success

def interactive_menu():
    while True:
        print("\nAtlhas1x Repair Menu")
        print("-" * 30)
        print("[1] Quick Repair")
        print("[2] Full Repair")
        print("[3] Verify Only")
        print("[0] Exit")
        print("[?] What is the difference?\n")
        
        try:
            choice = input("Choice: ").strip()
        except:
            return
            
        if choice == "1":
            if do_repair(full=False):
                ask_restart()
            break
        elif choice == "2":
            if do_repair(full=True):
                ask_restart()
            break
        elif choice == "3":
            res = verify_integrity()
            if res["error"]:
                print(f"\nError: {res['error']}")
            else:
                print(f"\nFiles checked:\n{res['checked']}")
                print(f"Problems detected:\n{len(res['problems'])}")
                for f, p in res["problems"].items():
                    print(f" - {f}: {p}")
                if not res["problems"]:
                    print("\nIntegrity: PASS")
            input("\nPress Enter to return...")
        elif choice == "?":
            print("\nQUICK REPAIR\nRecommended.\nOnly damaged or missing Atlhas1x files are restored.\n")
            print("FULL REPAIR\nRestores all official application files.\nReports, preferences and personal data are preserved.\n")
            print("VERIFY ONLY\nChecks installation integrity without changing anything.\n")
            input("Press Enter to return...")
        elif choice == "0":
            break

def ask_restart():
    print("\nStart Atlhas1x now?\n\n[Y] Yes\n[N] No")
    try:
        ans = input("\nChoice: ").strip().lower()
        if ans == "y":
            # Restart via Atlhas1x.bat
            if os.path.exists("Atlhas1x.bat"):
                subprocess.Popen(["cmd.exe", "/c", "Atlhas1x.bat"], creationflags=subprocess.CREATE_NEW_CONSOLE)
    except:
        pass

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check-integrity", action="store_true")
    parser.add_argument("--interactive", action="store_true")
    args = parser.parse_args()
    
    if args.check_integrity:
        if not check_and_prompt():
            sys.exit(1)
        sys.exit(0)
    elif args.interactive:
        interactive_menu()
    else:
        interactive_menu()

if __name__ == "__main__":
    main()
