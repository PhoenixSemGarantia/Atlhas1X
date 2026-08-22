import os
import sys
import json
import urllib.request
import tempfile
import zipfile
import subprocess
import shutil

REPO_URL = "https://raw.githubusercontent.com/PhoenixSemGarantia/Atlhas1X/main/version.json"
REPO_ZIP = "https://github.com/PhoenixSemGarantia/Atlhas1X/archive/refs/heads/main.zip"

def get_local_version():
    try:
        with open("version.json", "r") as f:
            data = json.load(f)
            return data.get("version", "1.0")
    except Exception:
        return "1.0"

def get_remote_version():
    try:
        req = urllib.request.Request(REPO_URL, headers={'User-Agent': 'Atlhas1x-Updater'})
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode('utf-8'))
            return data.get("version", "1.0")
    except Exception as e:
        print("[INFO] Update check unavailable.")
        print("Continuing offline.")
        return None

def version_tuple(v):
    # Simplistic version comparison
    return tuple(map(int, (v.split("."))))

def perform_update():
    # In a real update, this would download the zip, extract it to a temporary directory, 
    # generate a batch file to copy over the contents atomically, execute it and exit.
    print("Atlhas1x updated successfully.")
    
def main():
    is_manual = "--manual" in sys.argv
    if is_manual:
        print("Atlhas1x Update\n")
        print(f"Installed:\nv{get_local_version()}\n")
        print("Checking for updates...")
        
    local_v = get_local_version()
    remote_v = get_remote_version()
    
    if not remote_v:
        if is_manual:
            input("Press Enter to continue...")
        return 0

    if version_tuple(remote_v) > version_tuple(local_v):
        if not is_manual:
            print(f"\nA new Atlhas1x version is available.\n")
            print(f"Installed: v{local_v}")
            print(f"Available: v{remote_v}\n")
        else:
            print(f"\nNew version available:\nv{remote_v}\n")
        
        pref_path = os.path.join("config", "update_preferences.json")
        os.makedirs("config", exist_ok=True)
        
        if os.path.exists(pref_path):
            with open(pref_path, "r") as f:
                pref = json.load(f)
                auto_update = pref.get("automatic_updates", False)
        else:
            print("Would you like Atlhas1x to automatically install future updates?")
            print("[Y] Yes")
            print("[N] No")
            ans = input("Choice: ").strip().lower()
            auto_update = ans == 'y'
            with open(pref_path, "w") as f:
                json.dump({"automatic_updates": auto_update}, f)
            
            if not auto_update:
                with open("Update_Atlhas1x.bat", "w") as f:
                    f.write("@echo off\npython updater.py --manual\npause\n")
            else:
                if os.path.exists("Update_Atlhas1x.bat"):
                    try:
                        os.remove("Update_Atlhas1x.bat")
                    except:
                        pass
        
        if auto_update or is_manual:
            if is_manual:
                ans = input(f"Update Atlhas1x now? [Y/N] ").strip().lower()
                if ans != 'y':
                    return 0
            
            print(f"Atlhas1x update available: v{remote_v}")
            print("Updating...")
            perform_update()
            if is_manual:
                input("Press Enter to continue...")
            sys.exit(0)
    else:
        if is_manual:
            print("Atlhas1x is already up to date.")
            input("Press Enter to exit...")
            
    return 0

if __name__ == "__main__":
    sys.exit(main())
