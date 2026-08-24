import hashlib
import json
import os

FILES_TO_TRACK = [
    "Atlhas1x.bat",
    "atlhas1x.py",
    "security_sources.py",
    "threat_analysis.py",
    "updater.py",
    "repair.py",
    "yara_engine.py",
    "requirements.txt",
    "version.json",
    "config/security_sources.json",
    "README.md",
    "LICENSE",
    "CHANGELOG.md"
]

def get_file_hash(filepath):
    try:
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        return None

def main():
    version = "1.4.0"
    try:
        with open("version.json", "r") as f:
            version = json.load(f).get("version", "1.4.0")
    except:
        pass
        
    manifest = {
        "version": version,
        "files": {}
    }
    
    for file in FILES_TO_TRACK:
        if os.path.exists(file):
            h = get_file_hash(file)
            if h:
                manifest["files"][file] = h
                
    with open("app_manifest.json", "w") as f:
        json.dump(manifest, f, indent=4)
    print("app_manifest.json generated successfully.")

if __name__ == "__main__":
    main()
