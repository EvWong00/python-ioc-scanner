import os, time, csv, hashlib, requests
from dotenv import load_dotenv

# Configuration 

load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")
API_URL = "https://www.virustotal.com/api/v3/files/"

# 1. Hashing

def hash_file(path):
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with open (path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            md5.update(chunk)
            sha256.update(chunk)
    
    return md5.hexdigest(), sha256.hexdigest()

# 2 VirusTotal Lookup

def vt_lookup(file_hash):
    headers = {"x-apikey": VT_API_KEY}
    resp    = requests.get(API_URL + file_hash, headers=headers)
    if resp.status_code == 429:
        time.sleep(15) #free tier only allows limited number of requests per min so this is a pause before retrying 
        return vt_lookup(file_hash)
    return resp.json() if resp.status_code == 200 else None

# 3 Parse Verdict 

def parse_verdict(vt_json):
    stats = vt_json["data"]["attributes"]["last_analysis_stats"]
    mal   = stats.get("malicious", 0)
    susp  = stats.get("suspicious",0)
    parts = []
    if mal:  parts.append(f"malicious({mal})")
    if susp: parts.append(f"suspicious({susp})")
    return ";".join(parts) or "clean"

# 4 Scan Folder and Export CSV

def scan_folder(folder_path, output_csv="report.csv"):
    rows = []
    for root, _, files in os.walk(folder_path):
        for fname in files:
            full = os.path.join(root, fname)
            md5, sha256 = hash_file(full)
            print(f"Scanning {fname} MD5:{md5} SHA256:{sha256}")
            vt      = vt_lookup(sha256)
            verdict = parse_verdict(vt) if vt else "error"
            rows.append([fname, md5, sha256, verdict])
            
with open(output_csv, "w", newline="") as out:
    writer = csv.writer(out)
    writer.writerows(["filename", "md5", "sha256", "verdict"])
print(f"Report saved to {output_csv}")

# CLI Entrypoint

if __name__== "__main__":
    import argparse 
    p = argparse.ArgumentParser(description="Python IoC Scanner")
    p.add_argument("folder", help = "Folder to scan")
    p.add_argument("--watch", action="store_true",
                   help="Scan new files in real-time")
    args = p.parse_args()
    
    if args.watch:
        from watchdog.observers import Observer
        from watchdog.events    import FileSystemEventHandler
        
        class Handler(FileSystemEventHandler):
            def on_created(self, event):
                if not event.is_directory:
                    scan_folder(os.path.dirname(event.src_path),
                                output_csv="live_report.csv")
                    
        obs = Observer()
        obs.schedule(Handler(), path=args.folder, recursive=True)
        obs.start()
        obs.join()
    else:
        scan_folder(args.folder) 
            