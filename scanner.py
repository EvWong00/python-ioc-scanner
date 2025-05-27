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

    # 200 OK → good, return JSON
    if resp.status_code == 200:
        return resp.json()

    # 404 Not Found → no record, treat as clean
    if resp.status_code == 404:
        print(f"⚠️  No VT record for {file_hash}; marking clean")
        return {"data": {"attributes": {"last_analysis_stats": {}}}}

    # 429 Rate‑limited → pause & retry
    if resp.status_code == 429:
        print("⏳ Rate limit hit, sleeping 15s…")
        time.sleep(15)
        return vt_lookup(file_hash)

    # any other error → log and treat as clean
    print(f"❌ VT lookup failed ({resp.status_code}): {resp.text}")
    return {"data": {"attributes": {"last_analysis_stats": {}}}}


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
            vt    = vt_lookup(sha256)
            verdict = parse_verdict(vt)
            rows.append([fname, md5, sha256, verdict])

    # ← This block must be indented *inside* scan_folder
    with open(output_csv, "w", newline="") as out:
        writer = csv.writer(out)
        writer.writerow(["filename","md5","sha256","verdict"])
        writer.writerows(rows)
    print(f"Report saved to {output_csv}")

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Python IoC Scanner")
    p.add_argument("folder", help="Folder to scan")
    # (optional) p.add_argument("-o","--output", default="report.csv", help="Output CSV path")
    args = p.parse_args()

    # Call the function—this is where `output_csv` comes from
    scan_folder(args.folder)
            