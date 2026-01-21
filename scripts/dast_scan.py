import requests
import sys

TARGETS = [
    {"name": "Frontend (Web)", "url": "http://localhost:3000"},
    {"name": "Backend (API)", "url": "http://localhost:8000/docs"}
]

REQUIRED_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": None, # Just check presence
    "Strict-Transport-Security": None, # Just check presence
}

def scan_target(target):
    print(f"\nScanning {target['name']} ({target['url']})...")
    try:
        r = requests.get(target['url'], timeout=5)
        print(f"Status: {r.status_code}")
        
        issues = 0
        for header, expected_val in REQUIRED_HEADERS.items():
            val = r.headers.get(header)
            if not val:
                print(f"[FAIL] Missing Header: {header}")
                issues += 1
            elif expected_val and val != expected_val:
                # X-Frame-Options allows SAMEORIGIN too, so be lenient if needed
                if header == "X-Frame-Options" and val == "SAMEORIGIN":
                    print(f"[PASS] {header}: {val}")
                else:
                    print(f"[WARN] {header}: {val} (Expected: {expected_val})")
            else:
                print(f"[PASS] {header}: {val}")
        
        server = r.headers.get("Server")
        if server:
             print(f"[WARN] Server Header Leaked: {server}")
             issues += 1

        return issues

    except Exception as e:
        print(f"[ERROR] Could not connect: {e}")
        return 1

def main():
    total_issues = 0
    print("Starting DAST Security Header Scan...")
    for t in TARGETS:
        total_issues += scan_target(t)
    
    print(f"\nScan Complete. Total Issues Found: {total_issues}")
    if total_issues > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
