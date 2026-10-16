import json, urllib.request
for p in ("/api/receipts", "/api/state"):
    try:
        r = urllib.request.urlopen("https://sever-console.onrender.com"+p, timeout=60)
        b = r.read()
        print(p, r.status, len(b), "bytes")
    except Exception as e:
        print(p, "ERR", str(e)[:100])
