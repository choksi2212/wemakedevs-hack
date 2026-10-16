import psutil
for p in psutil.process_iter(["pid","name","cmdline"]):
    try:
        cl = " ".join(p.info["cmdline"] or [])
        if "audit5_e2e_driver" in cl:
            print(p.info["pid"], cl[:120])
    except Exception:
        pass
print("scan done")
