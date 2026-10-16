from falkordb import FalkorDB
import socket
fdb = FalkorDB(host="127.0.0.1", port=6379)
keys = [k.decode() if isinstance(k, bytes) else k for k in fdb.execute_command("KEYS", "sever_audit5_e2e*")]
print("leftover keys:", keys)
for port in (8380, 8381):
    s = socket.socket()
    try:
        s.connect(("127.0.0.1", port)); print("port", port, "STILL OPEN")
    except Exception as e:
        print("port", port, "free")
    finally:
        s.close()
