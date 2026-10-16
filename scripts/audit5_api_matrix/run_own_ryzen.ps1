Set-StrictMode -Off
$ErrorActionPreference = 'Continue'
$wt = 'N:\wemakedev\wemakedevs-hack-audit5wt'
$py = 'N:\wemakedev\venv\Scripts\python.exe'
$home2 = 'C:\Users\niklaus'

if (-not (Test-Path "$wt\sever\console\app.py")) { throw 'worktree missing' }
if (-not (Test-Path 'N:\wemakedev\data\ad_sample')) { throw 'sample dir missing' }

"=== env ==="
$env:SEVER_FALKOR_HOST = '127.0.0.1'
$env:SEVER_FALKOR_PORT = '6379'
$env:SEVER_FALKOR_GRAPH = 'sever_audit5_apimatrix'
$env:SEVER_SAMPLE_DIR = 'N:\wemakedev\data\ad_sample'
$env:SEVER_FALKOR_SOCKET_TIMEOUT = '3'
$env:SEVER_FALKOR_CONNECT_TIMEOUT = '3'
Remove-Item Env:\SEVER_DOCS -ErrorAction SilentlyContinue
Remove-Item Env:\SEVER_CONSOLE_NO_BOOTSTRAP -ErrorAction SilentlyContinue

$clean = @'
import redis
r = redis.Redis(host="127.0.0.1", port=6379)
for g in ("sever_audit5_apimatrix", "sever_audit5_apimatrix_plan_scratch"):
    try:
        r.execute_command("GRAPH.DELETE", g)
        print("deleted:", g)
    except Exception as e:
        print("skip:", g, type(e).__name__)
'@
$clean | Set-Content -Encoding ASCII "$env:TEMP\audit5_clean.py"
$poll = @'
import sys, time, requests
url = sys.argv[1]
for i in range(120):
    try:
        r = requests.get(url + "/api/state", timeout=4)
        if r.status_code == 200 and r.json().get("nodes") == 1480:
            print("READY nodes=%d edges=%d" % (r.json()["nodes"], r.json()["edges"]))
            sys.exit(0)
        print("poll", i, "status", r.status_code)
    except Exception as e:
        print("poll", i, type(e).__name__)
    time.sleep(2)
print("TIMEOUT")
sys.exit(1)
'@
$poll | Set-Content -Encoding ASCII "$env:TEMP\audit5_poll.py"
$verify = @'
import redis
r = redis.Redis(host="127.0.0.1", port=6379)
print("PING:", r.ping())
keys = r.execute_command("GRAPH.LIST")
print("GRAPHS:", [k.decode() if isinstance(k, bytes) else k for k in keys])
'@
$verify | Set-Content -Encoding ASCII "$env:TEMP\audit5_verify.py"

"=== clean slate ==="
& $py "$env:TEMP\audit5_clean.py"
Remove-Item "$wt\out\cases\sever_audit5_apimatrix*" -Force -ErrorAction SilentlyContinue
Remove-Item "$home2\audit5_own_results.jsonl*" -Force -ErrorAction SilentlyContinue

"=== boot console A (8305) ==="
$p1 = Start-Process -FilePath $py -ArgumentList '-m','uvicorn','sever.console.app:app','--host','127.0.0.1','--port','8305' -WorkingDirectory $wt -PassThru -WindowStyle Hidden -RedirectStandardError "$wt\uvicorn_a.err.log" -RedirectStandardOutput "$wt\uvicorn_a.out.log"
& $py "$env:TEMP\audit5_poll.py" http://127.0.0.1:8305
if ($LASTEXITCODE -ne 0) { throw 'console A not ready' }

"=== boot console B (8306) ==="
$p2 = Start-Process -FilePath $py -ArgumentList '-m','uvicorn','sever.console.app:app','--host','127.0.0.1','--port','8306' -WorkingDirectory $wt -PassThru -WindowStyle Hidden -RedirectStandardError "$wt\uvicorn_b.err.log" -RedirectStandardOutput "$wt\uvicorn_b.out.log"
& $py "$env:TEMP\audit5_poll.py" http://127.0.0.1:8306
if ($LASTEXITCODE -ne 0) { throw 'console B not ready' }

"=== run destructive matrix ==="
& $py "$home2\audit5_own_matrix.py"
$mx = $LASTEXITCODE
"matrix exit code: $mx"

"=== stop consoles ==="
Stop-Process -Id $p1.Id -Force -ErrorAction SilentlyContinue
Stop-Process -Id $p2.Id -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

"=== cleanup graph + ledger ==="
& $py "$env:TEMP\audit5_clean.py"
Remove-Item "$wt\out\cases\sever_audit5_apimatrix*" -Force -ErrorAction SilentlyContinue
Remove-Item "$wt\uvicorn_a.err.log", "$wt\uvicorn_a.out.log", "$wt\uvicorn_b.err.log", "$wt\uvicorn_b.out.log" -Force -ErrorAction SilentlyContinue

"=== engine health after run ==="
& $py "$env:TEMP\audit5_verify.py"

"=== matrix summary ==="
if (Test-Path "$home2\audit5_own_results.jsonl.summary.json") {
  Get-Content "$home2\audit5_own_results.jsonl.summary.json" | Select-Object -First 60
} else { "NO SUMMARY FILE - run failed early"; Get-Content "$wt\uvicorn_a.err.log" -ErrorAction SilentlyContinue | Select-Object -Last 30 }
"=== DONE ==="
