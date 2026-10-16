# Destructive OWN-instance api-matrix runbook (audit5/api-matrix).
# Boots two consoles (A :8305, B :8306) from a checkout of this repo, runs
# own_matrix.py against a LOCAL engine, then cleans up the disposable graph
# key sever_audit5_apimatrix and its ledgers.
#
# Machine-agnostic: every path derives from -Wt / -SampleDir / -Py or the
# environment — no host-specific defaults. Requires the engine up first
# (docker compose up -d, README section 9) and a python with the console
# extras installed (pip install -e ".[console]"). Results land in <Wt>\out
# (gitignored) as audit5_own_results.jsonl.
param(
    [string]$Wt = (Join-Path $PSScriptRoot '..\..\'),
    [string]$SampleDir = $(if ($env:SEVER_SAMPLE_DIR) { $env:SEVER_SAMPLE_DIR } else { Join-Path $PSScriptRoot '..\..\data\ad_sample' }),
    [string]$Py = (Get-Command python -ErrorAction SilentlyContinue).Source
)
Set-StrictMode -Off
$ErrorActionPreference = 'Continue'

if (-not $Py) { throw 'python not on PATH - install the console extras (README section 9) or pass -Py <python.exe>' }
$Wt = (Resolve-Path $Wt).Path
if (-not (Test-Path "$Wt\sever\console\app.py")) { throw 'worktree missing' }
if (-not (Test-Path $SampleDir)) { throw 'sample dir missing' }
New-Item -ItemType Directory -Force "$Wt\out" | Out-Null
Set-Location "$Wt\out"

"=== env ==="
$env:SEVER_FALKOR_HOST = '127.0.0.1'
$env:SEVER_FALKOR_PORT = '6379'
$env:SEVER_FALKOR_GRAPH = 'sever_audit5_apimatrix'
$env:SEVER_SAMPLE_DIR = $SampleDir
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
& $Py "$env:TEMP\audit5_clean.py"
Remove-Item "$Wt\out\cases\sever_audit5_apimatrix*" -Force -ErrorAction SilentlyContinue
Remove-Item "$Wt\out\audit5_own_results.jsonl*" -Force -ErrorAction SilentlyContinue

"=== boot console A (8305) ==="
$p1 = Start-Process -FilePath $Py -ArgumentList '-m','uvicorn','sever.console.app:app','--host','127.0.0.1','--port','8305' -WorkingDirectory $Wt -PassThru -WindowStyle Hidden -RedirectStandardError "$Wt\uvicorn_a.err.log" -RedirectStandardOutput "$Wt\uvicorn_a.out.log"
& $Py "$env:TEMP\audit5_poll.py" http://127.0.0.1:8305
if ($LASTEXITCODE -ne 0) { throw 'console A not ready' }

"=== boot console B (8306) ==="
$p2 = Start-Process -FilePath $Py -ArgumentList '-m','uvicorn','sever.console.app:app','--host','127.0.0.1','--port','8306' -WorkingDirectory $Wt -PassThru -WindowStyle Hidden -RedirectStandardError "$Wt\uvicorn_b.err.log" -RedirectStandardOutput "$Wt\uvicorn_b.out.log"
& $Py "$env:TEMP\audit5_poll.py" http://127.0.0.1:8306
if ($LASTEXITCODE -ne 0) { throw 'console B not ready' }

"=== run destructive matrix ==="
& $Py "$PSScriptRoot\own_matrix.py"
$mx = $LASTEXITCODE
"matrix exit code: $mx"

"=== stop consoles ==="
Stop-Process -Id $p1.Id -Force -ErrorAction SilentlyContinue
Stop-Process -Id $p2.Id -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

"=== cleanup graph + ledger ==="
& $Py "$env:TEMP\audit5_clean.py"
Remove-Item "$Wt\out\cases\sever_audit5_apimatrix*" -Force -ErrorAction SilentlyContinue
Remove-Item "$Wt\uvicorn_a.err.log", "$Wt\uvicorn_a.out.log", "$Wt\uvicorn_b.err.log", "$Wt\uvicorn_b.out.log" -Force -ErrorAction SilentlyContinue

"=== engine health after run ==="
& $Py "$env:TEMP\audit5_verify.py"

"=== matrix summary ==="
if (Test-Path "$Wt\out\audit5_own_results.jsonl.summary.json") {
  Get-Content "$Wt\out\audit5_own_results.jsonl.summary.json" | Select-Object -First 60
} else { "NO SUMMARY FILE - run failed early"; Get-Content "$Wt\uvicorn_a.err.log" -ErrorAction SilentlyContinue | Select-Object -Last 30 }
"=== DONE ==="
