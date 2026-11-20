@echo off
REM ==============================================================================
REM SafeOps - Single Command Startup Script (Windows)
REM ==============================================================================

echo ======================================================================
echo                SafeOps: Secure Two-Tier AIOps Platform                
echo ======================================================================

REM 1. Check Python
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Python 3 is not found in your system PATH.
    echo Please install Python 3.11 or newer and check 'Add python.exe to PATH'.
    pause
    exit /b 1
)

REM 2. Setup Virtual Environment
if not exist ".venv" (
    echo [1/3] Creating isolated Python virtual environment (.venv)...
    python -m venv .venv
)

call .venv\Scripts\activate.bat

REM 3. Install packages
echo [2/3] Verifying and installing required Python packages...
python -m pip install --quiet -r requirements.txt

REM 4. Launch Tier 2 and Tier 1 in separate background processes with own databases
echo [3/3] Launching Tier 2 SaaS (Port 8002, saas_cloud.db) and Tier 1 Collector (Port 8001, collector_local.db)...
start "SafeOps SaaS (Port 8002)" cmd /k "python -m uvicorn tier2_saas.app:app --host 0.0.0.0 --port 8002"
timeout /t 2 /nobreak >nul
start "SafeOps Collector (Port 8001)" cmd /k "python -m uvicorn tier1_collector.app:app --host 0.0.0.0 --port 8001"

echo.
echo ======================================================================
echo  SafeOps is now RUNNING as 2 Separate Processes!
echo ======================================================================
echo.
echo   [Tier 1: Customer-Side Collector (Port 8001, collector_local.db)]
echo   -^> Egress Proof Panel:      http://127.0.0.1:8001/egress
echo   -^> Chaos ^& Demo Controls:   http://127.0.0.1:8001/control
echo.
echo   [Tier 2: Cloud-Side SaaS Platform (Port 8002, saas_cloud.db)]
echo   -^> Multi-Tenant Dashboard:  http://127.0.0.1:8002/dashboard
echo   -^> AIOps ^& Remediation:     http://127.0.0.1:8002/incidents
echo   -^> Reliability SLA Panel:   http://127.0.0.1:8002/reliability
echo.
echo   [Moving SaaS to a Second Laptop]
echo   1. On second laptop: run python -m uvicorn tier2_saas.app:app --host 0.0.0.0 --port 8002
echo   2. On this laptop: edit config/collector_config.json and set "saas_url" to second laptop IP
echo.
echo ======================================================================
echo Close the two opened command windows to stop all services.
echo ======================================================================
pause
