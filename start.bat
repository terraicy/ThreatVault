@echo off
setlocal EnableDelayedExpansion
cd /d "%~dp0"

if not exist "logs" mkdir "logs"
set "STARTUP_LOG=%~dp0logs\startup.log"

echo. >> "%STARTUP_LOG%"
echo ================================================== >> "%STARTUP_LOG%"
echo [%date% %time%] ThreatVault startup >> "%STARTUP_LOG%"
echo ================================================== >> "%STARTUP_LOG%"

REM --- find Python (py launcher or python in PATH) ---
set "PY="
where py >nul 2>&1 && set "PY=py -3"
if not defined PY (
    where python >nul 2>&1 && set "PY=python"
)
if not defined PY (
    echo [ERROR] Python not found >> "%STARTUP_LOG%"
    echo.
    echo [ERROR] Python not found.
    echo Install Python 3.11+ from https://python.org
    echo Check "Add Python to PATH" during install.
    echo.
    echo Log: %STARTUP_LOG%
    pause
    exit /b 1
)
echo Using: %PY% >> "%STARTUP_LOG%"

cd /d "%~dp0backend"
if errorlevel 1 (
    echo [ERROR] backend folder not found >> "%STARTUP_LOG%"
    echo [ERROR] backend folder not found
    pause
    exit /b 1
)

REM --- virtual environment ---
if not exist ".venv\Scripts\python.exe" (
    echo Creating virtual environment... >> "%STARTUP_LOG%"
    echo Creating virtual environment...
    %PY% -m venv .venv >> "%STARTUP_LOG%" 2>&1
    if errorlevel 1 (
        echo [ERROR] venv creation failed >> "%STARTUP_LOG%"
        echo [ERROR] Failed to create .venv — see logs\startup.log
        pause
        exit /b 1
    )
)

call .venv\Scripts\activate.bat
if errorlevel 1 (
    echo [ERROR] venv activation failed >> "%STARTUP_LOG%"
    echo [ERROR] Failed to activate .venv
    pause
    exit /b 1
)

echo Installing dependencies... >> "%STARTUP_LOG%"
echo Installing dependencies (may take a few minutes)...
pip install -r requirements.txt >> "%STARTUP_LOG%" 2>&1
if errorlevel 1 (
    echo [ERROR] pip install failed >> "%STARTUP_LOG%"
    echo.
    echo [ERROR] pip install failed.
    echo See: %STARTUP_LOG%
    echo.
    pause
    exit /b 1
)

echo. >> "%STARTUP_LOG%"
echo Starting uvicorn... >> "%STARTUP_LOG%"
echo.
echo ========================================
echo   ThreatVault  http://localhost:8000
echo   Logs:        %~dp0logs\
echo ========================================
echo.

uvicorn app.main:app --reload --port 8000 --host 127.0.0.1
set "EXIT_CODE=!ERRORLEVEL!"
echo Server stopped (exit code !EXIT_CODE!) >> "%STARTUP_LOG%"

if !EXIT_CODE! neq 0 (
    echo.
    echo [ERROR] Server exited with code !EXIT_CODE!
    echo See: %STARTUP_LOG% and logs\threatvault.log
    pause
)
REM Project version: ThreatVault V1.1
