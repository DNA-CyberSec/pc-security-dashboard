@echo off
setlocal enabledelayedexpansion

echo ============================================================
echo   PC Security Agent - Installer
echo   Built by Rami Hacmon / DNACybersec
echo   https://pcguard-rami.web.app
echo ============================================================
echo.

:: ── Check for Python ──────────────────────────────────────────
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH.
    echo         Download from: https://www.python.org/downloads/
    echo         During install, check "Add Python to PATH".
    pause
    exit /b 1
)
for /f "tokens=*" %%i in ('python --version 2^>^&1') do set PYVER=%%i
echo [OK] %PYVER%
echo.

:: ── Install folder ────────────────────────────────────────────
set INSTALL_DIR=C:\pc-security-agent
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"
echo [OK] Install directory: %INSTALL_DIR%
echo.

:: ── Copy agent files ──────────────────────────────────────────
xcopy /E /I /Y "%~dp0*" "%INSTALL_DIR%\" >nul
echo [OK] Files copied
echo.

:: ── Install Python dependencies ───────────────────────────────
echo [INFO] Installing dependencies (this may take a minute)...
python -m pip install --upgrade pip --quiet
python -m pip install -r "%INSTALL_DIR%\requirements.txt"
if errorlevel 1 (
    echo [ERROR] Dependency install failed. See output above.
    pause
    exit /b 1
)
echo [OK] Dependencies installed
echo.

:: ── Set up .env ───────────────────────────────────────────────
if not exist "%INSTALL_DIR%\.env" (
    copy "%INSTALL_DIR%\.env.example" "%INSTALL_DIR%\.env" >nul
)

:: ── Check for AgentToken ──────────────────────────────────────
findstr /C:"pcg-" "%INSTALL_DIR%\.env" >nul 2>&1
if errorlevel 1 (
    echo ┌─────────────────────────────────────────────────────┐
    echo │  ACTION REQUIRED: Set your AgentToken               │
    echo │                                                     │
    echo │  1. Go to: https://pcguard-rami.web.app             │
    echo │  2. Sign in with Google                             │
    echo │  3. Go to the Setup page                            │
    echo │  4. Copy your AgentToken (starts with pcg-)         │
    echo │  5. Edit: %INSTALL_DIR%\.env
    echo │     Set: AGENT_TOKEN=pcg-...                        │
    echo └─────────────────────────────────────────────────────┘
    echo.
    set /p OPEN_ENV="Open .env in Notepad now? (y/n): "
    if /i "!OPEN_ENV!"=="y" notepad "%INSTALL_DIR%\.env"
) else (
    echo [OK] AgentToken found in .env
)

echo.
echo ============================================================
echo   Installation complete.
echo ============================================================
echo.
set /p START="Start the agent now? (y/n): "
if /i "!START!"=="y" (
    cd /d "%INSTALL_DIR%"
    python main.py
) else (
    echo.
    echo To start manually:
    echo   cd %INSTALL_DIR% ^&^& python main.py
    echo.
    echo To run at Windows startup:
    echo   Add to Task Scheduler: python %INSTALL_DIR%\main.py
)

pause
