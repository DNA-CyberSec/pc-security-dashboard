@echo off
echo ============================================================
echo   PCGuard — Build Windows .exe
echo ============================================================
echo.

:: Check for PyInstaller
pyinstaller --version >nul 2>&1
if errorlevel 1 (
    echo [INFO] Installing PyInstaller...
    pip install pyinstaller
)

:: Clean previous build
if exist dist\PCGuard-Setup.exe del /q dist\PCGuard-Setup.exe
if exist build rmdir /s /q build

echo [INFO] Building PCGuard-Setup.exe...
echo.

pyinstaller ^
  --onefile ^
  --windowed ^
  --name "PCGuard-Setup" ^
  --paths . ^
  --hidden-import=psutil ^
  --hidden-import=requests ^
  --hidden-import=schedule ^
  --hidden-import=dotenv ^
  --hidden-import=winreg ^
  --hidden-import=modules.scanner ^
  --hidden-import=modules.processes ^
  --hidden-import=modules.network ^
  --hidden-import=modules.privacy ^
  --hidden-import=modules.backup ^
  --hidden-import=modules.cleaner ^
  setup_wizard.py

if errorlevel 1 (
    echo.
    echo [ERROR] Build failed. See output above.
    pause
    exit /b 1
)

echo.
echo ============================================================
echo   Build complete!
echo   Output: dist\PCGuard-Setup.exe
echo ============================================================
echo.

:: Show file size
for %%F in (dist\PCGuard-Setup.exe) do echo File size: %%~zF bytes

pause
