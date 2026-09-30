@echo off
:: install.bat
:: Installs and starts the RansomDet minifilter driver.
:: Run as Administrator.

echo.
echo ================================================
echo   RansomDet Driver Installer
echo   Run as Administrator
echo ================================================
echo.

:: Check if running as admin
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: This script must be run as Administrator.
    echo Right-click install.bat and select "Run as administrator"
    pause
    exit /b 1
)

:: Check if .sys file exists
if not exist "RansomDet.sys" (
    echo ERROR: RansomDet.sys not found in current directory.
    echo Build the project in Visual Studio first.
    echo Expected: x64\Debug\RansomDet.sys
    echo Copy it to this folder alongside RansomDet.inf
    pause
    exit /b 1
)

echo [1/3] Stopping old driver if running...
sc stop RansomDet >nul 2>&1

echo [2/3] Installing driver...
pnputil /add-driver RansomDet.inf /install
if %errorLevel% neq 0 (
    echo ERROR: Installation failed.
    echo Make sure test signing is enabled:
    echo   bcdedit /set testsigning on
    echo Then reboot and try again.
    pause
    exit /b 1
)

echo [3/3] Starting driver...
sc start RansomDet
if %errorLevel% neq 0 (
    echo ERROR: Driver failed to start. Check:
    echo   1. Test signing enabled: bcdedit /set testsigning on
    echo   2. Reboot after enabling test signing
    echo   3. Check Event Viewer for driver errors
    pause
    exit /b 1
)

echo.
echo ================================================
echo   SUCCESS - RansomDet is running
echo ================================================
echo.

:: Show filter status
fltmc

echo.
echo Next step: run the user-mode monitor
echo   cd ..\monitor-service
echo   python monitor_client.py --backend http://192.168.56.1:8000
echo.
pause
