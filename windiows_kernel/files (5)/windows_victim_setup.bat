@echo off
:: windows_victim_setup.bat
:: Run as Administrator on the Windows 10 VM (10.0.8.35)
::
:: What this does:
::   1. Creates the test sandbox folder
::   2. Shares it over SMB so Kali can write to it
::   3. Opens firewall for SMB and backend communication
::   4. Prints connection info

echo.
echo ============================================================
echo   RansomDet — Windows Victim Setup
echo   Windows IP: 10.0.8.35
echo ============================================================
echo.

:: Check admin
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: Run as Administrator.
    pause & exit /b 1
)

:: ── 1. Create sandbox folder ──────────────────────────────────────────────────
echo [1/4] Creating test sandbox folder...
if exist C:\test-sandbox (
    echo   Already exists — clearing contents
    del /q /s C:\test-sandbox\* >nul 2>&1
) else (
    mkdir C:\test-sandbox
    echo   Created: C:\test-sandbox
)

:: Create some dummy files for Kali to attack
echo   Creating dummy files...
for %%i in (1 2 3 4 5 6 7 8 9 10) do (
    echo This is a test document number %%i for the ransomware detection demo. > C:\test-sandbox\document_%%i.txt
    echo Invoice data %%i > C:\test-sandbox\invoice_%%i.docx
    echo Report content %%i > C:\test-sandbox\report_%%i.pdf
)
echo   Created 30 dummy files in C:\test-sandbox

:: ── 2. Share the folder over SMB ─────────────────────────────────────────────
echo.
echo [2/4] Sharing folder over SMB...
:: Remove existing share if present
net share TestShare >nul 2>&1 && net share TestShare /delete >nul 2>&1

:: Create new share with full access for demo
net share TestShare=C:\test-sandbox /grant:Everyone,FULL
if %errorLevel% neq 0 (
    echo ERROR: Could not create share. Check permissions.
    pause & exit /b 1
)
echo   Share created: \\10.0.8.35\TestShare

:: ── 3. Configure firewall ─────────────────────────────────────────────────────
echo.
echo [3/4] Configuring Windows Firewall...

:: Allow SMB (port 445) from the local network
netsh advfirewall firewall add rule ^
    name="RansomDet-SMB" ^
    dir=in ^
    action=allow ^
    protocol=TCP ^
    localport=445 ^
    remoteip=10.0.8.0/22 >nul
echo   SMB port 445 opened for LAN

:: Allow the monitor client to reach the Mac backend (outbound)
netsh advfirewall firewall add rule ^
    name="RansomDet-Monitor-Out" ^
    dir=out ^
    action=allow ^
    protocol=TCP ^
    remoteport=8000 >nul
echo   Outbound port 8000 allowed (Mac FastAPI backend)

:: ── 4. Print connection summary ───────────────────────────────────────────────
echo.
echo [4/4] Setup complete.
echo.
echo ============================================================
echo   SHARE PATH  : \\10.0.8.35\TestShare
echo   LOCAL PATH  : C:\test-sandbox
echo   MAC BACKEND : http://10.0.8.160:8000
echo ============================================================
echo.
echo NEXT STEPS:
echo.
echo   On Windows (this machine):
echo     1. Compile RansomDet.sys in Visual Studio (if not done)
echo     2. Run install.bat to load the driver
echo     3. Run: python monitor_client.py --backend http://10.0.8.160:8000
echo.
echo   On Kali:
echo     Run: sudo bash kali_attack_setup.sh
echo.
echo   On Mac:
echo     Dashboard: http://localhost:5173
echo.
pause
