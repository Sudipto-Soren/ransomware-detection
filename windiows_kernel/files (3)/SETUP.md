# Track A — Windows Kernel Driver Setup Guide
## VirtualBox + Windows 11 + WDK + RansomDet Minifilter

This guide takes you from a fresh VirtualBox Windows 11 VM
to a running kernel driver that sends events to the Mac backend.

---

## Part 1 — VirtualBox Configuration

### 1.1 — Create the VM
- Download Windows 11 ISO from microsoft.com/software-download/windows11
- New VM → Name: RansomDetDev → Type: Microsoft Windows → Version: Windows 11 (64-bit)
- RAM: 4096 MB minimum (8192 recommended)
- Storage: 80 GB VDI, dynamically allocated
- Settings → System → Processor → 2+ CPUs
- Settings → System → Processor → Enable PAE/NX

### 1.2 — Disable Secure Boot (CRITICAL for test drivers)
- VM Settings → System → Motherboard
- Uncheck "Enable Secure Boot"
- Without this, Windows will refuse to load our test-signed driver

### 1.3 — Set up host-only network (Mac ↔ Windows communication)
On your Mac:
```
VirtualBox → File → Host Network Manager → Create
Note the IP: usually 192.168.56.1 (Mac side) / 192.168.56.101 (Windows side)
```
In VM Settings → Network:
- Adapter 1: NAT (for internet inside VM)
- Adapter 2: Host-Only Adapter → vboxnet0

### 1.4 — Set up shared folder (to copy driver files from Mac)
VM Settings → Shared Folders → Add:
- Folder Path: ~/Projects/ransomware-detection (your Mac project folder)
- Folder Name: ransomware-detection
- Auto-mount: Yes
- Mount point: Z:\
- Make Permanent: Yes

After Windows boots: open File Explorer → Z:\ → your project files appear here

---

## Part 2 — Windows Setup

### 2.1 — Enable Test Signing Mode
Open Command Prompt as Administrator:
```cmd
bcdedit /set testsigning on
```
Restart the VM. You should see "Test Mode" watermark in the bottom-right corner.
This allows loading drivers that aren't signed by Microsoft.

### 2.2 — Disable Driver Signature Enforcement (one-time, for development)
In Administrator Command Prompt:
```cmd
bcdedit /set nointegritychecks on
```
Or at boot: Hold Shift → Restart → Troubleshoot → Advanced → Startup Settings
→ Restart → Press F7 (Disable driver signature enforcement)

### 2.3 — Install Python 3.11+ on Windows
Download from python.org → install with "Add to PATH" checked.
```cmd
pip install requests pywin32
```

---

## Part 3 — Install Visual Studio 2022 + WDK

### 3.1 — Visual Studio 2022 Community
Download from visualstudio.microsoft.com/downloads/
During install, select these workloads:
- "Desktop development with C++"
- "Windows Driver Kit" (under "Other Toolsets")

### 3.2 — Windows Driver Kit (WDK)
Go to: https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk
Download the WDK that matches your Windows SDK version.
Run the installer — it adds the WDK extension to Visual Studio automatically.

### 3.3 — Verify installation
Open Visual Studio 2022 → Create New Project → search "Kernel Mode Driver"
If you see "Kernel Mode Driver, Empty (KMDF)" or "MiniFilter Driver", the WDK is installed correctly.

---

## Part 4 — Build the Driver

### 4.1 — Copy driver files from the shared folder
```cmd
mkdir C:\dev\RansomDet
xcopy Z:\driver\minifilter\* C:\dev\RansomDet\ /E
```

### 4.2 — Open and build in Visual Studio
1. Open Visual Studio 2022
2. File → Open → Project/Solution → C:\dev\RansomDet\RansomDet.vcxproj
3. Select configuration: Debug | x64
4. Build → Build Solution (Ctrl+Shift+B)

Expected output:
```
========== Build: 1 succeeded, 0 failed ==========
```
Output file: C:\dev\RansomDet\x64\Debug\RansomDet.sys

### 4.3 — Test-sign the driver
Visual Studio does this automatically in Debug configuration.
If you need to sign manually:
```cmd
# Open Developer Command Prompt for VS 2022 as Administrator
cd C:\dev\RansomDet\x64\Debug
makecert -r -pe -ss TemporaryTestCert -n "CN=RansomDetTest" RansomDetTest.cer
certmgr /add RansomDetTest.cer /s /r localMachine root
certmgr /add RansomDetTest.cer /s /r localMachine trustedpublisher
signtool sign /v /s TemporaryTestCert /fd sha256 RansomDet.sys
```

---

## Part 5 — Install and Load the Driver

### 5.1 — Install using pnputil (recommended)
Open Command Prompt as Administrator:
```cmd
cd C:\dev\RansomDet\x64\Debug
pnputil /add-driver RansomDet.inf /install
```

### 5.2 — Start the driver
```cmd
sc start RansomDet
```

### 5.3 — Verify it's loaded
```cmd
sc query RansomDet
```
Expected:
```
SERVICE_NAME: RansomDet
        TYPE               : 2  FILE_SYSTEM_DRIVER
        STATE              : 4  RUNNING
```

Also check with fltmc:
```cmd
fltmc
```
You should see "RansomDet" listed with altitude 360010.

### 5.4 — Check driver output in DebugView
Download DebugView from Sysinternals (microsoft.com/en-us/sysinternals/downloads/debugview)
Run as Administrator → Capture → Capture Kernel
You should see:
```
[RansomDet] Driver loaded. Waiting for user-mode monitor on \RansomDetPort.
```
And as files are accessed:
```
[RansomDet] No user-mode monitor connected yet.
```
(The second message appears until monitor_client.py connects)

---

## Part 6 — Run the User-Mode Monitor

### 6.1 — Find the Mac's IP on the host-only network
On your Mac:
```bash
ipconfig getifaddr vboxnet0
# Usually prints: 192.168.56.1
```

### 6.2 — Run monitor_client.py on Windows
Open Command Prompt as Administrator (required for FilterConnectCommunicationPort):
```cmd
cd Z:\monitor-service
python monitor_client.py --backend http://192.168.56.1:8000 --window 30
```

Expected output:
```
════════════════════════════════════════════════════
  RansomDet — Windows Kernel Monitor
════════════════════════════════════════════════════
  Backend  : http://192.168.56.1:8000
  Window   : 30s per session
  ✓ Connected to kernel driver port
  Monitoring started. Events will appear below.
────────────────────────────────────────────────────
  WRITE      [  1234] notepad.exe          ...Documents\report.docx
  CREATE     [  5678] explorer.exe         ...Downloads\file.txt
```

### 6.3 — Verify events reach the Mac dashboard
Open http://localhost:5173 on the Mac.
Within 30 seconds (one window), a new session should appear in the session feed.

---

## Part 7 — Driver Management Commands

```cmd
# Start
sc start RansomDet

# Stop
sc stop RansomDet

# Check status
sc query RansomDet
fltmc

# Uninstall completely
sc stop RansomDet
pnputil /delete-driver RansomDet.inf /uninstall /force

# Rebuild and reinstall after code changes
sc stop RansomDet
pnputil /delete-driver RansomDet.inf /uninstall /force
:: rebuild in VS2022 ::
pnputil /add-driver RansomDet.inf /install
sc start RansomDet
```

---

## Part 8 — Troubleshooting

| Symptom | Fix |
|---|---|
| `sc start` gives Error 1275 | Test signing not enabled. Run `bcdedit /set testsigning on` and reboot |
| `sc start` gives Error 577 | Driver not signed. Check 2.2 above |
| `FilterConnectCommunicationPort` fails with 0x80070005 | Run monitor_client.py as Administrator |
| `FilterConnectCommunicationPort` fails with 0x801F0017 | Driver not loaded. Run `sc start RansomDet` |
| Build error: "fltKernel.h not found" | WDK not installed or VS extension not installed |
| Events not reaching Mac | Check Mac firewall. On Mac: `sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add uvicorn` |
| Dashboard shows no sessions | Backend might not have the model loaded. Check Terminal 1 on Mac |

---

## Part 9 — Architecture Reminder

```
Windows VM (VirtualBox)                Mac (host)
─────────────────────────────          ──────────────────────
RansomDet.sys (kernel)                 FastAPI backend :8000
    │ FltSendMessage                       │
    ▼                                      │  HTTP POST
monitor_client.py (user mode)  ───────────┘  /api/sessions/ingest
    │  192.168.56.1:8000                   │
    │                                  dashboard :5173
    └── events match docs/event-schema.json ──┘
```

The schema file (docs/event-schema.json) is the contract that makes
both sides interchangeable. The backend doesn't care whether events
came from the kernel driver or the Mac-side watchdog — same schema,
same processing.
