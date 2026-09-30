# monitor-service/network_config.py
# Shared network configuration for all three machines.
# Edit these IPs if your network changes.

MAC_IP      = "10.0.8.160"     # Mac (backend + dashboard)
WINDOWS_IP  = "10.0.8.35"      # Windows 10 VM (victim)
# Kali IP is dynamic (bridged DHCP) — not needed here

BACKEND_URL       = f"http://{MAC_IP}:8000"
DASHBOARD_URL     = f"http://{MAC_IP}:5173"
WINDOWS_SHARE_UNC = f"\\\\{WINDOWS_IP}\\TestShare"
WINDOWS_SHARE_SMB = f"//{WINDOWS_IP}/TestShare"
SANDBOX_PATH_WIN  = "C:\\test-sandbox"
SANDBOX_PATH_KALI = "/mnt/win-sandbox"
