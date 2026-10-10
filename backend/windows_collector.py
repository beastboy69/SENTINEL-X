"""Read-only Windows Event Log metadata collector.

Uses built-in Windows PowerShell/Get-WinEvent. It stores event metadata only,
never event message text or PowerShell script contents. Polling is not an EDR
sensor and is not guaranteed to capture every event under all system conditions.
"""
import json
import platform
import subprocess

LOGS = {
    "System": "System",
    "Windows Defender Operational": "Microsoft-Windows-Windows Defender/Operational",
    "PowerShell Operational": "Microsoft-Windows-PowerShell/Operational",
}

SCRIPT = r'''
$ErrorActionPreference = 'Stop'
$logs = @(
  @{ Label = 'System'; Name = 'System' },
  @{ Label = 'Windows Defender Operational'; Name = 'Microsoft-Windows-Windows Defender/Operational' },
  @{ Label = 'PowerShell Operational'; Name = 'Microsoft-Windows-PowerShell/Operational' }
)
$cutoff = (Get-Date).AddMinutes(-15)
$events = [System.Collections.Generic.List[object]]::new()
$checks = [System.Collections.Generic.List[object]]::new()
foreach ($log in $logs) {
  try {
    $items = @(Get-WinEvent -FilterHashtable @{ LogName = $log.Name; StartTime = $cutoff } -MaxEvents 250 -ErrorAction Stop)
    foreach ($item in $items) {
      $events.Add([pscustomobject]@{
        source = $log.Label
        event_id = [int]$item.Id
        level = [string]$item.LevelDisplayName
        timestamp = $item.TimeCreated.ToUniversalTime().ToString('o')
        summary = ('Windows event metadata from ' + $log.Label + '; provider=' + [string]$item.ProviderName)
      })
    }
    $checks.Add([pscustomobject]@{ source = $log.Label; ok = $true; returned = $items.Count; error = $null })
  } catch {
    $message = $_.Exception.Message
    if ($message -match 'No events were found') {
      $checks.Add([pscustomobject]@{ source = $log.Label; ok = $true; returned = 0; error = $null })
    } else {
      $checks.Add([pscustomobject]@{ source = $log.Label; ok = $false; returned = 0; error = $message })
    }
  }
}
[pscustomobject]@{ events = @($events.ToArray()); logs = @($checks.ToArray()); collected_at = [DateTime]::UtcNow.ToString('o') } | ConvertTo-Json -Compress -Depth 5
'''

def collect_event_metadata():
    if platform.system() != "Windows":
        return {"ok": False, "available": False,
                "error": "Live Windows Event Log collection requires the backend to run on your Windows PC."}
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "RemoteSigned", "-Command", SCRIPT],
            capture_output=True, text=True, timeout=30, check=False,
            encoding="utf-8", errors="replace",
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "available": True,
                "error": f"Could not query Windows Event Logs ({exc.__class__.__name__})."}
    if result.returncode != 0:
        # Do not return potentially sensitive stderr to the browser.
        return {"ok": False, "available": True,
                "error": "PowerShell could not query Windows Event Logs. Check PowerShell availability and log permissions."}
    output = (result.stdout or "").strip()
    if not output:
        return {"ok": False, "available": True, "error": "PowerShell returned no collector response."}
    try:
        payload = json.loads(output)
        if not isinstance(payload, dict):
            raise ValueError("Unexpected collector response")
        raw_events = payload.get("events", [])
        raw_logs = payload.get("logs", [])
        if isinstance(raw_events, dict): raw_events = [raw_events]
        if isinstance(raw_logs, dict): raw_logs = [raw_logs]
        clean_events = []
        for item in raw_events:
            if not isinstance(item, dict) or item.get("source") not in LOGS:
                continue
            try:
                event_id = int(item["event_id"])
                timestamp = str(item["timestamp"])
            except (KeyError, TypeError, ValueError):
                continue
            clean_events.append({
                "source": item["source"], "event_id": event_id, "timestamp": timestamp,
                "level": str(item.get("level") or "Unknown")[:40],
                "summary": str(item.get("summary") or "Windows event metadata")[:300],
                "synthetic": False,
            })
        log_status = []
        for item in raw_logs:
            if not isinstance(item, dict) or item.get("source") not in LOGS:
                continue
            log_status.append({
                "source": item["source"], "ok": bool(item.get("ok")),
                "returned": int(item.get("returned") or 0),
                "error": str(item.get("error") or "")[:250] or None,
            })
        if not log_status:
            return {"ok": False, "available": True, "error": "Collector returned no per-log access status."}
        success_count = sum(1 for item in log_status if item["ok"])
        return {
            "ok": success_count > 0, "available": True, "events": clean_events,
            "logs": log_status, "collected_at": str(payload.get("collected_at") or ""),
            "partial": success_count < len(LOGS),
            "error": None if success_count else "No configured Windows event logs could be read. Check the per-log errors.",
        }
    except (ValueError, json.JSONDecodeError, TypeError):
        return {"ok": False, "available": True,
                "error": "PowerShell returned an unreadable event metadata response."}
